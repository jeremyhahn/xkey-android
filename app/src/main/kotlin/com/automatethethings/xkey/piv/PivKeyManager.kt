/*
 * Copyright (c) 2025 Jeremy Hahn
 * Copyright (c) 2025 Automate The Things, LLC
 *
 * This file is part of xKey.
 *
 * xKey is dual-licensed:
 *
 * 1. GNU Affero General Public License v3.0 (AGPL-3.0)
 *    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
 *
 * 2. Commercial License
 *    Contact licensing@automatethethings.com for commercial licensing options.
 */
package com.automatethethings.xkey.piv

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.annotation.VisibleForTesting
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.crypto.KeySecurityLevel
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.remote.SharePermissionLedger
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.ByteArrayInputStream
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.ProviderException
import java.security.PublicKey
import java.security.Signature
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.Collections
import java.util.EnumMap
import javax.crypto.KeyAgreement

/**
 * Summary information about a PIV slot, combining the slot definition with
 * its current state from the database and Android Keystore.
 *
 * @property slot The PIV slot enum value.
 * @property algorithm The algorithm used for the key in this slot, or null if empty.
 * @property hasKey Whether a key has been generated in this slot.
 * @property hasCertificate Whether a certificate has been imported for this slot.
 * @property publicKeyDer DER-encoded public key bytes (SubjectPublicKeyInfo), or null.
 * @property createdAt Unix timestamp in milliseconds when the key was created, or null.
 * @property lastUsedAt Unix timestamp in milliseconds when the key was last used, or null.
 * @property useCount Number of times the key has been used.
 */
data class PivSlotInfo(
    val slot: PivSlot,
    val algorithm: PivAlgorithm?,
    val hasKey: Boolean,
    val hasCertificate: Boolean,
    val publicKeyDer: ByteArray?,
    val createdAt: Long?,
    val lastUsedAt: Long?,
    val useCount: Int
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PivSlotInfo) return false

        return slot == other.slot &&
            algorithm == other.algorithm &&
            hasKey == other.hasKey &&
            hasCertificate == other.hasCertificate &&
            publicKeyDer.contentEquals(other.publicKeyDer) &&
            createdAt == other.createdAt &&
            lastUsedAt == other.lastUsedAt &&
            useCount == other.useCount
    }

    override fun hashCode(): Int {
        var result = slot.hashCode()
        result = 31 * result + (algorithm?.hashCode() ?: 0)
        result = 31 * result + hasKey.hashCode()
        result = 31 * result + hasCertificate.hashCode()
        result = 31 * result + (publicKeyDer?.contentHashCode() ?: 0)
        result = 31 * result + (createdAt?.hashCode() ?: 0)
        result = 31 * result + (lastUsedAt?.hashCode() ?: 0)
        result = 31 * result + useCount
        return result
    }
}

/**
 * Extension to check if the [ByteArray] contents are equal, handling nulls.
 */
private fun ByteArray?.contentEquals(other: ByteArray?): Boolean {
    if (this === other) return true
    if (this == null || other == null) return false
    // Arrays.equals, not contentEquals: this extension shadows the stdlib one
    // for a ByteArray receiver, so `this.contentEquals(other)` resolved back to
    // here and recursed until the stack ran out. Comparing any two PivSlotInfo
    // values that both carry a public key threw StackOverflowError.
    return java.util.Arrays.equals(this, other)
}

/**
 * Prefix of every PIV slot's Android Keystore alias ([PivSlot.keystoreAlias]).
 * These keys belong to [PivKeyManager] and its `piv_slots` rows: the general
 * key paths neither list nor resolve them, so nothing outside [PivKeyManager]
 * can delete or replace a slot key behind its row.
 */
const val PIV_KEYSTORE_ALIAS_PREFIX = "xkey_piv_"

/**
 * Manages PIV smart card key slots using Android Keystore for key storage
 * and Room for metadata persistence.
 *
 * Keys are generated and stored in Android Keystore using the alias convention
 * `xkey_piv_{slotHex}` (e.g., `xkey_piv_9A` for the Authentication slot).
 * Certificate and usage metadata is stored in the Room `piv_slots` table via
 * [PivSlotDao]. The Keystore entry is the proof that a slot holds a key and
 * which key it is; the row's `hasKey` and `publicKeyDer` are a cache, so a
 * decision that depends on the slot key reads the Keystore.
 *
 * Supported operations:
 * - **Generate**: Create a new key pair in a PIV slot with a specified algorithm.
 * - **Import certificate**: Store an X.509 certificate for an existing slot key.
 * - **Sign**: Produce a digital signature using a slot's private key.
 * - **Agree**: X25519 key agreement with a slot's private key.
 * - **List**: Enumerate all slots and their current state.
 * - **Delete**: Destroy a key and remove its metadata.
 *
 * Ed25519 and X25519 keys exist only in secure hardware: on a device below
 * Android 13, or where a probe key the Keystore makes under a disposable
 * alias is not in the TEE or StrongBox, they are refused before the slot is
 * touched and are not in [availableAlgorithms]. A slot key the Keystore still
 * reports as software-backed (or whose level cannot be read) is removed and
 * refused. There is no software fallback.
 *
 * All operations that modify key material or perform cryptographic operations
 * are logged via [AuditLogger] for security auditing.
 *
 * @param pivSlotDao The Room DAO for persisting PIV slot metadata.
 * @param generateKeyPair Generates the slot's key pair under its Keystore
 *   alias, replacing any key there; the Android Keystore unless a test
 *   substitutes it.
 * @param sdkInt The platform API level curve 25519 keys are checked against.
 * @param securityLevelOf Reads the security level of the key under an alias,
 *   or null when it cannot be read; the Android Keystore's [KeyInfo] unless a
 *   test substitutes it.
 * @param probeSecurityLevel Reads the security level the Keystore gives a
 *   curve 25519 key, or null when it cannot make one; by default a probe key
 *   generated with [generateKeyPair] under a disposable alias, read with
 *   [securityLevelOf], always deleted, and kept for the process.
 */
class PivKeyManager(
    private val pivSlotDao: PivSlotDao,
    private val generateKeyPair: (alias: String, algorithm: PivAlgorithm) -> KeyPair = ::generateInAndroidKeystore,
    private val sdkInt: Int = Build.VERSION.SDK_INT,
    securityLevelOf: ((alias: String) -> KeySecurityLevel?)? = null,
    private val probeSecurityLevel: ((algorithm: PivAlgorithm) -> KeySecurityLevel?)? = null
) {

    // Opened on first use, so constructing a manager does not need the
    // AndroidKeyStore provider (JVM unit tests substitute it).
    private val keyStore: KeyStore by lazy { KeyStore.getInstance("AndroidKeyStore").apply { load(null) } }

    private val readSecurityLevel: (String) -> KeySecurityLevel? = securityLevelOf ?: ::keystoreSecurityLevel

    companion object {
        private const val TAG = "PivKeyManager"

        /**
         * One probe at a time for the process: probes of one algorithm share
         * an alias, and the GATT service and the PIV screens each build a
         * manager.
         */
        private val probeLock = Mutex()

        /** Each probed algorithm's level (null: the Keystore cannot make it), for the process. */
        private val probedLevels: MutableMap<PivAlgorithm, KeySecurityLevel?> =
            Collections.synchronizedMap(EnumMap(PivAlgorithm::class.java))

        /**
         * The disposable alias the Keystore probe for [algorithm] generates
         * under. It carries [PIV_KEYSTORE_ALIAS_PREFIX], so the general key
         * paths skip it, and no [PivSlot.keystoreAlias] (the prefix and a
         * two-character hex id) can equal it.
         */
        internal fun probeAlias(algorithm: PivAlgorithm): String =
            "${PIV_KEYSTORE_ALIAS_PREFIX}probe_${algorithm.name}"

        /** Drop the process's probe answers, so the next check probes again. */
        @VisibleForTesting
        internal fun forgetHardwareProbes() = probedLevels.clear()

        private fun KeySecurityLevel?.isSecureHardware(): Boolean =
            this == KeySecurityLevel.TEE || this == KeySecurityLevel.STRONGBOX
    }

    /**
     * The algorithms this device can make a PIV slot key with: the API level
     * allows it and, for Ed25519 and X25519, the Keystore's probe key is in
     * the TEE or StrongBox. The PIV screens offer exactly this list. The
     * first call for a curve may generate and delete a probe key, so call it
     * off the main thread.
     */
    suspend fun availableAlgorithms(): List<PivAlgorithm> = PivAlgorithm.entries.filter { algorithm ->
        algorithm.isAvailableOn(sdkInt) &&
            (!algorithm.isCurve25519 || hardwareSecurityLevel(algorithm).isSecureHardware())
    }

    /**
     * Refuse a curve 25519 [algorithm] whose probe key is not in secure
     * hardware. Runs before the slot's alias is touched, so a refused
     * generation leaves the slot's key, row and certificate as they were.
     */
    private suspend fun requireSecureHardware(algorithm: PivAlgorithm) {
        if (!algorithm.isCurve25519) return
        val level = hardwareSecurityLevel(algorithm)
        if (level.isSecureHardware()) return
        Log.w(TAG, "Refused ${algorithm.displayName} PIV key: the Keystore probe read $level")
        throw PivAlgorithmUnavailableException(
            algorithm,
            if (level == null) "the Keystore cannot make it in secure hardware" else "the Keystore makes ${level.wire} keys"
        )
    }

    /**
     * The security level the Keystore gives a curve 25519 [algorithm] key, or
     * null when it cannot make one: [probeSecurityLevel] when a test injects
     * it, otherwise [probeInKeystore], once per algorithm for the process.
     */
    private suspend fun hardwareSecurityLevel(algorithm: PivAlgorithm): KeySecurityLevel? {
        probeSecurityLevel?.let { probe -> return runCatching { probe(algorithm) }.getOrNull() }
        return probeLock.withLock {
            if (probedLevels.containsKey(algorithm)) {
                probedLevels[algorithm]
            } else {
                // A cancelled caller must not leave the probe key behind.
                withContext(NonCancellable) { probeInKeystore(algorithm) }.also { probedLevels[algorithm] = it }
            }
        }
    }

    /**
     * Generate [algorithm] under its [probeAlias], read the key's security
     * level with the same reader as a slot key, and always delete the probe
     * key. Null when the Keystore cannot make the key or its level cannot be
     * read.
     */
    private fun probeInKeystore(algorithm: PivAlgorithm): KeySecurityLevel? {
        val alias = probeAlias(algorithm)
        return try {
            generateKeyPair(alias, algorithm)
            readSecurityLevel(alias)
        } catch (e: Exception) {
            Log.w(TAG, "Keystore probe for ${algorithm.displayName} failed: ${e.message}")
            null
        } finally {
            runCatching { keyStore.deleteEntry(alias) }
                .onFailure { Log.w(TAG, "Could not remove the ${algorithm.displayName} probe key: ${it.message}") }
        }
    }

    /**
     * Generate a new key pair in the specified PIV slot.
     *
     * Creates a key pair in Android Keystore using the slot's alias convention
     * and persists the metadata (algorithm, public key DER) in Room. If a key
     * already exists in the slot, it is overwritten.
     *
     * The key is configured with:
     * - ECDSA and RSA: SIGN and VERIFY, SHA-256 (and SHA-384 for EC); RSA uses PKCS1 padding
     * - Ed25519: SIGN and VERIFY over the raw message (no digest)
     * - X25519: AGREE_KEY only
     *
     * @param slot The PIV slot to generate the key in.
     * @param algorithm The cryptographic algorithm for key generation.
     * @return [PivSlotInfo] describing the newly generated key.
     * @throws PivAlgorithmUnavailableException If [algorithm] needs Android 13
     *   secure hardware this device does not have.
     * @throws java.security.GeneralSecurityException If key generation fails.
     */
    suspend fun generateKey(slot: PivSlot, algorithm: PivAlgorithm): PivSlotInfo {
        // Refused before the slot lock and before the alias is touched: the
        // slot keeps whatever key it holds.
        if (!algorithm.isAvailableOn(sdkInt)) {
            throw PivAlgorithmUnavailableException(algorithm, "this device runs API level $sdkInt")
        }
        return PivSlotLocks.withSlot(slot) {
            // Before the revoke and the slot's alias: a curve the Keystore
            // cannot make in secure hardware never replaces the slot's key.
            requireSecureHardware(algorithm)
            generateKeyLocked(slot, algorithm)
        }
    }

    private suspend fun generateKeyLocked(slot: PivSlot, algorithm: PivAlgorithm): PivSlotInfo {
        val alias = slot.keystoreAlias

        // The slot's alias is the key ID KeyStoreSyncManager discovers it by, so
        // a share of it may be waiting: replacing the key is a revoke of that ID.
        val (publicKeyDer, now) = SharePermissionLedger.revoking(alias) {
            // This replaces any key the slot held: from here the row must be made
            // to describe the new key, or the slot must be emptied.
            val keyPair = try {
                generateKeyPair(alias, algorithm)
            } catch (e: Exception) {
                // A Keystore that cannot make the curve leaves the alias as it was.
                if (algorithm.isCurve25519 && (e is GeneralSecurityException || e is ProviderException ||
                        e is UnsupportedOperationException || e is IllegalArgumentException)
                ) {
                    throw PivAlgorithmUnavailableException(algorithm, "the Keystore cannot create it (${e.message})", e)
                }
                throw e
            }

            if (algorithm.isCurve25519) {
                // Backstop: the probe passed, yet this key is not in secure
                // hardware. The slot's key is already replaced, so the slot
                // is emptied rather than left holding a software key.
                val level = runCatching { readSecurityLevel(alias) }.getOrNull()
                if (!level.isSecureHardware()) {
                    withContext(NonCancellable) { discardUnrecordedKey(slot) }
                    Log.w(TAG, "Refused ${algorithm.displayName} key in PIV slot ${slot.hexId}: security level $level")
                    throw PivAlgorithmUnavailableException(
                        algorithm,
                        if (level == null) "the key's security level cannot be read" else "the Keystore made a ${level.wire} key"
                    )
                }
            }

            val publicKeyDer = keyPair.public.encoded
            val now = System.currentTimeMillis()

            // Persist metadata in Room
            val entity = PivSlotEntity(
                slotId = slot.hexId,
                algorithm = algorithm.name,
                publicKeyDer = publicKeyDer,
                hasKey = true,
                createdAt = now,
                lastUsedAt = null,
                useCount = 0
            )
            // A cancelled caller must not stop the upsert half way: the row would
            // keep the replaced key's public key and algorithm.
            withContext(NonCancellable) {
                try {
                    pivSlotDao.upsert(entity)
                } catch (e: Exception) {
                    discardUnrecordedKey(slot)
                    throw e
                }
            }
            publicKeyDer to now
        }

        // Log to audit system
        AuditLogger.logKeyCreated(
            keyId = alias,
            keyLabel = slot.label,
            keyType = "piv",
            algorithm = algorithm.displayName
        )

        Log.i(TAG, "Generated ${algorithm.displayName} key in PIV slot ${slot.hexId} (${slot.label})")

        return PivSlotInfo(
            slot = slot,
            algorithm = algorithm,
            hasKey = true,
            hasCertificate = false,
            publicKeyDer = publicKeyDer,
            createdAt = now,
            lastUsedAt = null,
            useCount = 0
        )
    }

    /**
     * Empty [slot] after its Keystore key was replaced but the row could not
     * be written, or the new key is not in secure hardware: the replaced key
     * is gone, and leaving the new one would leave a row describing a key the
     * slot no longer holds. Best effort; the caller rethrows the failure.
     */
    private suspend fun discardUnrecordedKey(slot: PivSlot) {
        runCatching { keyStore.deleteEntry(slot.keystoreAlias) }
            .onFailure { Log.w(TAG, "Could not remove unrecorded key from PIV slot ${slot.hexId}: ${it.message}") }
        runCatching { pivSlotDao.deleteBySlotId(slot.hexId) }
            .onFailure { Log.w(TAG, "Could not clear PIV slot ${slot.hexId} row: ${it.message}") }
    }

    /**
     * The security level of the Keystore key under [alias], read from its
     * [KeyInfo], or null when the key or its [KeyInfo] cannot be read.
     */
    private fun keystoreSecurityLevel(alias: String): KeySecurityLevel? {
        val key = keyStore.getKey(alias, null) as? PrivateKey ?: return null
        val info = runCatching {
            KeyFactory.getInstance(key.algorithm, "AndroidKeyStore").getKeySpec(key, KeyInfo::class.java)
        }.recoverCatching {
            KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").getKeySpec(key, KeyInfo::class.java)
        }.getOrNull() ?: return null
        val keyInfoLevel = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) info.securityLevel else -1
        @Suppress("DEPRECATION")
        val insideSecureHardware = info.isInsideSecureHardware
        return KeystoreManager.securityLevelOf(Build.VERSION.SDK_INT, keyInfoLevel, insideSecureHardware, false)
    }

    /**
     * The SubjectPublicKeyInfo DER of the key the Android Keystore holds for
     * [slot], or null if the alias is gone. This, not the `piv_slots` row, is
     * the proof of the slot's key.
     */
    private fun liveSlotPublicKey(slot: PivSlot): ByteArray? {
        val alias = slot.keystoreAlias
        if (!keyStore.containsAlias(alias)) return null
        return keyStore.getCertificate(alias)?.publicKey?.encoded
    }

    /**
     * Import an X.509 certificate for an existing PIV slot.
     *
     * Parses [certDer] as exactly one DER-encoded X.509 certificate and stores
     * it in the Room database only when its SubjectPublicKeyInfo equals the
     * public key the Android Keystore holds for the slot, read under the slot
     * lock. The row's cached public key is not trusted; it is refreshed from
     * the Keystore on success, and the import is audited with the slot and the
     * certificate's subject. A refused import stores and audits nothing: a
     * certificate imported earlier stays.
     *
     * @param slot The PIV slot to import the certificate into.
     * @param certDer DER-encoded X.509 certificate bytes.
     * @throws PivSlotEmptyException If the slot does not contain a key.
     * @throws PivCertificateNotParseableException If [certDer] is not one DER certificate.
     * @throws PivCertificateKeyMismatchException If the certificate is for another key.
     */
    suspend fun importCertificate(slot: PivSlot, certDer: ByteArray) =
        PivSlotLocks.withSlot(slot) { importCertificateLocked(slot, certDer) }

    private suspend fun importCertificateLocked(slot: PivSlot, certDer: ByteArray) {
        val existing = pivSlotDao.getBySlotId(slot.hexId)
            ?: throw PivSlotEmptyException(slot)
        if (!existing.hasKey) throw PivSlotEmptyException(slot)
        val slotPublicKey = liveSlotPublicKey(slot) ?: run {
            Log.w(TAG, "PIV slot ${slot.hexId} row claims a key the Keystore does not hold")
            throw PivSlotEmptyException(slot)
        }

        val certificate = parseCertificate(certDer)
        if (!certificate.publicKey.encoded.contentEquals(slotPublicKey)) {
            Log.w(TAG, "Refused certificate for PIV slot ${slot.hexId}: its key is not the slot's key")
            throw PivCertificateKeyMismatchException(slot)
        }

        val updated = existing.copy(publicKeyDer = slotPublicKey, certificateDer = certDer)
        pivSlotDao.upsert(updated)

        AuditLogger.logPivCertImported(slot.hexId, certificate.subjectX500Principal.name)

        Log.i(TAG, "Imported certificate for PIV slot ${slot.hexId} (${slot.label})")
    }

    /**
     * Parse [certDer] as one X.509 certificate in DER. PEM text, a chain and
     * trailing bytes are refused: the parsed certificate must re-encode to
     * exactly the input.
     */
    private fun parseCertificate(certDer: ByteArray): X509Certificate {
        val certificate = try {
            CertificateFactory.getInstance("X.509")
                .generateCertificate(ByteArrayInputStream(certDer)) as? X509Certificate
        } catch (e: CertificateException) {
            throw PivCertificateNotParseableException("Not an X.509 certificate: ${e.message}", e)
        } catch (e: IllegalArgumentException) {
            // Some providers throw this on malformed ASN.1 rather than a CertificateException.
            throw PivCertificateNotParseableException("Not an X.509 certificate: ${e.message}", e)
        } ?: throw PivCertificateNotParseableException("Not an X.509 certificate")

        val reencoded = try {
            certificate.encoded
        } catch (e: CertificateException) {
            throw PivCertificateNotParseableException("Not an X.509 certificate: ${e.message}", e)
        }
        if (!java.util.Arrays.equals(reencoded, certDer)) {
            throw PivCertificateNotParseableException("Certificate is not a single DER-encoded X.509 certificate")
        }
        return certificate
    }

    /**
     * List all PIV slots and their current state.
     *
     * Returns information for every slot that has a database entry. Slots
     * without entries (never used) are not included. `hasKey` and
     * `publicKeyDer` come from the Android Keystore: a row whose alias is gone
     * is reported without a key.
     *
     * Each slot is read under its [PivSlotLocks] lock, and its row is read
     * again once the lock is held, so the algorithm, certificate flag and
     * public key all describe one generation of the slot even when another
     * manager regenerates it during the listing.
     *
     * @return List of [PivSlotInfo] for all slots with database entries.
     */
    suspend fun listSlots(): List<PivSlotInfo> {
        return pivSlotDao.getAll().mapNotNull { listed ->
            val slot = PivSlot.fromHexId(listed.slotId) ?: return@mapNotNull null
            PivSlotLocks.withSlot(slot) {
                val entity = pivSlotDao.getBySlotId(slot.hexId) ?: return@withSlot null
                val algorithm = PivAlgorithm.fromStoredName(entity.algorithm)
                val livePublicKey = if (entity.hasKey) liveSlotPublicKey(slot) else null
                PivSlotInfo(
                    slot = slot,
                    algorithm = algorithm,
                    hasKey = livePublicKey != null,
                    hasCertificate = entity.certificateDer != null,
                    publicKeyDer = livePublicKey,
                    createdAt = entity.createdAt,
                    lastUsedAt = entity.lastUsedAt,
                    useCount = entity.useCount
                )
            }
        }
    }

    /**
     * The algorithm the `piv_slots` row records for [slot], or null when the
     * slot has no row or the row names no known algorithm.
     */
    private suspend fun recordedAlgorithm(slot: PivSlot): PivAlgorithm? =
        PivAlgorithm.fromStoredName(pivSlotDao.getBySlotId(slot.hexId)?.algorithm)

    /**
     * Sign data using the private key in the specified PIV slot.
     *
     * Retrieves the private key from Android Keystore and produces a digital
     * signature with the slot's recorded algorithm:
     * - ES256: SHA256withECDSA; ES384: SHA384withECDSA
     * - RS2048: SHA256withRSA
     * - ED25519: Ed25519 over the raw [data] (no pre-hash)
     *
     * An X25519 key cannot sign and is refused. A caller-supplied [algorithm]
     * must be the slot's; it is used only for a slot whose row records none.
     *
     * Records the usage in the database and logs the operation to the audit system.
     *
     * @param slot The PIV slot containing the signing key.
     * @param data The data to sign.
     * @param algorithm The algorithm the caller expects, or null for the slot's.
     * @return The signature bytes.
     * @throws PivAlgorithmMismatchException If the slot's key is X25519 or not [algorithm].
     * @throws IllegalStateException If the slot does not contain a key in Android Keystore.
     * @throws java.security.GeneralSecurityException If the signing operation fails.
     */
    suspend fun sign(slot: PivSlot, data: ByteArray, algorithm: PivAlgorithm? = null): ByteArray =
        PivSlotLocks.withSlot(slot) { signLocked(slot, data, algorithm) }

    private suspend fun signLocked(slot: PivSlot, data: ByteArray, algorithm: PivAlgorithm?): ByteArray {
        val alias = slot.keystoreAlias
        val recorded = recordedAlgorithm(slot)
        // A slot without a recorded algorithm predates the row; the legacy
        // default is ES256.
        val effective = recorded ?: algorithm ?: PivAlgorithm.ES256
        if (!effective.canSign) {
            throw PivAlgorithmMismatchException("${effective.displayName} keys cannot sign")
        }
        if (algorithm != null && algorithm != effective) {
            throw PivAlgorithmMismatchException(
                "PIV slot ${slot.hexId} holds a ${effective.displayName} key, not ${algorithm.displayName}"
            )
        }

        val privateKey = keyStore.getKey(alias, null)
            ?: throw IllegalStateException("No key found in Android Keystore for PIV slot ${slot.hexId} (${slot.label})")

        val signatureAlgorithm = signatureAlgorithmOf(effective)

        val startTime = System.currentTimeMillis()
        val signature = Signature.getInstance(signatureAlgorithm)
        signature.initSign(privateKey as PrivateKey)
        signature.update(data)
        val signatureBytes = signature.sign()
        val durationMs = System.currentTimeMillis() - startTime

        // Record usage in Room
        pivSlotDao.recordUsage(slot.hexId)

        // Log to audit system
        AuditLogger.logSigningRequest(
            keyId = alias,
            keyLabel = slot.label,
            keyType = "piv",
            algorithm = signatureAlgorithm,
            success = true,
            durationMs = durationMs
        )

        Log.d(TAG, "Signed ${data.size} bytes with PIV slot ${slot.hexId} in ${durationMs}ms")

        return signatureBytes
    }

    private fun signatureAlgorithmOf(algorithm: PivAlgorithm): String = when (algorithm) {
        PivAlgorithm.ES256 -> "SHA256withECDSA"
        PivAlgorithm.ES384 -> "SHA384withECDSA"
        PivAlgorithm.RS2048, PivAlgorithm.RS3072, PivAlgorithm.RS4096 -> "SHA256withRSA"
        PivAlgorithm.ED25519 -> "Ed25519"
        PivAlgorithm.X25519 -> throw PivAlgorithmMismatchException("X25519 keys cannot sign")
    }

    /**
     * X25519 key agreement between the slot's private key and a peer's raw
     * 32-byte public key (RFC 7748), as a YubiKey's GENERAL AUTHENTICATE
     * key agreement returns it.
     *
     * Records the usage in the database and logs the operation to the audit system.
     *
     * @param slot The PIV slot holding an X25519 key.
     * @param peerPublicKeyRaw32 The peer's raw X25519 public key.
     * @return The 32-byte shared secret.
     * @throws IllegalArgumentException If the peer key is not 32 bytes, is all
     *   zeros, or the slot's key is not X25519 ([PivAlgorithmMismatchException]).
     * @throws PivSlotEmptyException If the slot holds no key.
     * @throws java.security.GeneralSecurityException If the agreement fails.
     */
    suspend fun agree(slot: PivSlot, peerPublicKeyRaw32: ByteArray): ByteArray {
        require(peerPublicKeyRaw32.size == PivPublicKeyEncoding.CURVE25519_KEY_SIZE) {
            "X25519 peer key is ${peerPublicKeyRaw32.size} bytes, not ${PivPublicKeyEncoding.CURVE25519_KEY_SIZE}"
        }
        require(peerPublicKeyRaw32.any { it != 0.toByte() }) { "X25519 peer key is all zeros" }
        return PivSlotLocks.withSlot(slot) { agreeLocked(slot, peerPublicKeyRaw32) }
    }

    private suspend fun agreeLocked(slot: PivSlot, peerPublicKeyRaw32: ByteArray): ByteArray {
        val recorded = recordedAlgorithm(slot)
        if (recorded != PivAlgorithm.X25519) {
            throw PivAlgorithmMismatchException(
                "PIV slot ${slot.hexId} holds ${recorded?.displayName ?: "no"} key, not X25519; it cannot agree"
            )
        }

        val alias = slot.keystoreAlias
        val privateKey = keyStore.getKey(alias, null) as? PrivateKey ?: throw PivSlotEmptyException(slot)
        val peerKey = x25519PublicKey(peerPublicKeyRaw32)

        val startTime = System.currentTimeMillis()
        val secret = KeyAgreement.getInstance("XDH").run {
            init(privateKey)
            doPhase(peerKey, true)
            generateSecret()
        }
        val durationMs = System.currentTimeMillis() - startTime
        if (secret.all { it == 0.toByte() }) {
            // RFC 7748 section 6.1: a low-order peer point yields all zeros.
            throw IllegalArgumentException("X25519 peer key is a low-order point")
        }

        pivSlotDao.recordUsage(slot.hexId)

        AuditLogger.logKeyUsed(
            keyId = alias,
            keyLabel = slot.label,
            keyType = "piv",
            operation = "key agreement",
            success = true,
            durationMs = durationMs
        )

        Log.d(TAG, "X25519 agreement with PIV slot ${slot.hexId} in ${durationMs}ms")

        return secret
    }

    private fun x25519PublicKey(raw32: ByteArray): PublicKey {
        val spec = X509EncodedKeySpec(PivPublicKeyEncoding.x25519Spki(raw32))
        return runCatching { KeyFactory.getInstance("XDH").generatePublic(spec) }
            .recoverCatching { KeyFactory.getInstance("X25519").generatePublic(spec) }
            .getOrThrow()
    }

    /**
     * Get the DER-encoded certificate for a PIV slot.
     *
     * Returns the certificate that was previously imported via [importCertificate],
     * or the auto-generated self-signed certificate from Android Keystore if no
     * explicit certificate was imported. An X25519 key cannot sign, so the
     * Keystore's placeholder certificate for it carries no valid signature: an
     * X25519 slot without an imported certificate has none.
     *
     * @param slot The PIV slot to get the certificate for.
     * @return DER-encoded certificate bytes, or null if the slot has no key.
     */
    suspend fun getCertificate(slot: PivSlot): ByteArray? =
        PivSlotLocks.withSlot(slot) { getCertificateLocked(slot) }

    private suspend fun getCertificateLocked(slot: PivSlot): ByteArray? {
        // First check for an explicitly imported certificate in Room
        val entity = pivSlotDao.getBySlotId(slot.hexId)
        if (entity?.certificateDer != null) {
            return entity.certificateDer
        }
        if (PivAlgorithm.fromStoredName(entity?.algorithm) == PivAlgorithm.X25519) {
            return null
        }

        // Fall back to the Android Keystore auto-generated certificate
        val alias = slot.keystoreAlias
        val cert = keyStore.getCertificate(alias) as? X509Certificate
        return cert?.encoded
    }

    /**
     * Get the DER-encoded public key for a PIV slot.
     *
     * Returns the SubjectPublicKeyInfo (SPKI) DER encoding of the public key
     * the Android Keystore holds for the slot. The `piv_slots` copy is not
     * consulted: it can name a key the slot no longer holds.
     *
     * @param slot The PIV slot to get the public key for.
     * @return DER-encoded public key bytes, or null if the slot has no key.
     */
    suspend fun getPublicKey(slot: PivSlot): ByteArray? = liveSlotPublicKey(slot)

    /**
     * Delete a key from a PIV slot.
     *
     * Removes the key from Android Keystore and deletes the metadata from Room.
     * This operation is irreversible.
     *
     * @param slot The PIV slot to clear.
     */
    suspend fun deleteKey(slot: PivSlot) =
        PivSlotLocks.withSlot(slot) { deleteKeyLocked(slot) }

    private suspend fun deleteKeyLocked(slot: PivSlot) {
        val alias = slot.keystoreAlias

        // The slot's alias is the key ID KeyStoreSyncManager discovers it by, so
        // a share of it may be waiting: removing the key is a revoke of that ID.
        SharePermissionLedger.revoking(alias) {
            // Remove from Android Keystore
            if (keyStore.containsAlias(alias)) {
                keyStore.deleteEntry(alias)
            }

            // Remove metadata from Room
            pivSlotDao.deleteBySlotId(slot.hexId)
        }

        // Log to audit system
        AuditLogger.logKeyDeleted(
            keyId = alias,
            keyLabel = slot.label,
            keyType = "piv"
        )

        Log.i(TAG, "Deleted key from PIV slot ${slot.hexId} (${slot.label})")
    }
}

/**
 * One lock per PIV slot for the whole process.
 *
 * [PivKeyManager.generateKey], [PivKeyManager.deleteKey] and
 * [PivKeyManager.importCertificate] each read and then write a slot's
 * Keystore entry and `piv_slots` row. The GATT service and the PIV screens
 * build their own [PivKeyManager], and GATT requests run concurrently, so the
 * lock lives here rather than on an instance: an import that has checked a
 * certificate against key A must finish before another caller can replace or
 * delete A, or its upsert would bring A's row back. [PivKeyManager.listSlots]
 * reads each slot under its lock so a listing never mixes two generations.
 * [PivKeyManager.sign], [PivKeyManager.agree] and
 * [PivKeyManager.getCertificate] read the row's algorithm or certificate and
 * the Keystore entry for one answer, so they hold the lock too: a generation
 * that has replaced the Keystore key but not yet written its row is waited
 * for. [PivKeyManager.getPublicKey] reads only the Keystore and takes no
 * lock. Different slots do not wait for each other. The lock is not
 * reentrant: a locked body never calls a public locking method.
 */
internal object PivSlotLocks {
    private val locks: Map<PivSlot, Mutex> = PivSlot.entries.associateWith { Mutex() }

    suspend fun <T> withSlot(slot: PivSlot, block: suspend () -> T): T =
        locks.getValue(slot).withLock { block() }
}

/**
 * The PIV slot holds no key, so there is nothing a certificate could belong to.
 * The handler reports it as `PIV_SLOT_NOT_FOUND`.
 */
class PivSlotEmptyException(slot: PivSlot) :
    IllegalStateException("No key exists in PIV slot ${slot.hexId} (${slot.label})")

/**
 * [algorithm] cannot be generated here: it needs Android 13 and a Keystore in
 * secure hardware, and xKey never makes a software PIV key. The slot keeps
 * the key it held, unless a generated key turned out not to be in secure
 * hardware, in which case the slot is emptied. The handler reports it as
 * `FEATURE_UNAVAILABLE`.
 */
class PivAlgorithmUnavailableException(
    val algorithm: PivAlgorithm,
    reason: String,
    cause: Throwable? = null
) : GeneralSecurityException("${algorithm.displayName} PIV keys need Android 13 secure hardware: $reason", cause)

/**
 * The slot's key cannot do what was asked: an X25519 key asked to sign, a
 * signing key asked to agree, or a caller naming another algorithm than the
 * slot's. The handler reports it as `INVALID_ALGORITHM`.
 */
class PivAlgorithmMismatchException(message: String) : IllegalArgumentException(message)

/**
 * A certificate offered for a PIV slot was refused and nothing was stored.
 * The handler reports every subclass as `INVALID_PARAMS`.
 */
sealed class PivCertificateRejectedException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

/** The bytes are not exactly one DER-encoded X.509 certificate. */
class PivCertificateNotParseableException(message: String, cause: Throwable? = null) :
    PivCertificateRejectedException(message, cause)

/** The certificate's SubjectPublicKeyInfo is not the slot key's public key. */
class PivCertificateKeyMismatchException(slot: PivSlot) :
    PivCertificateRejectedException(
        "Certificate public key does not match the key in PIV slot ${slot.hexId} (${slot.label})"
    )

/**
 * Generates a key pair in Android Keystore under [alias], overwriting any key
 * there.
 *
 * The key is configured with:
 * - ECDSA: SIGN and VERIFY, SHA-256 and SHA-384
 * - RSA: SIGN and VERIFY, SHA-256, PKCS1 padding
 * - Ed25519: SIGN and VERIFY, no digest (EdDSA signs the raw message)
 * - X25519: AGREE_KEY
 *
 * Curve 25519 keys are never requested in StrongBox, which does not support
 * them; the TEE makes them.
 */
private fun generateInAndroidKeystore(alias: String, algorithm: PivAlgorithm): KeyPair {
    // Build key generation parameters based on the algorithm
    val paramSpec = when {
        algorithm.isCurve25519 -> {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
                throw ProviderException("${algorithm.displayName} needs API level 33")
            }
            curve25519Spec(alias, algorithm)
        }
        algorithm.keyAlgorithm == "EC" -> {
            KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA384)
                .setKeySize(algorithm.keySizeBits)
                .build()
        }
        algorithm.keyAlgorithm == "RSA" -> {
            KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                .setKeySize(algorithm.keySizeBits)
                .build()
        }
        else -> throw IllegalArgumentException("Unsupported key algorithm: ${algorithm.keyAlgorithm}")
    }

    // Generate the key pair in Android Keystore
    val keyPairGenerator = KeyPairGenerator.getInstance(
        algorithm.keyAlgorithm,
        "AndroidKeyStore"
    )
    keyPairGenerator.initialize(paramSpec)
    return keyPairGenerator.generateKeyPair()
}

/** The Keystore spec for an Ed25519 or X25519 key under [alias] (API 33). */
@RequiresApi(Build.VERSION_CODES.TIRAMISU)
private fun curve25519Spec(alias: String, algorithm: PivAlgorithm): KeyGenParameterSpec =
    when (algorithm) {
        PivAlgorithm.ED25519 -> KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec("ed25519"))
            .setDigests(KeyProperties.DIGEST_NONE)
            .build()
        PivAlgorithm.X25519 -> KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_AGREE_KEY)
            .setAlgorithmParameterSpec(ECGenParameterSpec("x25519"))
            .build()
        else -> throw IllegalArgumentException("${algorithm.displayName} is not a curve 25519 algorithm")
    }
