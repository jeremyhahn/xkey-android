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

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import com.automatethethings.xkey.audit.AuditLogger
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.ByteArrayInputStream
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

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
 * - **List**: Enumerate all slots and their current state.
 * - **Delete**: Destroy a key and remove its metadata.
 *
 * All operations that modify key material or perform cryptographic operations
 * are logged via [AuditLogger] for security auditing.
 *
 * @param pivSlotDao The Room DAO for persisting PIV slot metadata.
 */
class PivKeyManager(private val pivSlotDao: PivSlotDao) {

    // Opened on first use, so constructing a manager does not need the
    // AndroidKeyStore provider (JVM unit tests substitute it).
    private val keyStore: KeyStore by lazy { KeyStore.getInstance("AndroidKeyStore").apply { load(null) } }

    companion object {
        private const val TAG = "PivKeyManager"
    }

    /**
     * Generate a new key pair in the specified PIV slot.
     *
     * Creates a key pair in Android Keystore using the slot's alias convention
     * and persists the metadata (algorithm, public key DER) in Room. If a key
     * already exists in the slot, it is overwritten.
     *
     * The key is configured with:
     * - Purpose: SIGN and VERIFY
     * - Digest: SHA-256 (EC) or SHA-256 (RSA)
     * - For EC keys: no padding required
     * - For RSA keys: PKCS1 padding
     *
     * @param slot The PIV slot to generate the key in.
     * @param algorithm The cryptographic algorithm for key generation.
     * @return [PivSlotInfo] describing the newly generated key.
     * @throws java.security.GeneralSecurityException If key generation fails.
     */
    suspend fun generateKey(slot: PivSlot, algorithm: PivAlgorithm): PivSlotInfo =
        PivSlotLocks.withSlot(slot) { generateKeyLocked(slot, algorithm) }

    private suspend fun generateKeyLocked(slot: PivSlot, algorithm: PivAlgorithm): PivSlotInfo {
        val alias = slot.keystoreAlias

        // Build key generation parameters based on the algorithm
        val paramSpec = when (algorithm.keyAlgorithm) {
            "EC" -> {
                KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
                )
                    .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA384)
                    .setKeySize(algorithm.keySizeBits)
                    .build()
            }
            "RSA" -> {
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
        // This replaces any key the slot held: from here the row must be made
        // to describe the new key, or the slot must be emptied.
        val keyPair = keyPairGenerator.generateKeyPair()

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
     * be written: the replaced key is gone, and leaving the new one would
     * leave a row describing a key the slot no longer holds. Best effort; the
     * caller rethrows the original failure.
     */
    private suspend fun discardUnrecordedKey(slot: PivSlot) {
        runCatching { keyStore.deleteEntry(slot.keystoreAlias) }
            .onFailure { Log.w(TAG, "Could not remove unrecorded key from PIV slot ${slot.hexId}: ${it.message}") }
        runCatching { pivSlotDao.deleteBySlotId(slot.hexId) }
            .onFailure { Log.w(TAG, "Could not clear PIV slot ${slot.hexId} row: ${it.message}") }
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
                val algorithm = entity.algorithm?.let { name ->
                    try {
                        PivAlgorithm.valueOf(name)
                    } catch (_: IllegalArgumentException) {
                        null
                    }
                }
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
     * Sign data using the private key in the specified PIV slot.
     *
     * Retrieves the private key from Android Keystore and produces a digital
     * signature. The signature algorithm is determined by the key type:
     * - EC keys: SHA256withECDSA (ES256) or SHA384withECDSA (ES384)
     * - RSA keys: SHA256withRSA
     *
     * Records the usage in the database and logs the operation to the audit system.
     *
     * @param slot The PIV slot containing the signing key.
     * @param data The data to sign.
     * @param algorithm The algorithm to use for signing (must match the key's algorithm).
     * @return The signature bytes.
     * @throws IllegalStateException If the slot does not contain a key in Android Keystore.
     * @throws java.security.GeneralSecurityException If the signing operation fails.
     */
    suspend fun sign(slot: PivSlot, data: ByteArray, algorithm: PivAlgorithm): ByteArray {
        val alias = slot.keystoreAlias

        val privateKey = keyStore.getKey(alias, null)
            ?: throw IllegalStateException("No key found in Android Keystore for PIV slot ${slot.hexId} (${slot.label})")

        val signatureAlgorithm = when (algorithm) {
            PivAlgorithm.ES256 -> "SHA256withECDSA"
            PivAlgorithm.ES384 -> "SHA384withECDSA"
            PivAlgorithm.RS2048 -> "SHA256withRSA"
        }

        val startTime = System.currentTimeMillis()
        val signature = Signature.getInstance(signatureAlgorithm)
        signature.initSign(privateKey as java.security.PrivateKey)
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

    /**
     * Get the DER-encoded certificate for a PIV slot.
     *
     * Returns the certificate that was previously imported via [importCertificate],
     * or the auto-generated self-signed certificate from Android Keystore if no
     * explicit certificate was imported.
     *
     * @param slot The PIV slot to get the certificate for.
     * @return DER-encoded certificate bytes, or null if the slot has no key.
     */
    suspend fun getCertificate(slot: PivSlot): ByteArray? {
        // First check for an explicitly imported certificate in Room
        val entity = pivSlotDao.getBySlotId(slot.hexId)
        if (entity?.certificateDer != null) {
            return entity.certificateDer
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

        // Remove from Android Keystore
        if (keyStore.containsAlias(alias)) {
            keyStore.deleteEntry(alias)
        }

        // Remove metadata from Room
        pivSlotDao.deleteBySlotId(slot.hexId)

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
 * Different slots do not wait for each other; signing and the getters take
 * no lock.
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
