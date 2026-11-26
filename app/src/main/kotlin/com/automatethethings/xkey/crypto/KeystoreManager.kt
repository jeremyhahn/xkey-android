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
package com.automatethethings.xkey.crypto

import android.content.Context
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.annotation.ChecksSdkIntAtLeast
import androidx.annotation.RequiresApi
import androidx.annotation.VisibleForTesting
import androidx.biometric.BiometricPrompt
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.piv.PIV_KEYSTORE_ALIAS_PREFIX
import com.automatethethings.xkey.storage.entity.KeyEntity
import java.security.Key
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.cert.Certificate
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.InvalidKeySpecException
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

/**
 * Where a key's material lives, read from the key's own [KeyInfo].
 *
 * @property wire The `securityLevel` value on the wire.
 */
enum class KeySecurityLevel(val wire: String) {
    SOFTWARE("software"),
    TEE("tee"),
    STRONGBOX("strongbox")
}

/**
 * The Keystore entry [alias] exists but its [KeyInfo] cannot be read, so its
 * security level is unknown. Never reported as [KeySecurityLevel.SOFTWARE].
 */
class KeyInfoUnavailableException(val alias: String, cause: Throwable?) :
    KeyStoreException("Cannot read the KeyInfo of $alias", cause)

/**
 * What a key-presence probe of one namespace found (#255 review r5): the key
 * is there, is not there, or the store holding it cannot be read. An
 * unreadable store is never absent.
 */
enum class KeyPresence { PRESENT, ABSENT, UNREADABLE }

/**
 * What [KeystoreManager.discardGeneratedKey] did with a generated key (#255
 * review r8): deleted it, found it already absent, or failed, leaving it
 * possibly still held.
 */
enum class GeneratedKeyDiscard { DELETED, ABSENT, FAILED }

/**
 * A store a user key's material can live in (#255 review r6): the Android
 * Keystore, the Ed25519 preferences (legacy general Ed25519 keys) and the
 * [SoftwareKeyStore] (exportable general keys) and the [PqcSoftwareKeyStore]
 * (software ML-DSA keys). A credential lives only in the Keystore; a general
 * key in any of them ([KeystoreManager.backendsOf]).
 */
enum class KeyBackend { KEYSTORE, ED25519, SOFTWARE, PQC }

/**
 * The store that would hold [alias] cannot be read, so whether a key is there
 * is unknown. A resolution that meets it refuses: it never falls back to
 * another namespace, and nothing is used or exported through it.
 */
class KeyPresenceUnreadableException(val alias: String, cause: Throwable?) :
    KeyStoreException("Cannot read whether a key is stored under $alias", cause)

/**
 * A credential and a general key share [keyId] and a key row's public key
 * names neither, or both: which of them the row describes is unknown, and
 * a delete of the row is refused with nothing removed (#270 review).
 */
class KeyOwnershipUnknownException(val keyId: String) :
    java.security.GeneralSecurityException("Cannot tell which key under $keyId its row describes")

/**
 * A key row's public key as the row records it ([KeystoreManager.rowKeyKind]):
 * SPKI [der], [cose] or both. A passkey's row holds COSE only, as the
 * credential provider and the sync write it (#270 verify r2).
 */
class RowPublicKey(val der: ByteArray?, val cose: ByteArray?) {
    val isEmpty: Boolean get() = der == null && cose == null
}

/**
 * Removing a key's material failed: a Keystore entry that could not be
 * deleted, a software key store that could not be read, or a removal that did
 * not reach disk. The material may still be there, so a caller keeps the
 * key's metadata and reports an error, never "deleted" or "no such key".
 */
class KeyDeletionException(message: String, cause: Throwable? = null) : Exception(message, cause)

/** A MAC and the algorithm that computed it ("HMAC-SHA256" or "HMAC-SHA512"). */
class HmacResult(val mac: ByteArray, val algorithm: String)

/**
 * An RSA decryption's plaintext and the audit name of the OAEP
 * parameterisation the cipher ran with.
 */
class DecryptResult(val plaintext: ByteArray, val algorithm: String)

/**
 * Signs with a per-operation Keystore key (user authentication required for
 * every use): initialises a Signature with [jcaAlgorithm] for the key under
 * [alias], passes it to the biometric prompt as its CryptoObject, and once
 * the prompt authorizes it signs [data] with that same Signature. The one way
 * [KeystoreManager.signApproved] and [KeystoreManager.signApprovedMlDsa]
 * reach such a key.
 */
fun interface CryptoObjectSigner {
    suspend fun sign(alias: String, jcaAlgorithm: String, data: ByteArray): ByteArray
}

/**
 * Manages cryptographic keys in Android Keystore for FIDO2 operations.
 *
 * This class provides hardware-backed key storage with StrongBox support
 * when available, and integrates with biometric authentication for
 * signing operations. Keys stored here never leave the secure hardware,
 * providing strong protection against extraction.
 *
 * Features:
 * - Hardware-backed key storage (StrongBox when available)
 * - Biometric binding for signing operations
 * - ECDSA P-256 key generation (ES256 algorithm)
 * - COSE public key encoding for WebAuthn/FIDO2
 * - Key attestation support
 *
 * Usage:
 * ```kotlin
 * val manager = KeystoreManager(context)
 *
 * // Generate a new credential key
 * val cosePublicKey = manager.generateKey("credential-id-base64", requireBiometric = true)
 *
 * // Sign data with biometric verification
 * val signature = manager.sign("credential-id-base64", UserKeyKind.CREDENTIAL, dataHash, biometricHelper)
 * ```
 *
 * @param context Application context for checking device capabilities.
 * @param sdkInt The device API level, [Build.VERSION.SDK_INT] by default.
 */
class KeystoreManager(
    private val context: Context,
    /** The device API level; a JVM test stands in a device here. */
    @VisibleForTesting private val sdkInt: Int = Build.VERSION.SDK_INT,
    /** Software ML-DSA keys; hardware ones live in [keyStore] through [PqcHardware.backend]. */
    private val pqcStore: PqcSoftwareKeyStore = PqcSoftwareKeyStore.registerShared(context)
) {

    private val keyStore: KeyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply {
        load(null)
    }

    /**
     * Check if StrongBox secure hardware is available on this device.
     *
     * StrongBox is a hardware-backed keystore backed by a dedicated
     * secure element, providing the highest level of key protection.
     * Available on devices running Android 9 (API 28) and above with
     * appropriate hardware.
     *
     * @return true if StrongBox is available.
     */
    fun isStrongBoxAvailable(): Boolean {
        return if (sdkInt >= Build.VERSION_CODES.P) {
            context.packageManager.hasSystemFeature(
                PackageManager.FEATURE_STRONGBOX_KEYSTORE
            )
        } else {
            false
        }
    }

    /**
     * Generate a new ECDSA P-256 key for a FIDO2 credential.
     *
     * The key is stored in Android Keystore with the following properties:
     * - Algorithm: ECDSA with P-256 curve (ES256)
     * - Purpose: Signing only (cannot be used for encryption)
     * - User authentication: Required if [requireBiometric] is true
     * - Hardware backing: StrongBox if available, otherwise TEE
     *
     * @param credentialId Base64-encoded credential ID (used as key alias).
     * @param requireBiometric If true, biometric authentication is required
     *                         for every signing operation.
     * @param requireStrongBox If true, key generation fails if StrongBox
     *                         is not available.
     * @return COSE-encoded public key bytes for use in WebAuthn responses.
     * @throws KeyGenerationException if key generation fails.
     * @throws StrongBoxUnavailableException if StrongBox is required but unavailable.
     */
    suspend fun generateKey(
        credentialId: String,
        requireBiometric: Boolean = true,
        requireStrongBox: Boolean = false
    ): ByteArray {
        val alias = buildAlias(credentialId)

        // Check StrongBox requirement
        if (requireStrongBox && !isStrongBoxAvailable()) {
            throw StrongBoxUnavailableException()
        }

        // Delete existing key if present (credential regeneration)
        if (keyStore.containsAlias(alias)) {
            withAliasGate(alias) { keyStore.deleteEntry(alias) }
        }

        val strongBoxSpec = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && isStrongBoxAvailable()
        // Only making the key falls back to the TEE. Once a key exists, a
        // later failure propagates and the key is never generated a second time.
        val keyPair = try {
            val specBuilder = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN
            )
                .setAlgorithmParameterSpec(ECGenParameterSpec(EC_CURVE))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(requireBiometric)

            // Configure authentication parameters for API 30+
            if (requireBiometric) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    specBuilder.setUserAuthenticationParameters(
                        AUTH_TIMEOUT_SECONDS,
                        KeyProperties.AUTH_BIOMETRIC_STRONG
                    )
                } else {
                    @Suppress("DEPRECATION")
                    specBuilder.setUserAuthenticationValidityDurationSeconds(AUTH_TIMEOUT_SECONDS)
                }
            }

            // Try to use StrongBox if available
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && isStrongBoxAvailable()) {
                specBuilder.setIsStrongBoxBacked(true)
            }

            // Enable key attestation if supported
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                specBuilder.setAttestationChallenge(generateAttestationChallenge())
            }

            val keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                KEYSTORE_PROVIDER
            )
            keyPairGenerator.initialize(specBuilder.build())

            withAliasGate(alias) { keyPairGenerator.generateKeyPair() }
        } catch (e: Exception) {
            // StrongBox fallback: only when StrongBox is unavailable, and nothing has been generated yet.
            if (strongBoxSpec && !requireStrongBox && StrongBoxFallback.isStrongBoxUnavailable(e)) {
                return generateKeyWithoutStrongBox(alias, requireBiometric)
                    .also { markStrongBoxSpec(alias, false) }
            }
            throw KeyGenerationException("Failed to generate key", e)
        }

        return afterGeneration {
            markStrongBoxSpec(alias, strongBoxSpec)
            // The audit line only; callers read the level themselves and see a failure.
            val strongBoxBacked =
                runCatching { credentialSecurityLevel(credentialId) }.getOrNull() == KeySecurityLevel.STRONGBOX

            // Log key creation
            AuditLogger.logKeyCreated(
                keyId = credentialId,
                keyLabel = credentialId,
                keyType = "fido2",
                algorithm = "ES256",
                strongBox = strongBoxBacked
            )

            encodeCOSEPublicKey(keyPair.public)
        }
    }

    /**
     * Generate a key with configurable authentication duration.
     *
     * This method provides fine-grained control over how authentication is
     * handled for the generated key:
     * - authDurationSeconds == 0: Require authentication for every use (PER_OPERATION)
     * - authDurationSeconds > 0: Key remains unlocked for N seconds after authentication
     * - authDurationSeconds < 0: Key does not require authentication (UV disabled)
     *
     * @param credentialId Credential identifier (used as key alias).
     * @param authDurationSeconds Time in seconds the key remains unlocked after auth.
     *                           0 = require auth for every use (PER_OPERATION)
     *                          -1 = key does not require authentication (UV disabled)
     * @param requireStrongBox Whether to require StrongBox hardware.
     * @return COSE-encoded public key bytes for use in WebAuthn responses.
     * @throws KeyGenerationException if key generation fails.
     * @throws StrongBoxUnavailableException if StrongBox is required but unavailable.
     */
    suspend fun generateKeyWithAuthDuration(
        credentialId: String,
        authDurationSeconds: Int,
        requireStrongBox: Boolean = false
    ): ByteArray {
        val alias = buildAlias(credentialId)

        // Check StrongBox requirement
        if (requireStrongBox && !isStrongBoxAvailable()) {
            throw StrongBoxUnavailableException()
        }

        // Delete existing key if present (credential regeneration)
        if (keyStore.containsAlias(alias)) {
            withAliasGate(alias) { keyStore.deleteEntry(alias) }
        }

        val strongBoxSpec = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && isStrongBoxAvailable()
        // Only making the key falls back to the TEE. Once a key exists, a
        // later failure propagates and the key is never generated a second time.
        val keyPair = try {
            val specBuilder = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN
            )
                .setAlgorithmParameterSpec(ECGenParameterSpec(EC_CURVE))
                .setDigests(KeyProperties.DIGEST_SHA256)

            // Configure authentication based on authDurationSeconds
            when {
                authDurationSeconds < 0 -> {
                    // No authentication required (UV disabled)
                    specBuilder.setUserAuthenticationRequired(false)
                }
                authDurationSeconds == 0 -> {
                    // Require authentication for every use (PER_OPERATION)
                    specBuilder.setUserAuthenticationRequired(true)
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                        specBuilder.setUserAuthenticationParameters(
                            0, // 0 = require auth for every use
                            // Device credential counts as user verification, so
                            // passkeys still work on devices with only a PIN.
                            KeyProperties.AUTH_BIOMETRIC_STRONG or
                                KeyProperties.AUTH_DEVICE_CREDENTIAL
                        )
                    } else {
                        // On older APIs, -1 means require auth for every cryptographic operation
                        @Suppress("DEPRECATION")
                        specBuilder.setUserAuthenticationValidityDurationSeconds(-1)
                    }
                }
                else -> {
                    // Authentication valid for N seconds
                    specBuilder.setUserAuthenticationRequired(true)
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                        specBuilder.setUserAuthenticationParameters(
                            authDurationSeconds,
                            KeyProperties.AUTH_BIOMETRIC_STRONG or
                                KeyProperties.AUTH_DEVICE_CREDENTIAL
                        )
                    } else {
                        @Suppress("DEPRECATION")
                        specBuilder.setUserAuthenticationValidityDurationSeconds(authDurationSeconds)
                    }
                }
            }

            // Try to use StrongBox if available
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && isStrongBoxAvailable()) {
                specBuilder.setIsStrongBoxBacked(true)
            }

            // Enable key attestation if supported
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                specBuilder.setAttestationChallenge(generateAttestationChallenge())
            }

            val keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                KEYSTORE_PROVIDER
            )
            keyPairGenerator.initialize(specBuilder.build())

            withAliasGate(alias) { keyPairGenerator.generateKeyPair() }
        } catch (e: Exception) {
            // StrongBox fallback: only when StrongBox is unavailable, and nothing has been generated yet.
            if (strongBoxSpec && !requireStrongBox && StrongBoxFallback.isStrongBoxUnavailable(e)) {
                return generateKeyWithAuthDurationWithoutStrongBox(alias, authDurationSeconds)
                    .also { markStrongBoxSpec(alias, false) }
            }
            throw KeyGenerationException("Failed to generate key with auth duration", e)
        }

        return afterGeneration {
            markStrongBoxSpec(alias, strongBoxSpec)
            encodeCOSEPublicKey(keyPair.public)
        }
    }

    /**
     * Fallback key generation with auth duration without StrongBox.
     */
    private fun generateKeyWithAuthDurationWithoutStrongBox(
        alias: String,
        authDurationSeconds: Int
    ): ByteArray {
        try {
            val specBuilder = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN
            )
                .setAlgorithmParameterSpec(ECGenParameterSpec(EC_CURVE))
                .setDigests(KeyProperties.DIGEST_SHA256)

            // Configure authentication based on authDurationSeconds
            when {
                authDurationSeconds < 0 -> {
                    specBuilder.setUserAuthenticationRequired(false)
                }
                authDurationSeconds == 0 -> {
                    specBuilder.setUserAuthenticationRequired(true)
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                        specBuilder.setUserAuthenticationParameters(
                            0,
                            // Same policy as the StrongBox path: a device with
                            // only a PIN can still use the passkey.
                            KeyProperties.AUTH_BIOMETRIC_STRONG or
                                KeyProperties.AUTH_DEVICE_CREDENTIAL
                        )
                    } else {
                        @Suppress("DEPRECATION")
                        specBuilder.setUserAuthenticationValidityDurationSeconds(-1)
                    }
                }
                else -> {
                    specBuilder.setUserAuthenticationRequired(true)
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                        specBuilder.setUserAuthenticationParameters(
                            authDurationSeconds,
                            KeyProperties.AUTH_BIOMETRIC_STRONG or
                                KeyProperties.AUTH_DEVICE_CREDENTIAL
                        )
                    } else {
                        @Suppress("DEPRECATION")
                        specBuilder.setUserAuthenticationValidityDurationSeconds(authDurationSeconds)
                    }
                }
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                specBuilder.setAttestationChallenge(generateAttestationChallenge())
            }

            val keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                KEYSTORE_PROVIDER
            )
            keyPairGenerator.initialize(specBuilder.build())

            val keyPair = withAliasGate(alias) { keyPairGenerator.generateKeyPair() }
            return encodeCOSEPublicKey(keyPair.public)
        } catch (e: Exception) {
            throw KeyGenerationException("Failed to generate key with auth duration without StrongBox", e)
        }
    }

    /**
     * Fallback key generation without StrongBox.
     */
    private fun generateKeyWithoutStrongBox(
        alias: String,
        requireBiometric: Boolean
    ): ByteArray {
        try {
            val specBuilder = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN
            )
                .setAlgorithmParameterSpec(ECGenParameterSpec(EC_CURVE))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(requireBiometric)

            if (requireBiometric) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    specBuilder.setUserAuthenticationParameters(
                        AUTH_TIMEOUT_SECONDS,
                        KeyProperties.AUTH_BIOMETRIC_STRONG
                    )
                } else {
                    @Suppress("DEPRECATION")
                    specBuilder.setUserAuthenticationValidityDurationSeconds(AUTH_TIMEOUT_SECONDS)
                }
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                specBuilder.setAttestationChallenge(generateAttestationChallenge())
            }

            val keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                KEYSTORE_PROVIDER
            )
            keyPairGenerator.initialize(specBuilder.build())

            val keyPair = withAliasGate(alias) { keyPairGenerator.generateKeyPair() }
            return encodeCOSEPublicKey(keyPair.public)
        } catch (e: Exception) {
            throw KeyGenerationException("Failed to generate key without StrongBox", e)
        }
    }

    /**
     * Sign a data hash using a credential key.
     *
     * This operation requires biometric verification if the key was created
     * with [requireBiometric] = true and the authentication has expired.
     * Due to AUTH_TIMEOUT_SECONDS, a recent biometric auth may still be valid,
     * allowing signing without prompting again (grace period for rapid requests).
     *
     * @param credentialId Base64-encoded credential ID.
     * @param dataHash SHA-256 hash of the data to sign (32 bytes).
     * @param biometricHelper Helper for showing biometric prompts.
     * @param title Title for the biometric prompt.
     * @param subtitle Subtitle for the biometric prompt (e.g., relying party).
     * @param onTurn Called with the prompt's queue key on its turn, before it
     *   shows ([BiometricHelper.authenticate]); not called without a prompt.
     * @return DER-encoded ECDSA signature.
     * @throws KeyNotFoundException if no key exists for the credential.
     * @throws SigningException if signing fails.
     * @throws UserCancelledException if user cancels biometric.
     * @throws BiometricLockoutException if biometric is locked out.
     */
    suspend fun sign(
        credentialId: String,
        kind: UserKeyKind,
        dataHash: ByteArray,
        biometricHelper: BiometricHelper,
        title: String = "xKey Authentication",
        subtitle: String = "Verify your identity to sign",
        onTurn: (key: String) -> Unit = {}
    ): ByteArray {
        // The key of [kind] only (#255 review r3): a passkey the desktop made
        // through local.generateKey is a general key, one the FIDO2 RPCs made
        // a credential, and the caller names which ([soleKind]).
        val alias = resolveKeystoreAlias(credentialId, kind) ?: throw KeyNotFoundException(credentialId)

        // The selected key and its public key, read together under the
        // alias's gate: a prompt that runs before initSign signs only if the
        // alias still holds this key afterwards (signWithPrompt).
        val (privateKey, selectedPublicKeyDer) = withAliasGate(alias) {
            val key = keyStore.getKey(alias, null) as? PrivateKey
                ?: throw KeyNotFoundException(credentialId)
            key to (publicKeyDERAt(alias) ?: throw KeyNotFoundException(credentialId))
        }

        // First, try to sign without biometric (uses cached auth if within timeout)
        try {
            val signature = freshSignature(alias, privateKey, SIGNATURE_ALGORITHM)
            signature.update(dataHash)
            return signature.sign()
        } catch (e: Exception) {
            // The key requires fresh user authentication: proceed with the
            // prompt. Devices refuse at initSign (UserNotAuthenticatedException)
            // or only at sign() (SignatureException over a Keystore error).
            // Anything else here is a real failure, not a reason to prompt. The
            // algorithm is fixed to ECDSA, so a non-EC key resolved by
            // resolveKeystoreAlias throws InvalidKeyException — which used to
            // escape past this function's documented SigningException contract
            // and surface to the desktop as INTERNAL_ERROR.
            if (!requiresUserAuthentication(e)) throw SigningException("Signing operation failed", e)
        }

        // Biometric required - show prompt, with a fresh Signature: the silent
        // one may have been initialised (and fed) before the refusal.
        try {
            return signWithPrompt(
                alias, privateKey, selectedPublicKeyDer, SIGNATURE_ALGORITHM, dataHash,
                biometricHelper, title, subtitle, onTurn
            )
        } catch (e: XKeyCryptoException) {
            // Re-throw our typed exceptions
            throw e
        } catch (e: Exception) {
            throw SigningException("Signing operation failed", e)
        }
    }

    /**
     * Signs [data] with [privateKey] behind a biometric prompt, in the flow
     * the key's kind allows: the one place a prompt meets a Keystore key.
     *
     * - A time-window key (authentication valid for a number of seconds)
     *   cannot be bound to a CryptoObject, and its provider may refuse
     *   `initSign` until the user has authenticated. The user authenticates
     *   first, without a CryptoObject; then a fresh Signature is
     *   initialised and signs inside the new window.
     * - A per-operation key (validity 0) is bound to the prompt: `initSign`,
     *   then the prompt unlocks that Signature through its CryptoObject.
     *   Should its `initSign` refuse for want of authentication (the key's
     *   [KeyInfo] was unreadable, and it is a time-window key after all), the
     *   time-window flow runs instead, so no key is initialised before the
     *   authentication it needs.
     *
     * The time-window flow prompts before it initialises a key, and on API
     * 28-30 a Keystore key handle names its alias, not the key: were the
     * alias deleted and regenerated while the prompt waits, `initSign` would
     * sign with the replacement under the user's fresh authentication. So
     * after the prompt it signs through [signApproved], which rereads the key
     * under [alias] and signs only if its public key is still
     * [selectedPublicKeyDer], the one read with [privateKey] before the
     * prompt, all inside the alias's gate.
     *
     * @throws ApprovedKeyChangedException if [alias] no longer holds the selected key.
     */
    private suspend fun signWithPrompt(
        alias: String,
        privateKey: PrivateKey,
        selectedPublicKeyDer: ByteArray,
        algorithm: String,
        data: ByteArray,
        biometricHelper: BiometricHelper,
        title: String,
        subtitle: String,
        onTurn: (key: String) -> Unit
    ): ByteArray {
        suspend fun authenticateThenSign(): ByteArray {
            biometricHelper.authenticateWithoutCrypto(title = title, subtitle = subtitle, onTurn = onTurn)
            return signApproved(alias, selectedPublicKeyDer, data, algorithm)
        }

        if (isTimeWindowKey(alias, privateKey)) return authenticateThenSign()

        val signature = Signature.getInstance(algorithm)
        try {
            signature.initSign(privateKey)
        } catch (e: Exception) {
            if (requiresUserAuthentication(e)) return authenticateThenSign()
            throw e
        }
        // The prompt waits for its queue turn, and onTurn posts its wake
        // notification on that turn; success unlocks the signature object.
        biometricHelper.authenticate(
            cryptoObject = BiometricPrompt.CryptoObject(signature),
            title = title,
            subtitle = subtitle,
            onTurn = onTurn
        )
        signature.update(data)
        return signature.sign()
    }

    /**
     * True when the key under [alias] authenticates for a time window
     * (validity > 0 seconds) rather than per operation. An unreadable
     * [KeyInfo] reads as per-operation; [signWithPrompt] recovers if the
     * key then refuses `initSign`.
     */
    private fun isTimeWindowKey(alias: String, key: Key): Boolean = try {
        @Suppress("DEPRECATION")
        keyInfoReader(alias, key).userAuthenticationValidityDurationSeconds > 0
    } catch (e: Exception) {
        false
    }

    /**
     * Sign without showing biometric prompt.
     *
     * This works when the key doesn't require auth or auth is cached
     * (within the authentication validity duration configured at key generation).
     *
     * Use cases:
     * - Keys generated with [generateKeyWithAuthDuration] with authDurationSeconds < 0 (no auth required)
     * - Keys within their authentication validity window after a recent biometric auth
     * - Keys generated with [generateKey] with requireBiometric = false
     *
     * @param credentialId Base64-encoded credential ID.
     * @param dataHash SHA-256 hash of the data to sign (32 bytes).
     * @return DER-encoded ECDSA signature.
     * @throws KeyNotFoundException if no key exists for the credential.
     * @throws BiometricRequiredException if key requires biometric authentication
     *         and the authentication has expired or was never performed.
     * @throws SigningException if signing fails.
     */
    suspend fun signWithoutBiometric(
        credentialId: String,
        kind: UserKeyKind,
        dataHash: ByteArray
    ): ByteArray {
        // The key of [kind] only (#255 review r3), the one whose public key
        // the caller was given: never a key of the other namespace sharing
        // the id.
        val alias = resolveKeystoreAlias(credentialId, kind) ?: throw KeyNotFoundException(credentialId)

        val privateKey = keyStore.getKey(alias, null) as? PrivateKey
            ?: throw KeyNotFoundException(credentialId)

        try {
            val signature = freshSignature(alias, privateKey, SIGNATURE_ALGORITHM)
            signature.update(dataHash)
            return signature.sign()
        } catch (e: Exception) {
            if (requiresUserAuthentication(e)) throw BiometricRequiredException()
            throw SigningException("Signing operation failed", e)
        }
    }

    /**
     * True when [e] is Keystore refusing a key operation for want of user
     * authentication: the one test every silent key operation here uses to
     * choose the prompt (or [BiometricRequiredException]) over a failure.
     *
     * Devices refuse in two shapes. Most throw
     * [android.security.keystore.UserNotAuthenticatedException] from
     * `initSign`/`init`; some accept the init and refuse only at
     * `sign()`/`doFinal()` (or in a `ProviderException`), with an
     * `android.security.KeyStoreException` whose numeric error code is
     * `ERROR_USER_AUTHENTICATION_REQUIRED` somewhere in the cause chain.
     * That error code exists from API 33; below it only the first shape is
     * recognised.
     */
    private fun requiresUserAuthentication(e: Throwable): Boolean {
        var current: Throwable? = e
        var depth = 0
        while (current != null && depth < MAX_CAUSE_DEPTH) {
            if (current is android.security.keystore.UserNotAuthenticatedException) return true
            if (current is BiometricRequiredException) return true
            if (hasKeystoreErrorCodes() && isUserAuthenticationRequired(current)) return true
            val next = current.cause
            current = if (next === current) null else next
            depth++
        }
        return false
    }

    /** True from API 33, where android.security.KeyStoreException carries its error code. */
    @ChecksSdkIntAtLeast(api = Build.VERSION_CODES.TIRAMISU)
    private fun hasKeystoreErrorCodes(): Boolean = sdkInt >= Build.VERSION_CODES.TIRAMISU

    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    private fun isUserAuthenticationRequired(e: Throwable): Boolean =
        e is android.security.KeyStoreException &&
            e.numericErrorCode == android.security.KeyStoreException.ERROR_USER_AUTHENTICATION_REQUIRED

    /**
     * Check if a key exists for a credential.
     *
     * @param credentialId Base64-encoded credential ID.
     * @return true if a key exists for this credential.
     */
    fun keyExists(credentialId: String, kind: UserKeyKind): Boolean {
        val alias = resolveKeystoreAlias(credentialId, kind) ?: return false
        return keyStore.containsAlias(alias)
    }

    /**
     * Delete a credential key from the keystore.
     *
     * @param credentialId Base64-encoded credential ID.
     * @return [GeneratedKeyDiscard.DELETED] for a key now gone,
     *   [GeneratedKeyDiscard.ABSENT] when there was none, and
     *   [GeneratedKeyDiscard.FAILED] when the key may still be there: a
     *   caller keeps whatever retries the delete on FAILED, never treating
     *   it as gone.
     */
    fun deleteKey(credentialId: String, kind: UserKeyKind): GeneratedKeyDiscard {
        // The key of [kind] only: a delete of one key never removes the
        // other key sharing its id. The Keystore entry is the only backend
        // this deletes, so it reads that alias alone and never the
        // cross-backend presence guard (#255 review r7): an unreadable
        // Ed25519 or software store never stops the delete of a Keystore key.
        val alias = userKeyAlias(credentialId, kind)
        var outcome = discardGeneratedKey(alias)
        // A general alias with no Keystore entry may hold a software ML-DSA record.
        if (outcome == GeneratedKeyDiscard.ABSENT && kind == UserKeyKind.GENERAL) outcome = discardPqcKey(alias)
        if (outcome != GeneratedKeyDiscard.DELETED) return outcome

        // Log key deletion
        AuditLogger.logKeyDeleted(
            keyId = credentialId,
            keyLabel = credentialId,
            keyType = "fido2"
        )

        return outcome
    }

    /**
     * Get the public key for a credential.
     *
     * @param credentialId Base64-encoded credential ID.
     * @return The public key, or null if not found.
     */
    fun getPublicKey(credentialId: String, kind: UserKeyKind): PublicKey? {
        val alias = resolveKeystoreAlias(credentialId, kind) ?: return null
        return keyStore.getCertificate(alias)?.publicKey
    }

    /**
     * Get the COSE-encoded public key for a credential.
     *
     * @param credentialId Base64-encoded credential ID.
     * @return COSE-encoded public key bytes, or null if not found.
     */
    fun getCOSEPublicKey(credentialId: String, kind: UserKeyKind): ByteArray? {
        // The key of [kind] only, as every export reads (#255 review r3).
        val alias = resolveKeystoreAlias(credentialId, kind) ?: return null
        val publicKey = runCatching { keyStore.getCertificate(alias)?.publicKey }.getOrNull()
            ?: return null
        return encodeCOSEPublicKey(publicKey)
    }

    /**
     * Get the attestation certificate chain for a key.
     *
     * The certificate chain can be used to verify that the key was generated
     * in secure hardware (StrongBox or TEE) and includes key attestation
     * information if the device supports it.
     *
     * @param credentialId Base64-encoded credential ID.
     * @return Certificate chain, or null if not available.
     */
    fun getAttestationChain(credentialId: String, kind: UserKeyKind): List<Certificate>? {
        // The key of [kind] only, as the export and signing paths read.
        val alias = resolveKeystoreAlias(credentialId, kind) ?: return null
        return keyStore.getCertificateChain(alias)?.toList()
    }

    /**
     * List all xKey credential IDs stored in the keystore.
     *
     * @return List of credential IDs (without the key alias prefix).
     */
    fun listCredentials(): List<String> {
        return keyStore.aliases().toList()
            .filter { it.startsWith(KEY_ALIAS_PREFIX) }
            .map { it.removePrefix(KEY_ALIAS_PREFIX) }
    }

    /**
     * Check if a key is backed by StrongBox.
     *
     * Reads the key's own level ([keySecurityLevel]), not the device's: a key
     * generated without StrongBox, or one whose StrongBox spec fell back to
     * the TEE, is not StrongBox-backed on a StrongBox device.
     *
     * @param credentialId Credential ID or general key ID.
     * @return true if the key is StrongBox-backed, false otherwise or if missing.
     */
    fun isKeyStrongBoxBacked(credentialId: String, kind: UserKeyKind): Boolean =
        keySecurityLevel(credentialId, kind) == KeySecurityLevel.STRONGBOX

    /**
     * The security level of a key, read from its [KeyInfo].
     *
     * Resolves [keyId]'s key of [kind] ([resolveKey]), never the other
     * key sharing its id. A key with no Keystore entry (an Ed25519 key
     * in EncryptedSharedPreferences) is [KeySecurityLevel.SOFTWARE].
     *
     * @param keyId Credential ID, general key ID or raw alias.
     * @return The key's level, or null if no such key exists.
     * @throws KeyInfoUnavailableException if a Keystore entry exists but its
     *         KeyInfo cannot be read.
     */
    fun keySecurityLevel(keyId: String, kind: UserKeyKind): KeySecurityLevel? {
        val alias = resolveKeystoreAlias(keyId, kind) ?: return null
        if (!keyStore.containsAlias(alias)) return KeySecurityLevel.SOFTWARE
        return aliasSecurityLevel(alias)
    }

    /**
     * The security level of the FIDO2 credential [credentialId]
     * (`xkey_credential_<id>`), or null if it does not exist.
     *
     * @throws KeyInfoUnavailableException if its KeyInfo cannot be read.
     */
    fun credentialSecurityLevel(credentialId: String): KeySecurityLevel? {
        val alias = buildAlias(credentialId)
        if (!keyStore.containsAlias(alias)) return null
        return aliasSecurityLevel(alias)
    }

    /**
     * The security level of the general key [keyId] (`xkey_key_<id>`, or its
     * Ed25519 entry in EncryptedSharedPreferences, which is software), or null
     * if it does not exist. Never consults a credential of the same id.
     *
     * @throws KeyInfoUnavailableException if its KeyInfo cannot be read.
     */
    fun generalKeySecurityLevel(keyId: String): KeySecurityLevel? {
        val alias = buildGeneralAlias(keyId)
        if (keyStore.containsAlias(alias)) return aliasSecurityLevel(alias)
        if (hasSoftwareEd25519Key(alias)) {
            return KeySecurityLevel.SOFTWARE
        }
        if (pqcStore.contains(alias)) return KeySecurityLevel.SOFTWARE
        return null
    }

    /**
     * Reads the [KeyInfo] of the Keystore key held at an alias. Replaceable
     * so tests can make the read fail. A Keystore Ed25519 key names its
     * algorithm "EdDSA", which has no AndroidKeyStore KeyFactory: its KeyInfo
     * is read through the EC factory, as PivKeyManager reads it.
     */
    @VisibleForTesting
    internal var keyInfoReader: (alias: String, key: Key) -> KeyInfo = { _, key ->
        when (key) {
            is PrivateKey -> runCatching {
                KeyFactory.getInstance(key.algorithm, KEYSTORE_PROVIDER).getKeySpec(key, KeyInfo::class.java)
            }.recoverCatching { e ->
                if (key.algorithm == "EdDSA" || key.algorithm == "Ed25519") {
                    KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER)
                        .getKeySpec(key, KeyInfo::class.java)
                } else {
                    throw e
                }
            }.getOrThrow()
            is SecretKey -> SecretKeyFactory.getInstance(key.algorithm, KEYSTORE_PROVIDER)
                .getKeySpec(key, KeyInfo::class.java) as KeyInfo
            else -> throw InvalidKeySpecException("no KeyInfo for a ${key.javaClass.name}")
        }
    }

    /**
     * The security level of the existing Keystore entry [alias].
     *
     * @throws KeyInfoUnavailableException if the entry holds no key or its
     *         [KeyInfo] cannot be read: a failed read is never software.
     */
    private fun aliasSecurityLevel(alias: String): KeySecurityLevel {
        val info = try {
            val key = keyStore.getKey(alias, null)
                ?: throw KeyInfoUnavailableException(alias, null)
            keyInfoReader(alias, key)
        } catch (e: KeyInfoUnavailableException) {
            throw e
        } catch (e: Exception) {
            throw KeyInfoUnavailableException(alias, e)
        }

        val keyInfoLevel = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            info.securityLevel
        } else {
            KEY_INFO_LEVEL_UNKNOWN
        }
        @Suppress("DEPRECATION")
        val insideSecureHardware = info.isInsideSecureHardware
        return securityLevelOf(
            Build.VERSION.SDK_INT,
            keyInfoLevel,
            insideSecureHardware,
            alias in strongBoxSpecAliases
        )
    }

    /** Records whether the spec that generated [alias] asked for StrongBox. */
    private fun markStrongBoxSpec(alias: String, strongBoxSpec: Boolean) {
        if (strongBoxSpec) strongBoxSpecAliases.add(alias) else strongBoxSpecAliases.remove(alias)
    }

    /**
     * Runs the steps that follow a successful key generation. Their failures
     * propagate as they are (or wrapped as a [KeyGenerationException]) and are
     * never treated as a reason to generate the key again elsewhere.
     */
    private inline fun afterGeneration(block: () -> ByteArray): ByteArray = try {
        block()
    } catch (e: XKeyCryptoException) {
        throw e
    } catch (e: Exception) {
        throw KeyGenerationException("Failed after key generation", e)
    }

    // -------------------------------------------------------------------------
    // Multi-Algorithm Key Generation
    // -------------------------------------------------------------------------

    /**
     * Generate a key using the specified algorithm.
     *
     * Supports EC (P-256, P-384, P-521) and RSA (2048, 3072, 4096) keys.
     * EC algorithms generate ECDSA signing keys on the specified curve.
     * RSA algorithms generate RSA signing (and decryption) keys of the
     * specified bit length.
     *
     * @param keyId Unique key identifier.
     * @param algorithm One of "ES256", "ES384", "ES512", "RS256", "RS384", "RS512".
     * @param authDurationSeconds Authentication validity: -1 = no auth, 0 = per-op, >0 = seconds.
     * @param preferStrongBox Whether to prefer StrongBox hardware.
     * @param keySizeBits RSA modulus (2048, 3072 or 4096); null takes the
     *   size the hash implies. Ignored for EC and Ed25519.
     * @return DER-encoded public key bytes.
     * @throws KeyGenerationException if key generation fails or [keySizeBits]
     *   is not a size the Keystore makes.
     * @throws UnsupportedAlgorithmException if the algorithm is not supported.
     */
    suspend fun generateKeyForAlgorithm(
        keyId: String,
        algorithm: String,
        authDurationSeconds: Int = 5,
        preferStrongBox: Boolean = true,
        keySizeBits: Int? = null
    ): ByteArray {
        val alias = buildGeneralAlias(keyId)
        if (algorithm.startsWith("RS") && keySizeBits != null && keySizeBits !in setOf(2048, 3072, 4096)) {
            throw KeyGenerationException("Unsupported RSA modulus size: $keySizeBits")
        }

        // Delete existing key if present
        if (keyStore.containsAlias(alias)) {
            withAliasGate(alias) { keyStore.deleteEntry(alias) }
        }

        val isEC = algorithm.startsWith("ES")
        val isRSA = algorithm.startsWith("RS")
        val isEd25519 = algorithm == "Ed25519" || algorithm == "EdDSA"
        if (!isEC && !isRSA && !isEd25519) {
            throw UnsupportedAlgorithmException(algorithm)
        }

        try {
            val keyPair = when {
                isEd25519 -> {
                    if (sdkInt < Build.VERSION_CODES.TIRAMISU) {
                        throw UnsupportedAlgorithmException("Ed25519 requires API 33+")
                    }
                    // A legacy software Ed25519 key under the alias is deleted, never replaced.
                    if (hasSoftwareEd25519Key(alias)) {
                        throw KeyGenerationException("A legacy software Ed25519 key holds $keyId; delete it first")
                    }
                    generateKeystoreEd25519KeyPair(alias, authDurationSeconds)
                }
                isEC -> generateECKeyPair(alias, algorithm, authDurationSeconds, preferStrongBox)
                else -> generateRSAKeyPair(alias, algorithm, authDurationSeconds, preferStrongBox, keySizeBits)
            }

            // Log key creation. The audit line only; callers read the level
            // themselves and see a failure.
            val strongBoxBacked =
                runCatching { generalKeySecurityLevel(keyId) }.getOrNull() == KeySecurityLevel.STRONGBOX
            AuditLogger.logKeyCreated(
                keyId = keyId,
                keyLabel = keyId,
                keyType = "signing",
                algorithm = algorithm,
                strongBox = strongBoxBacked
            )

            return keyPair.public.encoded
        } catch (e: UnsupportedAlgorithmException) {
            throw e
        } catch (e: KeyGenerationException) {
            throw e
        } catch (e: Exception) {
            throw KeyGenerationException("Failed to generate $algorithm key", e)
        }
    }

    /**
     * Generate an EC key pair for the specified algorithm.
     */
    private fun generateECKeyPair(
        alias: String,
        algorithm: String,
        authDurationSeconds: Int,
        preferStrongBoxForCurve: Boolean
    ): java.security.KeyPair {
        val curve = getECCurve(algorithm)
        // StrongBox guarantees P-256 only: P-384 and P-521 go to the TEE.
        val preferStrongBox = preferStrongBoxForCurve && curve == EC_CURVE_P256
        val digest = getDigestProperty(algorithm)

        // PURPOSE_AGREE_KEY (API 31+) is required for local.ecdh; Keystore
        // rejects KeyAgreement on keys generated without it.
        val ecPurposes = KeyProperties.PURPOSE_SIGN or
            (if (android.os.Build.VERSION.SDK_INT >= 31) KeyProperties.PURPOSE_AGREE_KEY else 0)

        val specBuilder = KeyGenParameterSpec.Builder(
            alias,
            ecPurposes
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec(curve))
            .setDigests(digest)

        applyAuthDuration(specBuilder, authDurationSeconds)
        val strongBoxSpec = applyStrongBox(specBuilder, preferStrongBox)
        applyAttestationChallenge(specBuilder)

        try {
            val keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                KEYSTORE_PROVIDER
            )
            keyPairGenerator.initialize(specBuilder.build())
            return withAliasGate(alias) { keyPairGenerator.generateKeyPair() }.also { markStrongBoxSpec(alias, strongBoxSpec) }
        } catch (e: Exception) {
            // StrongBox fallback
            if (preferStrongBox && isStrongBoxAvailable()) {
                val fallbackBuilder = KeyGenParameterSpec.Builder(
                    alias,
                    ecPurposes
                )
                    .setAlgorithmParameterSpec(ECGenParameterSpec(curve))
                    .setDigests(digest)

                applyAuthDuration(fallbackBuilder, authDurationSeconds)
                applyAttestationChallenge(fallbackBuilder)

                val keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC,
                    KEYSTORE_PROVIDER
                )
                keyPairGenerator.initialize(fallbackBuilder.build())
                return withAliasGate(alias) { keyPairGenerator.generateKeyPair() }.also { markStrongBoxSpec(alias, false) }
            }
            throw e
        }
    }

    /**
     * Generate an RSA key pair for the specified algorithm.
     */
    /**
     * Generates an RSA key for OAEP encryption at an explicit modulus size.
     *
     * [generateKeyForAlgorithm] derives the modulus from a *signature* algorithm
     * name, so every encryption key came out at the RS256 size of 2048 no matter
     * what the caller asked for. Bumping the algorithm name is not a fix either:
     * that would also change the permitted digest, and [rsaDecrypt] is fixed to
     * `OAEPWithSHA-256AndMGF1Padding`, so Keystore would refuse every decrypt.
     * Size and digest are therefore separated here.
     *
     * @param keyId Logical key identifier; stored under the general alias namespace.
     * @param keySizeBits Modulus size — 2048, 3072 or 4096.
     * @param authDurationSeconds Seconds the key stays unlocked; -1 for no authentication.
     * @param preferStrongBox Whether to prefer StrongBox hardware.
     * @return DER-encoded public key bytes.
     * @throws KeyGenerationException if key generation fails.
     */
    suspend fun generateRSAEncryptionKey(
        keyId: String,
        keySizeBits: Int,
        authDurationSeconds: Int = 5,
        preferStrongBox: Boolean = true
    ): ByteArray {
        require(keySizeBits in setOf(2048, 3072, 4096)) {
            "Unsupported RSA modulus size: $keySizeBits"
        }
        val alias = buildGeneralAlias(keyId)
        if (keyStore.containsAlias(alias)) withAliasGate(alias) { keyStore.deleteEntry(alias) }

        val specBuilder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_DECRYPT
        )
            .setKeySize(keySizeBits)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)

        applyAuthDuration(specBuilder, authDurationSeconds)
        // StrongBox guarantees RSA 2048 only; larger moduli go to the TEE.
        applyStrongBox(specBuilder, preferStrongBox && keySizeBits == 2048)
        applyAttestationChallenge(specBuilder)

        try {
            val generator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_RSA,
                KEYSTORE_PROVIDER
            )
            generator.initialize(specBuilder.build())
            return withAliasGate(alias) { generator.generateKeyPair() }.public.encoded
        } catch (e: Exception) {
            throw KeyGenerationException("Failed to generate RSA encryption key", e)
        }
    }

    private fun generateRSAKeyPair(
        alias: String,
        algorithm: String,
        authDurationSeconds: Int,
        preferStrongBoxForSize: Boolean,
        requestedKeySize: Int? = null
    ): java.security.KeyPair {
        val keySize = requestedKeySize ?: getRSAKeySize(algorithm)
        // StrongBox guarantees RSA 2048 only: larger moduli go to the TEE.
        val preferStrongBox = preferStrongBoxForSize && keySize == 2048
        val digest = getDigestProperty(algorithm)

        val specBuilder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_DECRYPT
        )
            .setKeySize(keySize)
            .setDigests(digest)
            .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)

        applyAuthDuration(specBuilder, authDurationSeconds)
        val strongBoxSpec = applyStrongBox(specBuilder, preferStrongBox)
        applyAttestationChallenge(specBuilder)

        try {
            val keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_RSA,
                KEYSTORE_PROVIDER
            )
            keyPairGenerator.initialize(specBuilder.build())
            return withAliasGate(alias) { keyPairGenerator.generateKeyPair() }.also { markStrongBoxSpec(alias, strongBoxSpec) }
        } catch (e: Exception) {
            // StrongBox fallback
            if (preferStrongBox && isStrongBoxAvailable()) {
                val fallbackBuilder = KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_DECRYPT
                )
                    .setKeySize(keySize)
                    .setDigests(digest)
                    .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)

                applyAuthDuration(fallbackBuilder, authDurationSeconds)
                applyAttestationChallenge(fallbackBuilder)

                val keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_RSA,
                    KEYSTORE_PROVIDER
                )
                keyPairGenerator.initialize(fallbackBuilder.build())
                return withAliasGate(alias) { keyPairGenerator.generateKeyPair() }.also { markStrongBoxSpec(alias, false) }
            }
            throw e
        }
    }

    /** An Ed25519 signing key in the Android Keystore (API 33+); StrongBox makes no Ed25519 keys. */
    private fun generateKeystoreEd25519KeyPair(alias: String, authDurationSeconds: Int): java.security.KeyPair {
        val specBuilder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("ed25519"))
            .setDigests(KeyProperties.DIGEST_NONE)
        applyAuthDuration(specBuilder, authDurationSeconds)
        applyAttestationChallenge(specBuilder)
        val keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER)
        keyPairGenerator.initialize(specBuilder.build())
        return withAliasGate(alias) { keyPairGenerator.generateKeyPair() }.also { markStrongBoxSpec(alias, false) }
    }

    /**
     * Whether this device can hold Ed25519 keys at all: they exist only
     * from API 33, so below it no key under any id is one.
     */
    @androidx.annotation.ChecksSdkIntAtLeast(api = Build.VERSION_CODES.TIRAMISU)
    fun holdsEd25519Keys(): Boolean = Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU

    /**
     * The one read of whether a software Ed25519 key is stored under [alias].
     *
     * SharedPreferences drops a removed key from its in-memory map before it
     * writes to disk, and keeps it dropped when the write fails, so after a
     * removal that is in flight or did not commit the cache says "absent"
     * while the key is still on disk. Such an alias is in
     * [uncommittedSoftwareRemovals] from before its commit starts and
     * reads as present here until a retry of its removal reaches disk
     * ([removalStillUncommitted], [removeSoftwareEd25519Key]).
     *
     * @param strict throw [KeyDeletionException] when the store cannot be
     *   opened or read; otherwise an unreadable store answers "no key", which
     *   is safe for a lookup but never for a caller that drops a row on it.
     */
    private fun softwareEd25519KeyStored(alias: String, strict: Boolean): Boolean {
        if (!softwareEd25519Supported()) return false
        if (alias in uncommittedSoftwareRemovals) return true
        return try {
            ed25519Read(alias) { ed25519Prefs()?.contains(alias) == true }
        } catch (e: KeyPresenceUnreadableException) {
            if (strict) throw KeyDeletionException("The software key store could not be read", e)
            false
        }
    }

    /**
     * Removes [alias] from the software Ed25519 store and commits. The alias
     * is recorded in [uncommittedSoftwareRemovals] before the commit starts
     * and cleared only once it reaches disk, so the key reads as present
     * while the removal is in flight and after one that did not commit.
     * Call it inside `withAliasGate(alias)`.
     *
     * @return true if the removal reached disk.
     * @throws KeyDeletionException if the store cannot be opened, or the
     *   removal throws.
     */
    private fun commitSoftwareRemovalLocked(alias: String): Boolean {
        val prefs = try {
            ed25519Prefs() ?: return true
        } catch (e: Exception) {
            throw KeyDeletionException("The software key store could not be read to delete $alias", e)
        }
        // Pending before the cache drops the key, so no read sees it absent before disk does.
        uncommittedSoftwareRemovals.add(alias)
        val committed = try {
            prefs.edit().remove(alias).commit()
        } catch (e: Exception) {
            throw KeyDeletionException("Deleting software key $alias failed", e)
        }
        if (committed) uncommittedSoftwareRemovals.remove(alias)
        return committed
    }

    /** True on API 33+, where Ed25519 keys are generated in software. */
    internal fun softwareEd25519Supported(): Boolean =
        sdkInt >= Build.VERSION_CODES.TIRAMISU

    /**
     * Retries the removal of [alias] if an earlier one did not commit.
     *
     * @return true while that removal still has not reached disk (the key is
     *   present), false if none is pending or the retry committed.
     * @throws KeyDeletionException if the store cannot be opened.
     */
    private fun removalStillUncommitted(alias: String): Boolean {
        // Under the gate, so a removal in flight ends before this reads.
        return withAliasGate(alias) {
            alias in uncommittedSoftwareRemovals && !commitSoftwareRemovalLocked(alias)
        }
    }

    /**
     * Removes the software Ed25519 key stored under [alias], if any. Call it
     * inside `withAliasGate(alias)`.
     *
     * @return true if a key was stored and its removal committed, false if
     *   none is stored (or the device keeps no software Ed25519 keys). An
     *   earlier removal that did not commit counts as stored: it is retried.
     * @throws KeyDeletionException if the store cannot be opened or read, so
     *   a key may be in it, or the removal does not commit: the key is still
     *   on disk, and that is never "no key".
     */
    private fun removeSoftwareEd25519Key(alias: String): Boolean {
        if (!softwareEd25519KeyStored(alias, strict = true)) return false
        if (!commitSoftwareRemovalLocked(alias)) {
            throw KeyDeletionException("Deleting software key $alias did not reach disk")
        }
        return true
    }

    /**
     * Throws [KeyDeletionException] if the software Ed25519 key store cannot
     * be opened: a delete that found no key must not report the key absent
     * when the store it would be in was unreadable.
     */
    private fun requireSoftwareKeyStoreReadable() {
        if (!softwareEd25519Supported()) return
        try {
            ed25519Prefs()
        } catch (e: Exception) {
            throw KeyDeletionException("The software key store could not be read", e)
        }
    }

    /**
     * Removes the Keystore entry, the software ML-DSA record and the software
     * Ed25519 key under [alias]. Call it inside `withAliasGate(alias)`, so the
     * existence checks and the removals are one step against any other delete
     * of the alias.
     *
     * The one choke point of every [KeystoreManager] key delete: a removal
     * that fails throws, so no caller reads it as an absent key and drops the
     * key's metadata while its material stays.
     *
     * @return true if any of them existed and was removed, false if none existed.
     * @throws KeyDeletionException if the Keystore entry cannot be checked or
     *   deleted, the software ML-DSA record cannot be removed or revoked, or
     *   the software key cannot be removed.
     */
    private fun removeAliasLocked(alias: String): Boolean {
        val inKeystore = try {
            // The gate is reentrant: callers already hold it, this keeps the delete gated on its own.
            withAliasGate(alias) { keyStore.containsAlias(alias).also { if (it) keyStore.deleteEntry(alias) } }
        } catch (e: Exception) {
            throw KeyDeletionException("Keystore entry $alias could not be deleted", e)
        }
        // A general alias may hold a software ML-DSA record instead of a
        // Keystore entry; no other alias form does (resolveKeystoreAlias).
        val inPqc = try {
            alias.startsWith(KEY_ALIAS_PREFIX_GENERAL) && pqcStore.delete(alias)
        } catch (e: Exception) {
            throw KeyDeletionException("ML-DSA key $alias could not be deleted", e)
        }
        val inSoftware = removeSoftwareEd25519Key(alias)
        return inKeystore || inPqc || inSoftware
    }

    /**
     * Generate an AES symmetric key stored in Android Keystore.
     *
     * The key supports AES-GCM encryption and decryption operations.
     * AES-GCM provides both confidentiality and authenticity through
     * authenticated encryption with associated data (AEAD).
     *
     * @param keyId Unique key identifier.
     * @param keySizeBits Key size: 128 or 256 bits.
     * @param authDurationSeconds Authentication validity: -1 = no auth, 0 = per-op, >0 = seconds.
     * @throws KeyGenerationException if key generation fails.
     */
    suspend fun generateSymmetricKey(
        keyId: String,
        keySizeBits: Int = 256,
        authDurationSeconds: Int = -1
    ) {
        val alias = buildGeneralAlias(keyId)

        if (keySizeBits != 128 && keySizeBits != 192 && keySizeBits != 256) {
            throw KeyGenerationException("AES key size must be 128, 192 or 256 bits, got $keySizeBits")
        }

        // Delete existing key if present
        if (keyStore.containsAlias(alias)) {
            withAliasGate(alias) { keyStore.deleteEntry(alias) }
        }

        try {
            val specBuilder = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setKeySize(keySizeBits)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)

            applyAuthDuration(specBuilder, authDurationSeconds)

            val keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                KEYSTORE_PROVIDER
            )
            keyGenerator.init(specBuilder.build())
            withAliasGate(alias) { keyGenerator.generateKey() }
            markStrongBoxSpec(alias, false)
        } catch (e: KeyGenerationException) {
            throw e
        } catch (e: Exception) {
            throw KeyGenerationException("Failed to generate AES-$keySizeBits key", e)
        }
    }

    /**
     * Generate an HMAC key stored in Android Keystore.
     *
     * Supports HMAC-SHA256 and HMAC-SHA512 for message authentication
     * code computation.
     *
     * @param keyId Unique key identifier.
     * @param algorithm "HMAC-SHA256" or "HMAC-SHA512".
     * @throws KeyGenerationException if key generation fails.
     * @throws UnsupportedAlgorithmException if the algorithm is not supported.
     */
    suspend fun generateHMACKey(
        keyId: String,
        algorithm: String = "HMAC-SHA256"
    ) {
        val alias = buildGeneralAlias(keyId)

        val jcaAlgorithm = when (algorithm) {
            "HMAC-SHA256" -> KeyProperties.KEY_ALGORITHM_HMAC_SHA256
            "HMAC-SHA384" -> KeyProperties.KEY_ALGORITHM_HMAC_SHA384
            "HMAC-SHA512" -> KeyProperties.KEY_ALGORITHM_HMAC_SHA512
            else -> throw UnsupportedAlgorithmException(algorithm)
        }

        // Delete existing key if present
        if (keyStore.containsAlias(alias)) {
            withAliasGate(alias) { keyStore.deleteEntry(alias) }
        }

        try {
            val specBuilder = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )

            val keyGenerator = KeyGenerator.getInstance(jcaAlgorithm, KEYSTORE_PROVIDER)
            keyGenerator.init(specBuilder.build())
            withAliasGate(alias) { keyGenerator.generateKey() }
            markStrongBoxSpec(alias, false)
        } catch (e: UnsupportedAlgorithmException) {
            throw e
        } catch (e: Exception) {
            throw KeyGenerationException("Failed to generate $algorithm key", e)
        }
    }

    // -------------------------------------------------------------------------
    // Multi-Algorithm Signing
    // -------------------------------------------------------------------------

    /**
     * Sign data with an algorithm-aware signature.
     *
     * Uses the appropriate JCA signature algorithm based on the specified
     * COSE/JOSE algorithm name. The data is signed raw (not pre-hashed)
     * as the JCA Signature API handles hashing internally.
     *
     * @param keyId Key identifier.
     * @param data Data to sign (raw bytes, not pre-hashed).
     * @param algorithm Signing algorithm: "ES256", "ES384", "ES512", "RS256", "RS384", "RS512".
     * @return Signature bytes (DER-encoded for EC, PKCS#1 for RSA).
     * @throws KeyNotFoundException if no key exists for the identifier.
     * @throws BiometricRequiredException if key requires biometric authentication.
     * @throws SigningException if signing fails.
     */
    suspend fun signWithAlgorithm(
        keyId: String,
        data: ByteArray,
        algorithm: String
    ): ByteArray {
        val alias = buildGeneralAlias(keyId)
        val jcaAlgorithm = getJCASignatureAlgorithm(algorithm)

        val privateKey = keyStore.getKey(alias, null) as? PrivateKey
            ?: throw KeyNotFoundException(keyId)

        try {
            val signature = freshSignature(alias, privateKey, jcaAlgorithm)
            signature.update(data)
            return signature.sign()
        } catch (e: Exception) {
            if (requiresUserAuthentication(e)) throw BiometricRequiredException()
            throw SigningException("Signing with $algorithm failed", e)
        }
    }

    /**
     * The X.509 public key of the entry under Keystore [alias] exactly, with
     * no alias resolution: what an approval snapshots and rechecks for the
     * alias its signer ([signApproved]) signs with.
     *
     * @return DER-encoded public key bytes, or null if [alias] holds no key.
     */
    fun publicKeyDERAt(alias: String): ByteArray? =
        keyStore.getCertificate(alias)?.publicKey?.encoded ?: pqcStore.publicKeyDer(alias)

    /**
     * The Keystore alias the key of key row [keyId] (of [keyType]) lives under.
     *
     * Every row but a FIDO2 one is a general key ([generalKeyAlias]). A FIDO2
     * row is a credential ([credentialAlias]) when the phone registered it,
     * but a general key when the desktop created it with `local.generateKey`.
     * A credential and a general key may share an id, so a FIDO2 row takes
     * the alias whose public key is the row's own [storedPublicKeyDer]; a row
     * with no stored key (or one neither alias holds) takes the credential if
     * there is one, else the general key. This never resolves by id alone,
     * which prefers the credential whatever the row is.
     */
    fun keyRowAlias(keyId: String, keyType: String, storedPublicKeyDer: ByteArray?): String {
        val general = generalKeyAlias(keyId)
        if (keyType != FIDO2_KEY_TYPE) return general
        val credential = credentialAlias(keyId)
        if (storedPublicKeyDer != null && storedPublicKeyDer.isNotEmpty()) {
            listOf(credential, general)
                .firstOrNull { publicKeyDERAt(it)?.contentEquals(storedPublicKeyDer) == true }
                ?.let { return it }
        }
        return if (publicKeyDERAt(credential) != null) credential else general
    }

    /**
     * Signs [data] with JCA [jcaAlgorithm] using the key under [alias], only
     * if that key is still the one the owner approved: the public key under
     * [alias] must equal [approvedPublicKeyDer]. The key approved and the key
     * signed with are read from the one alias, so no other entry (such as a
     * FIDO2 alias of the same id) can stand in for it. The check, the key read
     * and the signature run inside [withAliasGate] for [alias], which every
     * delete and key generation under an alias also takes, so no key can be
     * replaced between the check and the signature.
     *
     * A per-operation key ([isPerOperationKey]) signs only through
     * [cryptoObjectSigner], the prompt that authorizes its Signature as a
     * CryptoObject, and only a signature that verifies under
     * [approvedPublicKeyDer] is returned.
     *
     * @param cryptoObjectSigner The CryptoObject-bound prompt a per-operation
     *   key signs through; null where there is none.
     * @throws KeyNotFoundException if [alias] holds no key.
     * @throws ApprovedKeyChangedException if the key under [alias] is not the approved one.
     * @throws BiometricRequiredException if the key requires user authentication,
     *   or is a per-operation key and there is no [cryptoObjectSigner].
     * @throws SigningException if signing fails.
     */

    suspend fun signApproved(
        alias: String,
        approvedPublicKeyDer: ByteArray,
        data: ByteArray,
        jcaAlgorithm: String,
        cryptoObjectSigner: CryptoObjectSigner? = null
    ): ByteArray {
        val signed: ByteArray? = withAliasGate(alias) {
            val current = publicKeyDERAt(alias) ?: throw KeyNotFoundException(alias)
            if (!current.contentEquals(approvedPublicKeyDer)) throw ApprovedKeyChangedException(alias)
            val privateKey = keyStore.getKey(alias, null) as? PrivateKey
                ?: throw KeyNotFoundException(alias)
            if (isPerOperationKey(alias)) return@withAliasGate null
            try {
                val signature = freshSignature(alias, privateKey, jcaAlgorithm)
                signature.update(data)
                signature.sign()
            } catch (e: Exception) {
                if (requiresUserAuthentication(e)) throw BiometricRequiredException()
                throw SigningException("Signing with $jcaAlgorithm failed", e)
            }
        }
        return signed ?: signBoundToPrompt(alias, approvedPublicKeyDer, data, jcaAlgorithm, null, cryptoObjectSigner)
    }

    /**
     * Signs [data] with the per-operation key under [alias] through
     * [cryptoObjectSigner], the CryptoObject-bound prompt, outside the alias
     * gate so the prompt never holds it. The signature counts only if it
     * verifies under [approvedPublicKeyDer]: the approved key made it, whatever
     * the alias held while the prompt waited.
     *
     * @param set The ML-DSA parameter set of the key, or null for a JCA key.
     * @throws BiometricRequiredException when there is no [cryptoObjectSigner].
     * @throws ApprovedKeyChangedException when the signature is not the approved key's.
     */
    private suspend fun signBoundToPrompt(
        alias: String,
        approvedPublicKeyDer: ByteArray,
        data: ByteArray,
        jcaAlgorithm: String,
        set: MlDsaParameterSet?,
        cryptoObjectSigner: CryptoObjectSigner?
    ): ByteArray {
        val signer = cryptoObjectSigner ?: throw BiometricRequiredException()
        val signature = signer.sign(alias, jcaAlgorithm, data)
        if (!verifiesUnder(approvedPublicKeyDer, jcaAlgorithm, set, data, signature)) {
            throw ApprovedKeyChangedException(alias)
        }
        return signature
    }

    /**
     * Whether [signature] over [data] verifies under the X.509 [publicKeyDer].
     * Internal so a device test can run it on the device's own providers.
     */
    @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    internal fun verifiesUnder(
        publicKeyDer: ByteArray,
        jcaAlgorithm: String,
        set: MlDsaParameterSet?,
        data: ByteArray,
        signature: ByteArray
    ): Boolean = try {
        if (set != null) {
            val verifier = org.bouncycastle.crypto.signers.MLDSASigner()
            verifier.init(false, org.bouncycastle.crypto.util.PublicKeyFactory.createKey(publicKeyDer))
            verifier.update(data, 0, data.size)
            verifier.verifySignature(signature)
        } else {
            val keyAlgorithm = when {
                jcaAlgorithm == "Ed25519" -> "Ed25519"
                jcaAlgorithm.uppercase().contains("RSA") -> "RSA"
                else -> "EC"
            }
            val publicKey = java.security.KeyFactory.getInstance(keyAlgorithm)
                .generatePublic(java.security.spec.X509EncodedKeySpec(publicKeyDer))
            Signature.getInstance(jcaAlgorithm).run {
                initVerify(publicKey)
                update(data)
                verify(signature)
            }
        }
    } catch (e: Exception) {
        false
    }

    /**
     * True when the Keystore key under [alias] needs the user's
     * authentication for every use (validity 0): such a key signs only with
     * a Signature its prompt authorized as a CryptoObject. An unreadable
     * [KeyInfo] reads as not per-operation.
     */
    fun isPerOperationKey(alias: String): Boolean = try {
        val key = if (keyStore.containsAlias(alias)) keyStore.getKey(alias, null) as? PrivateKey else null
        if (key == null) {
            false
        } else {
            val info = keyInfoReader(alias, key)
            @Suppress("DEPRECATION")
            info.isUserAuthenticationRequired && info.userAuthenticationValidityDurationSeconds <= 0
        }
    } catch (e: Exception) {
        false
    }

    /**
     * A Signature initialised for [privateKey] under [alias] outside any
     * prompt: the one place this class does so. A per-operation key is
     * refused first, since only its prompt's CryptoObject can authorize it.
     *
     * @throws BiometricRequiredException for a per-operation key.
     */
    private fun freshSignature(alias: String, privateKey: PrivateKey, jcaAlgorithm: String): Signature {
        if (isPerOperationKey(alias)) throw BiometricRequiredException()
        val signature = Signature.getInstance(jcaAlgorithm)
        signature.initSign(privateKey)
        return signature
    }

    /**
     * [signApproved] for an ML-DSA key: signs [data] (pure ML-DSA) with the
     * [set] key under [alias], only while that key is the approved one. A
     * software key signs through [PqcSoftwareKeyStore]; a Keystore key through
     * [PqcHardware.backend]'s JCA algorithm, and a per-operation Keystore key
     * only through [cryptoObjectSigner].
     *
     * @throws KeyNotFoundException if [alias] holds no key.
     * @throws ApprovedKeyChangedException if the key under [alias] is not the approved one.
     * @throws UnsupportedAlgorithmException if the key is not a [set] key, or
     *   no hardware backend can sign with it.
     * @param userAuthenticatedAt When the user last authenticated for this
     *   use ([PqcSoftwareKeyStore.userAuthenticationTime]), or null. A
     *   software key checks it against its sealed policy; the Keystore
     *   enforces a hardware key's own.
     * @param cryptoObjectSigner As for [signApproved].
     * @throws BiometricRequiredException if the key requires user authentication.
     * @throws SigningException if signing fails.
     */

    suspend fun signApprovedMlDsa(
        alias: String,
        approvedPublicKeyDer: ByteArray,
        data: ByteArray,
        set: MlDsaParameterSet,
        userAuthenticatedAt: Long? = null,
        cryptoObjectSigner: CryptoObjectSigner? = null
    ): ByteArray {
        var jcaAlgorithm = ""
        val signed: ByteArray? = withAliasGate(alias) {
            val current = publicKeyDERAt(alias) ?: throw KeyNotFoundException(alias)
            if (!current.contentEquals(approvedPublicKeyDer)) throw ApprovedKeyChangedException(alias)
            MlDsaParameterSet.requireSpkiSet(current, set)
            if (!keyStore.containsAlias(alias)) {
                try {
                    return@withAliasGate pqcStore.sign(alias, set, data, userAuthenticatedAt)
                } catch (e: PqcKeyRecordException) {
                    throw SigningException("Signing with ${set.wireName} failed", e)
                }
            }
            val backend = PqcHardware.backend
                ?: throw UnsupportedAlgorithmException(set.wireName)
            jcaAlgorithm = backend.jcaSignatureAlgorithm(set)
            val privateKey = keyStore.getKey(alias, null) as? PrivateKey
                ?: throw KeyNotFoundException(alias)
            if (isPerOperationKey(alias)) return@withAliasGate null
            try {
                val signature = freshSignature(alias, privateKey, jcaAlgorithm)
                signature.update(data)
                signature.sign()
            } catch (e: Exception) {
                if (requiresUserAuthentication(e)) throw BiometricRequiredException()
                throw SigningException("Signing with ${set.wireName} failed", e)
            }
        }
        return signed ?: signBoundToPrompt(alias, approvedPublicKeyDer, data, jcaAlgorithm, set, cryptoObjectSigner)
    }

    /**
     * Makes an ML-DSA [set] key for [keyId] under its general alias, held as
     * [backing] says, replacing any key under that alias, and audits it.
     *
     * @return the SubjectPublicKeyInfo DER.
     * @throws UnsupportedAlgorithmException for [PqcBacking.HARDWARE] when
     *   the device does not make [set] in hardware.
     */
    fun generateMlDsaKey(
        keyId: String,
        set: MlDsaParameterSet,
        backing: PqcBacking,
        authDurationSeconds: Int = 5,
        preferStrongBox: Boolean = true
    ): ByteArray {
        val alias = buildGeneralAlias(keyId)
        val spki = withAliasGate(alias) {
            // The gate is reentrant: the inner take keeps the write visibly gated.
            if (keyStore.containsAlias(alias)) withAliasGate(alias) { keyStore.deleteEntry(alias) }
            pqcStore.delete(alias)
            when (backing) {
                PqcBacking.SOFTWARE -> pqcStore.generate(alias, set, authDurationSeconds)
                PqcBacking.HARDWARE -> {
                    val backend = PqcHardware.backend?.takeIf { set in it.supportedParameterSets() }
                        ?: throw UnsupportedAlgorithmException(set.wireName)
                    backend.generate(alias, set, authDurationSeconds, preferStrongBox)
                }
            }
        }
        AuditLogger.logKeyCreated(
            keyId = keyId,
            keyLabel = keyId,
            keyType = "general",
            algorithm = set.wireName,
            strongBox = runCatching { generalKeySecurityLevel(keyId) }.getOrNull() == KeySecurityLevel.STRONGBOX
        )
        return spki
    }

    // -------------------------------------------------------------------------
    // RSA Decryption
    // -------------------------------------------------------------------------

    /**
     * Decrypt data using an RSA key with OAEP padding.
     *
     * Uses RSA/ECB/OAEPWithSHA-256AndMGF1Padding for decryption, which
     * provides semantic security against chosen-ciphertext attacks.
     *
     * @param keyId Key identifier.
     * @param ciphertext Data to decrypt.
     * @return Decrypted plaintext bytes.
     * @throws KeyNotFoundException if no key exists for the identifier.
     * @throws BiometricRequiredException if key requires biometric authentication.
     * @throws DecryptionException if decryption fails.
     */
    suspend fun rsaDecrypt(keyId: String, ciphertext: ByteArray): ByteArray =
        rsaDecryptWithAlgorithm(keyId, ciphertext).plaintext

    /**
     * [rsaDecrypt], also naming the OAEP parameterisation that ran, for the
     * audit entry.
     */
    suspend fun rsaDecryptWithAlgorithm(keyId: String, ciphertext: ByteArray): DecryptResult {
        val alias = buildGeneralAlias(keyId)

        val privateKey = keyStore.getKey(alias, null) as? PrivateKey
            ?: throw KeyNotFoundException(keyId)

        try {
            return rsaOaepDecrypt(privateKey, ciphertext)
        } catch (e: Exception) {
            if (requiresUserAuthentication(e)) throw BiometricRequiredException()
            throw DecryptionException("RSA decryption failed", e)
        }
    }

    // -------------------------------------------------------------------------
    // AES-GCM Symmetric Encryption / Decryption
    // -------------------------------------------------------------------------

    /**
     * Encrypt data using an AES-GCM key.
     *
     * Produces output in the format: IV (12 bytes) || ciphertext || tag.
     * The IV is generated by Android Keystore and prepended to the output
     * for use during decryption. The 128-bit authentication tag is appended
     * by the GCM cipher mode.
     *
     * @param keyId Key identifier.
     * @param plaintext Data to encrypt.
     * @param aad Optional additional authenticated data.
     * @return Concatenation of IV (12 bytes) + ciphertext + authentication tag.
     * @throws KeyNotFoundException if no key exists for the identifier.
     * @throws BiometricRequiredException if key requires biometric authentication.
     * @throws EncryptionException if encryption fails.
     */
    suspend fun symmetricEncrypt(
        keyId: String,
        plaintext: ByteArray,
        aad: ByteArray? = null
    ): ByteArray {
        val alias = buildGeneralAlias(keyId)

        val secretKey = keyStore.getKey(alias, null) as? SecretKey
            ?: throw KeyNotFoundException(keyId)

        try {
            val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)

            if (aad != null) {
                cipher.updateAAD(aad)
            }

            val iv = cipher.iv
            val encrypted = cipher.doFinal(plaintext)

            // Return IV || ciphertext || tag
            return iv + encrypted
        } catch (e: Exception) {
            if (requiresUserAuthentication(e)) throw BiometricRequiredException()
            throw EncryptionException("AES-GCM encryption failed", e)
        }
    }

    /**
     * Decrypt data using an AES-GCM key.
     *
     * Expects input in the format: IV (12 bytes) || ciphertext || tag.
     * The first 12 bytes are extracted as the initialization vector,
     * and the remainder is the ciphertext with appended authentication tag.
     *
     * @param keyId Key identifier.
     * @param ciphertext IV (12 bytes) + ciphertext + authentication tag.
     * @param aad Optional additional authenticated data (must match what was used during encryption).
     * @return Decrypted plaintext bytes.
     * @throws KeyNotFoundException if no key exists for the identifier.
     * @throws BiometricRequiredException if key requires biometric authentication.
     * @throws DecryptionException if decryption fails or authentication tag verification fails.
     */
    suspend fun symmetricDecrypt(
        keyId: String,
        ciphertext: ByteArray,
        aad: ByteArray? = null
    ): ByteArray {
        val alias = buildGeneralAlias(keyId)

        if (ciphertext.size < GCM_IV_SIZE) {
            throw DecryptionException("Ciphertext too short: must be at least $GCM_IV_SIZE bytes for IV")
        }

        val secretKey = keyStore.getKey(alias, null) as? SecretKey
            ?: throw KeyNotFoundException(keyId)

        try {
            val iv = ciphertext.copyOfRange(0, GCM_IV_SIZE)
            val encryptedData = ciphertext.copyOfRange(GCM_IV_SIZE, ciphertext.size)

            val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv))

            if (aad != null) {
                cipher.updateAAD(aad)
            }

            return cipher.doFinal(encryptedData)
        } catch (e: DecryptionException) {
            throw e
        } catch (e: Exception) {
            if (requiresUserAuthentication(e)) throw BiometricRequiredException()
            throw DecryptionException("AES-GCM decryption failed", e)
        }
    }

    // -------------------------------------------------------------------------
    // HMAC
    // -------------------------------------------------------------------------

    /**
     * Compute an HMAC over the provided data.
     *
     * The HMAC algorithm (SHA-256 or SHA-512) is determined by the key type
     * that was specified during key generation with [generateHMACKey].
     *
     * @param keyId Key identifier.
     * @param data Data to authenticate.
     * @return HMAC bytes (32 bytes for SHA-256, 64 bytes for SHA-512).
     * @throws KeyNotFoundException if no key exists for the identifier.
     * @throws HMACException if HMAC computation fails.
     */
    suspend fun computeHMAC(keyId: String, data: ByteArray): ByteArray =
        computeHMACWithAlgorithm(keyId, data).mac

    /**
     * [computeHMAC], also naming the MAC algorithm that ran ("HMAC-SHA256" or
     * "HMAC-SHA512"), as the Keystore key determines it: an audit entry
     * records this, never the key's stored metadata.
     */
    suspend fun computeHMACWithAlgorithm(keyId: String, data: ByteArray): HmacResult {
        val alias = buildGeneralAlias(keyId)

        val secretKey = keyStore.getKey(alias, null) as? SecretKey
            ?: throw KeyNotFoundException(keyId)

        try {
            // Determine HMAC algorithm from key algorithm
            val macAlgorithm = when (secretKey.algorithm) {
                KeyProperties.KEY_ALGORITHM_HMAC_SHA256, "HmacSHA256" -> "HmacSHA256"
                KeyProperties.KEY_ALGORITHM_HMAC_SHA384, "HmacSHA384" -> "HmacSHA384"
                KeyProperties.KEY_ALGORITHM_HMAC_SHA512, "HmacSHA512" -> "HmacSHA512"
                else -> "HmacSHA256"
            }

            val mac = Mac.getInstance(macAlgorithm)
            mac.init(secretKey)
            val name = when (macAlgorithm) {
                "HmacSHA512" -> "HMAC-SHA512"
                "HmacSHA384" -> "HMAC-SHA384"
                else -> "HMAC-SHA256"
            }
            return HmacResult(mac.doFinal(data), name)
        } catch (e: Exception) {
            throw HMACException("Failed to compute HMAC", e)
        }
    }

    // -------------------------------------------------------------------------
    // ECDH Key Agreement
    // -------------------------------------------------------------------------

    /**
     * Perform ECDH key agreement using a local EC private key and a peer's public key.
     *
     * Derives a shared secret using the Elliptic Curve Diffie-Hellman protocol.
     * The local key must be an EC key generated with [generateKeyForAlgorithm]
     * using an ES256/ES384/ES512 algorithm.
     *
     * @param keyId Local EC key identifier.
     * @param peerPublicKeyDer DER-encoded (X.509 SubjectPublicKeyInfo) peer public key.
     * @return Shared secret bytes.
     * @throws KeyNotFoundException if no local key exists for the identifier.
     * @throws BiometricRequiredException if key requires biometric authentication.
     * @throws ECDHException if key agreement fails.
     */
    suspend fun performECDH(keyId: String, peerPublicKeyDer: ByteArray): ByteArray {
        val alias = buildGeneralAlias(keyId)

        val privateKey = keyStore.getKey(alias, null) as? PrivateKey
            ?: throw KeyNotFoundException(keyId)

        try {
            val keyFactory = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC)
            val peerPublicKey = keyFactory.generatePublic(X509EncodedKeySpec(peerPublicKeyDer))

            val keyAgreement = KeyAgreement.getInstance("ECDH")
            try {
                keyAgreement.init(privateKey)
            } catch (e: java.security.InvalidKeyException) {
                // An EC key generated before the device reached API 31 (or
                // before PURPOSE_AGREE_KEY was requested) cannot agree.
                if (requiresUserAuthentication(e) ||
                    e is android.security.keystore.KeyPermanentlyInvalidatedException
                ) throw e
                throw ECDHException(
                    "key $keyId was not generated with PURPOSE_AGREE_KEY " +
                        "(EC keys made below Android 12 / API 31 cannot do ECDH)",
                    e
                )
            }
            keyAgreement.doPhase(peerPublicKey, true)
            return keyAgreement.generateSecret()
        } catch (e: ECDHException) {
            throw e
        } catch (e: Exception) {
            if (requiresUserAuthentication(e)) throw BiometricRequiredException()
            throw ECDHException("ECDH key agreement failed", e)
        }
    }

    // -------------------------------------------------------------------------
    // Public Key Export
    // -------------------------------------------------------------------------

    /**
     * Get a general key's public key in DER format (X.509 SubjectPublicKeyInfo).
     *
     * @param keyId Key identifier.
     * @return DER-encoded public key bytes, or null if the key does not exist.
     */
    fun getPublicKeyDER(keyId: String, kind: UserKeyKind): ByteArray? {
        val alias = resolveKeystoreAlias(keyId, kind) ?: return null
        return publicKeyDERAt(alias)
    }

    /**
     * The user key a key row under [keyId] of [keyType] and
     * public key ([publicKey], DER or COSE, read only when it is needed) describes, given the id's material [generation]
     * entries: every delete of a key row resolves its key here (#270
     * review). With at most one key under the id, the row's type says it.
     * With a credential and a general key sharing the id, the type does
     * not (`local.generateKey` makes fido2 rows under the general alias):
     * the row's public key must be exactly one of the two keys', or
     * [KeyOwnershipUnknownException] refuses the delete. A row with no public
     * key while the software store holds the id is the software key's: it
     * resolves to the general key (a symmetric key has no public key to match).
     *
     * The key is read from the material ([ownersOf]), never from the type
     * alone (#270 verify): with one key under the id, the row is that key's
     * (a fido2 row's key can be under the general alias), unless the row's
     * public key names another key, when the row's own key is gone and the
     * type names it. Only with no material under the id does the type say.
     * So a retry, which never switches kind, still deletes the row's key.
     */
    fun rowKeyKind(keyId: String, keyType: String, publicKey: () -> RowPublicKey, generation: Set<String>): UserKeyKind {
        val held = ownersOf(keyId, generation)
        if (held.isEmpty()) return userKeyKindOf(keyType)
        val row = publicKey()
        // The row's key read in each encoding it holds ([matchRowPublicKey]). Each key's public half is
        // read from the backend that stores it: a Keystore certificate, or a legacy software Ed25519
        // key's preferences entry, which has no certificate (PR #400 review).
        val rowPublicKeyMatch = { kind: UserKeyKind ->
            val alias = userKeyAlias(keyId, kind)
            matchRowPublicKey(
                row,
                {
                    runCatching { getPublicKeyDER(keyId, kind) }.getOrNull()
                        ?: if ("$ED25519_ENTRY$alias" in generation) legacyEd25519PublicKeyDer(alias) else null
                },
                { getCOSEPublicKey(keyId, kind) }
            )
        }
        held.singleOrNull()?.let { only ->
            // A key with no readable public half (symmetric, software) is
            // the row's: only a public key that differs names another key.
            val own = row.isEmpty || rowPublicKeyMatch(only) != false
            return if (own) only else userKeyKindOf(keyType)
        }
        // A row with no public key beside a software store record is that
        // software (symmetric) key's: a credential's row always records its
        // public key, so the general namespace owns it, as [rowOwnerKind]
        // reads it (#270 review of 33427e39).
        if (row.isEmpty && com.automatethethings.xkey.storage.SOFTWARE_ENTRY in generation) {
            return UserKeyKind.GENERAL
        }
        val owners = if (row.isEmpty) emptyList() else UserKeyKind.entries.filter {
            rowPublicKeyMatch(it) == true
        }
        return owners.singleOrNull() ?: throw KeyOwnershipUnknownException(keyId)
    }


    /**
     * Get a general key's public key in PEM format.
     *
     * The PEM format wraps the DER-encoded public key in Base64 with
     * standard "BEGIN PUBLIC KEY" / "END PUBLIC KEY" header and footer.
     *
     * @param keyId Key identifier.
     * @return PEM-encoded public key string, or null if the key does not exist.
     */
    fun getPublicKeyPEM(keyId: String, kind: UserKeyKind): String? {
        val der = getPublicKeyDER(keyId, kind) ?: return null
        val base64 = Base64.encodeToString(der, Base64.NO_WRAP)

        val sb = StringBuilder()
        sb.appendLine("-----BEGIN PUBLIC KEY-----")
        var offset = 0
        while (offset < base64.length) {
            val end = minOf(offset + PEM_LINE_LENGTH, base64.length)
            sb.appendLine(base64.substring(offset, end))
            offset = end
        }
        sb.append("-----END PUBLIC KEY-----")
        return sb.toString()
    }

    /**
     * Get a general key's public key in OpenSSH authorized_keys format.
     *
     * Encodes the public key using the OpenSSH wire format as defined in
     * RFC 4253 (SSH Transport Layer Protocol) and RFC 5656 (EC SSH keys).
     *
     * Supported key types:
     * - EC P-256: "ecdsa-sha2-nistp256"
     * - EC P-384: "ecdsa-sha2-nistp384"
     * - EC P-521: "ecdsa-sha2-nistp521"
     * - RSA: "ssh-rsa"
     *
     * @param keyId Key identifier.
     * @return OpenSSH public key string, or null if the key does not exist or type is unsupported.
     */
    fun getPublicKeySSH(keyId: String, kind: UserKeyKind): String? {
        val alias = resolveKeystoreAlias(keyId, kind) ?: return null
        val cert = keyStore.getCertificate(alias) ?: return null
        val publicKey = cert.publicKey

        return when (publicKey) {
            is ECPublicKey -> encodeSSHECPublicKey(publicKey)
            is RSAPublicKey -> encodeSSHRSAPublicKey(publicKey)
            else -> null
        }
    }

    // -------------------------------------------------------------------------
    // Key Attestation
    // -------------------------------------------------------------------------

    /**
     * Get key attestation certificate chain with caller-provided challenge.
     *
     * Generates a dedicated ephemeral attestation key with the caller's
     * challenge bound via [KeyGenParameterSpec.Builder.setAttestationChallenge].
     * The resulting certificate chain proves the device's TEE/StrongBox is
     * genuine and includes the caller's challenge for freshness verification.
     *
     * The ephemeral key is deleted after retrieving the certificate chain.
     *
     * @param keyId Key identifier (used to namespace the temporary alias).
     * @param challenge Nonce bytes from the requesting party, embedded in the
     *                  attestation extension of the leaf certificate.
     * @return Certificate chain (leaf -> intermediate -> root), or null if
     *         attestation is not supported (API < 24).
     */
    fun getKeyAttestationWithChallenge(
        keyId: String,
        challenge: ByteArray
    ): List<Certificate>? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) return null

        val tempAlias = "xkey_attest_${keyId}_${System.nanoTime()}"
        try {
            val specBuilder = KeyGenParameterSpec.Builder(
                tempAlias,
                KeyProperties.PURPOSE_SIGN
            )
                .setAlgorithmParameterSpec(ECGenParameterSpec(EC_CURVE))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(challenge)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && isStrongBoxAvailable()) {
                specBuilder.setIsStrongBoxBacked(true)
            }

            val chain = try {
                generateAttestationKeyPair(tempAlias, specBuilder)
            } catch (e: Exception) {
                // StrongBox fallback: retry without StrongBox backing
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && isStrongBoxAvailable()) {
                    val fallbackBuilder = KeyGenParameterSpec.Builder(
                        tempAlias,
                        KeyProperties.PURPOSE_SIGN
                    )
                        .setAlgorithmParameterSpec(ECGenParameterSpec(EC_CURVE))
                        .setDigests(KeyProperties.DIGEST_SHA256)
                        .setAttestationChallenge(challenge)
                    generateAttestationKeyPair(tempAlias, fallbackBuilder)
                } else {
                    throw e
                }
            }

            return chain
        } catch (e: Exception) {
            throw AttestationException("Failed to generate attestation key", e)
        } finally {
            try {
                withAliasGate(tempAlias) { keyStore.deleteEntry(tempAlias) }
            } catch (_: Exception) {
                // Best-effort cleanup
            }
        }
    }

    /**
     * Generate an ephemeral key pair and return its attestation certificate chain.
     */
    private fun generateAttestationKeyPair(
        alias: String,
        specBuilder: KeyGenParameterSpec.Builder
    ): List<Certificate> {
        // Delete if a stale entry exists from a previous failed attempt
        if (keyStore.containsAlias(alias)) {
            withAliasGate(alias) { keyStore.deleteEntry(alias) }
        }
        val keyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            KEYSTORE_PROVIDER
        )
        keyPairGenerator.initialize(specBuilder.build())
        withAliasGate(alias) { keyPairGenerator.generateKeyPair() }

        return keyStore.getCertificateChain(alias)?.toList()
            ?: throw AttestationException("No certificate chain available for attestation key")
    }

    // -------------------------------------------------------------------------
    // Key Management (General Keys)
    // -------------------------------------------------------------------------

    /**
     * The Keystore alias of [keyId]'s user key of [kind] ([resolveKey]), or
     * null if that key does not exist.
     * A software ML-DSA key resolves to its general alias, which holds no
     * Keystore entry: callers read its public key through [publicKeyDERAt].
     */
    fun resolveKeystoreAlias(keyId: String, kind: UserKeyKind): String? = resolveKey(keyId, kind)?.alias

    /**
     * The one resolver of a key id (#255 review r2, r3): the Keystore alias
     * a lookup of [keyId]'s user key of [kind] reads. Every resolution names
     * its namespace, and reads that namespace's own alias only (a general key
     * also as its Ed25519 entry): a credential and a general key sharing an
     * id are never read as one another, so the key a caller signs with is the
     * one whose public key it was given. The deleted-key gate
     * ([com.automatethethings.xkey.storage.KeyPolicyStore.requireUsable])
     * asks this same resolver which key a use reaches.
     *
     * A caller that does not know which namespace holds an id asks
     * [soleKind] first, which names none when both do.
     *
     * A namespace whose store cannot be read is never taken for an empty one
     * (#255 review r5): its probe throws [KeyPresenceUnreadableException], so
     * [soleKind], [exportKind] and [userKeyIdInUse] refuse rather than fall
     * back to the other namespace.
     *
     * Presence is decided by [holdsUserKey] alone, over every backend of
     * [kind] (#255 review r6): a general key kept in the [SoftwareKeyStore]
     * holds its id like any other, and resolves to no Keystore alias, so a
     * Keystore read of it finds nothing rather than another key.
     *
     * @return The resolved alias, or null if no Keystore or Ed25519 key of [kind] holds the id.
     * @throws KeyPresenceUnreadableException if a backend of the namespace cannot be read.
     */
    fun resolveKey(keyId: String, kind: UserKeyKind): ResolvedKey? {
        if (!holdsUserKey(keyId, kind)) return null
        val own = userKeyAlias(keyId, kind)
        return when {
            presenceIn(KeyBackend.KEYSTORE, keyId, kind) == KeyPresence.PRESENT -> ResolvedKey(own, kind)
            kind == UserKeyKind.GENERAL && presenceIn(KeyBackend.ED25519, keyId, kind) == KeyPresence.PRESENT ->
                ResolvedKey(own, kind)
            kind == UserKeyKind.GENERAL && presenceIn(KeyBackend.PQC, keyId, kind) == KeyPresence.PRESENT ->
                ResolvedKey(own, kind)
            else -> null
        }
    }

    /** The backends a user key of [kind] can live in: a credential only in the Keystore, a general key in any. */
    fun backendsOf(kind: UserKeyKind): List<KeyBackend> = when (kind) {
        UserKeyKind.CREDENTIAL -> listOf(KeyBackend.KEYSTORE)
        UserKeyKind.GENERAL -> KeyBackend.entries
    }

    /**
     * The one presence probe of a user-key namespace (#255 review r6):
     * whether [keyId] holds a key of [kind] in any of its backends
     * ([backendsOf]). [KeyPresence.UNREADABLE] when any backend cannot be
     * read, even if another holds the key, since which key the id names is
     * then unknown; [KeyPresence.PRESENT] when one holds it; otherwise
     * [KeyPresence.ABSENT]. Every resolver path ([resolveKey], [soleKind],
     * [exportKind], [userKeyIdInUse] and both generators' checks through it)
     * asks this, so none skips a backend.
     */
    fun userKeyPresence(keyId: String, kind: UserKeyKind): KeyPresence {
        val found = backendsOf(kind).map { presenceIn(it, keyId, kind) }
        return when {
            KeyPresence.UNREADABLE in found -> KeyPresence.UNREADABLE
            KeyPresence.PRESENT in found -> KeyPresence.PRESENT
            else -> KeyPresence.ABSENT
        }
    }

    /**
     * Whether [keyId] holds a key of [kind] ([userKeyPresence]).
     *
     * @throws KeyPresenceUnreadableException if a backend of the namespace cannot be read.
     */
    fun holdsUserKey(keyId: String, kind: UserKeyKind): Boolean = when (userKeyPresence(keyId, kind)) {
        KeyPresence.PRESENT -> true
        KeyPresence.ABSENT -> false
        KeyPresence.UNREADABLE -> throw KeyPresenceUnreadableException(userKeyAlias(keyId, kind), null)
    }

    /** What [backend] holds for [keyId]'s user key of [kind]; a store that cannot be read is UNREADABLE. */
    internal fun presenceIn(backend: KeyBackend, keyId: String, kind: UserKeyKind): KeyPresence = when (backend) {
        KeyBackend.KEYSTORE -> try {
            if (keyStore.containsAlias(userKeyAlias(keyId, kind))) KeyPresence.PRESENT else KeyPresence.ABSENT
        } catch (e: Exception) {
            KeyPresence.UNREADABLE
        }
        KeyBackend.ED25519 -> ed25519Presence(userKeyAlias(keyId, kind))
        KeyBackend.SOFTWARE -> softwareKeyPresence(keyId)
        KeyBackend.PQC -> pqcPresence(userKeyAlias(keyId, kind))
    }

    /** What the software ML-DSA store holds at [alias]; a store that cannot be read is UNREADABLE. */
    internal fun pqcPresence(alias: String): KeyPresence =
        try {
            if (pqcStore.contains(alias)) KeyPresence.PRESENT else KeyPresence.ABSENT
        } catch (e: Exception) {
            KeyPresence.UNREADABLE
        }

    /** What the [SoftwareKeyStore] holds for [keyId]; a store that cannot be read is UNREADABLE. */
    internal fun softwareKeyPresence(keyId: String): KeyPresence =
        try {
            softwareKeys().presence(keyId)
        } catch (e: Exception) {
            KeyPresence.UNREADABLE
        }

    /**
     * The store of exportable general keys, read by [softwareKeyPresence]:
     * one store, so its migration and its kept metadata scan serve every
     * resolver call (#255).
     */
    private val softwareKeyStore: SoftwareKeyStore by lazy { SoftwareKeyStore(context) }

    /** The store of exportable general keys, read by [softwareKeyPresence]. */
    internal fun softwareKeys(): SoftwareKeyStore = softwareKeyStore

    /**
     * The one user-key namespace holding [keyId] (#255 review r3): the
     * credential or the general key, or null when neither exists or both do.
     * A path that serves a key from either namespace (a passkey made by the
     * FIDO2 RPCs is a credential, one made through `local.generateKey` a
     * general key) resolves, gates and reads with the kind named here, and an
     * id held in both namespaces is refused, never read as either.
     */
    fun soleKind(keyId: String): UserKeyKind? {
        val credential = holdsUserKey(keyId, UserKeyKind.CREDENTIAL)
        val general = holdsUserKey(keyId, UserKeyKind.GENERAL)
        return when {
            credential && !general -> UserKeyKind.CREDENTIAL
            general && !credential -> UserKeyKind.GENERAL
            else -> null
        }
    }

    /**
     * The namespace a public-key share or export of [keyId] reads (#255
     * review r4): the credential namespace when only a credential holds the
     * id, so a credential that lives only under its credential alias shares
     * and exports like a general key (SPEC key-sharing allows hardware
     * public-key sharing in either namespace); otherwise the general
     * namespace, where the general key, a software key or no key is found.
     * A general key beside a credential of its id exports its own key, never
     * the credential's (#255 review r2). A caller resolves this once, then
     * gates and reads with the same kind. The general namespace counts every
     * backend ([userKeyPresence]): a software key beside a credential of its
     * id exports as the general key it is, never as the credential (#255
     * review r6).
     */
    fun exportKind(keyId: String): UserKeyKind =
        if (!holdsUserKey(keyId, UserKeyKind.GENERAL) && holdsUserKey(keyId, UserKeyKind.CREDENTIAL)) {
            UserKeyKind.CREDENTIAL
        } else {
            UserKeyKind.GENERAL
        }

    /**
     * Whether [keyId] is in use in either user-key namespace: a key is
     * created under an id only when this is false (#255 review r3), so a
     * credential and a general key never come to share an id. Every
     * namespace is probed, so one that cannot be read refuses
     * ([KeyPresenceUnreadableException]) even when another holds the id
     * (#255 review r5).
     */
    fun userKeyIdInUse(keyId: String): Boolean =
        UserKeyKind.entries.map { holdsUserKey(keyId, it) }.any { it }

    /**
     * The alias a raw [keyId] names outside the user-key namespaces: the
     * raw alias itself (never a PIV slot's, which only PivKeyManager
     * reaches), as a Keystore entry or an Ed25519 entry; null if none.
     */
    private fun rawAlias(keyId: String): String? = when {
        keyId.startsWith(PIV_KEYSTORE_ALIAS_PREFIX) -> null
        keyStore.containsAlias(keyId) || hasSoftwareEd25519Key(keyId) -> keyId
        else -> null
    }

    /**
     * Whether any key is stored under [keyId]: a user key of either kind or
     * a raw alias. A presence check only; nothing is read through it.
     */
    fun holdsAnyKey(keyId: String): Boolean = userKeyIdInUse(keyId) || rawAlias(keyId) != null

    /**
     * Whether [keyId] names an internal key of the app (a CA, the
     * attestation, sealing or encryption keys) or a foreign one: a raw alias
     * with no user key under the id. A presence check only.
     */
    fun holdsInternalKey(keyId: String): Boolean = !userKeyIdInUse(keyId) && rawAlias(keyId) != null

    /**
     * The user keys that own [keyId] ([ownersOf]), from the material stored
     * under it in every backend: the Keystore and Ed25519 entries of its
     * user-key namespace ([userKeyGeneration]) and its software store record
     * (#270 verify). Empty when no user key holds the id. A backend that
     * cannot be read throws, never reads as "no owner".
     */
    fun userKeyOwners(keyId: String): Set<UserKeyKind> {
        val material = userKeyGeneration(keyId).keys.toMutableSet()
        if (softwareKeys().generation(keyId) != null) material += com.automatethethings.xkey.storage.SOFTWARE_ENTRY
        return ownersOf(keyId, material)
    }

    /**
     * Whether an Ed25519 software key is stored under [alias] (API 33+ only),
     * three-way (#255 review r5): a store that cannot be read is
     * [KeyPresence.UNREADABLE], never [KeyPresence.ABSENT].
     */
    internal fun ed25519Presence(alias: String): KeyPresence =
        try {
            if (hasSoftwareEd25519Key(alias)) KeyPresence.PRESENT else KeyPresence.ABSENT
        } catch (e: KeyPresenceUnreadableException) {
            KeyPresence.UNREADABLE
        }

    /**
     * True if an Ed25519 software key is stored under [alias] (API 33+ only).
     * A store that cannot be read throws [KeyPresenceUnreadableException],
     * never reads as absent, so no resolver path (an id's namespace, its
     * export kind, whether it is in use) falls through to another namespace
     * on a read failure (#255 review r5).
     */
    internal fun hasSoftwareEd25519Key(alias: String): Boolean =
        alias in uncommittedSoftwareRemovals || ed25519Read(alias) { ed25519Prefs()?.contains(alias) == true }

    /**
     * The SubjectPublicKeyInfo DER of the legacy software Ed25519 key stored
     * under [alias], derived from its PKCS#8 preferences entry (it keeps no
     * public key or certificate), or null if none is stored. The one reader
     * of a legacy entry's value, and only for [rowKeyKind]'s ownership
     * compare: a legacy key never signs and is never migrated. A store that
     * cannot be read throws [KeyPresenceUnreadableException]. Internal for
     * tests only; KeyOwnershipChokePointTest pins rowKeyKind as its one caller.
     */
    @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    internal fun legacyEd25519PublicKeyDer(alias: String): ByteArray? {
        val prefs = ed25519Read(alias) { ed25519Prefs() } ?: return null
        val encoded = ed25519Read(alias) { prefs.getString(alias, null) } ?: return null
        val params = org.bouncycastle.crypto.util.PrivateKeyFactory.createKey(Base64.decode(encoded, Base64.NO_WRAP))
            as org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
        return org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory
            .createSubjectPublicKeyInfo(params.generatePublicKey()).encoded
    }

    /**
     * True only when no key material for [keyId] is stored in any backend
     * ([holdsAnyKey]), counting a software Ed25519 removal that did not
     * commit as present after one retry of it.
     *
     * @throws KeyPresenceUnreadableException or [KeyDeletionException] if a
     *   store cannot be read, so presence is unknown: the caller must keep the row.
     */
    fun keyMaterialAbsent(keyId: String): Boolean {
        val softwareAliases = listOfNotNull(
            KEY_ALIAS_PREFIX_GENERAL + keyId,
            keyId.takeUnless { it.startsWith(PIV_KEYSTORE_ALIAS_PREFIX) }
        )
        // A removal that did not commit left the key on disk though the
        // store's cache no longer lists it: retry it, and until it reaches
        // disk the key is present.
        if (softwareAliases.any { removalStillUncommitted(it) }) return false
        // An unreadable backend throws KeyPresenceUnreadableException here: presence is unknown.
        if (holdsAnyKey(keyId)) return false
        // Ask the software store again under each alias's gate, failing loudly on an unreadable store.
        return softwareAliases.none { alias ->
            withAliasGate(alias) { softwareEd25519KeyStored(alias, strict = true) }
        }
    }

    /**
     * The one way an Ed25519 preference is read (#255 review round 2): the
     * store can pass contains() while the read of the encrypted value fails
     * (a SecurityException on corrupt ciphertext, a GeneralSecurityException,
     * an I/O error), and a failure to open it fails the same way. Any such
     * failure of [read] is [KeyPresenceUnreadableException] for [alias], so
     * every caller, the key screens' refusal included, sees a store that
     * cannot be read rather than an unchecked exception.
     */
    private inline fun <T> ed25519Read(alias: String, read: () -> T): T =
        try {
            read()
        } catch (e: KeyPresenceUnreadableException) {
            throw e
        } catch (e: Exception) {
            throw KeyPresenceUnreadableException(alias, e)
        }

    /**
     * The EncryptedSharedPreferences holding Ed25519 software keys, or null
     * below API 33, where none are generated. Every Ed25519 read, write and
     * delete goes through it.
     */
    internal fun ed25519Prefs(): SharedPreferences? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return null
        return EncryptedSharedPreferences.create(
            context,
            ED25519_PREFS_NAME,
            MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    /**
     * The generation of the user key [keyId] held in this manager's backends:
     * one entry per piece of material in its user-key namespace
     * ([userKeyAliases]), `keystore:<alias>` for an Android Keystore entry
     * and `ed25519:<alias>` for an Ed25519 software key, each mapped to a tag
     * that changes when the material under that alias is replaced (the
     * entry's creation date and certificate digest, or the digest of the
     * stored key). Empty when no material is held. A backend that cannot be
     * read throws: an unreadable Ed25519 store, or a value in it that cannot
     * be read, is [KeyPresenceUnreadableException] ([ed25519Read]), never
     * taken for an empty one, so a delete refuses before it removes any row
     * (#255 review).
     */
    fun userKeyGeneration(keyId: String): Map<String, String> {
        val generation = LinkedHashMap<String, String>()
        val prefs = ed25519Read(keyId) { ed25519Prefs() }
        for (alias in userKeyAliases(keyId)) {
            keystoreTag(alias)?.let { generation[KEYSTORE_ENTRY + alias] = it }
            val ed25519 = ed25519Read(alias) { prefs?.getString(alias, null) }
            if (ed25519 != null) generation[ED25519_ENTRY + alias] = digestHex(ed25519.toByteArray())
            // A removal that did not commit left the key on disk though the cache no longer lists it.
            else if (alias in uncommittedSoftwareRemovals) generation[ED25519_ENTRY + alias] = UNCOMMITTED_REMOVAL_TAG
            pqcTag(alias)?.let { generation[PQC_ENTRY + alias] = it }
        }
        return generation
    }

    /**
     * The tag of the software ML-DSA record at [alias] (the digest of its
     * public key), or null if there is none; a store that cannot be read
     * throws [KeyPresenceUnreadableException].
     */
    private fun pqcTag(alias: String): String? {
        if (!alias.startsWith(KEY_ALIAS_PREFIX_GENERAL)) return null
        val held = try {
            pqcStore.contains(alias)
        } catch (e: Exception) {
            throw KeyPresenceUnreadableException(alias, e)
        }
        return if (held) digestHex(pqcStore.publicKeyDer(alias) ?: ByteArray(0)) else null
    }

    /**
     * Delete the material of [generation] (from [userKeyGeneration]) that is
     * still in place: an entry whose alias now holds material with another
     * tag was replaced by a later write and is left alone. Returns the
     * entries of [generation] still held after the delete; empty means the
     * generation is gone. An Ed25519 remove whose commit() fails is still
     * held: the preferences' in-memory cache already shows it absent, but
     * nothing durable says so, so only a commit that returned true counts.
     */
    fun deleteUserKeyGeneration(keyId: String, generation: Map<String, String>): Map<String, String> {
        val namespace = userKeyAliases(keyId)
        val prefs = if (generation.keys.any { it.startsWith(ED25519_ENTRY) }) ed25519Read(keyId) { ed25519Prefs() } else null
        val uncommitted = LinkedHashMap<String, String>()
        for ((entry, tag) in generation) {
            when {
                entry.startsWith(KEYSTORE_ENTRY) -> {
                    val alias = entry.removePrefix(KEYSTORE_ENTRY)
                    if (alias in namespace) withAliasGate(alias) { if (keystoreTag(alias) == tag) keyStore.deleteEntry(alias) }
                }
                entry.startsWith(ED25519_ENTRY) -> {
                    val alias = entry.removePrefix(ED25519_ENTRY)
                    val stored = ed25519Read(alias) { prefs?.getString(alias, null) }
                    // Absent from the cache is not absent from disk: a remove
                    // whose commit() failed already left the cache without it.
                    // So an absent entry is removed again, and only a commit()
                    // that returns true counts (a commit after a failed one
                    // writes the file again); replaced material is left.
                    val ours = stored == null || digestHex(stored.toByteArray()) == tag
                    if (alias in namespace && prefs != null && ours) {
                        // Pending before the commit, so no read takes the key absent before disk does.
                        uncommittedSoftwareRemovals.add(alias)
                        if (prefs.edit().remove(alias).commit()) uncommittedSoftwareRemovals.remove(alias) else uncommitted[entry] = tag
                    }
                }
                entry.startsWith(PQC_ENTRY) -> {
                    val alias = entry.removePrefix(PQC_ENTRY)
                    // A delete that throws may have removed the record without advancing its generation: still owed.
                    if (alias in namespace) withAliasGate(alias) {
                        if (pqcTag(alias) == tag) {
                            try {
                                pqcStore.delete(alias)
                            } catch (e: java.io.IOException) {
                                uncommitted[entry] = tag
                            }
                        }
                    }
                }
            }
        }
        val left = userKeyGeneration(keyId)
        return generation.filter { (entry, tag) -> left[entry] == tag } + uncommitted
    }

    /** The tag of the Keystore entry at [alias], or null if there is none. */
    private fun keystoreTag(alias: String): String? {
        if (!keyStore.containsAlias(alias)) return null
        val created = keyStore.getCreationDate(alias)?.time ?: 0L
        val certificate = keyStore.getCertificate(alias)?.encoded ?: ByteArray(0)
        return "$created:${digestHex(certificate)}"
    }

    private fun digestHex(bytes: ByteArray): String =
        java.security.MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    /**
     * List all key aliases managed by xKey.
     *
     * Returns both credential keys (prefixed with "xkey_credential_") and
     * general-purpose keys (prefixed with "xkey_key_"), with their prefixes
     * stripped.
     *
     * @return List of key identifiers without alias prefixes.
     */
    fun listAllKeys(): List<String> {
        return keyStore.aliases().toList()
            .filter { it.startsWith(KEY_ALIAS_PREFIX) || it.startsWith(KEY_ALIAS_PREFIX_GENERAL) }
            .map { alias ->
                when {
                    alias.startsWith(KEY_ALIAS_PREFIX_GENERAL) -> alias.removePrefix(KEY_ALIAS_PREFIX_GENERAL)
                    alias.startsWith(KEY_ALIAS_PREFIX) -> alias.removePrefix(KEY_ALIAS_PREFIX)
                    else -> alias
                }
            }
    }

    /**
     * List all key aliases in the Android Keystore.
     *
     * Returns every alias this app has access to, regardless of prefix.
     * This includes FIDO2 credentials, general keys, and any other keys
     * stored by the app or system libraries.
     *
     * @return List of all Keystore aliases.
     */
    fun listAllKeystoreAliases(): List<String> {
        return keyStore.aliases().toList()
    }

    /**
     * Delete a key by its raw Keystore alias.
     *
     * @param alias The Keystore alias to delete.
     * @return true if the key was deleted, false if it didn't exist.
     * @throws KeyDeletionException if removing it failed: its material may
     *   still be there.
     */
    fun deleteByAlias(alias: String): Boolean {
        // PIV slot keys are deleted through PivKeyManager with their row.
        if (alias.startsWith(PIV_KEYSTORE_ALIAS_PREFIX)) return false
        // The app's wrap keys seal other keys and are never a user's to delete.
        if (KeystoreAeadCipher.isInternalAlias(alias)) return false
        return withAliasGate(alias) { removeAliasLocked(alias) }
    }

    /**
     * The one cleanup of a Keystore key this code just generated (#255
     * review r7): deletes exactly [alias] from the Android Keystore, its own
     * backend, and consults no other. It never goes through the
     * cross-backend presence guard ([holdsUserKey]), so an unreadable Ed25519
     * or software key store cannot leave a generated private key behind (an
     * ephemeral ECDH key, or a key whose generation failed half-way). PIV
     * slot aliases are never touched. A failed delete is reported, never
     * thrown, so a cleanup in a finally block never replaces the failure
     * that brought it there; it is never reported as an absent key (#255
     * review r8), so a caller cannot take a key left behind for one deleted.
     *
     * @return [GeneratedKeyDiscard.DELETED] if [alias] was held and is now
     *   gone, [GeneratedKeyDiscard.ABSENT] if it was not held, and
     *   [GeneratedKeyDiscard.FAILED] if it may still be held: the delete
     *   failed, the alias is still there after it, or a PIV alias was named.
     */
    fun discardGeneratedKey(alias: String): GeneratedKeyDiscard {
        if (alias.startsWith(PIV_KEYSTORE_ALIAS_PREFIX)) return GeneratedKeyDiscard.FAILED
        return try {
            // A presence read that fails is taken as held: the delete is tried.
            if (!runCatching { keyStore.containsAlias(alias) }.getOrDefault(true)) return GeneratedKeyDiscard.ABSENT
            withAliasGate(alias) { keyStore.deleteEntry(alias) }
            if (keyStore.containsAlias(alias)) GeneratedKeyDiscard.FAILED else GeneratedKeyDiscard.DELETED
        } catch (e: Exception) {
            GeneratedKeyDiscard.FAILED
        }
    }

    /**
     * Deletes the software ML-DSA record under [alias] ([PqcSoftwareKeyStore.delete],
     * which revokes its wrap key and advances its generation), reporting a
     * failed delete as [GeneratedKeyDiscard.FAILED], never as an absent key.
     */
    private fun discardPqcKey(alias: String): GeneratedKeyDiscard = try {
        if (withAliasGate(alias) { pqcStore.delete(alias) }) GeneratedKeyDiscard.DELETED else GeneratedKeyDiscard.ABSENT
    } catch (e: Exception) {
        GeneratedKeyDiscard.FAILED
    }

    /**
     * [discardGeneratedKey] for an ML-DSA key this code just generated under
     * [keyId]'s general alias: its Keystore entry (a hardware key), else its
     * software ML-DSA record.
     */
    fun discardGeneratedMlDsaKey(keyId: String): GeneratedKeyDiscard {
        val alias = generalKeyAlias(keyId)
        val outcome = discardGeneratedKey(alias)
        return if (outcome == GeneratedKeyDiscard.ABSENT) discardPqcKey(alias) else outcome
    }

    /**
     * Check if a general-purpose key exists in the keystore.
     *
     * @param keyId Key identifier.
     * @return true if the key exists.
     */
    fun generalKeyExists(keyId: String): Boolean {
        val alias = buildGeneralAlias(keyId)
        return keyStore.containsAlias(alias) || pqcStore.contains(alias)
    }

    /** Whether [keyId] is a software ML-DSA key ([PqcSoftwareKeyStore]). */
    fun pqcSoftwareKeyExists(keyId: String): Boolean = pqcStore.contains(buildGeneralAlias(keyId))

    /**
     * Whether [keyId] has live key material in any backend ([holdsAnyKey]:
     * Keystore, Ed25519, software store or software ML-DSA).
     */
    fun keyMaterialExists(keyId: String): Boolean = holdsAnyKey(keyId)

    /**
     * Whether [keyId] is a software ML-DSA key sealed with a user-authentication
     * policy, so its signer must authenticate the user first whatever the
     * request asks. A record that does not open counts as requiring it.
     */
    fun pqcSoftwareKeyRequiresUserAuth(keyId: String): Boolean = try {
        (pqcStore.authDurationSeconds(buildGeneralAlias(keyId)) ?: PqcSoftwareKeyStore.NO_USER_AUTHENTICATION) >= 0
    } catch (e: PqcKeyRecordException) {
        true
    }

    /**
     * Delete a general-purpose key from the keystore.
     *
     * @param keyId Key identifier.
     * @return true if the key was deleted, false if it did not exist.
     * @throws KeyDeletionException if removing it failed: its material may
     *   still be there.
     */
    fun deleteGeneralKey(keyId: String): Boolean {
        val alias = buildGeneralAlias(keyId)
        // A software ML-DSA record and a Keystore entry never share an
        // alias; either one is the key, and removeAliasLocked removes both.
        if (!withAliasGate(alias) { removeAliasLocked(alias) }) return false

        // Log key deletion
        AuditLogger.logKeyDeleted(
            keyId = keyId,
            keyLabel = keyId,
            keyType = "general"
        )

        return true
    }

    /**
     * Delete exactly FIDO2 credential [credentialId]'s Keystore entry
     * (`xkey_credential_<id>`), never the general key of the same ID, and
     * audit the deletion as [deleteKey] does.
     *
     * @param credentialId Credential identifier.
     * @return true if the entry was deleted, false if it did not exist.
     * @throws KeyDeletionException if removing it failed: its material may
     *   still be there.
     */
    fun deleteCredentialKey(credentialId: String): Boolean {
        val alias = credentialAlias(credentialId)
        if (!withAliasGate(alias) { removeAliasLocked(alias) }) return false

        AuditLogger.logKeyDeleted(
            keyId = credentialId,
            keyLabel = credentialId,
            keyType = FIDO2_KEY_TYPE
        )

        return true
    }

    // -------------------------------------------------------------------------
    // Private Helpers - Key Generation
    // -------------------------------------------------------------------------

    /**
     * Apply authentication duration settings to a key spec builder.
     *
     * Configures user authentication requirements based on the duration:
     * - Negative: no authentication required
     * - Zero: authentication required for every cryptographic operation
     * - Positive: authentication remains valid for the specified number of seconds
     */
    private fun applyAuthDuration(
        specBuilder: KeyGenParameterSpec.Builder,
        authDurationSeconds: Int
    ) {
        when {
            authDurationSeconds < 0 -> {
                specBuilder.setUserAuthenticationRequired(false)
            }
            authDurationSeconds == 0 -> {
                specBuilder.setUserAuthenticationRequired(true)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    specBuilder.setUserAuthenticationParameters(
                        0,
                        KeyProperties.AUTH_BIOMETRIC_STRONG
                    )
                } else {
                    @Suppress("DEPRECATION")
                    specBuilder.setUserAuthenticationValidityDurationSeconds(-1)
                }
            }
            else -> {
                specBuilder.setUserAuthenticationRequired(true)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    specBuilder.setUserAuthenticationParameters(
                        authDurationSeconds,
                        KeyProperties.AUTH_BIOMETRIC_STRONG
                    )
                } else {
                    @Suppress("DEPRECATION")
                    specBuilder.setUserAuthenticationValidityDurationSeconds(authDurationSeconds)
                }
            }
        }
    }

    /**
     * Apply StrongBox backing to a key spec builder if available and preferred.
     *
     * @return true if the spec now asks for StrongBox.
     */
    private fun applyStrongBox(
        specBuilder: KeyGenParameterSpec.Builder,
        preferStrongBox: Boolean
    ): Boolean {
        if (preferStrongBox &&
            sdkInt >= Build.VERSION_CODES.P &&
            isStrongBoxAvailable()
        ) {
            specBuilder.setIsStrongBoxBacked(true)
            return true
        }
        return false
    }

    /**
     * Apply attestation challenge to a key spec builder if supported.
     */
    private fun applyAttestationChallenge(specBuilder: KeyGenParameterSpec.Builder) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            specBuilder.setAttestationChallenge(generateAttestationChallenge())
        }
    }

    // -------------------------------------------------------------------------
    // Private Helpers - Algorithm Mapping
    // -------------------------------------------------------------------------

    /**
     * Get the EC curve name for a COSE/JOSE algorithm identifier.
     *
     * @param algorithm "ES256", "ES384", or "ES512".
     * @return SEC curve name (e.g., "secp256r1").
     * @throws KeyGenerationException if the algorithm is not a supported EC algorithm.
     */
    private fun getECCurve(algorithm: String): String = when (algorithm) {
        "ES256" -> EC_CURVE_P256
        "ES384" -> EC_CURVE_P384
        "ES512" -> EC_CURVE_P521
        else -> throw KeyGenerationException("Unsupported EC algorithm: $algorithm")
    }


    /**
     * Get the RSA key size in bits from a JOSE algorithm identifier.
     *
     * @param algorithm "RS256", "RS384", or "RS512".
     * @return RSA key size in bits.
     * @throws KeyGenerationException if the algorithm is not a supported RSA algorithm.
     */
    private fun getRSAKeySize(algorithm: String): Int = when (algorithm) {
        "RS256" -> 2048
        "RS384" -> 3072
        "RS512" -> 4096
        else -> throw KeyGenerationException("Unsupported RSA algorithm: $algorithm")
    }

    /**
     * Get the JCA signature algorithm name from a COSE/JOSE algorithm identifier.
     *
     * @param algorithm "ES256", "ES384", "ES512", "RS256", "RS384", or "RS512".
     * @return JCA signature algorithm name (e.g., "SHA256withECDSA").
     * @throws SigningException if the algorithm is not supported.
     */
    private fun getJCASignatureAlgorithm(algorithm: String): String = jcaSignatureAlgorithm(algorithm)

    /**
     * Get the JCA digest property constant from a COSE/JOSE algorithm identifier.
     *
     * @param algorithm Algorithm identifier.
     * @return Android KeyProperties digest constant.
     */
    private fun getDigestProperty(algorithm: String): String = when (algorithm) {
        "ES256", "RS256" -> KeyProperties.DIGEST_SHA256
        "ES384", "RS384" -> KeyProperties.DIGEST_SHA384
        "ES512", "RS512" -> KeyProperties.DIGEST_SHA512
        else -> KeyProperties.DIGEST_SHA256
    }

    /**
     * Build the keystore alias for a general-purpose key.
     */
    private fun buildGeneralAlias(keyId: String): String = generalKeyAlias(keyId)

    // -------------------------------------------------------------------------
    // Private Helpers - SSH Key Encoding
    // -------------------------------------------------------------------------

    /**
     * Encode an EC public key in OpenSSH wire format.
     *
     * Format: "ecdsa-sha2-{curve} {base64-encoded-blob}"
     * Blob: string(key-type) || string(curve-name) || string(ec-point)
     */
    private fun encodeSSHECPublicKey(publicKey: ECPublicKey): String {
        val params = publicKey.params
        val fieldSize = params.curve.field.fieldSize

        val (keyType, curveName, coordinateSize) = when (fieldSize) {
            256 -> Triple("ecdsa-sha2-nistp256", "nistp256", EC_COORDINATE_SIZE_P256)
            384 -> Triple("ecdsa-sha2-nistp384", "nistp384", EC_COORDINATE_SIZE_P384)
            521 -> Triple("ecdsa-sha2-nistp521", "nistp521", EC_COORDINATE_SIZE_P521)
            else -> return ""
        }

        val x = padCoordinate(publicKey.w.affineX.toByteArray(), coordinateSize)
        val y = padCoordinate(publicKey.w.affineY.toByteArray(), coordinateSize)

        // EC point: 0x04 || x || y (uncompressed)
        val ecPoint = byteArrayOf(0x04) + x + y

        val blob = java.io.ByteArrayOutputStream()
        writeSSHString(blob, keyType.toByteArray(Charsets.UTF_8))
        writeSSHString(blob, curveName.toByteArray(Charsets.UTF_8))
        writeSSHString(blob, ecPoint)

        val base64Blob = Base64.encodeToString(blob.toByteArray(), Base64.NO_WRAP)
        return "$keyType $base64Blob"
    }

    /**
     * Encode an RSA public key in OpenSSH wire format.
     *
     * Format: "ssh-rsa {base64-encoded-blob}"
     * Blob: string("ssh-rsa") || mpint(e) || mpint(n)
     */
    private fun encodeSSHRSAPublicKey(publicKey: RSAPublicKey): String {
        val keyType = "ssh-rsa"

        val blob = java.io.ByteArrayOutputStream()
        writeSSHString(blob, keyType.toByteArray(Charsets.UTF_8))
        writeSSHMPInt(blob, publicKey.publicExponent.toByteArray())
        writeSSHMPInt(blob, publicKey.modulus.toByteArray())

        val base64Blob = Base64.encodeToString(blob.toByteArray(), Base64.NO_WRAP)
        return "$keyType $base64Blob"
    }

    /**
     * Write a length-prefixed string in SSH wire format (uint32 length + data).
     */
    private fun writeSSHString(out: java.io.ByteArrayOutputStream, data: ByteArray) {
        val length = data.size
        out.write((length shr 24) and 0xFF)
        out.write((length shr 16) and 0xFF)
        out.write((length shr 8) and 0xFF)
        out.write(length and 0xFF)
        out.write(data)
    }

    /**
     * Write an SSH mpint (multiple precision integer).
     *
     * MPInt format: uint32 length followed by the integer in two's complement
     * big-endian format. If the high bit is set, a leading zero byte is prepended.
     */
    private fun writeSSHMPInt(out: java.io.ByteArrayOutputStream, data: ByteArray) {
        writeSSHString(out, data)
    }

    // -------------------------------------------------------------------------
    // Existing Private Methods
    // -------------------------------------------------------------------------

    /**
     * Encode a public key in COSE_Key format for WebAuthn.
     *
     * @param publicKey The EC public key to encode.
     * @return CBOR-encoded COSE_Key bytes.
     * @throws KeyGenerationException if encoding fails.
     */
    private fun encodeCOSEPublicKey(publicKey: PublicKey): ByteArray {
        val ecKey = publicKey as? ECPublicKey
            ?: throw KeyGenerationException("Public key is not an EC key")

        val point = ecKey.w
        val x = padCoordinate(point.affineX.toByteArray(), EC_COORDINATE_SIZE)
        val y = padCoordinate(point.affineY.toByteArray(), EC_COORDINATE_SIZE)

        return CborEncoder.encodeCOSEEC2Key(x, y)
    }

    /**
     * Pad or trim an EC coordinate to the required size.
     *
     * BigInteger.toByteArray() may return:
     * - A leading zero byte if the high bit is set (to indicate positive)
     * - Fewer than required bytes if the value is small
     */
    private fun padCoordinate(bytes: ByteArray, size: Int): ByteArray {
        return when {
            bytes.size == size -> bytes
            bytes.size > size -> {
                // Remove leading zeros (e.g., sign byte)
                bytes.takeLast(size).toByteArray()
            }
            else -> {
                // Pad with leading zeros
                ByteArray(size - bytes.size) + bytes
            }
        }
    }

    /**
     * Generate a random attestation challenge.
     */
    private fun generateAttestationChallenge(): ByteArray {
        val challenge = ByteArray(ATTESTATION_CHALLENGE_SIZE)
        java.security.SecureRandom().nextBytes(challenge)
        return challenge
    }

    /**
     * Build the keystore alias from a credential ID.
     */
    private fun buildAlias(credentialId: String): String = credentialAlias(credentialId)

    companion object {
        /** The full Keystore alias of general-purpose key [keyId]. */
        fun generalKeyAlias(keyId: String): String = KEY_ALIAS_PREFIX_GENERAL + keyId

        /** The full Keystore alias of FIDO2 credential [credentialId]. */
        fun credentialAlias(credentialId: String): String = KEY_ALIAS_PREFIX + credentialId

        /**
         * The JCA signature algorithm a key of COSE/JOSE [algorithm] signs with.
         *
         * @param algorithm "ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "EdDSA" or "Ed25519".
         * @throws SigningException if the algorithm is not supported.
         */
        fun jcaSignatureAlgorithm(algorithm: String): String =
            JCA_SIGNATURE_ALGORITHMS[algorithm] ?: throw SigningException("Unsupported algorithm: $algorithm")

        /** True when a key of [algorithm] signs through [jcaSignatureAlgorithm]; ML-DSA keys do not. */
        fun hasJcaSignature(algorithm: String): Boolean = algorithm in JCA_SIGNATURE_ALGORITHMS

        /**
         * The keys among [keys] of a type in [keyTypes] that sign through a
         * JCA signature, in [keys]' order: the one selection every co-signing
         * key choice (automatic or picked) goes through, so an ML-DSA key is
         * never chosen to co-sign. A co-signature is a media signature, so the
         * key must also be one the media verifier checks
         * ([com.automatethethings.xkey.media.SignatureVerifier.offersSigning]):
         * an EdDSA key is never chosen either.
         */
        fun jcaSigningKeys(
            keys: List<KeyEntity>,
            keyTypes: Collection<String>
        ): List<KeyEntity> =
            keys.filter { it.keyType in keyTypes && com.automatethethings.xkey.media.SignatureVerifier.offersSigning(it.algorithm) }

        private val JCA_SIGNATURE_ALGORITHMS = mapOf(
            "ES256" to SIG_ALGORITHM_ES256,
            "ES384" to SIG_ALGORITHM_ES384,
            "ES512" to SIG_ALGORITHM_ES512,
            "RS256" to SIG_ALGORITHM_RS256,
            "RS384" to SIG_ALGORITHM_RS384,
            "RS512" to SIG_ALGORITHM_RS512,
            "EdDSA" to "Ed25519",
            "Ed25519" to "Ed25519"
        )

        /** The JCA algorithm passkey assertions sign their hash with. */
        const val PASSKEY_SIGNATURE_ALGORITHM = "SHA256withECDSA"

        /**
         * The lock for one Keystore alias and how many threads hold it or
         * wait on it. [users] changes only inside the registry's per-key
         * `compute`, so an entry is dropped exactly when its last user leaves.
         */
        private class AliasGate {
            val lock = java.util.concurrent.locks.ReentrantLock()
            var users = 0
        }

        /**
         * One gate per Keystore alias, shared by every instance in the
         * process. An alias has an entry only while some thread holds or
         * waits on its gate, so churned aliases leave nothing behind.
         */
        private val aliasGates = java.util.concurrent.ConcurrentHashMap<String, AliasGate>()

        /**
         * Software Ed25519 aliases whose removal did not reach disk. The
         * SharedPreferences cache that already dropped them lives exactly as
         * long as this process, so a process-scoped record covers exactly the
         * window in which that cache can lie; after a restart the store is
         * read from disk again, where the key still is.
         */
        private val uncommittedSoftwareRemovals: MutableSet<String> =
            java.util.concurrent.ConcurrentHashMap.newKeySet()

        /** The generation tag of a software Ed25519 key whose removal did not commit. */
        private const val UNCOMMITTED_REMOVAL_TAG = "uncommitted-removal"

        /**
         * Runs [block] holding the process-wide gate for Keystore [alias].
         * [signApproved] checks and signs inside it, and every delete or key
         * generation under an alias takes it, so a key cannot be replaced
         * between an approved-key check and its signature. [block] cannot
         * suspend: the gate is a thread lock.
         *
         * A caller joins the alias's entry before it waits on the lock and
         * leaves it after it unlocks, both inside the registry's atomic
         * per-key `compute`. Two concurrent users of one alias therefore
         * always share one lock, and the entry goes once neither needs it.
         */
        fun <T> withAliasGate(alias: String, block: () -> T): T {
            val gate = aliasGates.compute(alias) { _, existing ->
                (existing ?: AliasGate()).also { it.users++ }
            }!!
            try {
                gate.lock.lock()
                try {
                    return block()
                } finally {
                    gate.lock.unlock()
                }
            } finally {
                aliasGates.compute(alias) { _, existing ->
                    check(existing === gate) { "alias gate for $alias replaced while in use" }
                    gate.users--
                    if (gate.users == 0) null else gate
                }
            }
        }

        /** How many aliases the gate registry holds an entry for. */
        @androidx.annotation.VisibleForTesting
        internal fun aliasGateCount(): Int = aliasGates.size

        /** Android Keystore provider name. */
        private const val KEYSTORE_PROVIDER = "AndroidKeyStore"

        /**
         * Prefix for all xKey credential key aliases. Code outside this class
         * names an alias through [credentialAlias], [generalKeyAlias] or
         * [keyRowAlias], never by hand (KeystoreAliasNamingChokePointTest).
         */
        internal const val KEY_ALIAS_PREFIX = "xkey_credential_"

        /** Prefix for general-purpose key aliases (see [KEY_ALIAS_PREFIX]). */
        internal const val KEY_ALIAS_PREFIX_GENERAL = "xkey_key_"

        /** A FIDO2 key row's type (protocol KeyTypes.FIDO2; crypto does not import protocol). */
        private const val FIDO2_KEY_TYPE = "fido2"

        /**
         * The user-key namespace of [keyId]: the only Keystore aliases a
         * delete of a user's key may touch, its credential and general
         * aliases. An id that resolves to any other alias
         * ([holdsInternalKey]) names an internal key (a CA, the
         * attestation, sealing or encryption keys) or a foreign one.
         */
        fun userKeyAliases(keyId: String): List<String> =
            listOf(credentialAlias(keyId), generalKeyAlias(keyId))

        /** The one alias of [keyId]'s user key of [kind]. */
        fun userKeyAlias(keyId: String, kind: UserKeyKind): String = when (kind) {
            UserKeyKind.CREDENTIAL -> credentialAlias(keyId)
            UserKeyKind.GENERAL -> generalKeyAlias(keyId)
        }

        /**
         * Whether the [userKeyGeneration] entry [entry] is material of
         * [keyId]'s user key of [kind]: a credential and a general key can
         * share an id, and a delete of one never reaches the other's.
         */
        fun isEntryOf(entry: String, keyId: String, kind: UserKeyKind): Boolean {
            val alias = when {
                entry.startsWith(KEYSTORE_ENTRY) -> entry.removePrefix(KEYSTORE_ENTRY)
                entry.startsWith(ED25519_ENTRY) -> entry.removePrefix(ED25519_ENTRY)
                entry.startsWith(PQC_ENTRY) -> entry.removePrefix(PQC_ENTRY)
                else -> return false
            }
            return alias == userKeyAlias(keyId, kind)
        }

        /** The kind of user key a key row of [keyType] describes. */
        fun userKeyKindOf(keyType: String): UserKeyKind =
            if (keyType == "fido2") UserKeyKind.CREDENTIAL else UserKeyKind.GENERAL

        /**
         * Which of the keys under [keyId] an RPC delete removes (#255
         * review), given the kind of the id's key row ([rowKind], resolved
         * by [rowKeyKind]; with no row, the kind the method names: the
         * credential for the legacy `deleteKey`, else the general key) and
         * its material [generation] entries. With one key under the
         * id, that key (its row, if any, is its own). With a credential and
         * a general key sharing the id, the legacy `deleteKey` names the
         * credential and `local.deleteKey` the row's key, or with no row the
         * general key. With no material under the id, still one kind (the
         * row's, else the one the method names), never every alias: a key
         * written under the id meanwhile in the other namespace stays
         * (#270 round 4).
         */
        fun deleteTarget(keyId: String, rowKind: UserKeyKind, generation: Set<String>, legacy: Boolean): UserKeyKind {
            val owners = ownersOf(keyId, generation)
            val credential = UserKeyKind.CREDENTIAL in owners
            val general = UserKeyKind.GENERAL in owners
            return when {
                credential && !general -> UserKeyKind.CREDENTIAL
                general && !credential -> UserKeyKind.GENERAL
                !credential -> rowKind
                legacy -> UserKeyKind.CREDENTIAL
                else -> rowKind
            }
        }

        /**
         * The user key a delete naming [kind] removes, given the id's
         * material [generation] entries: [kind], unless only the other kind
         * holds material under the id. A key row's type does not say where
         * its material is: `local.generateKey` makes a fido2-typed key under
         * the general alias (#255 verify), and its delete must reach it.
         */
        fun presentKind(keyId: String, generation: Set<String>, kind: UserKeyKind): UserKeyKind {
            val other = if (kind == UserKeyKind.CREDENTIAL) UserKeyKind.GENERAL else UserKeyKind.CREDENTIAL
            val owners = ownersOf(keyId, generation)
            return if (kind !in owners && other in owners) other else kind
        }

        /**
         * The one reading of which user keys own [keyId] (#270 verify): the
         * kinds whose material [material] (entries of [userKeyGeneration],
         * [com.automatethethings.xkey.storage.keyMaterialGeneration] or a
         * tombstone's recorded generation) shows under the id, in every
         * backend: Keystore and Ed25519 entries of the kind's alias, and a
         * software store record for the general key. Every delete, replay,
         * settle and sync decides a key's namespace here, from its stored
         * material, never from a row's type or a presence probe's cache.
         */
        fun ownersOf(keyId: String, material: Set<String>): Set<UserKeyKind> =
            UserKeyKind.entries.filterTo(LinkedHashSet()) { holdsKind(keyId, material, it) }

        /**
         * Whether a key is the one [row] records, read in each encoding the
         * row holds ([der], [cose]; #270 verify r2: a passkey row's key is
         * COSE only): true if one matches, false if one differs and none
         * matches, null if the key's public half cannot be read in either
         * (a symmetric or non-EC key has none to compare).
         */
        fun matchRowPublicKey(row: RowPublicKey, der: () -> ByteArray?, cose: () -> ByteArray?): Boolean? {
            val byDer = row.der?.let { d -> runCatching(der).getOrNull()?.contentEquals(d) }
            val byCose = row.cose?.let { c -> runCatching(cose).getOrNull()?.contentEquals(c) }
            return when {
                byDer == true || byCose == true -> true
                byDer == false || byCose == false -> false
                else -> null
            }
        }

        /** Whether [generation] holds material of [keyId]'s [kind] key; a software key is a general key. */
        fun holdsKind(keyId: String, generation: Set<String>, kind: UserKeyKind): Boolean = generation.any {
            isEntryOf(it, keyId, kind) || kind == UserKeyKind.GENERAL && it == com.automatethethings.xkey.storage.SOFTWARE_ENTRY
        }

        /** EncryptedSharedPreferences file for Ed25519 software-backed keys. */
        private const val ED25519_PREFS_NAME = "xkey_ed25519_keys"

        /** [userKeyGeneration] entry prefix of an Android Keystore entry. */
        const val KEYSTORE_ENTRY = "keystore:"

        /** [userKeyGeneration] entry prefix of an Ed25519 software key. */
        const val ED25519_ENTRY = "ed25519:"

        /** [userKeyGeneration] entry prefix of a software ML-DSA key ([PqcSoftwareKeyStore]). */
        const val PQC_ENTRY = "pqc:"

        /** EC curve for FIDO2 (NIST P-256). */
        private const val EC_CURVE = "secp256r1"

        /** EC curves. */
        private const val EC_CURVE_P256 = "secp256r1"
        private const val EC_CURVE_P384 = "secp384r1"
        private const val EC_CURVE_P521 = "secp521r1"

        /** EC coordinate sizes in bytes. */
        private const val EC_COORDINATE_SIZE_P256 = 32
        private const val EC_COORDINATE_SIZE_P384 = 48
        private const val EC_COORDINATE_SIZE_P521 = 66

        /** Signature algorithms. */
        private const val SIG_ALGORITHM_ES256 = "SHA256withECDSA"
        private const val SIG_ALGORITHM_ES384 = "SHA384withECDSA"
        private const val SIG_ALGORITHM_ES512 = "SHA512withECDSA"
        private const val SIG_ALGORITHM_RS256 = "SHA256withRSA"
        private const val SIG_ALGORITHM_RS384 = "SHA384withRSA"
        private const val SIG_ALGORITHM_RS512 = "SHA512withRSA"

        /** Signature algorithm (ECDSA with SHA-256). */
        private const val SIGNATURE_ALGORITHM = "SHA256withECDSA"

        /** EC coordinate size for P-256 in bytes. */
        private const val EC_COORDINATE_SIZE = 32

        /** Attestation challenge size in bytes. */
        private const val ATTESTATION_CHALLENGE_SIZE = 32

        /** AES-GCM IV size in bytes. */
        private const val GCM_IV_SIZE = 12

        /** AES-GCM authentication tag length in bits. */
        private const val GCM_TAG_LENGTH_BITS = 128

        /** RSA OAEP cipher transformation. */
        private const val RSA_OAEP_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"

        /** AES GCM cipher transformation. */
        private const val AES_GCM_TRANSFORMATION = "AES/GCM/NoPadding"

        /** How far [requiresUserAuthentication] walks a cause chain. */
        private const val MAX_CAUSE_DEPTH = 8

        /**
         * Audit names of the fixed algorithms [symmetricEncrypt]/[symmetricDecrypt]
         * ([AES_GCM_TRANSFORMATION], 128-bit tag) and [performECDH] run. RSA
         * decrypt has no constant: [rsaDecryptWithAlgorithm] names the
         * [rsaOaepSpec] its cipher runs.
         */
        const val EXECUTED_AES_GCM = "AES-GCM"
        const val EXECUTED_ECDH = "ECDH"

        /**
         * The one OAEP parameterisation [rsaOaepDecrypt] runs: SHA-256 OAEP
         * digest, MGF1 over SHA-1, empty label. It is passed explicitly, so the
         * MGF1 digest never depends on which provider is first: AndroidKeyStore
         * and SunJCE default to SHA-1, but Conscrypt and Bouncy Castle default
         * to the OAEP digest (SHA-256). SHA-1 MGF1 is what AndroidKeyStore has
         * always run for this transformation, and every Keystore RSA key
         * accepts it. Peers encrypt with this spec; the audit name is
         * [rsaOaepAlgorithm] of it.
         */
        fun rsaOaepSpec(): OAEPParameterSpec =
            OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)

        /**
         * Decrypts [ciphertext] with [privateKey] under [RSA_OAEP_TRANSFORMATION]
         * and [rsaOaepSpec]: the decrypt step of [rsaDecryptWithAlgorithm].
         * The audit name follows the spec the cipher was initialised with.
         */
        fun rsaOaepDecrypt(privateKey: PrivateKey, ciphertext: ByteArray): DecryptResult {
            val spec = rsaOaepSpec()
            val cipher = Cipher.getInstance(RSA_OAEP_TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, privateKey, spec)
            return DecryptResult(cipher.doFinal(ciphertext), rsaOaepAlgorithm(spec))
        }

        /**
         * The audit name of an OAEP decrypt run with [spec]: "RSA-OAEP-256"
         * when both digests are SHA-256 and "RSA-OAEP" when both are SHA-1 (the
         * JOSE names), else "RSA-OAEP-<digest>-MGF1-<mgf1 digest>", e.g.
         * "RSA-OAEP-SHA-256-MGF1-SHA-1". With no spec reported, only the
         * transformation's own digest is known: "RSA-OAEP-SHA-256-MGF1-unknown".
         */
        fun rsaOaepAlgorithm(spec: OAEPParameterSpec?): String {
            if (spec == null) return "RSA-OAEP-SHA-256-MGF1-unknown"
            val digest = digestName(spec.digestAlgorithm)
            val mgf1 = (spec.mgfParameters as? MGF1ParameterSpec)?.digestAlgorithm?.let(::digestName)
                ?: "unknown"
            return when {
                digest == "SHA-256" && mgf1 == "SHA-256" -> "RSA-OAEP-256"
                digest == "SHA-1" && mgf1 == "SHA-1" -> "RSA-OAEP"
                else -> "RSA-OAEP-$digest-MGF1-$mgf1"
            }
        }

        /** "SHA256", "sha-256" and "SHA-256" all name SHA-256. */
        private fun digestName(name: String): String {
            val upper = name.uppercase()
            return if (upper.startsWith("SHA") && !upper.startsWith("SHA-")) "SHA-" + upper.removePrefix("SHA") else upper
        }

        /** PEM line length for Base64 encoding. */
        private const val PEM_LINE_LENGTH = 64

        /**
         * Authentication timeout in seconds.
         * After biometric auth, the key remains unlocked for this duration.
         * This prevents double prompts when Chrome sends rapid sequential requests
         * (e.g., conditional UI discovery + actual auth).
         * Value of 5 seconds balances UX with security.
         */
        private const val AUTH_TIMEOUT_SECONDS = 5

        /** `KeyProperties.SECURITY_LEVEL_*` values (API 31), inlined for API 28-30. */
        private const val KEY_INFO_LEVEL_UNKNOWN_SECURE = -2
        private const val KEY_INFO_LEVEL_UNKNOWN = -1
        private const val KEY_INFO_LEVEL_SOFTWARE = 0
        private const val KEY_INFO_LEVEL_TRUSTED_ENVIRONMENT = 1
        private const val KEY_INFO_LEVEL_STRONGBOX = 2

        /**
         * Aliases whose generating spec asked for StrongBox and succeeded.
         * KeyInfo cannot tell StrongBox from the TEE before API 31, so this is
         * the API 28-30 signal; it is per process, so after a restart such a
         * key reads as the TEE, an under-claim and never an over-claim.
         */
        private val strongBoxSpecAliases: MutableSet<String> =
            java.util.concurrent.ConcurrentHashMap.newKeySet()

        /**
         * Maps a key's [KeyInfo] to its [KeySecurityLevel].
         *
         * @param sdkInt The platform API level.
         * @param keyInfoLevel `KeyInfo.securityLevel` on API 31+, else
         *                     `SECURITY_LEVEL_UNKNOWN` (-1).
         * @param insideSecureHardware `KeyInfo.isInsideSecureHardware`.
         * @param strongBoxSpec Whether the spec that generated the key asked
         *                      for StrongBox and succeeded.
         */
        fun securityLevelOf(
            sdkInt: Int,
            keyInfoLevel: Int,
            insideSecureHardware: Boolean,
            strongBoxSpec: Boolean
        ): KeySecurityLevel {
            if (sdkInt >= Build.VERSION_CODES.S) {
                when (keyInfoLevel) {
                    KEY_INFO_LEVEL_STRONGBOX -> return KeySecurityLevel.STRONGBOX
                    KEY_INFO_LEVEL_TRUSTED_ENVIRONMENT,
                    KEY_INFO_LEVEL_UNKNOWN_SECURE -> return KeySecurityLevel.TEE
                    KEY_INFO_LEVEL_SOFTWARE -> return KeySecurityLevel.SOFTWARE
                }
            }
            return when {
                !insideSecureHardware -> KeySecurityLevel.SOFTWARE
                strongBoxSpec -> KeySecurityLevel.STRONGBOX
                else -> KeySecurityLevel.TEE
            }
        }
    }
}

/**
 * Which of the two user keys that can share an id a delete is for
 * (#255 review): a FIDO2 credential (`xkey_credential_<id>`) or a general
 * key (`xkey_key_<id>`, with its Ed25519 and software key store material).
 */
enum class UserKeyKind { CREDENTIAL, GENERAL }

/**
 * A key id resolved by [KeystoreManager.resolveKey]: the Keystore [alias] a
 * lookup reads, and the user key it is ([kind]).
 */
data class ResolvedKey(val alias: String, val kind: UserKeyKind)
