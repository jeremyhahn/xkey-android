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
import androidx.annotation.RequiresApi
import androidx.annotation.VisibleForTesting
import androidx.biometric.BiometricPrompt
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.piv.PIV_KEYSTORE_ALIAS_PREFIX
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

/** A MAC and the algorithm that computed it ("HMAC-SHA256" or "HMAC-SHA512"). */
class HmacResult(val mac: ByteArray, val algorithm: String)

/**
 * An RSA decryption's plaintext and the audit name of the OAEP
 * parameterisation the cipher ran with.
 */
class DecryptResult(val plaintext: ByteArray, val algorithm: String)

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
 * val signature = manager.sign("credential-id-base64", dataHash, biometricHelper)
 * ```
 *
 * @param context Application context for checking device capabilities.
 */
class KeystoreManager(private val context: Context) {

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
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
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
            keyStore.deleteEntry(alias)
        }

        try {
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

            val keyPair = keyPairGenerator.generateKeyPair()
            markStrongBoxSpec(alias, Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && isStrongBoxAvailable())
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

            return encodeCOSEPublicKey(keyPair.public)
        } catch (e: Exception) {
            // Handle StrongBox fallback - some devices claim StrongBox but fail
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
                isStrongBoxAvailable() &&
                !requireStrongBox
            ) {
                return generateKeyWithoutStrongBox(alias, requireBiometric)
                    .also { markStrongBoxSpec(alias, false) }
            }
            throw KeyGenerationException("Failed to generate key", e)
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
            keyStore.deleteEntry(alias)
        }

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

            val keyPair = keyPairGenerator.generateKeyPair()
            markStrongBoxSpec(alias, Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && isStrongBoxAvailable())
            return encodeCOSEPublicKey(keyPair.public)
        } catch (e: Exception) {
            // Handle StrongBox fallback - some devices claim StrongBox but fail
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
                isStrongBoxAvailable() &&
                !requireStrongBox
            ) {
                return generateKeyWithAuthDurationWithoutStrongBox(alias, authDurationSeconds)
                    .also { markStrongBoxSpec(alias, false) }
            }
            throw KeyGenerationException("Failed to generate key with auth duration", e)
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

            val keyPair = keyPairGenerator.generateKeyPair()
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

            val keyPair = keyPairGenerator.generateKeyPair()
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
        dataHash: ByteArray,
        biometricHelper: BiometricHelper,
        title: String = "xKey Authentication",
        subtitle: String = "Verify your identity to sign",
        onTurn: (key: String) -> Unit = {}
    ): ByteArray {
        // Resolve across both alias namespaces, as signWithoutBiometric does.
        // With the FIDO2-only alias, a passkey the desktop created through
        // local.generateKey could never be signed with a prompt either.
        val alias = resolveKeystoreAlias(credentialId) ?: throw KeyNotFoundException(credentialId)

        val privateKey = keyStore.getKey(alias, null) as? PrivateKey
            ?: throw KeyNotFoundException(credentialId)

        // First, try to sign without biometric (uses cached auth if within timeout)
        try {
            val signature = Signature.getInstance(SIGNATURE_ALGORITHM)
            signature.initSign(privateKey)
            signature.update(dataHash)
            return signature.sign()
        } catch (e: android.security.keystore.UserNotAuthenticatedException) {
            // Key requires fresh biometric authentication - proceed with prompt
        } catch (e: Exception) {
            // Anything else here is a real failure, not a reason to prompt. The
            // algorithm is fixed to ECDSA, so a non-EC key resolved by
            // resolveKeystoreAlias throws InvalidKeyException — which used to
            // escape past this function's documented SigningException contract
            // and surface to the desktop as INTERNAL_ERROR.
            throw SigningException("Signing operation failed", e)
        }

        // Biometric required - show prompt
        try {
            val signature = Signature.getInstance(SIGNATURE_ALGORITHM)
            signature.initSign(privateKey)

            // Create CryptoObject for biometric binding
            val cryptoObject = BiometricPrompt.CryptoObject(signature)

            // Authenticate with biometric - this unlocks the signature object.
            // The prompt waits for its queue turn, and onTurn posts its wake
            // notification on that turn.
            biometricHelper.authenticate(
                cryptoObject = cryptoObject,
                title = title,
                subtitle = subtitle,
                onTurn = onTurn
            )

            // After successful biometric, the signature object is unlocked
            signature.update(dataHash)
            return signature.sign()
        } catch (e: XKeyCryptoException) {
            // Re-throw our typed exceptions
            throw e
        } catch (e: Exception) {
            throw SigningException("Signing operation failed", e)
        }
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
        dataHash: ByteArray
    ): ByteArray {
        // Resolve across BOTH alias namespaces, as the DER/PEM/SSH/COSE exports do.
        // The FIDO2-only alias alone means a passkey created through the general
        // key path — which is how the desktop creates one — can never be signed.
        val alias = resolveKeystoreAlias(credentialId) ?: throw KeyNotFoundException(credentialId)

        val privateKey = keyStore.getKey(alias, null) as? PrivateKey
            ?: throw KeyNotFoundException(credentialId)

        try {
            val signature = Signature.getInstance(SIGNATURE_ALGORITHM)
            signature.initSign(privateKey)
            signature.update(dataHash)
            return signature.sign()
        } catch (e: android.security.keystore.UserNotAuthenticatedException) {
            throw BiometricRequiredException()
        } catch (e: Exception) {
            throw SigningException("Signing operation failed", e)
        }
    }

    /**
     * Check if a key exists for a credential.
     *
     * @param credentialId Base64-encoded credential ID.
     * @return true if a key exists for this credential.
     */
    fun keyExists(credentialId: String): Boolean {
        val alias = resolveKeystoreAlias(credentialId) ?: return false
        return keyStore.containsAlias(alias)
    }

    /**
     * Delete a credential key from the keystore.
     *
     * @param credentialId Base64-encoded credential ID.
     * @return true if the key was deleted, false if it didn't exist.
     */
    fun deleteKey(credentialId: String): Boolean {
        // Resolving here also means a key created in the general namespace is
        // actually removed; callers that deleted through the FIDO2-only alias
        // were silently leaking those entries.
        val alias = resolveKeystoreAlias(credentialId) ?: return false
        keyStore.deleteEntry(alias)

        // Log key deletion
        AuditLogger.logKeyDeleted(
            keyId = credentialId,
            keyLabel = credentialId,
            keyType = "fido2"
        )

        return true
    }

    /**
     * Get the public key for a credential.
     *
     * @param credentialId Base64-encoded credential ID.
     * @return The public key, or null if not found.
     */
    fun getPublicKey(credentialId: String): PublicKey? {
        val alias = resolveKeystoreAlias(credentialId) ?: return null
        return keyStore.getCertificate(alias)?.publicKey
    }

    /**
     * Get the COSE-encoded public key for a credential.
     *
     * @param credentialId Base64-encoded credential ID.
     * @return COSE-encoded public key bytes, or null if not found.
     */
    fun getCOSEPublicKey(credentialId: String): ByteArray? {
        // Resolve across BOTH alias namespaces, as the DER/PEM/SSH exports do.
        // Using the FIDO2-only alias here made `local.getPublicKey` with
        // format=cose fail for every key created through local.generateKey.
        val alias = resolveKeystoreAlias(credentialId) ?: return null
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
    fun getAttestationChain(credentialId: String): List<Certificate>? {
        // Resolve across both alias namespaces, as the export and signing paths do.
        val alias = resolveKeystoreAlias(credentialId) ?: return null
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
    fun isKeyStrongBoxBacked(credentialId: String): Boolean =
        keySecurityLevel(credentialId) == KeySecurityLevel.STRONGBOX

    /**
     * The security level of a key, read from its [KeyInfo].
     *
     * Resolves [keyId] as [resolveKeystoreAlias] does, so a credential wins
     * over a general key of the same id: callers that know which namespace
     * they generated in use [credentialSecurityLevel] or
     * [generalKeySecurityLevel]. A key with no Keystore entry (an Ed25519 key
     * in EncryptedSharedPreferences) is [KeySecurityLevel.SOFTWARE].
     *
     * @param keyId Credential ID, general key ID or raw alias.
     * @return The key's level, or null if no such key exists.
     * @throws KeyInfoUnavailableException if a Keystore entry exists but its
     *         KeyInfo cannot be read.
     */
    fun keySecurityLevel(keyId: String): KeySecurityLevel? {
        val alias = resolveKeystoreAlias(keyId) ?: return null
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
        return null
    }

    /**
     * Reads the [KeyInfo] of the Keystore key held at an alias. Replaceable
     * so tests can make the read fail.
     */
    @VisibleForTesting
    internal var keyInfoReader: (alias: String, key: Key) -> KeyInfo = { _, key ->
        when (key) {
            is PrivateKey -> KeyFactory.getInstance(key.algorithm, KEYSTORE_PROVIDER)
                .getKeySpec(key, KeyInfo::class.java)
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
     * @return DER-encoded public key bytes.
     * @throws KeyGenerationException if key generation fails.
     * @throws UnsupportedAlgorithmException if the algorithm is not supported.
     */
    suspend fun generateKeyForAlgorithm(
        keyId: String,
        algorithm: String,
        authDurationSeconds: Int = 5,
        preferStrongBox: Boolean = true
    ): ByteArray {
        val alias = buildGeneralAlias(keyId)

        // Delete existing key if present
        if (keyStore.containsAlias(alias)) {
            keyStore.deleteEntry(alias)
        }

        val isEC = algorithm.startsWith("ES")
        val isRSA = algorithm.startsWith("RS")
        val isEd25519 = algorithm == "Ed25519"
        if (!isEC && !isRSA && !isEd25519) {
            throw UnsupportedAlgorithmException(algorithm)
        }

        try {
            val keyPair = when {
                isEd25519 -> {
                    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
                        throw UnsupportedAlgorithmException("Ed25519 requires API 33+")
                    }
                    generateEd25519KeyPair(alias, authDurationSeconds)
                }
                isEC -> generateECKeyPair(alias, algorithm, authDurationSeconds, preferStrongBox)
                else -> generateRSAKeyPair(alias, algorithm, authDurationSeconds, preferStrongBox)
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
        preferStrongBox: Boolean
    ): java.security.KeyPair {
        val curve = getECCurve(algorithm)
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
            return keyPairGenerator.generateKeyPair().also { markStrongBoxSpec(alias, strongBoxSpec) }
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
                return keyPairGenerator.generateKeyPair().also { markStrongBoxSpec(alias, false) }
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
        if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)

        val specBuilder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_DECRYPT
        )
            .setKeySize(keySizeBits)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)

        applyAuthDuration(specBuilder, authDurationSeconds)
        applyStrongBox(specBuilder, preferStrongBox)
        applyAttestationChallenge(specBuilder)

        try {
            val generator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_RSA,
                KEYSTORE_PROVIDER
            )
            generator.initialize(specBuilder.build())
            return generator.generateKeyPair().public.encoded
        } catch (e: Exception) {
            throw KeyGenerationException("Failed to generate RSA encryption key", e)
        }
    }

    private fun generateRSAKeyPair(
        alias: String,
        algorithm: String,
        authDurationSeconds: Int,
        preferStrongBox: Boolean
    ): java.security.KeyPair {
        val keySize = getRSAKeySize(algorithm)
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
            return keyPairGenerator.generateKeyPair().also { markStrongBoxSpec(alias, strongBoxSpec) }
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
                return keyPairGenerator.generateKeyPair().also { markStrongBoxSpec(alias, false) }
            }
            throw e
        }
    }

    /**
     * Generate an Ed25519 key pair using JCE software provider.
     *
     * Android Keystore does not support Ed25519, so the private key is stored
     * in EncryptedSharedPreferences (AES-256-GCM encrypted).
     */
    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    private fun generateEd25519KeyPair(
        alias: String,
        authDurationSeconds: Int
    ): java.security.KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance("Ed25519")
        val keyPair = keyPairGenerator.generateKeyPair()

        // Store private key in EncryptedSharedPreferences since Android Keystore
        // does not support Ed25519
        val prefs = checkNotNull(ed25519Prefs())
        // commit(), not apply(): a key is generated only once its write is
        // durable; cached presence never stands in for it (#255 review).
        val stored = prefs.edit()
            .putString(alias, Base64.encodeToString(keyPair.private.encoded, Base64.NO_WRAP))
            .commit()
        if (!stored) throw KeyGenerationException("Could not store the Ed25519 key $alias")

        return keyPair
    }

    /**
     * Retrieve an Ed25519 private key from EncryptedSharedPreferences.
     */
    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    fun getEd25519PrivateKey(alias: String): PrivateKey? {
        val prefs = ed25519Prefs() ?: return null
        val encoded = prefs.getString(alias, null) ?: return null
        val keyBytes = Base64.decode(encoded, Base64.NO_WRAP)
        val keyFactory = KeyFactory.getInstance("Ed25519")
        return keyFactory.generatePrivate(PKCS8EncodedKeySpec(keyBytes))
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

        if (keySizeBits != 128 && keySizeBits != 256) {
            throw KeyGenerationException("AES key size must be 128 or 256 bits, got $keySizeBits")
        }

        // Delete existing key if present
        if (keyStore.containsAlias(alias)) {
            keyStore.deleteEntry(alias)
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
            keyGenerator.generateKey()
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
            "HMAC-SHA512" -> KeyProperties.KEY_ALGORITHM_HMAC_SHA512
            else -> throw UnsupportedAlgorithmException(algorithm)
        }

        // Delete existing key if present
        if (keyStore.containsAlias(alias)) {
            keyStore.deleteEntry(alias)
        }

        try {
            val specBuilder = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )

            val keyGenerator = KeyGenerator.getInstance(jcaAlgorithm, KEYSTORE_PROVIDER)
            keyGenerator.init(specBuilder.build())
            keyGenerator.generateKey()
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
            val signature = Signature.getInstance(jcaAlgorithm)
            signature.initSign(privateKey)
            signature.update(data)
            return signature.sign()
        } catch (e: android.security.keystore.UserNotAuthenticatedException) {
            throw BiometricRequiredException()
        } catch (e: Exception) {
            throw SigningException("Signing with $algorithm failed", e)
        }
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
        } catch (e: android.security.keystore.UserNotAuthenticatedException) {
            throw BiometricRequiredException()
        } catch (e: Exception) {
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
        } catch (e: android.security.keystore.UserNotAuthenticatedException) {
            throw BiometricRequiredException()
        } catch (e: Exception) {
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
        } catch (e: android.security.keystore.UserNotAuthenticatedException) {
            throw BiometricRequiredException()
        } catch (e: DecryptionException) {
            throw e
        } catch (e: Exception) {
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
                KeyProperties.KEY_ALGORITHM_HMAC_SHA512, "HmacSHA512" -> "HmacSHA512"
                else -> "HmacSHA256"
            }

            val mac = Mac.getInstance(macAlgorithm)
            mac.init(secretKey)
            val name = if (macAlgorithm == "HmacSHA512") "HMAC-SHA512" else "HMAC-SHA256"
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
                if (e is android.security.keystore.UserNotAuthenticatedException ||
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
        } catch (e: android.security.keystore.UserNotAuthenticatedException) {
            throw BiometricRequiredException()
        } catch (e: ECDHException) {
            throw e
        } catch (e: Exception) {
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
    fun getPublicKeyDER(keyId: String): ByteArray? {
        val alias = resolveKeystoreAlias(keyId) ?: return null
        val cert = keyStore.getCertificate(alias) ?: return null
        return cert.publicKey.encoded
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
    fun getPublicKeyPEM(keyId: String): String? {
        val der = getPublicKeyDER(keyId) ?: return null
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
    fun getPublicKeySSH(keyId: String): String? {
        val alias = resolveKeystoreAlias(keyId) ?: return null
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
                keyStore.deleteEntry(tempAlias)
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
            keyStore.deleteEntry(alias)
        }
        val keyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            KEYSTORE_PROVIDER
        )
        keyPairGenerator.initialize(specBuilder.build())
        keyPairGenerator.generateKeyPair()

        return keyStore.getCertificateChain(alias)?.toList()
            ?: throw AttestationException("No certificate chain available for attestation key")
    }

    // -------------------------------------------------------------------------
    // Key Management (General Keys)
    // -------------------------------------------------------------------------

    /**
     * Resolves a key identifier to its actual Android Keystore alias.
     *
     * Tries the following patterns in order:
     * 1. FIDO2 credential alias: xkey_credential_ + keyId
     * 2. General key alias: xkey_key_ + keyId
     * 3. Raw alias: keyId itself (for non-xKey keys)
     *
     * @param keyId The key identifier to resolve.
     * @return The Keystore alias, or null if no matching entry exists.
     */
    fun resolveKeystoreAlias(keyId: String): String? {
        val credentialAlias = KEY_ALIAS_PREFIX + keyId
        if (keyStore.containsAlias(credentialAlias)) return credentialAlias

        val generalAlias = KEY_ALIAS_PREFIX_GENERAL + keyId
        if (keyStore.containsAlias(generalAlias)) return generalAlias

        // A PIV slot key is reached only through PivKeyManager, which keeps
        // its piv_slots row in step; a raw alias must not resolve to it.
        if (!keyId.startsWith(PIV_KEYSTORE_ALIAS_PREFIX) && keyStore.containsAlias(keyId)) return keyId

        // Check Ed25519 software-backed keys. Callers use the result as a
        // Keystore alias, so a key stored under the general alias resolves to
        // that alias, never to keyId: keyId may be a PIV slot's raw alias.
        if (hasSoftwareEd25519Key(generalAlias)) return generalAlias
        if (!keyId.startsWith(PIV_KEYSTORE_ALIAS_PREFIX) && hasSoftwareEd25519Key(keyId)) return keyId

        return null
    }

    /** True if an Ed25519 software key is stored under [alias] (API 33+ only). */
    internal fun hasSoftwareEd25519Key(alias: String): Boolean =
        try {
            ed25519Prefs()?.contains(alias) == true
        } catch (e: Exception) {
            false
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
     * read throws: an unreadable Ed25519 store is never taken for an empty
     * one, so a delete refuses before it removes any row (#255 review).
     */
    fun userKeyGeneration(keyId: String): Map<String, String> {
        val generation = LinkedHashMap<String, String>()
        val prefs = ed25519Prefs()
        for (alias in userKeyAliases(keyId)) {
            keystoreTag(alias)?.let { generation[KEYSTORE_ENTRY + alias] = it }
            prefs?.getString(alias, null)?.let { generation[ED25519_ENTRY + alias] = digestHex(it.toByteArray()) }
        }
        return generation
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
        val prefs = if (generation.keys.any { it.startsWith(ED25519_ENTRY) }) ed25519Prefs() else null
        val uncommitted = LinkedHashMap<String, String>()
        for ((entry, tag) in generation) {
            when {
                entry.startsWith(KEYSTORE_ENTRY) -> {
                    val alias = entry.removePrefix(KEYSTORE_ENTRY)
                    if (alias in namespace && keystoreTag(alias) == tag) keyStore.deleteEntry(alias)
                }
                entry.startsWith(ED25519_ENTRY) -> {
                    val alias = entry.removePrefix(ED25519_ENTRY)
                    val stored = prefs?.getString(alias, null)
                    if (alias in namespace && stored != null && digestHex(stored.toByteArray()) == tag) {
                        if (!prefs.edit().remove(alias).commit()) uncommitted[entry] = tag
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
     */
    fun deleteByAlias(alias: String): Boolean {
        // PIV slot keys are deleted through PivKeyManager with their row.
        if (alias.startsWith(PIV_KEYSTORE_ALIAS_PREFIX)) return false
        if (!keyStore.containsAlias(alias)) return false
        keyStore.deleteEntry(alias)
        return true
    }

    /**
     * Check if a general-purpose key exists in the keystore.
     *
     * @param keyId Key identifier.
     * @return true if the key exists.
     */
    fun generalKeyExists(keyId: String): Boolean {
        val alias = buildGeneralAlias(keyId)
        return keyStore.containsAlias(alias)
    }

    /**
     * Delete a general-purpose key from the keystore.
     *
     * @param keyId Key identifier.
     * @return true if the key was deleted, false if it did not exist.
     */
    fun deleteGeneralKey(keyId: String): Boolean {
        val alias = buildGeneralAlias(keyId)
        if (!keyStore.containsAlias(alias)) {
            return false
        }
        keyStore.deleteEntry(alias)

        // Log key deletion
        AuditLogger.logKeyDeleted(
            keyId = keyId,
            keyLabel = keyId,
            keyType = "general"
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
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
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
    private fun getJCASignatureAlgorithm(algorithm: String): String = when (algorithm) {
        "ES256" -> SIG_ALGORITHM_ES256
        "ES384" -> SIG_ALGORITHM_ES384
        "ES512" -> SIG_ALGORITHM_ES512
        "RS256" -> SIG_ALGORITHM_RS256
        "RS384" -> SIG_ALGORITHM_RS384
        "RS512" -> SIG_ALGORITHM_RS512
        else -> throw SigningException("Unsupported algorithm: $algorithm")
    }

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
    private fun buildGeneralAlias(keyId: String): String = KEY_ALIAS_PREFIX_GENERAL + keyId

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
    private fun buildAlias(credentialId: String): String {
        return KEY_ALIAS_PREFIX + credentialId
    }

    companion object {
        /** Android Keystore provider name. */
        private const val KEYSTORE_PROVIDER = "AndroidKeyStore"

        /** Prefix for all xKey credential key aliases. */
        private const val KEY_ALIAS_PREFIX = "xkey_credential_"

        /** Prefix for general-purpose key aliases. */
        private const val KEY_ALIAS_PREFIX_GENERAL = "xkey_key_"

        /**
         * The user-key namespace of [keyId]: the only Keystore aliases a
         * delete of a user's key may touch, its credential and general
         * aliases. An id that resolves to any other alias
         * ([resolveKeystoreAlias]) names an internal key (a CA, the
         * attestation, sealing or encryption keys) or a foreign one.
         */
        fun userKeyAliases(keyId: String): List<String> =
            listOf(KEY_ALIAS_PREFIX + keyId, KEY_ALIAS_PREFIX_GENERAL + keyId)

        /** EncryptedSharedPreferences file for Ed25519 software-backed keys. */
        private const val ED25519_PREFS_NAME = "xkey_ed25519_keys"

        /** [userKeyGeneration] entry prefix of an Android Keystore entry. */
        const val KEYSTORE_ENTRY = "keystore:"

        /** [userKeyGeneration] entry prefix of an Ed25519 software key. */
        const val ED25519_ENTRY = "ed25519:"

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
