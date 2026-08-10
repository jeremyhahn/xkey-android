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

/**
 * Base exception for all xKey crypto operations.
 */
sealed class XKeyCryptoException(
    message: String,
    cause: Throwable? = null
) : Exception(message, cause)

/**
 * Exception thrown when a requested key is not found in the keystore.
 *
 * @param credentialId The credential ID that was not found.
 */
class KeyNotFoundException(
    val credentialId: String
) : XKeyCryptoException("Key not found for credential: $credentialId")

/**
 * Exception thrown when key generation fails.
 *
 * @param reason Description of why key generation failed.
 * @param cause The underlying exception, if any.
 */
class KeyGenerationException(
    val reason: String,
    cause: Throwable? = null
) : XKeyCryptoException("Key generation failed: $reason", cause)

/**
 * Exception thrown when a signing operation fails.
 *
 * @param reason Description of why signing failed.
 * @param cause The underlying exception, if any.
 */
class SigningException(
    val reason: String,
    cause: Throwable? = null
) : XKeyCryptoException("Signing operation failed: $reason", cause)

/**
 * Exception thrown when biometric authentication is required but not performed.
 */
class BiometricRequiredException : XKeyCryptoException(
    "Biometric authentication is required for this operation"
)

/**
 * Exception thrown when the user cancels biometric authentication.
 */
class UserCancelledException : XKeyCryptoException(
    "User cancelled biometric authentication"
)

/**
 * Exception thrown when biometric authentication is locked out due to too many failed attempts.
 *
 * @param isPermanent True if the lockout is permanent and requires device authentication.
 */
class BiometricLockoutException(
    val isPermanent: Boolean = false
) : XKeyCryptoException(
    if (isPermanent) {
        "Biometric authentication is permanently locked. Device credentials required."
    } else {
        "Biometric authentication is temporarily locked. Please try again later."
    }
)

/**
 * Exception thrown for general biometric authentication errors.
 *
 * @param errorCode The BiometricPrompt error code.
 * @param errorMessage The error message from the system.
 */
class BiometricException(
    val errorCode: Int,
    errorMessage: String
) : XKeyCryptoException("Biometric authentication error ($errorCode): $errorMessage")

/**
 * Exception thrown when biometric hardware is unavailable.
 *
 * @param reason Description of why biometrics are unavailable.
 */
class BiometricUnavailableException(
    val reason: String
) : XKeyCryptoException("Biometric authentication unavailable: $reason")

/**
 * Exception thrown when StrongBox is required but not available.
 */
class StrongBoxUnavailableException : XKeyCryptoException(
    "StrongBox secure hardware is not available on this device"
)

/**
 * Exception thrown when CBOR encoding fails.
 *
 * @param reason Description of the encoding failure.
 * @param cause The underlying exception, if any.
 */
class CborEncodingException(
    val reason: String,
    cause: Throwable? = null
) : XKeyCryptoException("CBOR encoding failed: $reason", cause)

/**
 * Exception thrown when key attestation fails.
 *
 * @param reason Description of why attestation failed.
 * @param cause The underlying exception, if any.
 */
class AttestationException(
    val reason: String,
    cause: Throwable? = null
) : XKeyCryptoException("Key attestation failed: $reason", cause)

/**
 * Exception thrown when credential storage operations fail.
 *
 * @param operation The storage operation that failed.
 * @param cause The underlying exception, if any.
 */
class CredentialStorageException(
    val operation: String,
    cause: Throwable? = null
) : XKeyCryptoException("Credential storage $operation failed", cause)

/**
 * Exception thrown when decryption fails.
 *
 * @param reason Description of why decryption failed.
 * @param cause The underlying exception, if any.
 */
class DecryptionException(
    val reason: String,
    cause: Throwable? = null
) : XKeyCryptoException("Decryption failed: $reason", cause)

/**
 * Exception thrown when encryption fails.
 *
 * @param reason Description of why encryption failed.
 * @param cause The underlying exception, if any.
 */
class EncryptionException(
    val reason: String,
    cause: Throwable? = null
) : XKeyCryptoException("Encryption failed: $reason", cause)

/**
 * Exception thrown when HMAC computation fails.
 *
 * @param reason Description of why HMAC computation failed.
 * @param cause The underlying exception, if any.
 */
class HMACException(
    val reason: String,
    cause: Throwable? = null
) : XKeyCryptoException("HMAC computation failed: $reason", cause)

/**
 * Exception thrown when ECDH key agreement fails.
 *
 * @param reason Description of why key agreement failed.
 * @param cause The underlying exception, if any.
 */
class ECDHException(
    val reason: String,
    cause: Throwable? = null
) : XKeyCryptoException("ECDH key agreement failed: $reason", cause)

/**
 * Exception thrown when an unsupported algorithm is requested.
 *
 * @param algorithm The unsupported algorithm name.
 */
class UnsupportedAlgorithmException(
    val algorithm: String
) : XKeyCryptoException("Unsupported algorithm: $algorithm")
