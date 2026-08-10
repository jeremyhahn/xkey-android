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

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.suspendCancellableCoroutine
import java.util.concurrent.Executor
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Helper for biometric authentication in xKey.
 *
 * This class provides a coroutine-based API for biometric authentication,
 * supporting both standalone authentication and crypto-bound authentication
 * where the biometric unlocks a cryptographic operation.
 *
 * Usage:
 * ```kotlin
 * val helper = BiometricHelper(activity)
 *
 * // Check availability
 * if (helper.isBiometricAvailable()) {
 *     // Authenticate for a crypto operation
 *     helper.authenticate(cryptoObject, "Sign In", "Verify to sign in to example.com")
 * }
 * ```
 *
 * @param activity The FragmentActivity to show biometric prompts on.
 */
class BiometricHelper(
    private val activity: FragmentActivity
) {
    private val executor: Executor = ContextCompat.getMainExecutor(activity)
    private val biometricManager: BiometricManager = BiometricManager.from(activity)

    /**
     * Check if strong biometric authentication is available on this device.
     *
     * This checks for Class 3 (formerly "Strong") biometrics as required for
     * FIDO2 authenticators. Returns false if:
     * - No biometric hardware is present
     * - Biometric hardware is unavailable (e.g., in use by another app)
     * - No biometrics are enrolled
     * - Biometric security requirements cannot be met
     *
     * @return true if biometric authentication can be used.
     */
    fun isBiometricAvailable(): Boolean {
        return when (biometricManager.canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG
        )) {
            BiometricManager.BIOMETRIC_SUCCESS -> true
            else -> false
        }
    }

    /**
     * Get detailed biometric availability status.
     *
     * @return A [BiometricStatus] describing the current biometric state.
     */
    fun getBiometricStatus(): BiometricStatus {
        return when (biometricManager.canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG
        )) {
            BiometricManager.BIOMETRIC_SUCCESS -> BiometricStatus.AVAILABLE
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> BiometricStatus.NO_HARDWARE
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> BiometricStatus.HARDWARE_UNAVAILABLE
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> BiometricStatus.NONE_ENROLLED
            BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED ->
                BiometricStatus.SECURITY_UPDATE_REQUIRED
            BiometricManager.BIOMETRIC_STATUS_UNKNOWN -> BiometricStatus.UNKNOWN
            else -> BiometricStatus.UNKNOWN
        }
    }

    /**
     * Authenticate with biometric for a cryptographic operation.
     *
     * This method shows a biometric prompt and, upon successful authentication,
     * unlocks the provided [CryptoObject] for use. The prompt uses Class 3
     * (Strong) biometrics only, ensuring FIDO2 compliance.
     *
     * This is a suspend function that completes when:
     * - Authentication succeeds (returns normally)
     * - Authentication fails permanently (throws exception)
     * - User cancels (throws [UserCancelledException])
     *
     * Note: Failed authentication attempts (wrong fingerprint, etc.) do not
     * throw immediately - the user can retry. Only permanent failures throw.
     *
     * @param cryptoObject The [BiometricPrompt.CryptoObject] to unlock.
     * @param title Title shown in the biometric prompt.
     * @param subtitle Subtitle providing context (e.g., relying party name).
     * @param description Optional additional description.
     * @throws UserCancelledException if the user cancels authentication.
     * @throws BiometricLockoutException if too many failed attempts occurred.
     * @throws BiometricException for other authentication errors.
     */
    suspend fun authenticate(
        cryptoObject: BiometricPrompt.CryptoObject,
        title: String = DEFAULT_TITLE,
        subtitle: String = DEFAULT_SUBTITLE,
        description: String? = null
    ) = suspendCancellableCoroutine { continuation ->
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                if (continuation.isActive) {
                    continuation.resume(Unit)
                }
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                if (continuation.isActive) {
                    val exception = mapErrorToException(errorCode, errString.toString())
                    continuation.resumeWithException(exception)
                }
            }

            override fun onAuthenticationFailed() {
                // Called on each failed attempt (wrong fingerprint, etc.)
                // Don't fail the continuation - user can retry
                // The system will call onAuthenticationError after too many failures
            }
        }

        val promptInfoBuilder = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setNegativeButtonText(NEGATIVE_BUTTON_TEXT)
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .setConfirmationRequired(true)

        if (description != null) {
            promptInfoBuilder.setDescription(description)
        }

        val promptInfo = promptInfoBuilder.build()
        val biometricPrompt = BiometricPrompt(activity, executor, callback)

        continuation.invokeOnCancellation {
            biometricPrompt.cancelAuthentication()
        }

        biometricPrompt.authenticate(promptInfo, cryptoObject)
    }

    /**
     * Authenticate with biometric without a crypto object.
     *
     * This performs standalone biometric verification, useful when you need
     * to verify user presence but don't have a specific cryptographic operation
     * to perform. For FIDO2 operations, prefer [authenticate] with a CryptoObject.
     *
     * @param title Title shown in the biometric prompt.
     * @param subtitle Subtitle providing context.
     * @param description Optional additional description.
     * @throws UserCancelledException if the user cancels authentication.
     * @throws BiometricLockoutException if too many failed attempts occurred.
     * @throws BiometricException for other authentication errors.
     */
    suspend fun authenticateWithoutCrypto(
        title: String = DEFAULT_TITLE,
        subtitle: String = DEFAULT_SUBTITLE,
        description: String? = null
    ) = suspendCancellableCoroutine { continuation ->
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                if (continuation.isActive) {
                    continuation.resume(Unit)
                }
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                if (continuation.isActive) {
                    val exception = mapErrorToException(errorCode, errString.toString())
                    continuation.resumeWithException(exception)
                }
            }

            override fun onAuthenticationFailed() {
                // User can retry - don't fail yet
            }
        }

        val promptInfoBuilder = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setNegativeButtonText(NEGATIVE_BUTTON_TEXT)
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .setConfirmationRequired(true)

        if (description != null) {
            promptInfoBuilder.setDescription(description)
        }

        val promptInfo = promptInfoBuilder.build()
        val biometricPrompt = BiometricPrompt(activity, executor, callback)

        continuation.invokeOnCancellation {
            biometricPrompt.cancelAuthentication()
        }

        biometricPrompt.authenticate(promptInfo)
    }

    /**
     * Map BiometricPrompt error codes to typed exceptions.
     */
    private fun mapErrorToException(errorCode: Int, errorMessage: String): XKeyCryptoException {
        return when (errorCode) {
            BiometricPrompt.ERROR_USER_CANCELED,
            BiometricPrompt.ERROR_NEGATIVE_BUTTON -> {
                UserCancelledException()
            }
            BiometricPrompt.ERROR_LOCKOUT -> {
                BiometricLockoutException(isPermanent = false)
            }
            BiometricPrompt.ERROR_LOCKOUT_PERMANENT -> {
                BiometricLockoutException(isPermanent = true)
            }
            BiometricPrompt.ERROR_NO_BIOMETRICS -> {
                BiometricUnavailableException("No biometrics enrolled")
            }
            BiometricPrompt.ERROR_HW_NOT_PRESENT -> {
                BiometricUnavailableException("No biometric hardware")
            }
            BiometricPrompt.ERROR_HW_UNAVAILABLE -> {
                BiometricUnavailableException("Biometric hardware unavailable")
            }
            BiometricPrompt.ERROR_UNABLE_TO_PROCESS -> {
                BiometricException(errorCode, "Unable to process: $errorMessage")
            }
            BiometricPrompt.ERROR_TIMEOUT -> {
                BiometricException(errorCode, "Authentication timed out")
            }
            BiometricPrompt.ERROR_CANCELED -> {
                UserCancelledException()
            }
            BiometricPrompt.ERROR_NO_SPACE -> {
                BiometricException(errorCode, "Not enough storage space")
            }
            BiometricPrompt.ERROR_VENDOR -> {
                BiometricException(errorCode, "Vendor error: $errorMessage")
            }
            BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL -> {
                BiometricUnavailableException("No device credentials set up")
            }
            BiometricPrompt.ERROR_SECURITY_UPDATE_REQUIRED -> {
                BiometricUnavailableException("Security update required")
            }
            else -> {
                BiometricException(errorCode, errorMessage)
            }
        }
    }

    companion object {
        private const val DEFAULT_TITLE = "xKey Authentication"
        private const val DEFAULT_SUBTITLE = "Verify your identity"
        private const val NEGATIVE_BUTTON_TEXT = "Cancel"
    }
}

/**
 * Detailed biometric availability status.
 */
enum class BiometricStatus {
    /** Biometric authentication is available and can be used. */
    AVAILABLE,

    /** No biometric hardware is present on the device. */
    NO_HARDWARE,

    /** Biometric hardware is currently unavailable. */
    HARDWARE_UNAVAILABLE,

    /** No biometrics are enrolled on the device. */
    NONE_ENROLLED,

    /** A security update is required before biometrics can be used. */
    SECURITY_UPDATE_REQUIRED,

    /** The biometric status could not be determined. */
    UNKNOWN
}
