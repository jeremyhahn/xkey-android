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
package com.automatethethings.xkey.auth

import android.content.BroadcastReceiver
import android.content.Context
import androidx.core.content.ContextCompat
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import androidx.biometric.BiometricPrompt
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.crypto.BiometricException
import com.automatethethings.xkey.crypto.BiometricLockoutException
import com.automatethethings.xkey.crypto.KeyNotFoundException
import com.automatethethings.xkey.crypto.SigningException
import com.automatethethings.xkey.crypto.UserCancelledException
import com.automatethethings.xkey.ui.CryptoSigningActivity
import com.automatethethings.xkey.ui.TransparentBiometricActivity
import kotlinx.coroutines.CancellableContinuation
import kotlinx.coroutines.suspendCancellableCoroutine
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import kotlin.coroutines.resume

/**
 * Launches [TransparentBiometricActivity] from background services and handles results.
 *
 * This class provides a coroutine-based API for requesting biometric authentication
 * from contexts where a biometric prompt cannot be directly shown (e.g., services).
 * It uses broadcast receivers to communicate with the activity and maps the results
 * to typed exceptions.
 *
 * Thread Safety:
 * - Uses [AtomicLong] for request ID generation
 * - Uses [ConcurrentHashMap] for pending request storage
 * - Safe to call from multiple coroutines concurrently
 *
 * Lifecycle:
 * - Call [register] when the service starts
 * - Call [unregister] when the service stops
 * - All pending requests will be cancelled on unregister
 *
 * Usage:
 * ```kotlin
 * val launcher = BiometricActivityLauncher(context)
 * launcher.register()
 *
 * try {
 *     launcher.requestAuthentication(
 *         title = "xKey Authentication",
 *         subtitle = "Sign in to example.com"
 *     )
 *     // Authentication succeeded
 * } catch (e: UserCancelledException) {
 *     // User cancelled
 * } catch (e: BiometricLockoutException) {
 *     // Too many failed attempts
 * } catch (e: BiometricException) {
 *     // Other biometric error
 * } finally {
 *     launcher.unregister()
 * }
 * ```
 *
 * @param context The application context for registering receivers and launching activities.
 */
class BiometricActivityLauncher(
    private val context: Context
) {
    /**
     * Result of a biometric authentication request.
     */
    sealed class BiometricResult {
        /**
         * Authentication succeeded.
         */
        data object Success : BiometricResult()

        /**
         * Authentication failed with an error.
         *
         * @param code The error code from [BiometricPrompt] or a custom error code.
         * @param message A human-readable error description.
         */
        data class Error(
            val code: Int,
            val message: String
        ) : BiometricResult()
    }

    /**
     * Result of a crypto signing request.
     */
    sealed class CryptoSigningResult {
        /**
         * Signing succeeded.
         *
         * @param signature The Base64-encoded signature.
         */
        data class Success(val signature: String) : CryptoSigningResult()

        /**
         * Signing failed with an error.
         *
         * @param code The error code.
         * @param message A human-readable error description.
         */
        data class Error(
            val code: Int,
            val message: String
        ) : CryptoSigningResult()
    }

    /**
     * Atomic counter for generating unique request IDs.
     */
    private val requestIdGenerator = AtomicLong(0L)

    /**
     * Map of pending authentication requests, keyed by request ID.
     * Values are continuations that will be resumed when results arrive.
     */
    private val pendingRequests = ConcurrentHashMap<Long, CancellableContinuation<BiometricResult>>()

    /**
     * Map of pending crypto signing requests, keyed by request ID.
     * Values are continuations that will be resumed when results arrive.
     */
    private val pendingCryptoRequests = ConcurrentHashMap<Long, CancellableContinuation<CryptoSigningResult>>()

    /**
     * Whether the receiver is currently registered.
     */
    @Volatile
    private var isRegistered = false

    /**
     * Broadcast receiver that listens for biometric authentication results.
     */
    private val resultReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action != TransparentBiometricActivity.ACTION_BIOMETRIC_RESULT) {
                return
            }

            val requestIdString = intent.getStringExtra(
                TransparentBiometricActivity.EXTRA_REQUEST_ID
            ) ?: return

            val requestId = requestIdString.toLongOrNull() ?: return

            val continuation = pendingRequests.remove(requestId) ?: return

            val success = intent.getBooleanExtra(
                TransparentBiometricActivity.EXTRA_SUCCESS,
                false
            )

            val result = if (success) {
                BiometricResult.Success
            } else {
                val errorCode = intent.getIntExtra(
                    TransparentBiometricActivity.EXTRA_ERROR_CODE,
                    BiometricPrompt.ERROR_VENDOR
                )
                val errorMessage = intent.getStringExtra(
                    TransparentBiometricActivity.EXTRA_ERROR_MESSAGE
                ) ?: "Unknown error"

                BiometricResult.Error(errorCode, errorMessage)
            }

            continuation.resume(result)
        }
    }

    /**
     * Broadcast receiver that listens for crypto signing results.
     */
    private val cryptoSigningReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action != CryptoSigningActivity.ACTION_CRYPTO_SIGNING_RESULT) {
                return
            }

            val requestIdString = intent.getStringExtra(
                CryptoSigningActivity.EXTRA_REQUEST_ID
            ) ?: return

            val requestId = requestIdString.toLongOrNull() ?: return

            val continuation = pendingCryptoRequests.remove(requestId) ?: return

            val success = intent.getBooleanExtra(
                CryptoSigningActivity.EXTRA_SUCCESS,
                false
            )

            val result = if (success) {
                val signature = intent.getStringExtra(
                    CryptoSigningActivity.EXTRA_SIGNATURE
                ) ?: ""
                CryptoSigningResult.Success(signature)
            } else {
                val errorCode = intent.getIntExtra(
                    CryptoSigningActivity.EXTRA_ERROR_CODE,
                    BiometricPrompt.ERROR_VENDOR
                )
                val errorMessage = intent.getStringExtra(
                    CryptoSigningActivity.EXTRA_ERROR_MESSAGE
                ) ?: "Unknown error"

                CryptoSigningResult.Error(errorCode, errorMessage)
            }

            continuation.resume(result)
        }
    }

    /**
     * Registers the broadcast receivers to listen for biometric and crypto signing results.
     *
     * Must be called before [requestAuthentication] or [requestCryptoSignature].
     * Typically called when the owning service starts.
     *
     * Safe to call multiple times; subsequent calls are no-ops.
     */
    fun register() {
        if (isRegistered) {
            return
        }

        val biometricFilter = IntentFilter(TransparentBiometricActivity.ACTION_BIOMETRIC_RESULT)
        val cryptoFilter = IntentFilter(CryptoSigningActivity.ACTION_CRYPTO_SIGNING_RESULT)

        // ContextCompat applies RECEIVER_NOT_EXPORTED on API 33+ and the
        // legacy two-argument form below it. These are internal result
        // broadcasts and must never be exported.
        ContextCompat.registerReceiver(
            context,
            resultReceiver,
            biometricFilter,
            ContextCompat.RECEIVER_NOT_EXPORTED
        )
        ContextCompat.registerReceiver(
            context,
            cryptoSigningReceiver,
            cryptoFilter,
            ContextCompat.RECEIVER_NOT_EXPORTED
        )

        isRegistered = true
    }

    /**
     * Unregisters the broadcast receivers and cancels all pending requests.
     *
     * Should be called when the owning service stops to prevent leaks.
     * Any pending authentication or signing requests will receive a cancellation error.
     *
     * Safe to call multiple times; subsequent calls are no-ops.
     */
    fun unregister() {
        if (!isRegistered) {
            return
        }

        try {
            context.unregisterReceiver(resultReceiver)
        } catch (e: IllegalArgumentException) {
            // Receiver was already unregistered
        }

        try {
            context.unregisterReceiver(cryptoSigningReceiver)
        } catch (e: IllegalArgumentException) {
            // Receiver was already unregistered
        }

        isRegistered = false

        // Cancel all pending authentication requests
        val pendingIds = pendingRequests.keys.toList()
        for (requestId in pendingIds) {
            val continuation = pendingRequests.remove(requestId)
            continuation?.cancel()
        }

        // Cancel all pending crypto signing requests
        val pendingCryptoIds = pendingCryptoRequests.keys.toList()
        for (requestId in pendingCryptoIds) {
            val continuation = pendingCryptoRequests.remove(requestId)
            continuation?.cancel()
        }
    }

    /**
     * Requests biometric authentication by launching [TransparentBiometricActivity].
     *
     * This is a suspending function that waits until the user completes or cancels
     * the biometric prompt. The function returns normally on success or throws
     * an appropriate typed exception on failure.
     *
     * @param title The title to display in the biometric prompt.
     * @param subtitle The subtitle providing context (e.g., relying party name).
     * @param description Optional additional description text.
     * @param showOnLockScreen Whether to show the prompt over the lock screen.
     *
     * @throws UserCancelledException If the user cancelled authentication.
     * @throws BiometricLockoutException If authentication is locked due to failed attempts.
     * @throws BiometricException For other biometric authentication errors.
     * @throws IllegalStateException If the receiver is not registered.
     */
    suspend fun requestAuthentication(
        title: String,
        subtitle: String,
        description: String? = null,
        showOnLockScreen: Boolean = false
    ) {
        check(isRegistered) {
            "BiometricActivityLauncher must be registered before requesting authentication"
        }

        val result = suspendCancellableCoroutine { continuation ->
            val requestId = requestIdGenerator.incrementAndGet()

            pendingRequests[requestId] = continuation

            continuation.invokeOnCancellation {
                pendingRequests.remove(requestId)
            }

            val intent = TransparentBiometricActivity.createIntent(
                context = context,
                requestId = requestId.toString(),
                title = title,
                subtitle = subtitle,
                description = description,
                showOnLockScreen = showOnLockScreen
            ).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }

            context.startActivity(intent)
        }

        when (result) {
            is BiometricResult.Success -> {
                // Log successful biometric authentication
                AuditLogger.logBiometricSuccess(purpose = "authentication")
                // Authentication succeeded, return normally
                return
            }
            is BiometricResult.Error -> {
                // Log failed biometric authentication
                AuditLogger.logBiometricFailure(purpose = "authentication", errorCode = result.code)
                throw mapErrorToException(result.code, result.message)
            }
        }
    }

    /**
     * Requests crypto-bound biometric signing by launching [CryptoSigningActivity].
     *
     * This method is used for PER_OPERATION mode keys that require the biometric
     * authentication to be cryptographically bound to the signing operation.
     * Unlike [requestAuthentication], this method performs the actual signing
     * within the activity and returns the signature.
     *
     * @param credentialId The credential ID (key alias suffix in keystore).
     * @param dataHash The data hash to sign (raw bytes).
     * @param title The title to display in the biometric prompt.
     * @param subtitle The subtitle providing context (e.g., relying party name).
     * @param showOnLockScreen Whether to show the prompt over the lock screen.
     *
     * @return The DER-encoded ECDSA signature bytes.
     *
     * @throws UserCancelledException If the user cancelled authentication.
     * @throws BiometricLockoutException If authentication is locked due to failed attempts.
     * @throws BiometricException For other biometric authentication errors.
     * @throws KeyNotFoundException If the key doesn't exist for the credential.
     * @throws SigningException If signing fails.
     * @throws IllegalStateException If the receiver is not registered.
     */
    suspend fun requestCryptoSignature(
        credentialId: String,
        dataHash: ByteArray,
        title: String,
        subtitle: String,
        showOnLockScreen: Boolean = false
    ): ByteArray {
        check(isRegistered) {
            "BiometricActivityLauncher must be registered before requesting crypto signature"
        }

        val dataHashBase64 = Base64.getEncoder().encodeToString(dataHash)

        val result = suspendCancellableCoroutine { continuation ->
            val requestId = requestIdGenerator.incrementAndGet()

            pendingCryptoRequests[requestId] = continuation

            continuation.invokeOnCancellation {
                pendingCryptoRequests.remove(requestId)
            }

            val intent = CryptoSigningActivity.createIntent(
                context = context,
                requestId = requestId.toString(),
                credentialId = credentialId,
                dataHashBase64 = dataHashBase64,
                title = title,
                subtitle = subtitle,
                showOnLockScreen = showOnLockScreen
            ).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }

            context.startActivity(intent)
        }

        when (result) {
            is CryptoSigningResult.Success -> {
                // Log successful biometric authentication for signing
                AuditLogger.logBiometricSuccess(purpose = "signing")
                return Base64.getDecoder().decode(result.signature)
            }
            is CryptoSigningResult.Error -> {
                // Log failed biometric authentication for signing
                AuditLogger.logBiometricFailure(purpose = "signing", errorCode = result.code)
                throw mapCryptoErrorToException(result.code, result.message)
            }
        }
    }

    /**
     * Maps a biometric error code to the appropriate typed exception.
     *
     * @param errorCode The error code from [BiometricPrompt] or custom error.
     * @param errorMessage The human-readable error message.
     * @return The appropriate exception for the error.
     */
    private fun mapErrorToException(errorCode: Int, errorMessage: String): Exception {
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

            else -> {
                BiometricException(errorCode, errorMessage)
            }
        }
    }

    /**
     * Maps a crypto signing error code to the appropriate typed exception.
     *
     * @param errorCode The error code from [CryptoSigningActivity] or BiometricPrompt.
     * @param errorMessage The human-readable error message.
     * @return The appropriate exception for the error.
     */
    private fun mapCryptoErrorToException(errorCode: Int, errorMessage: String): Exception {
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

            CryptoSigningActivity.ERROR_CODE_KEY_NOT_FOUND -> {
                // Extract credential ID from error message if possible
                val credentialId = extractCredentialId(errorMessage)
                KeyNotFoundException(credentialId)
            }

            CryptoSigningActivity.ERROR_CODE_SIGNING_FAILED,
            CryptoSigningActivity.ERROR_CODE_CRYPTO_ERROR -> {
                SigningException(errorMessage)
            }

            else -> {
                BiometricException(errorCode, errorMessage)
            }
        }
    }

    /**
     * Extracts credential ID from error message.
     * Error messages are typically "Key not found for credential: <id>"
     */
    private fun extractCredentialId(errorMessage: String): String {
        val prefix = "Key not found for credential: "
        return if (errorMessage.startsWith(prefix)) {
            errorMessage.removePrefix(prefix)
        } else {
            "unknown"
        }
    }
}
