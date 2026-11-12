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
import kotlin.coroutines.resumeWithException

/**
 * Launches [TransparentBiometricActivity] from background services and handles results.
 *
 * This class provides a coroutine-based API for requesting biometric authentication
 * from contexts where a biometric prompt cannot be directly shown (e.g., services).
 * It uses broadcast receivers to communicate with the activity and maps the results
 * to typed exceptions.
 *
 * Thread Safety:
 * - Request ids are process-wide ([PendingAuthentications]), so a result
 *   broadcast reaches only the launcher, and the request, that issued it
 * - Pending requests live in a [ConcurrentHashMap]
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
     * Pending authentication requests, each resumed by the result broadcast
     * carrying its id.
     */
    private val pendingRequests = PendingAuthentications()

    /**
     * Pending crypto signing requests. A request cancelled while it waits
     * takes its prompt down with it.
     */
    private val pendingCryptoRequests = PendingCryptoSignatures()

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

            val requestId = intent.getStringExtra(
                TransparentBiometricActivity.EXTRA_REQUEST_ID
            ) ?: return

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

            // An id this launcher never issued answers nothing.
            pendingRequests.complete(requestId, result)
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

            pendingCryptoRequests.complete(requestId, result)
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
        pendingRequests.cancelAll()

        // Cancel all pending crypto signing requests, and their prompts
        pendingCryptoRequests.cancelAll()
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
     * @param onLaunch Called with this request's id and prompt intent just
     *   before the prompt starts. Anything else that presents the prompt, such
     *   as the lock-screen notification, must open that same intent, so its
     *   result completes this request rather than one nobody waits on.
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
        showOnLockScreen: Boolean = false,
        onLaunch: (requestId: String, prompt: Intent) -> Unit = { _, _ -> }
    ) {
        check(isRegistered) {
            "BiometricActivityLauncher must be registered before requesting authentication"
        }

        val result = pendingRequests.await { requestId ->
            val intent = TransparentBiometricActivity.createIntent(
                context = context,
                requestId = requestId,
                title = title,
                subtitle = subtitle,
                description = description,
                showOnLockScreen = showOnLockScreen
            ).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }

            onLaunch(requestId, intent)
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
     * @param keyAlias A full Keystore alias to sign with instead of the
     *   credential's (the user verification key); null for a credential key.
     * @param onLaunch As for [requestAuthentication]: called with this
     *   request's id and prompt intent just before the prompt starts. The
     *   request has one owner, the first activity started for it: a repeat
     *   delivery of the same intent (the notification's full-screen intent,
     *   or a tap on it) finishes without prompting and answers nothing
     *   (CryptoSigningCancellations), so the live request is never failed by it.
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
        showOnLockScreen: Boolean = false,
        keyAlias: String? = null,
        onLaunch: (requestId: String, prompt: Intent) -> Unit = { _, _ -> }
    ): ByteArray {
        check(isRegistered) {
            "BiometricActivityLauncher must be registered before requesting crypto signature"
        }

        val dataHashBase64 = Base64.getEncoder().encodeToString(dataHash)

        // Cancelling this coroutine dismisses the prompt and signs nothing.
        val result = pendingCryptoRequests.await { requestId ->
            val intent = CryptoSigningActivity.createIntent(
                context = context,
                requestId = requestId,
                credentialId = credentialId,
                dataHashBase64 = dataHashBase64,
                title = title,
                subtitle = subtitle,
                showOnLockScreen = showOnLockScreen,
                keyAlias = keyAlias
            ).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }

            onLaunch(requestId, intent)
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

/**
 * The authentication requests a [BiometricActivityLauncher] is waiting on.
 *
 * Each request gets an id here, and only here; whatever presents its prompt
 * (the launcher's activity start or the lock-screen notification) carries that
 * id, and the result broadcast carrying it is what completes the request. Ids
 * are process-wide, so a result never completes another launcher's request.
 * Every request is settled exactly once: by its result, by the failure to
 * launch its prompt, or by its cancellation.
 */
internal class PendingAuthentications {
    private val pending =
        ConcurrentHashMap<Long, CancellableContinuation<BiometricActivityLauncher.BiometricResult>>()

    /**
     * Allocates a request id, [launch]es the prompt for it and waits for its
     * result. A failure to launch fails the request; cancelling the caller
     * withdraws it.
     */
    suspend fun await(launch: (requestId: String) -> Unit): BiometricActivityLauncher.BiometricResult =
        suspendCancellableCoroutine { continuation ->
            val id = nextRequestId.incrementAndGet()
            pending[id] = continuation
            continuation.invokeOnCancellation { pending.remove(id, continuation) }
            try {
                launch(id.toString())
            } catch (e: Exception) {
                if (pending.remove(id, continuation)) continuation.resumeWithException(e)
            }
        }

    /** Resumes [requestId]'s caller with [result]; false when nothing waits on that id. */
    fun complete(requestId: String, result: BiometricActivityLauncher.BiometricResult): Boolean {
        val id = requestId.toLongOrNull() ?: return false
        val continuation = pending.remove(id) ?: return false
        continuation.resume(result)
        return true
    }

    /** Cancels every waiting request. */
    fun cancelAll() {
        for (id in pending.keys.toList()) {
            pending.remove(id)?.cancel()
        }
    }

    private companion object {
        /** Process-wide, so ids from two launchers never name the same request. */
        val nextRequestId = AtomicLong(0L)
    }
}
