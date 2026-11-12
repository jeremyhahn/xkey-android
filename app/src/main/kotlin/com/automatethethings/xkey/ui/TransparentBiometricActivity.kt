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
package com.automatethethings.xkey.ui

import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import androidx.activity.OnBackPressedCallback
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.automatethethings.xkey.R

/**
 * Transparent activity for showing biometric prompts from background services.
 *
 * This activity has a fully transparent theme, allowing the biometric prompt
 * to appear over whatever the user was doing. It handles the complete lifecycle
 * of a biometric authentication request, broadcasting results back to the
 * requesting service.
 *
 * Key features:
 * - Transparent UI that shows only the biometric prompt
 * - Support for showing over the lock screen (when requested)
 * - Broadcasts authentication results via local broadcast
 * - Properly handles user cancellation and back press
 * - Answers every request it was started for exactly once, including one
 *   it gives way to and one whose activity goes away unanswered
 *
 * The activity is singleTop. The launcher starts one request at a time
 * (PendingAuthentications), so a start that reaches this instance is either
 * a repeat delivery of the request on screen (the lock-screen notification's
 * full-screen intent or a tap on it), which is ignored, or a newer request
 * after the one shown here was withdrawn, which this instance hands to a
 * fresh one ([onNewIntent]). Request ids grow, so a late delivery of an older
 * request never displaces the one on screen.
 *
 * Usage from a service:
 * ```kotlin
 * val intent = TransparentBiometricActivity.createIntent(
 *     context = this,
 *     requestId = "unique-request-id",
 *     title = "xKey Authentication",
 *     subtitle = "Verify to sign in to example.com",
 *     description = null,
 *     showOnLockScreen = true
 * )
 * intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
 * startActivity(intent)
 * ```
 */
class TransparentBiometricActivity : FragmentActivity() {

    private var requestId: String = ""
    private var biometricPrompt: BiometricPrompt? = null
    private var hasFinished = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_transparent_biometric)

        // Extract intent parameters
        requestId = intent.getStringExtra(EXTRA_REQUEST_ID) ?: run {
            sendErrorResult(
                errorCode = ERROR_CODE_INVALID_REQUEST,
                errorMessage = "Missing request ID"
            )
            finish()
            return
        }

        val title = intent.getStringExtra(EXTRA_TITLE) ?: DEFAULT_TITLE
        val subtitle = intent.getStringExtra(EXTRA_SUBTITLE) ?: DEFAULT_SUBTITLE
        val description = intent.getStringExtra(EXTRA_DESCRIPTION)
        val showOnLockScreen = intent.getBooleanExtra(EXTRA_SHOW_ON_LOCK_SCREEN, false)

        // Configure lock screen display if requested
        if (showOnLockScreen) {
            configureLockScreenDisplay()
        }

        // Handle back press as cancellation
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                handleCancellation()
            }
        })

        // Show biometric prompt immediately
        showBiometricPrompt(title, subtitle, description)
    }

    /**
     * A start that reached this instance instead of creating one. The
     * request on screen, delivered again, keeps its prompt; an older request
     * is a late delivery of one already settled and is dropped. A newer
     * request means the one shown here was withdrawn: this prompt answers
     * cancelled (nobody waits on it) and goes away, and the newer request is
     * started in a fresh instance, so it gets a prompt and a result of its own.
     */
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        val next = intent.getStringExtra(EXTRA_REQUEST_ID) ?: return
        if (!isNewer(next, requestId)) return
        if (!hasFinished) {
            sendErrorResult(
                errorCode = BiometricPrompt.ERROR_CANCELED,
                errorMessage = "Replaced by a newer approval request"
            )
        }
        finishWithResult()
        biometricPrompt?.cancelAuthentication()
        // Finishing first, so the start below creates an instance rather
        // than reaching this one again.
        startActivity(Intent(intent).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    }

    override fun onDestroy() {
        // Going away unanswered (the task swiped away, the activity
        // destroyed by the system) cancels the request, so its caller, and
        // every request queued behind it, does not wait forever. A
        // configuration change recreates the activity for the same request.
        if (!hasFinished && !isChangingConfigurations && requestId.isNotEmpty()) {
            sendErrorResult(
                errorCode = BiometricPrompt.ERROR_CANCELED,
                errorMessage = "The approval prompt went away unanswered"
            )
            hasFinished = true
        }
        super.onDestroy()
        biometricPrompt?.cancelAuthentication()
        biometricPrompt = null
    }

    /**
     * Configures the activity to show over the lock screen.
     *
     * Uses the appropriate APIs based on Android version:
     * - Android O_MR1 (27) and above: setShowWhenLocked, setTurnScreenOn
     * - Earlier versions: Window flags (though minSdk is 28, included for completeness)
     */
    private fun configureLockScreenDisplay() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O_MR1) {
            setShowWhenLocked(true)
            setTurnScreenOn(true)
        } else {
            @Suppress("DEPRECATION")
            window.addFlags(
                android.view.WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED or
                android.view.WindowManager.LayoutParams.FLAG_TURN_SCREEN_ON
            )
        }
    }

    /**
     * Shows the biometric authentication prompt.
     *
     * Uses BIOMETRIC_STRONG authenticators for FIDO2 compliance, which requires
     * Class 3 biometrics as defined by Android's biometric classification.
     *
     * @param title The title to display in the prompt.
     * @param subtitle The subtitle providing context (e.g., relying party).
     * @param description Optional additional description text.
     */
    private fun showBiometricPrompt(
        title: String,
        subtitle: String,
        description: String?
    ) {
        val executor = ContextCompat.getMainExecutor(this)

        val callback = object : BiometricPrompt.AuthenticationCallback() {
            // A prompt this activity already answered for (cancelled on
            // hand-off or on destroy) reports nothing more.
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                if (hasFinished) return
                sendSuccessResult()
                finishWithResult()
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                if (hasFinished) return
                sendErrorResult(errorCode, errString.toString())
                finishWithResult()
            }

            override fun onAuthenticationFailed() {
                // Called on each failed attempt (wrong fingerprint, etc.)
                // Don't finish - user can retry. The system will call
                // onAuthenticationError after too many failures.
            }
        }

        biometricPrompt = BiometricPrompt(this, executor, callback)

        val promptInfoBuilder = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setNegativeButtonText(getString(R.string.button_cancel))
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .setConfirmationRequired(true)

        if (description != null) {
            promptInfoBuilder.setDescription(description)
        }

        try {
            biometricPrompt?.authenticate(promptInfoBuilder.build())
        } catch (e: Exception) {
            sendErrorResult(
                errorCode = ERROR_CODE_PROMPT_FAILED,
                errorMessage = "Failed to show biometric prompt: ${e.message}"
            )
            finishWithResult()
        }
    }

    /**
     * Handles user cancellation (back press or negative button).
     */
    private fun handleCancellation() {
        if (hasFinished) return
        biometricPrompt?.cancelAuthentication()
        sendErrorResult(
            errorCode = BiometricPrompt.ERROR_USER_CANCELED,
            errorMessage = "User cancelled authentication"
        )
        finishWithResult()
    }

    /**
     * Sends a success result broadcast.
     */
    private fun sendSuccessResult() {
        val intent = Intent(ACTION_BIOMETRIC_RESULT).apply {
            setPackage(packageName)
            putExtra(EXTRA_REQUEST_ID, requestId)
            putExtra(EXTRA_SUCCESS, true)
        }
        sendBroadcast(intent)
    }

    /**
     * Sends an error result broadcast.
     *
     * @param errorCode The BiometricPrompt error code or custom error code.
     * @param errorMessage A human-readable error description.
     */
    private fun sendErrorResult(errorCode: Int, errorMessage: String) {
        val intent = Intent(ACTION_BIOMETRIC_RESULT).apply {
            setPackage(packageName)
            putExtra(EXTRA_REQUEST_ID, requestId)
            putExtra(EXTRA_SUCCESS, false)
            putExtra(EXTRA_ERROR_CODE, errorCode)
            putExtra(EXTRA_ERROR_MESSAGE, errorMessage)
        }
        sendBroadcast(intent)
    }

    /**
     * Finishes the activity, ensuring we only finish once.
     */
    private fun finishWithResult() {
        if (!hasFinished) {
            hasFinished = true
            finish()
            // No animation for transparent activity
            @Suppress("DEPRECATION")
            overridePendingTransition(0, 0)
        }
    }

    companion object {
        /**
         * Whether [candidate] names a request issued after [current]. Launcher
         * ids are increasing numbers; any other id (a wake-only notification's
         * `verifyUser-…`, `sign-…`) answers no launcher request, so it never
         * displaces a prompt, and a launcher request always displaces it.
         */
        internal fun isNewer(candidate: String, current: String): Boolean {
            val next = candidate.toLongOrNull() ?: return false
            val shown = current.toLongOrNull() ?: return true
            return next > shown
        }

        /**
         * Broadcast action for biometric authentication results.
         */
        const val ACTION_BIOMETRIC_RESULT = "com.automatethethings.xkey.BIOMETRIC_RESULT"

        /**
         * Extra key for the unique request identifier.
         * Type: String
         */
        const val EXTRA_REQUEST_ID = "com.automatethethings.xkey.extra.REQUEST_ID"

        /**
         * Extra key for the biometric prompt title.
         * Type: String
         */
        const val EXTRA_TITLE = "com.automatethethings.xkey.extra.TITLE"

        /**
         * Extra key for the biometric prompt subtitle.
         * Type: String
         */
        const val EXTRA_SUBTITLE = "com.automatethethings.xkey.extra.SUBTITLE"

        /**
         * Extra key for the biometric prompt description.
         * Type: String (optional)
         */
        const val EXTRA_DESCRIPTION = "com.automatethethings.xkey.extra.DESCRIPTION"

        /**
         * Extra key indicating whether the prompt succeeded.
         * Type: Boolean
         */
        const val EXTRA_SUCCESS = "com.automatethethings.xkey.extra.SUCCESS"

        /**
         * Extra key for the error code on failure.
         * Type: Int (BiometricPrompt error code or custom error)
         */
        const val EXTRA_ERROR_CODE = "com.automatethethings.xkey.extra.ERROR_CODE"

        /**
         * Extra key for the error message on failure.
         * Type: String
         */
        const val EXTRA_ERROR_MESSAGE = "com.automatethethings.xkey.extra.ERROR_MESSAGE"

        /**
         * Extra key indicating whether to show over the lock screen.
         * Type: Boolean (default: false)
         */
        const val EXTRA_SHOW_ON_LOCK_SCREEN = "com.automatethethings.xkey.extra.SHOW_ON_LOCK_SCREEN"

        /**
         * Custom error code indicating an invalid request (missing required extras).
         */
        const val ERROR_CODE_INVALID_REQUEST = -1000

        /**
         * Custom error code indicating the biometric prompt could not be shown.
         */
        const val ERROR_CODE_PROMPT_FAILED = -1001

        private const val DEFAULT_TITLE = "xKey Authentication"
        private const val DEFAULT_SUBTITLE = "Verify your identity"

        /**
         * Creates an intent to launch the transparent biometric activity.
         *
         * @param context The context to create the intent from.
         * @param requestId A unique identifier for this authentication request.
         *                  Used to correlate the result broadcast with the request.
         * @param title The title to display in the biometric prompt.
         * @param subtitle The subtitle providing context (e.g., relying party name).
         * @param description Optional additional description text.
         * @param showOnLockScreen Whether to show the prompt over the lock screen.
         * @return An intent configured to launch the activity.
         *
         * Note: The caller should add FLAG_ACTIVITY_NEW_TASK if launching from a service.
         */
        fun createIntent(
            context: Context,
            requestId: String,
            title: String = DEFAULT_TITLE,
            subtitle: String = DEFAULT_SUBTITLE,
            description: String? = null,
            showOnLockScreen: Boolean = false
        ): Intent {
            return Intent(context, TransparentBiometricActivity::class.java).apply {
                putExtra(EXTRA_REQUEST_ID, requestId)
                putExtra(EXTRA_TITLE, title)
                putExtra(EXTRA_SUBTITLE, subtitle)
                if (description != null) {
                    putExtra(EXTRA_DESCRIPTION, description)
                }
                putExtra(EXTRA_SHOW_ON_LOCK_SCREEN, showOnLockScreen)
            }
        }
    }
}
