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
import android.security.keystore.KeyProperties
import android.util.Log
import androidx.activity.OnBackPressedCallback
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.automatethethings.xkey.R
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.util.Base64

/**
 * Transparent activity for performing crypto-bound biometric signing from background services.
 *
 * This activity handles the complete flow for PER_OPERATION mode keys:
 * 1. Receives credential ID and data hash via intent
 * 2. Retrieves the private key from Android Keystore
 * 3. Creates a Signature object and initializes it with the key
 * 4. Shows crypto-bound biometric prompt (CryptoObject wrapping Signature)
 * 5. After successful biometric auth, performs the signing
 * 6. Broadcasts the signature result back to the service
 *
 * This is necessary because PER_OPERATION keys (authDurationSeconds=0) require
 * the biometric authentication to be cryptographically bound to the signing
 * operation. Regular activity-based biometric auth doesn't satisfy this requirement.
 *
 * Usage from a service:
 * ```kotlin
 * val intent = CryptoSigningActivity.createIntent(
 *     context = this,
 *     requestId = "unique-request-id",
 *     credentialId = "base64-credential-id",
 *     dataHash = base64EncodedDataHash,
 *     title = "xKey Authentication",
 *     subtitle = "Sign in to example.com"
 * )
 * intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
 * startActivity(intent)
 * ```
 */
class CryptoSigningActivity : FragmentActivity() {

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

        val credentialId = intent.getStringExtra(EXTRA_CREDENTIAL_ID) ?: run {
            sendErrorResult(
                errorCode = ERROR_CODE_INVALID_REQUEST,
                errorMessage = "Missing credential ID"
            )
            finish()
            return
        }

        val dataHashBase64 = intent.getStringExtra(EXTRA_DATA_HASH) ?: run {
            sendErrorResult(
                errorCode = ERROR_CODE_INVALID_REQUEST,
                errorMessage = "Missing data hash"
            )
            finish()
            return
        }

        val title = intent.getStringExtra(EXTRA_TITLE) ?: DEFAULT_TITLE
        val subtitle = intent.getStringExtra(EXTRA_SUBTITLE) ?: DEFAULT_SUBTITLE
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

        // Decode data hash
        val dataHash = try {
            Base64.getDecoder().decode(dataHashBase64)
        } catch (e: Exception) {
            sendErrorResult(
                errorCode = ERROR_CODE_INVALID_REQUEST,
                errorMessage = "Invalid data hash encoding: ${e.message}"
            )
            finish()
            return
        }

        // Perform crypto-bound signing
        performCryptoSigning(credentialId, dataHash, title, subtitle)
    }

    override fun onDestroy() {
        super.onDestroy()
        biometricPrompt?.cancelAuthentication()
        biometricPrompt = null
    }

    /**
     * Configures the activity to show over the lock screen.
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
     * Performs crypto-bound signing with biometric authentication.
     *
     * @param credentialId The credential ID (key alias suffix in keystore).
     * @param dataHash The data hash to sign.
     * @param title Title for the biometric prompt.
     * @param subtitle Subtitle for the biometric prompt.
     */
    private fun performCryptoSigning(
        credentialId: String,
        dataHash: ByteArray,
        title: String,
        subtitle: String
    ) {
        // Get private key from keystore
        val alias = KEY_ALIAS_PREFIX + credentialId
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }

        val privateKey = keyStore.getKey(alias, null) as? PrivateKey
        if (privateKey == null) {
            sendErrorResult(
                errorCode = ERROR_CODE_KEY_NOT_FOUND,
                errorMessage = "Key not found for credential: $credentialId"
            )
            finishWithResult()
            return
        }

        // Initialize signature object
        val signature: Signature
        try {
            signature = Signature.getInstance(SIGNATURE_ALGORITHM)
            signature.initSign(privateKey)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize signature", e)
            sendErrorResult(
                errorCode = ERROR_CODE_CRYPTO_ERROR,
                errorMessage = "Failed to initialize signature: ${e.message}"
            )
            finishWithResult()
            return
        }

        // Create crypto object for biometric binding
        val cryptoObject = BiometricPrompt.CryptoObject(signature)

        // Show biometric prompt with crypto object
        showBiometricPrompt(cryptoObject, dataHash, title, subtitle)
    }

    /**
     * Shows the crypto-bound biometric authentication prompt.
     *
     * @param cryptoObject The CryptoObject wrapping the Signature.
     * @param dataHash The data hash to sign after successful authentication.
     * @param title The title for the biometric prompt.
     * @param subtitle The subtitle for the biometric prompt.
     */
    private fun showBiometricPrompt(
        cryptoObject: BiometricPrompt.CryptoObject,
        dataHash: ByteArray,
        title: String,
        subtitle: String
    ) {
        val executor = ContextCompat.getMainExecutor(this)

        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                // Get the authenticated signature from the result
                val authenticatedSignature = result.cryptoObject?.signature
                if (authenticatedSignature == null) {
                    sendErrorResult(
                        errorCode = ERROR_CODE_CRYPTO_ERROR,
                        errorMessage = "No signature in authentication result"
                    )
                    finishWithResult()
                    return
                }

                // Perform the signing with the authenticated signature
                try {
                    authenticatedSignature.update(dataHash)
                    val signatureBytes = authenticatedSignature.sign()
                    val signatureBase64 = Base64.getEncoder().encodeToString(signatureBytes)
                    sendSuccessResult(signatureBase64)
                } catch (e: Exception) {
                    Log.e(TAG, "Signing failed after authentication", e)
                    sendErrorResult(
                        errorCode = ERROR_CODE_SIGNING_FAILED,
                        errorMessage = "Signing failed: ${e.message}"
                    )
                }
                finishWithResult()
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
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

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setNegativeButtonText(getString(R.string.button_cancel))
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .setConfirmationRequired(true)
            .build()

        try {
            biometricPrompt?.authenticate(promptInfo, cryptoObject)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to show biometric prompt", e)
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
        biometricPrompt?.cancelAuthentication()
        sendErrorResult(
            errorCode = BiometricPrompt.ERROR_USER_CANCELED,
            errorMessage = "User cancelled authentication"
        )
        finishWithResult()
    }

    /**
     * Sends a success result broadcast with the signature.
     *
     * @param signatureBase64 The Base64-encoded signature.
     */
    private fun sendSuccessResult(signatureBase64: String) {
        val intent = Intent(ACTION_CRYPTO_SIGNING_RESULT).apply {
            setPackage(packageName)
            putExtra(EXTRA_REQUEST_ID, requestId)
            putExtra(EXTRA_SUCCESS, true)
            putExtra(EXTRA_SIGNATURE, signatureBase64)
        }
        sendBroadcast(intent)
    }

    /**
     * Sends an error result broadcast.
     *
     * @param errorCode The error code.
     * @param errorMessage A human-readable error description.
     */
    private fun sendErrorResult(errorCode: Int, errorMessage: String) {
        val intent = Intent(ACTION_CRYPTO_SIGNING_RESULT).apply {
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
        private const val TAG = "CryptoSigningActivity"

        /** Android Keystore provider name. */
        private const val KEYSTORE_PROVIDER = "AndroidKeyStore"

        /** Prefix for all xKey credential key aliases. */
        private const val KEY_ALIAS_PREFIX = "xkey_credential_"

        /** Signature algorithm (ECDSA with SHA-256). */
        private const val SIGNATURE_ALGORITHM = "SHA256withECDSA"

        /**
         * Broadcast action for crypto signing results.
         */
        const val ACTION_CRYPTO_SIGNING_RESULT = "com.automatethethings.xkey.CRYPTO_SIGNING_RESULT"

        /**
         * Extra key for the unique request identifier.
         * Type: String
         */
        const val EXTRA_REQUEST_ID = "com.automatethethings.xkey.extra.REQUEST_ID"

        /**
         * Extra key for the credential ID.
         * Type: String
         */
        const val EXTRA_CREDENTIAL_ID = "com.automatethethings.xkey.extra.CREDENTIAL_ID"

        /**
         * Extra key for the data hash to sign (Base64 encoded).
         * Type: String
         */
        const val EXTRA_DATA_HASH = "com.automatethethings.xkey.extra.DATA_HASH"

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
         * Extra key indicating whether to show over the lock screen.
         * Type: Boolean (default: false)
         */
        const val EXTRA_SHOW_ON_LOCK_SCREEN = "com.automatethethings.xkey.extra.SHOW_ON_LOCK_SCREEN"

        /**
         * Extra key indicating whether the operation succeeded.
         * Type: Boolean
         */
        const val EXTRA_SUCCESS = "com.automatethethings.xkey.extra.SUCCESS"

        /**
         * Extra key for the signature result (Base64 encoded).
         * Type: String
         */
        const val EXTRA_SIGNATURE = "com.automatethethings.xkey.extra.SIGNATURE"

        /**
         * Extra key for the error code on failure.
         * Type: Int
         */
        const val EXTRA_ERROR_CODE = "com.automatethethings.xkey.extra.ERROR_CODE"

        /**
         * Extra key for the error message on failure.
         * Type: String
         */
        const val EXTRA_ERROR_MESSAGE = "com.automatethethings.xkey.extra.ERROR_MESSAGE"

        /**
         * Custom error code indicating an invalid request.
         */
        const val ERROR_CODE_INVALID_REQUEST = -1000

        /**
         * Custom error code indicating the biometric prompt could not be shown.
         */
        const val ERROR_CODE_PROMPT_FAILED = -1001

        /**
         * Custom error code indicating the key was not found.
         */
        const val ERROR_CODE_KEY_NOT_FOUND = -1002

        /**
         * Custom error code indicating a cryptographic error.
         */
        const val ERROR_CODE_CRYPTO_ERROR = -1003

        /**
         * Custom error code indicating signing failed.
         */
        const val ERROR_CODE_SIGNING_FAILED = -1004

        private const val DEFAULT_TITLE = "xKey Authentication"
        private const val DEFAULT_SUBTITLE = "Verify your identity to sign"

        /**
         * Creates an intent to launch the crypto signing activity.
         *
         * @param context The context to create the intent from.
         * @param requestId A unique identifier for this signing request.
         * @param credentialId The credential ID (key alias suffix).
         * @param dataHashBase64 The Base64-encoded data hash to sign.
         * @param title The title for the biometric prompt.
         * @param subtitle The subtitle for the biometric prompt.
         * @param showOnLockScreen Whether to show the prompt over the lock screen.
         * @return An intent configured to launch the activity.
         */
        fun createIntent(
            context: Context,
            requestId: String,
            credentialId: String,
            dataHashBase64: String,
            title: String = DEFAULT_TITLE,
            subtitle: String = DEFAULT_SUBTITLE,
            showOnLockScreen: Boolean = false
        ): Intent {
            return Intent(context, CryptoSigningActivity::class.java).apply {
                putExtra(EXTRA_REQUEST_ID, requestId)
                putExtra(EXTRA_CREDENTIAL_ID, credentialId)
                putExtra(EXTRA_DATA_HASH, dataHashBase64)
                putExtra(EXTRA_TITLE, title)
                putExtra(EXTRA_SUBTITLE, subtitle)
                putExtra(EXTRA_SHOW_ON_LOCK_SCREEN, showOnLockScreen)
            }
        }
    }
}
