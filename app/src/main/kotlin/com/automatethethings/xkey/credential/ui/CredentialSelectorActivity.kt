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
package com.automatethethings.xkey.credential.ui

import android.app.Activity
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.GetCredentialResponse
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.CreateCredentialInterruptedException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialInterruptedException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.PendingIntentHandler
import androidx.lifecycle.lifecycleScope
import com.automatethethings.xkey.auth.PromptOwnership
import com.automatethethings.xkey.credential.handler.CreateCredentialHandler
import com.automatethethings.xkey.credential.handler.GetCredentialHandler
import com.automatethethings.xkey.crypto.BiometricHelper
import com.automatethethings.xkey.databinding.ActivityCredentialSelectorBinding
import kotlinx.coroutines.launch
import org.json.JSONObject

/**
 * Activity for handling credential selection and creation flows.
 *
 * This activity is launched via PendingIntent from the CredentialProviderService
 * when the user selects a credential or account in the system credential picker.
 * It handles biometric authentication and completes the credential operation.
 *
 * For create operations:
 * - Shows biometric prompt
 * - Creates the credential in Keystore
 * - Returns attestation response
 *
 * For get operations:
 * - Shows biometric prompt
 * - Signs the challenge
 * - Returns assertion response
 */
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
class CredentialSelectorActivity : AppCompatActivity() {

    private lateinit var binding: ActivityCredentialSelectorBinding

    private val createHandler by lazy { CreateCredentialHandler(this) }
    private val getHandler by lazy { GetCredentialHandler(this, BiometricHelper(this)) }

    private var currentAction: String? = null

    /** The queue key of this activity's user-verification prompt, once it asked for a turn. */
    private var promptKey: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityCredentialSelectorBinding.inflate(layoutInflater)
        setContentView(binding.root)

        currentAction = intent.action
        Log.i(TAG, "=== CredentialSelectorActivity onCreate: action=$currentAction ===")
        when (currentAction) {
            ACTION_CREATE_CREDENTIAL -> handleCreateCredential()
            ACTION_GET_CREDENTIAL -> handleGetCredential()
            else -> {
                Log.e(TAG, "Unknown action: ${intent.action}")
                finishWithError("Unknown action")
            }
        }
    }

    /**
     * Handle credential creation flow.
     */
    private fun handleCreateCredential() {
        Log.i(TAG, "handleCreateCredential: begin phase")
        val requestJson = intent.getStringExtra(EXTRA_REQUEST_JSON)
        if (requestJson == null) {
            Log.e(TAG, "handleCreateCredential: EXTRA_REQUEST_JSON is null")
            finishWithError("Missing request JSON")
            return
        }
        Log.d(TAG, "handleCreateCredential: requestJson length=${requestJson.length}")

        // Parse request to get RP info for biometric prompt
        val rpName = try {
            val json = JSONObject(requestJson)
            val rp = json.getJSONObject("rp")
            rp.optString("name", rp.getString("id"))
        } catch (e: Exception) {
            "Unknown"
        }

        // Show biometric prompt
        attemptUserVerification(
            title = "Create xKey Credential",
            subtitle = "Register with $rpName"
        ) { cancelled, userVerified ->
            if (cancelled) {
                finishWithUserCancelled()
            } else {
                performCreateCredential(requestJson, userVerified)
            }
        }
    }

    /**
     * Perform the actual credential creation after biometric auth.
     */
    private fun performCreateCredential(requestJson: String, userVerified: Boolean) {
        Log.i(TAG, "performCreateCredential: starting")
        lifecycleScope.launch {
            try {
                val request = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)
                if (request != null) {
                    Log.i(TAG, "performCreateCredential: got ProviderCreateCredentialRequest, calling handler")
                    val responseJson = createHandler.handleCreateCredential(request, userVerified)
                    Log.i(TAG, "performCreateCredential: handler returned response (${responseJson.length} chars)")
                    val response = CreatePublicKeyCredentialResponse(responseJson)
                    val resultData = Intent()
                    PendingIntentHandler.setCreateCredentialResponse(resultData, response)
                    setResult(Activity.RESULT_OK, resultData)
                    Log.i(TAG, "=== performCreateCredential SUCCESS ===")
                } else {
                    Log.e(TAG, "performCreateCredential: retrieveProviderCreateCredentialRequest returned null")
                    finishWithError("Failed to retrieve create request")
                    return@launch
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error creating credential", e)
                finishWithError(e.message ?: "Unknown error")
                return@launch
            }
            finish()
        }
    }

    /**
     * Handle credential assertion flow.
     *
     * Unlike the create flow, biometric authentication is handled inside the
     * signing operation via CryptoObject binding. This correctly supports both
     * time-based auth keys (UV="preferred") and per-operation keys (UV="required").
     */
    private fun handleGetCredential() {
        Log.d(TAG, "handleGetCredential started")
        val credentialId = intent.getStringExtra(EXTRA_CREDENTIAL_ID)
        val requestJson = intent.getStringExtra(EXTRA_REQUEST_JSON)
        Log.d(TAG, "credentialId=$credentialId, requestJson present=${requestJson != null}")

        if (credentialId == null || requestJson == null) {
            Log.e(TAG, "Missing extras: credentialId=$credentialId, requestJson=$requestJson")
            finishWithError("Missing credential ID or request JSON")
            return
        }

        // Proceed directly to signing — biometric is handled via CryptoObject
        // in GetCredentialHandler when the key requires it
        performGetCredential(credentialId)
    }

    /**
     * Perform the actual credential assertion after biometric auth.
     */
    private fun performGetCredential(credentialId: String) {
        Log.d(TAG, "performGetCredential: credentialId=$credentialId")
        lifecycleScope.launch {
            try {
                Log.d(TAG, "Retrieving ProviderGetCredentialRequest from intent")
                val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
                if (request != null) {
                    Log.d(TAG, "Got request, calling handleGetCredential")
                    val responseJson = getHandler.handleGetCredential(request, credentialId)
                    Log.d(TAG, "handleGetCredential succeeded, building response")
                    val credential = PublicKeyCredential(responseJson)
                    val response = GetCredentialResponse(credential)
                    val resultData = Intent()
                    PendingIntentHandler.setGetCredentialResponse(resultData, response)
                    setResult(Activity.RESULT_OK, resultData)
                    Log.d(TAG, "Set RESULT_OK")
                } else {
                    Log.e(TAG, "retrieveProviderGetCredentialRequest returned null!")
                    finishWithError("Failed to retrieve get request")
                    return@launch
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error getting credential: ${e.javaClass.name}: ${e.message}", e)
                if (e.cause != null) {
                    Log.e(TAG, "  Caused by: ${e.cause!!.javaClass.name}: ${e.cause!!.message}")
                }
                finishWithError(e.message ?: "Unknown error")
                return@launch
            }
            finish()
        }
    }

    /**
     * Show biometric authentication prompt.
     */
    /**
     * Attempts user verification and reports what actually happened.
     *
     * [onResult] receives `cancelled = true` when the user dismissed or failed
     * the prompt, and otherwise `userVerified` reflecting whether verification
     * genuinely took place. When the device has no usable authenticator the
     * ceremony continues with `userVerified = false` — the handlers decide
     * whether that satisfies the relying party, since only they know what was
     * requested.
     */
    private fun attemptUserVerification(
        title: String,
        subtitle: String,
        onResult: (cancelled: Boolean, userVerified: Boolean) -> Unit
    ) {
        val biometricManager = BiometricManager.from(this)
        // Device credential counts as user verification under WebAuthn, so a
        // PIN-only device can still verify.
        val authenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG or
            BiometricManager.Authenticators.DEVICE_CREDENTIAL
        val canAuthenticate = biometricManager.canAuthenticate(authenticators)

        Log.i(TAG, "attemptUserVerification: canAuthenticate=$canAuthenticate (SUCCESS=${BiometricManager.BIOMETRIC_SUCCESS})")
        if (canAuthenticate != BiometricManager.BIOMETRIC_SUCCESS) {
            Log.i(TAG, "attemptUserVerification: no authenticator enrolled; continuing unverified")
            onResult(false, false)
            return
        }

        val executor = ContextCompat.getMainExecutor(this)

        // The system Credential Manager starts this activity, but its prompt
        // still takes a turn in the one prompt queue: it shows only once no
        // other approval holds the screen, and hands the screen on when it
        // is answered or the activity goes away.
        val key = PromptOwnership.promptKey(intent, "credentialSelector")
        promptKey = key
        val answered: (Boolean, Boolean) -> Unit = { cancelled, verified ->
            PromptOwnership.process.end(key)
            onResult(cancelled, verified)
        }

        val biometricCallback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                answered(false, true)
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                super.onAuthenticationError(errorCode, errString)
                Log.e(TAG, "Biometric error: $errorCode - $errString")
                answered(true, false)
            }

            override fun onAuthenticationFailed() {
                super.onAuthenticationFailed()
                // Don't call back here - user can retry
            }
        }

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setAllowedAuthenticators(authenticators)
            .build()

        PromptOwnership.process.enqueue(key) {
            executor.execute {
                if (isFinishing || isDestroyed) {
                    PromptOwnership.process.end(key)
                } else {
                    BiometricPrompt(this, executor, biometricCallback).authenticate(promptInfo)
                }
            }
        }
    }

    override fun onDestroy() {
        // Gone unanswered (or still waiting its turn): its entry hands the
        // screen on rather than holding it.
        promptKey?.let { PromptOwnership.process.end(it) }
        super.onDestroy()
    }

    /**
     * Finish with an error result, using the correct exception type for the operation.
     */
    private fun finishWithError(message: String) {
        val resultData = Intent()
        if (currentAction == ACTION_GET_CREDENTIAL) {
            PendingIntentHandler.setGetCredentialException(
                resultData, GetCredentialUnknownException(message)
            )
        } else {
            PendingIntentHandler.setCreateCredentialException(
                resultData, CreateCredentialUnknownException(message)
            )
        }
        setResult(Activity.RESULT_CANCELED, resultData)
        finish()
    }

    /**
     * Finish with a user cancelled result, using the correct exception type for the operation.
     */
    private fun finishWithUserCancelled() {
        val resultData = Intent()
        if (currentAction == ACTION_GET_CREDENTIAL) {
            PendingIntentHandler.setGetCredentialException(
                resultData, GetCredentialInterruptedException("User cancelled")
            )
        } else {
            PendingIntentHandler.setCreateCredentialException(
                resultData, CreateCredentialInterruptedException("User cancelled")
            )
        }
        setResult(Activity.RESULT_CANCELED, resultData)
        finish()
    }

    companion object {
        private const val TAG = "CredentialSelectorAct"

        const val ACTION_CREATE_CREDENTIAL = "com.automatethethings.xkey.credential.ACTION_CREATE"
        const val ACTION_GET_CREDENTIAL = "com.automatethethings.xkey.credential.ACTION_GET"

        const val EXTRA_REQUEST_JSON = "request_json"
        const val EXTRA_CREDENTIAL_ID = "credential_id"
    }
}
