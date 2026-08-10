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
package com.automatethethings.xkey.credential

import android.os.Build
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.ProviderClearCredentialStateRequest
import com.automatethethings.xkey.credential.handler.CreateCredentialHandler
import com.automatethethings.xkey.credential.handler.GetCredentialHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/**
 * Android CredentialProviderService implementation for passkey operations.
 *
 * This service enables the xKey app to act as a platform authenticator
 * for devices without native passkey support (e.g., GrapheneOS). It implements
 * the CredentialProviderService API introduced in Android 14.
 *
 * The service handles two main flows:
 *
 * 1. **Registration (Create)**: When a website requests to create a new passkey:
 *    - `onBeginCreateCredentialRequest` returns CreateEntry options with PendingIntents
 *    - User selects an entry, system launches CredentialSelectorActivity via PendingIntent
 *    - Activity handles biometric auth and credential creation
 *
 * 2. **Authentication (Get)**: When a website requests to authenticate:
 *    - `onBeginGetCredentialRequest` returns matching CredentialEntry options with PendingIntents
 *    - User selects a credential, system launches CredentialSelectorActivity via PendingIntent
 *    - Activity handles biometric auth and assertion signing
 *
 * Cryptographic keys are stored in Android Keystore with StrongBox support
 * when available. Credential metadata is stored in Room database for efficient
 * querying by relying party.
 *
 * To enable this service:
 * 1. Go to Settings > Passwords & accounts
 * 2. Select "xKey" as a credential provider
 * 3. The app will now handle passkey requests from browsers and apps
 */
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
class XKeyCredentialService : CredentialProviderService() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private val createHandler by lazy { CreateCredentialHandler(this) }
    private val getHandler by lazy { GetCredentialHandler(this) }

    /**
     * Handle the begin phase of credential creation.
     *
     * Called by the system when an app/website requests to create a new credential.
     * Returns CreateEntry options for the system credential picker UI.
     */
    override fun onBeginCreateCredentialRequest(
        request: BeginCreateCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>
    ) {
        Log.i(TAG, "=== onBeginCreateCredentialRequest INVOKED ===")
        Log.d(TAG, "Request type: ${request::class.simpleName}")
        serviceScope.launch {
            try {
                val response = createHandler.handleBeginCreateCredential(request)
                Log.i(TAG, "onBeginCreateCredentialRequest SUCCESS - returning CreateEntry")
                callback.onResult(response)
            } catch (e: Exception) {
                Log.e(TAG, "Error in onBeginCreateCredentialRequest", e)
                callback.onError(CreateCredentialUnknownException(e.message))
            }
        }
    }

    /**
     * Handle the begin phase of credential retrieval.
     *
     * Called by the system when an app/website requests to authenticate.
     * Returns matching CredentialEntry options for the system credential picker UI.
     */
    override fun onBeginGetCredentialRequest(
        request: BeginGetCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>
    ) {
        Log.i(TAG, "=== onBeginGetCredentialRequest INVOKED ===")
        serviceScope.launch {
            try {
                val response = getHandler.handleBeginGetCredential(request)
                Log.i(TAG, "onBeginGetCredentialRequest SUCCESS")
                callback.onResult(response)
            } catch (e: Exception) {
                Log.e(TAG, "Error in onBeginGetCredentialRequest", e)
                callback.onError(GetCredentialUnknownException(e.message))
            }
        }
    }

    /**
     * Handle credential state clearing.
     *
     * Called when the system requests to clear stored credential state.
     * This does NOT delete the actual credentials, only session state.
     */
    override fun onClearCredentialStateRequest(
        request: ProviderClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, ClearCredentialException>
    ) {
        // Clear any cached session state if needed
        // We don't delete credentials here - that's a user action
        callback.onResult(null)
    }

    companion object {
        private const val TAG = "XKeyCredentialSvc"
    }
}
