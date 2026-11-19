/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
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
package com.automatethethings.xkey.media

import android.app.Activity
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.result.IntentSenderRequest
import androidx.activity.result.contract.ActivityResultContracts
import com.automatethethings.xkey.audit.AuditLogger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/**
 * Asks the user, in one MediaStore write request, for write access to the
 * captures the auto-signer could not write ([MediaWriteAuthorizations]);
 * once granted it signs them through their content URIs, and on a refusal
 * it drops them unsigned. Opened from the write-access notification.
 */
class MediaWriteRequestActivity : ComponentActivity() {

    private val launcher = registerForActivityResult(ActivityResultContracts.StartIntentSenderForResult()) { result ->
        val context = applicationContext
        val granted = result.resultCode == Activity.RESULT_OK
        // The publication outlives this screen, which finishes at once.
        publishing.launch {
            try {
                if (granted) {
                    MediaWriteAuthorizations.publishGranted(context) { write ->
                        AuditLogger.logMediaAutoSigned(write.keyId, write.keyLabel, write.uri)
                    }
                } else {
                    MediaWriteAuthorizations.deny(context)
                }
            } catch (e: Exception) {
                Log.e(TAG, "Publishing granted media failed", e)
            } finally {
                MediaWriteAuthorizations.notifyPending(context)
            }
        }
        finish()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // A recreated screen already launched its request; its result still arrives.
        if (savedInstanceState != null) return
        val request = try {
            MediaWriteAuthorizations.request(applicationContext)
        } catch (e: Exception) {
            Log.e(TAG, "Cannot create the write request", e)
            null
        }
        if (request == null) {
            finish()
            return
        }
        launcher.launch(IntentSenderRequest.Builder(request.intentSender).build())
    }

    private companion object {
        const val TAG = "MediaWriteRequest"
        val publishing = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    }
}
