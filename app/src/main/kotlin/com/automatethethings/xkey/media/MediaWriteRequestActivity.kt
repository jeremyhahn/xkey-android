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

import android.Manifest
import android.app.Activity
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.result.IntentSenderRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.lifecycle.lifecycleScope
import com.automatethethings.xkey.audit.AuditLogger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/**
 * Asks the user, in one MediaStore write request, for write access to the
 * captures the auto-signer could not write ([MediaWriteAuthorizations]);
 * once granted it signs them through their content URIs, and on a refusal
 * it drops the ones it asked for, unsigned. Opened from the write-access
 * notification.
 *
 * The grant lasts only as long as the activity that asked for it, so the
 * screen finishes only once publication has ended. The captures the shown
 * request names are kept in its saved state, so a refusal never drops one
 * queued while the dialog was open, even across recreation.
 */
class MediaWriteRequestActivity : ComponentActivity() {

    /** The captures the shown request asks for. */
    private var requested: ArrayList<String> = arrayListOf()

    /** Whether the user has answered it, so publication has started. */
    private var answered = false

    private val launcher = registerForActivityResult(ActivityResultContracts.StartIntentSenderForResult()) { result ->
        answered = true
        publish(result.resultCode == Activity.RESULT_OK, requested.toList())
    }

    /** Location access answered (either way): the write request follows; without it nothing is rewritten. */
    private val locationLauncher = registerForActivityResult(ActivityResultContracts.RequestPermission()) {
        launchWriteRequest()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (savedInstanceState != null) {
            // A recreated screen already launched its request; an unanswered one still delivers its result here.
            requested = savedInstanceState.getStringArrayList(KEY_REQUESTED) ?: arrayListOf()
            answered = savedInstanceState.getBoolean(KEY_ANSWERED)
            if (answered) finishAfter(publication)
            return
        }
        // A capture is rewritten only from its original bytes, location
        // included (MediaPublisher.openOriginal): ask for that first.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q &&
            checkSelfPermission(Manifest.permission.ACCESS_MEDIA_LOCATION) != PackageManager.PERMISSION_GRANTED
        ) {
            locationLauncher.launch(Manifest.permission.ACCESS_MEDIA_LOCATION)
            return
        }
        launchWriteRequest()
    }

    /** Ask, in one write request, for every queued capture; finish when none waits. */
    private fun launchWriteRequest() {
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
        requested = ArrayList(request.requested)
        val intent = request.intent
        if (intent == null) {
            // No queued capture needs a grant (Android 10 has no write request): publish now.
            answered = true
            publish(true, requested.toList())
            return
        }
        launcher.launch(IntentSenderRequest.Builder(intent.intentSender).build())
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putStringArrayList(KEY_REQUESTED, requested)
        outState.putBoolean(KEY_ANSWERED, answered)
    }

    private fun publish(granted: Boolean, uris: List<String>) {
        val context = applicationContext
        // Off the main thread, outliving a recreation; this screen waits for it.
        val job = publishing.launch {
            try {
                if (granted) {
                    MediaWriteAuthorizations.publishGranted(context) { write ->
                        AuditLogger.logMediaAutoSigned(write.keyId, write.keyLabel, write.uri)
                    }
                } else {
                    MediaWriteAuthorizations.deny(context, uris)
                }
            } catch (e: Exception) {
                Log.e(TAG, "Publishing granted media failed", e)
            } finally {
                MediaWriteAuthorizations.notifyPending(context)
            }
        }
        publication = job
        finishAfter(job)
    }

    /** Finish once [job] has ended (at once when none runs, as after a process death). */
    private fun finishAfter(job: Job?) {
        lifecycleScope.launch {
            job?.join()
            finish()
        }
    }

    private companion object {
        const val TAG = "MediaWriteRequest"
        const val KEY_REQUESTED = "requested"
        const val KEY_ANSWERED = "answered"
        val publishing = CoroutineScope(SupervisorJob() + Dispatchers.IO)

        /** The publication running for the last answered request. */
        @Volatile
        var publication: Job? = null
    }
}
