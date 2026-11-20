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
import android.net.Uri
import android.os.Bundle
import android.util.Log
import android.widget.Toast
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
import java.io.IOException

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

    /**
     * The request phase: false while the location-access question comes
     * first, true once the write request (or, with none needed, publication)
     * has started. Kept in the saved state, so a recreation during the
     * location dialog waits on its answer instead of a write request never launched.
     */
    private var writeRequestLaunched = false

    private val launcher = registerForActivityResult(ActivityResultContracts.StartIntentSenderForResult()) { result ->
        answered = true
        publish(result.resultCode == Activity.RESULT_OK, requested.toList())
    }

    /** Location access answered (either way): the write request follows; without it nothing is rewritten. */
    private val locationAccess = MediaLocationAccess(this)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (savedInstanceState != null) {
            requested = savedInstanceState.getStringArrayList(KEY_REQUESTED) ?: arrayListOf()
            answered = savedInstanceState.getBoolean(KEY_ANSWERED)
            writeRequestLaunched = savedInstanceState.getBoolean(KEY_WRITE_REQUEST_LAUNCHED)
            // Recreated while the location dialog was open: wait on its answer again.
            if (!writeRequestLaunched) {
                askLocationThenRequest()
                return
            }
            // The write request was launched; an unanswered one still delivers its result here.
            if (answered) finishAfter(publication)
            return
        }
        askLocationThenRequest()
    }

    /**
     * A capture is rewritten only from its original bytes, location included
     * (MediaPublisher.openOriginal): ask for that first, then launch the
     * write request. After a recreation this joins the location request the
     * previous instance left open ([MediaLocationAccess]). A queue that
     * cannot be read or parsed is left as it is: the user is told the
     * waiting captures cannot be loaded, and the screen ends.
     */
    private fun askLocationThenRequest() {
        val queued = try {
            MediaWriteAuthorizations.pending(applicationContext).map { Uri.parse(it.uri) }
        } catch (e: IOException) {
            Log.e(TAG, "Cannot read the write-request queue", e)
            Toast.makeText(applicationContext, QUEUE_UNREADABLE_MESSAGE, Toast.LENGTH_LONG).show()
            finish()
            return
        }
        locationAccess.withOriginals(queued) { launchWriteRequest() }
    }

    /** Ask, in one write request, for every queued capture; finish when none waits. */
    private fun launchWriteRequest() {
        writeRequestLaunched = true
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
        outState.putBoolean(KEY_WRITE_REQUEST_LAUNCHED, writeRequestLaunched)
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
            } catch (e: MediaPublisher.UserActionRequiredException) {
                // Android 10 asks at the write: this screen launches the question.
                userAction = e
            } catch (e: Exception) {
                Log.e(TAG, "Publishing granted media failed", e)
            } finally {
                MediaWriteAuthorizations.notifyPending(context)
            }
        }
        publication = job
        finishAfter(job)
    }

    /**
     * Finish once [job] has ended (at once when none runs, as after a process
     * death), unless Android 10 refused a write until the user allows it:
     * then its question is launched, and the answer publishes again or drops
     * that capture, as a write request's does.
     */
    private fun finishAfter(job: Job?) {
        lifecycleScope.launch {
            job?.join()
            val action = userAction
            if (action == null) {
                finish()
                return@launch
            }
            userAction = null
            requested = arrayListOf(action.target.toString())
            answered = false
            launcher.launch(IntentSenderRequest.Builder(action.intentSender).build())
        }
    }

    private companion object {
        const val TAG = "MediaWriteRequest"
        const val QUEUE_UNREADABLE_MESSAGE = "Captures waiting for access cannot be loaded"
        const val KEY_REQUESTED = "requested"
        const val KEY_ANSWERED = "answered"
        const val KEY_WRITE_REQUEST_LAUNCHED = "write_request_launched"
        val publishing = CoroutineScope(SupervisorJob() + Dispatchers.IO)

        /** The publication running for the last answered request. */
        @Volatile
        var publication: Job? = null

        /** The Android 10 question the last publication stopped at, until launched. */
        @Volatile
        var userAction: MediaPublisher.UserActionRequiredException? = null
    }
}
