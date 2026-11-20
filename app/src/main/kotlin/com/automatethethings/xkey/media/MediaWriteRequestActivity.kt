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
import kotlinx.coroutines.launch
import java.io.IOException
import java.util.UUID

class MediaWriteRequestActivity : ComponentActivity() {

    /** The captures the shown request asks for. */
    private var requested: ArrayList<String> = arrayListOf()

    /** Whether the user has answered it, so publication has started. */
    private var answered = false

    /** The answer: true for a grant (publish), false for a refusal (drop [requested]). */
    private var granted = false

    /**
     * The id of the publication the answer started, in [MediaSaveRuns], until
     * this screen takes its outcome. Kept in the saved state with [granted]
     * and [requested], so the instance restored after a process death, which
     * took the publication with it, runs the same work again.
     */
    private var publicationId: String? = null

    /**
     * The request phase: false while the location-access question comes
     * first, true once the write request (or, with none needed, publication)
     * has started. Kept in the saved state, so a recreation during the
     * location dialog waits on its answer instead of a write request never launched.
     */
    private var writeRequestLaunched = false

    private val launcher = registerForActivityResult(ActivityResultContracts.StartIntentSenderForResult()) { result ->
        publish(result.resultCode == Activity.RESULT_OK, requested)
    }

    /** Location access answered (either way): the write request follows; without it nothing is rewritten. */
    private val locationAccess = MediaLocationAccess(this)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (savedInstanceState != null) {
            requested = savedInstanceState.getStringArrayList(KEY_REQUESTED) ?: arrayListOf()
            answered = savedInstanceState.getBoolean(KEY_ANSWERED)
            granted = savedInstanceState.getBoolean(KEY_GRANTED)
            publicationId = savedInstanceState.getString(KEY_PUBLICATION)
            writeRequestLaunched = savedInstanceState.getBoolean(KEY_WRITE_REQUEST_LAUNCHED)
            // Recreated while the location dialog was open: wait on its answer again.
            if (!writeRequestLaunched) {
                askLocationThenRequest()
                return
            }
            // The write request was launched; an unanswered one still delivers its result here.
            // An answered one joins its publication, or runs it again when the process died.
            if (answered) awaitPublication()
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
            publish(true, requested)
            return
        }
        launcher.launch(IntentSenderRequest.Builder(intent.intentSender).build())
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putStringArrayList(KEY_REQUESTED, requested)
        outState.putBoolean(KEY_ANSWERED, answered)
        outState.putBoolean(KEY_GRANTED, granted)
        outState.putString(KEY_PUBLICATION, publicationId)
        outState.putBoolean(KEY_WRITE_REQUEST_LAUNCHED, writeRequestLaunched)
    }

    override fun onDestroy() {
        // Gone for good, not recreated: no instance takes the outcome, and the
        // publication, which goes on, is forgotten once it ends.
        if (isFinishing && !isChangingConfigurations) publicationId?.let { MediaSaveRuns.abandon<Any?>(it) }
        super.onDestroy()
    }

    /** The user answered the request for [uris]: record the answer, then start its publication. */
    private fun publish(grant: Boolean, uris: List<String>) {
        answered = true
        granted = grant
        requested = ArrayList(uris)
        publicationId = UUID.randomUUID().toString()
        awaitPublication()
    }

    /**
     * Join the publication [publicationId] names, running it when this
     * process has none ([MediaSaveRuns.attach]: a process death took it):
     * publication of the granted captures, or the refusal of [requested].
     * Either is safe to run again, as the queue records what is done. Its
     * outcome is taken only while resumed ([MediaSaveRuns.outcome]), so never
     * after the state was saved: a screen stopped first leaves it, the
     * Android 10 question included, to the instance restored from that state.
     */
    private fun awaitPublication() {
        val id = publicationId ?: run {
            // Answered by an earlier build that kept no id: run the answer again.
            publicationId = UUID.randomUUID().toString()
            publicationId!!
        }
        val context = applicationContext
        val grant = granted
        val uris = requested.toList()
        val run = MediaSaveRuns.attach(id) { publication(context, grant, uris) }
        lifecycleScope.launch {
            MediaSaveRuns.outcome(run, lifecycle) { outcome ->
                MediaSaveRuns.finished(id)
                publicationId = null
                val action = outcome.getOrNull()
                if (action == null) {
                    finish()
                    return@outcome
                }
                // Android 10 asks at the write: this screen launches the question.
                requested = arrayListOf(action.target.toString())
                answered = false
                launcher.launch(IntentSenderRequest.Builder(action.intentSender).build())
            }
        }
    }

    private companion object {
        const val TAG = "MediaWriteRequest"
        const val QUEUE_UNREADABLE_MESSAGE = "Captures waiting for access cannot be loaded"
        const val KEY_REQUESTED = "requested"
        const val KEY_ANSWERED = "answered"
        const val KEY_GRANTED = "granted"
        const val KEY_PUBLICATION = "publication"
        const val KEY_WRITE_REQUEST_LAUNCHED = "write_request_launched"

        /**
         * Publish the granted captures, or drop the refused [uris]; the
         * Android 10 question it stops at, or null once it has ended. A
         * failure is logged: the queue keeps what was not done.
         */
        suspend fun publication(
            context: android.content.Context,
            granted: Boolean,
            uris: List<String>
        ): MediaPublisher.UserActionRequiredException? = try {
            if (granted) {
                MediaWriteAuthorizations.publishGranted(context) { write ->
                    AuditLogger.logMediaAutoSigned(write.keyId, write.keyLabel, write.uri)
                }
            } else {
                MediaWriteAuthorizations.deny(context, uris)
            }
            null
        } catch (e: MediaPublisher.UserActionRequiredException) {
            e
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            Log.e(TAG, "Publishing granted media failed", e)
            null
        } finally {
            MediaWriteAuthorizations.notifyPending(context)
        }
    }
}
