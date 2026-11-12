/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
 *
 * This file is part of xkey-android.
 *
 * xkey-android is dual-licensed:
 *
 * 1. GNU Affero General Public License v3.0 (AGPL-3.0)
 *    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
 *
 * 2. Commercial License
 *    Contact licensing@automatethethings.com for commercial licensing options.
 */

package com.automatethethings.xkey.auth

import androidx.biometric.BiometricPrompt
import com.automatethethings.xkey.auth.BiometricActivityLauncher.CryptoSigningResult
import com.automatethethings.xkey.ui.CryptoSigningCancellations
import kotlinx.coroutines.CancellableContinuation
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * The crypto signing requests [BiometricActivityLauncher] is waiting on.
 *
 * A request whose waiting coroutine is cancelled -- its session revoked or
 * unpaired, its transport gone, its handler timed out -- takes its prompt down
 * with it: [cancelPrompt] reaches the activity showing that request, and only
 * that one, which dismisses the prompt and signs nothing.
 * Leaving the prompt up would let a touch meant for nothing sign anyway.
 *
 * Requests take turns on screen through [prompts], which owns each request's
 * one queue entry (`signature-<id>`) from enqueue to settle, one prompt at a
 * time in arrival order: a request that arrives while another is
 * prompting waits for it to settle, and one cancelled while it waits is
 * never shown. Every request is settled exactly once: by its result, by the
 * failure to launch its prompt, by its active deadline passing or its
 * notification expiring with its prompt never up ([expireUnshown]), or by its
 * cancellation. The screen is shared with the generic approvals
 * ([PendingAuthentications]), so a signature whose start Android blocked
 * must let go of it as they do, or every approval behind it times out unseen.
 *
 * @param cancelPrompt dismisses the prompt for a request id
 * @param prompts the owner of the turns the requests take on screen;
 *   process-wide, since there is one screen whichever launcher a request came
 *   through
 * @param expirePrompt ends a request's prompt unshown, so a late start of it
 *   prompts for nothing; false while its activity has the request
 * @param activeDeadlineMillis how long a launched request waits for its
 *   prompt to come up; the generic approvals' own deadline
 */
internal class PendingCryptoSignatures(
    private val cancelPrompt: (requestId: String) -> Unit = CryptoSigningCancellations::cancel,
    private val prompts: PromptOwnership = PromptOwnership.process,
    private val expirePrompt: (requestId: String) -> Boolean = CryptoSigningCancellations::expireUnshown,
    private val activeDeadlineMillis: Long = PendingAuthentications.ACTIVE_DEADLINE_MILLIS,
) {
    private val pending = ConcurrentHashMap<Long, CancellableContinuation<CryptoSigningResult>>()

    /**
     * Allocates a request id, [launch]es the prompt for it when its turn
     * comes, and waits for its result. Cancelling the caller cancels the
     * prompt, or, while the request still waits for its turn, withdraws it.
     * A launched request whose prompt is still not up [activeDeadlineMillis]
     * after its launch fails with [BiometricPrompt.ERROR_TIMEOUT] and hands
     * the screen on ([expireUnshown]); one the owner is answering keeps
     * waiting, since its prompt answers when it goes away.
     */
    suspend fun await(launch: (requestId: String) -> Unit): CryptoSigningResult = coroutineScope {
        val id = nextRequestId.incrementAndGet()
        val key = NotificationKeys.signature(id.toString())
        val launched = CompletableDeferred<Unit>()
        // Its own clock, started with the launch: no notification has to
        // exist for an unseen request to let go of the screen.
        // (`this.launch` is the coroutine builder, not the parameter.)
        val activeDeadline = this.launch {
            launched.await()
            delay(activeDeadlineMillis)
            expireUnshown(id.toString(), PromptOwnership.Event.DEADLINE)
        }
        try {
            suspendCancellableCoroutine { continuation ->
                pending[id] = continuation
                prompts.enqueue(key, PromptOwnership.Kind.CRYPTO_SIGNING) {
                    // Withdrawn as its turn came: its entry is released already.
                    if (pending[id] !== continuation) return@enqueue
                    try {
                        launch(id.toString())
                        launched.complete(Unit)
                    } catch (e: Exception) {
                        if (prompts.settle(key, PromptOwnership.Outcome.FAILED) &&
                            pending.remove(id, continuation)
                        ) {
                            continuation.resumeWithException(e)
                        }
                    }
                }
                // Registered after the enqueue, so a caller already cancelled
                // runs this at once and its entry is never left held.
                continuation.invokeOnCancellation {
                    pending.remove(id, continuation)
                    // The prompt goes down before the next one comes up.
                    prompts.end(key) { wasActive ->
                        if (wasActive) cancelPrompt(id.toString())
                    }
                }
            }
        } finally {
            activeDeadline.cancel()
        }
    }

    /**
     * Fails launched request [requestId] with [BiometricPrompt.ERROR_TIMEOUT]
     * unless its activity has it; false when it was left waiting, or nothing
     * waits on that id. Called by [event]: its notification expiring or its
     * active deadline passing, whichever comes first. Another launcher's
     * request is left alone, its prompt included.
     */
    fun expireUnshown(
        requestId: String,
        event: PromptOwnership.Event = PromptOwnership.Event.NOTIFICATION_EXPIRY,
    ): Boolean {
        val key = NotificationKeys.signature(requestId)
        val id = requestId.toLongOrNull()
        val continuation = id?.let { pending[it] }
        if (!prompts.accept(key, event) || id == null || continuation == null || !expirePrompt(requestId)) {
            return false
        }
        if (!prompts.expire(key, event)) return false
        if (!pending.remove(id, continuation)) return false
        continuation.resume(
            CryptoSigningResult.Error(
                BiometricPrompt.ERROR_TIMEOUT,
                "The signing prompt was never shown before its deadline"
            )
        )
        return true
    }

    /**
     * Resumes [requestId]'s caller with [result]; false when nothing waits on
     * it. Only the ACTIVE request accepts a result: one for a request still
     * queued or already settled is refused. Every launcher's receiver hears
     * every result, so one for another launcher's ACTIVE request is left to
     * that launcher, and the shared entry is not touched.
     */
    fun complete(requestId: Long, result: CryptoSigningResult): Boolean {
        val key = NotificationKeys.signature(requestId.toString())
        val continuation = pending[requestId]
        if (!prompts.accept(key, PromptOwnership.Event.ACTIVITY_RESULT) || continuation == null) return false
        val outcome = promptOutcome((result as? CryptoSigningResult.Error)?.code)
        if (!prompts.settle(key, outcome, PromptOwnership.Event.ACTIVITY_RESULT)) return false
        if (!pending.remove(requestId, continuation)) return false
        continuation.resume(result)
        return true
    }

    /** Cancels every waiting request, and with it its prompt. */
    fun cancelAll() {
        // Newest first, so a request still waiting for its turn is withdrawn
        // before the one on screen leaves and could hand the turn to it.
        for (requestId in pending.keys.sortedDescending()) {
            pending[requestId]?.cancel()
        }
    }

    private companion object {
        /** Process-wide, so ids from two launchers never name the same prompt. */
        val nextRequestId = AtomicLong(PromptRequestIds.firstOfProcess())
    }
}
