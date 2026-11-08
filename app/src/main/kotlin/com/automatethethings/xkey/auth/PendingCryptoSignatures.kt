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

import com.automatethethings.xkey.auth.BiometricActivityLauncher.CryptoSigningResult
import com.automatethethings.xkey.ui.CryptoSigningCancellations
import kotlinx.coroutines.CancellableContinuation
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
 * Requests take turns on screen through [prompts], one prompt at a time in
 * arrival order: a request that arrives while another is
 * prompting waits for it to settle, and one cancelled while it waits is
 * never shown. Every request is settled exactly once: by its result, by the
 * failure to launch its prompt, or by its cancellation.
 *
 * @param cancelPrompt dismisses the prompt for a request id
 * @param prompts the turns the requests take on screen; process-wide, since
 *   there is one screen whichever launcher a request came through
 */
internal class PendingCryptoSignatures(
    private val cancelPrompt: (requestId: String) -> Unit = CryptoSigningCancellations::cancel,
    private val prompts: SigningPromptQueue = SigningPromptQueue.process,
) {
    private val pending = ConcurrentHashMap<Long, Request>()

    /** One request: whoever removes it from [pending] settles it. */
    private inner class Request(
        val id: Long,
        val continuation: CancellableContinuation<CryptoSigningResult>,
        private val launch: (requestId: String) -> Unit,
    ) : SigningPromptQueue.Turn {
        override fun show() {
            // Cancelled before its turn came: it never comes up.
            if (pending[id] !== this) {
                prompts.leave(this)
                return
            }
            try {
                launch(id.toString())
            } catch (e: Exception) {
                if (pending.remove(id, this)) {
                    prompts.leave(this)
                    continuation.resumeWithException(e)
                }
            }
        }
    }

    /**
     * Allocates a request id, [launch]es the prompt for it when its turn
     * comes, and waits for its result. Cancelling the caller cancels the
     * prompt, or, while the request still waits for its turn, withdraws it.
     */
    suspend fun await(launch: (requestId: String) -> Unit): CryptoSigningResult =
        suspendCancellableCoroutine { continuation ->
            val request = Request(nextRequestId.incrementAndGet(), continuation, launch)
            pending[request.id] = request
            continuation.invokeOnCancellation {
                pending.remove(request.id, request)
                // The prompt goes down before the next one comes up.
                prompts.leave(request) { wasShowing ->
                    if (wasShowing) cancelPrompt(request.id.toString())
                }
            }
            prompts.join(request)
        }

    /** Resumes [requestId]'s caller with [result]; false when nothing waits on it. */
    fun complete(requestId: Long, result: CryptoSigningResult): Boolean {
        val request = pending.remove(requestId) ?: return false
        prompts.leave(request)
        request.continuation.resume(result)
        return true
    }

    /** Cancels every waiting request, and with it its prompt. */
    fun cancelAll() {
        // Newest first, so a request still waiting for its turn is withdrawn
        // before the one on screen leaves and could hand the turn to it.
        for (requestId in pending.keys.sortedDescending()) {
            pending[requestId]?.continuation?.cancel()
        }
    }

    private companion object {
        /** Process-wide, so ids from two launchers never name the same prompt. */
        val nextRequestId = AtomicLong(0L)
    }
}

/**
 * One crypto signing prompt on screen at a time, the rest waiting in arrival
 * order.
 *
 * [com.automatethethings.xkey.ui.CryptoSigningActivity] reads its request
 * when it is created and the system shows one biometric authentication at a
 * time, so a request launched while another prompts would displace it or be
 * lost. Here the next request is shown only when the one on screen leaves,
 * and a request that leaves while it waits is dropped from the line unseen.
 */
internal class SigningPromptQueue {

    /** A request waiting for the screen or holding it. */
    fun interface Turn {
        /** Shows the request's prompt. Called once, outside the queue's lock. */
        fun show()
    }

    private val waiting = ArrayDeque<Turn>()
    private var showing: Turn? = null

    /** Shows [turn] now if no prompt is up, otherwise after the turns ahead of it. */
    fun join(turn: Turn) {
        val showNow = synchronized(this) {
            if (showing == null) {
                showing = turn
                true
            } else {
                waiting.addLast(turn)
                false
            }
        }
        if (showNow) turn.show()
    }

    /**
     * Takes [turn] out of the line, or off the screen. [beforeNext] learns
     * which, and runs before the next turn is shown. Leaving twice is a no-op.
     */
    fun leave(turn: Turn, beforeNext: (wasShowing: Boolean) -> Unit = {}) {
        val wasShowing: Boolean
        val next: Turn?
        synchronized(this) {
            wasShowing = showing === turn
            if (wasShowing) {
                next = waiting.removeFirstOrNull()
                showing = next
            } else {
                waiting.remove(turn)
                next = null
            }
        }
        beforeNext(wasShowing)
        next?.show()
    }

    companion object {
        /** The one screen every launcher in the process prompts on. */
        val process = SigningPromptQueue()
    }
}
