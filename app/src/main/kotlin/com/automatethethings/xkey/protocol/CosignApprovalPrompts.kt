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
package com.automatethethings.xkey.protocol

import android.content.Intent
import com.automatethethings.xkey.auth.BiometricActivityLauncher
import com.automatethethings.xkey.auth.PromptOwnership
import kotlinx.coroutines.cancel
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.cancellation.CancellationException

/**
 * The co-sign was not approved: refused, cancelled or timed out.
 */
class CosignNotApprovedException(message: String) : Exception(message)

/**
 * Asks the owner to approve co-signatures (#177), each as one entry in the
 * process-wide [PromptOwnership] queue that every other prompt (FIDO2,
 * attestation, signing) takes its turn in.
 *
 * A co-sign is a [BiometricActivityLauncher.requestAuthentication] request:
 * the launcher enqueues it under its `approval-<id>` key, starts its prompt
 * only once that key is ACTIVE, and settles the key by the prompt's own
 * result, by its deadlines, or by its withdrawal when the caller goes away.
 * The prompt activity prompts only for a key the queue holds ACTIVE, so a
 * co-sign withdrawn before its activity comes up never shows, and the queue
 * hands the screen to the next prompt at once.
 *
 * @param launcher Queues and starts the prompts, and hears their results.
 * @param timeoutMs How long a shown prompt waits for the owner before the
 *   co-sign fails; its wait for a turn on screen is the queue's own deadline.
 */
class CosignApprovalPrompts(
    private val launcher: BiometricActivityLauncher,
    private val timeoutMs: Long = DEFAULT_TIMEOUT_MS
) {
    /**
     * Returns when the owner approves; throws [CosignNotApprovedException]
     * on a refusal, at the queue's deadline, or [timeoutMs] after the prompt
     * starts. Cancelling the caller withdraws the request from the queue.
     *
     * @param onLaunch As for [BiometricActivityLauncher.requestAuthentication]:
     *   called with the request's queue key and prompt intent as its turn comes.
     */
    suspend fun approve(
        title: String,
        subtitle: String,
        locked: Boolean,
        onLaunch: (key: String, prompt: Intent) -> Unit = { _, _ -> }
    ) {
        val timedOut = AtomicBoolean(false)
        try {
            coroutineScope {
                launcher.requestAuthentication(
                    title = title,
                    subtitle = subtitle,
                    showOnLockScreen = locked
                ) { key, prompt ->
                    onLaunch(key, prompt)
                    // The owner's time to answer starts with the prompt. Running
                    // out withdraws the request, which settles its queue entry.
                    launch {
                        delay(timeoutMs)
                        timedOut.set(true)
                        this@coroutineScope.cancel()
                    }
                }
                coroutineContext.cancelChildren()
            }
        } catch (e: CancellationException) {
            if (timedOut.get()) throw CosignNotApprovedException("no answer within ${timeoutMs / 1000} s")
            throw e
        } catch (e: Exception) {
            throw CosignNotApprovedException(e.message ?: "not approved")
        }
    }

    companion object {
        /** One shown prompt's wait for the owner. */
        const val DEFAULT_TIMEOUT_MS = 60_000L
    }
}
