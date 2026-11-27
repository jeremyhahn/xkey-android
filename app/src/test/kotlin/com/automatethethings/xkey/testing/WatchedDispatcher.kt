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

package com.automatethethings.xkey.testing

import java.util.concurrent.Executors
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.coroutines.CoroutineContext
import kotlin.coroutines.resume
import kotlinx.coroutines.CancellableContinuation
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Delay
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.InternalCoroutinesApi
import kotlinx.coroutines.Runnable

/**
 * Runs its tasks on [target] and counts those queued or running, and the
 * delays its coroutines wait in. With no task, everything the code under
 * test was handed has run to its next suspension or to its end; with no
 * delay as well, nothing is left that could still run without a new event
 * from outside. A wait for either is a wait for the work itself, not for a
 * time it is hoped to fit in.
 */
@OptIn(InternalCoroutinesApi::class)
class WatchedDispatcher(
    private val target: CoroutineDispatcher = Dispatchers.Default
) : CoroutineDispatcher(), Delay {
    private val tasks = AtomicInteger()
    private val delays = AtomicInteger()

    override fun dispatch(context: CoroutineContext, block: Runnable) {
        tasks.incrementAndGet()
        try {
            target.dispatch(context, Runnable {
                try {
                    block.run()
                } finally {
                    tasks.decrementAndGet()
                }
            })
        } catch (e: Throwable) {
            tasks.decrementAndGet()
            throw e
        }
    }

    override fun scheduleResumeAfterDelay(timeMillis: Long, continuation: CancellableContinuation<Unit>) {
        delays.incrementAndGet()
        val settled = AtomicBoolean()
        val settle = { if (settled.compareAndSet(false, true)) delays.decrementAndGet() }
        val wake = timer.schedule({
            // The resume dispatches (and counts) the coroutine before the delay stops counting.
            continuation.resume(Unit)
            settle()
        }, timeMillis, TimeUnit.MILLISECONDS)
        continuation.invokeOnCancellation {
            wake.cancel(false)
            settle()
        }
    }

    /** Waits until no task is queued or running; fails with [what] if that never happens. */
    fun awaitIdle(what: String) = ThreadWait.until(what) { tasks.get() == 0 }

    /** Waits until no task is queued or running and no delay is pending; fails with [what] if that never happens. */
    fun awaitQuiet(what: String) = ThreadWait.until(what) { tasks.get() == 0 && delays.get() == 0 }

    private companion object {
        val timer = (Executors.newScheduledThreadPool(1) { runnable ->
            Thread(runnable, "watched-dispatcher-timer").apply { isDaemon = true }
        } as ScheduledThreadPoolExecutor).apply { removeOnCancelPolicy = true }
    }
}
