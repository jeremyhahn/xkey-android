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
 *
 * Quiet is one counter, [outstanding]: each task and each pending delay
 * holds one count, and a hand-over takes the new count before it drops the
 * old one (a running task's delay or dispatch is counted before the task
 * ends; a wake counts the resumed task before the delay stops counting).
 * So the count is never zero while work is still on its way, and one read
 * of it is a consistent snapshot. A delay cancelled from outside this
 * dispatcher is the one hand-over that drops first: that cancel has
 * dispatched the coroutine by the time it returns, so wait for quiet only
 * after it.
 *
 * [timer] and [probe] are seams for this class's own test: [probe] runs
 * inside the quiet check right after its read, where a test can land a
 * wake that a check made of separate reads would miss.
 */
@OptIn(InternalCoroutinesApi::class)
class WatchedDispatcher internal constructor(
    private val target: CoroutineDispatcher,
    private val timer: Timer,
    private val probe: () -> Unit
) : CoroutineDispatcher(), Delay {
    constructor(target: CoroutineDispatcher = Dispatchers.Default) : this(target, sharedTimer, {})

    /** Schedules [wake] after [millis]; the returned function cancels it. */
    internal fun interface Timer {
        fun schedule(millis: Long, wake: Runnable): () -> Unit
    }

    /** Tasks queued or running. */
    private val tasks = AtomicInteger()

    /** Tasks queued or running, plus pending delays. */
    private val outstanding = AtomicInteger()

    override fun dispatch(context: CoroutineContext, block: Runnable) {
        outstanding.incrementAndGet()
        tasks.incrementAndGet()
        try {
            target.dispatch(context, Runnable {
                try {
                    block.run()
                } finally {
                    tasks.decrementAndGet()
                    outstanding.decrementAndGet()
                }
            })
        } catch (e: Throwable) {
            tasks.decrementAndGet()
            outstanding.decrementAndGet()
            throw e
        }
    }

    override fun scheduleResumeAfterDelay(timeMillis: Long, continuation: CancellableContinuation<Unit>) {
        outstanding.incrementAndGet()
        val settled = AtomicBoolean()
        val settle = { if (settled.compareAndSet(false, true)) outstanding.decrementAndGet() }
        val cancelWake = timer.schedule(timeMillis, Runnable {
            // The resume dispatches (and counts) the coroutine before the delay stops counting.
            continuation.resume(Unit)
            settle()
        })
        continuation.invokeOnCancellation {
            cancelWake()
            settle()
        }
    }

    /** True when no task is queued or running and no delay is pending, read as one snapshot. */
    internal fun isQuiet(): Boolean {
        val count = outstanding.get()
        probe()
        return count == 0
    }

    /** Waits until no task is queued or running; fails with [what] if that never happens. */
    fun awaitIdle(what: String) = ThreadWait.until(what) { tasks.get() == 0 }

    /** Waits until no task is queued or running and no delay is pending; fails with [what] if that never happens. */
    fun awaitQuiet(what: String) = ThreadWait.until(what) { isQuiet() }

    private companion object {
        val pool = (Executors.newScheduledThreadPool(1) { runnable ->
            Thread(runnable, "watched-dispatcher-timer").apply { isDaemon = true }
        } as ScheduledThreadPoolExecutor).apply { removeOnCancelPolicy = true }

        val sharedTimer = Timer { millis, wake ->
            val scheduled = pool.schedule(wake, millis, TimeUnit.MILLISECONDS)
            return@Timer { scheduled.cancel(false) }
        }
    }
}
