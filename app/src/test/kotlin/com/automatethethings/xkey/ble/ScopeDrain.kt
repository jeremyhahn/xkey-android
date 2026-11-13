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

package com.automatethethings.xkey.ble

import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock
import kotlin.coroutines.CoroutineContext
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull

/**
 * Waits until every coroutine [owner] started on its scope has finished. A
 * test calls it after the owner's `destroy()` and before it unmocks.
 *
 * `destroy()` cancels the scope but does not wait for it. A coroutine still
 * running then (a connection's event consumer settling its disconnect, a
 * request worker, the teardown a disconnect launched) runs on to its end on
 * its own thread. If the test has unmocked `Log` by then, its next `Log`
 * call throws, and kotlinx-coroutines-test reports that exception in
 * whichever `runTest` comes next, as `UncaughtExceptionsBeforeTest` (#63).
 */
internal fun awaitScopeFinished(owner: Any, timeoutMs: Long = 5_000L) {
    val scope = try {
        owner.javaClass.getDeclaredField("scope").apply { isAccessible = true }.get(owner) as CoroutineScope
    } catch (e: NoSuchFieldException) {
        throw AssertionError("${owner.javaClass.simpleName}.scope is a seam these BLE tests drive", e)
    }
    val job = scope.coroutineContext[Job]
        ?: throw AssertionError("${owner.javaClass.simpleName}.scope has no job")
    if (!job.isCancelled) throw AssertionError("destroy() cancels ${owner.javaClass.simpleName}.scope")
    runBlocking { withTimeoutOrNull(timeoutMs) { job.join() } }
        ?: throw AssertionError(
            "${owner.javaClass.simpleName}'s coroutines still run $timeoutMs ms after destroy(): " +
                job.children.toList()
        )
}

/**
 * Puts a [TrackingDispatcher] under [owner]'s scope, in place of the
 * dispatcher it was built with, and returns it. Call it before the test
 * delivers the first callback: a coroutine already started stays on the
 * old scope.
 */
internal fun trackScope(owner: Any): TrackingDispatcher {
    val field = try {
        owner.javaClass.getDeclaredField("scope").apply { isAccessible = true }
    } catch (e: NoSuchFieldException) {
        throw AssertionError("${owner.javaClass.simpleName}.scope is a seam these BLE tests drive", e)
    }
    val dispatcher = TrackingDispatcher()
    field.set(owner, CoroutineScope(SupervisorJob() + dispatcher))
    return dispatcher
}

/**
 * A dispatcher that knows when the coroutines it runs have nothing left to
 * do, so a test waits on what the server does rather than for a settle
 * window (#160).
 *
 * It counts the steps it has been handed and not yet finished. A callback,
 * a `Mutex.unlock` or a `complete` dispatches the coroutine it resumes
 * before it returns, and a step that resumes another dispatches it before
 * it ends, so the count reaches zero only once everything they set going
 * has run up to its next suspension: a lock, a readiness, a timer, or its
 * end.
 */
internal class TrackingDispatcher : CoroutineDispatcher() {

    private companion object {
        const val TIMEOUT_MS = 5_000L

        // How often [eventually] re-checks when no step finishes, for state
        // a thread other than this dispatcher's sets.
        const val RECHECK_MS = 100L
    }

    private val lock = ReentrantLock()
    private val stepFinished = lock.newCondition()
    private var running = 0
    private var finished = 0L
    private val threads = AtomicInteger()

    // A thread per step that needs one, gone a second after it is idle.
    private val executor = ThreadPoolExecutor(0, Int.MAX_VALUE, 1, TimeUnit.SECONDS, SynchronousQueue()) { task ->
        Thread(task, "tracked-scope-${threads.incrementAndGet()}").apply { isDaemon = true }
    }

    override fun dispatch(context: CoroutineContext, block: Runnable) {
        lock.withLock { running++ }
        try {
            executor.execute {
                try {
                    block.run()
                } finally {
                    stepEnded()
                }
            }
        } catch (e: Throwable) {
            stepEnded()
            throw e
        }
    }

    private fun stepEnded() = lock.withLock {
        running--
        finished++
        stepFinished.signalAll()
    }

    /**
     * Waits until no step is queued or running: every coroutine on the
     * scope is suspended or done. Fails the test after [timeoutMs].
     */
    fun awaitIdle(what: String, timeoutMs: Long = TIMEOUT_MS) {
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs)
        lock.withLock {
            while (running > 0) {
                val left = TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime())
                if (left <= 0) throw AssertionError("timed out waiting until $what: $running steps still run")
                stepFinished.await(left, TimeUnit.MILLISECONDS)
            }
        }
    }

    /**
     * Waits until [check] holds, re-checking it each time a step finishes
     * and at least every [RECHECK_MS]. Fails the test after [timeoutMs].
     */
    fun eventually(what: String, timeoutMs: Long = TIMEOUT_MS, check: () -> Boolean) {
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs)
        while (true) {
            val seen = lock.withLock { finished }
            if (check()) return
            val left = TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime())
            if (left <= 0) throw AssertionError("timed out waiting until $what")
            lock.withLock {
                if (finished == seen) stepFinished.await(minOf(left, RECHECK_MS), TimeUnit.MILLISECONDS)
            }
        }
    }
}
