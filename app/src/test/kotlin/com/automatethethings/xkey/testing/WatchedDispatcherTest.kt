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

import kotlin.coroutines.CoroutineContext
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Runnable
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class WatchedDispatcherTest {
    /** Queues tasks until the test runs them, so a resumed task stays queued. */
    private class Queue : CoroutineDispatcher() {
        val queued = ArrayDeque<Runnable>()

        override fun dispatch(context: CoroutineContext, block: Runnable) {
            queued.addLast(block)
        }

        fun runAll() {
            while (queued.isNotEmpty()) queued.removeFirst().run()
        }
    }

    private val queue = Queue()

    /** Wakes the test fires by hand. */
    private val wakes = ArrayDeque<Runnable>()

    /** Runs once, inside the next quiet check. */
    private var duringCheck: (() -> Unit)? = null

    private val dispatcher = WatchedDispatcher(
        queue,
        timer = { _, wake -> wakes.addLast(wake); { wakes.remove(wake) } },
        probe = { duringCheck?.also { duringCheck = null }?.invoke() }
    )

    @Test
    fun `a delay that resumes its coroutine during the quiet check is not quiet`() {
        var resumed = false
        CoroutineScope(dispatcher).launch {
            delay(1_000)
            resumed = true
        }
        queue.runAll()
        assertEquals("the coroutine waits in its delay", 1, wakes.size)
        assertFalse("a pending delay is work", dispatcher.isQuiet())

        // The wake lands mid-check: the delay ends and its resumed task is queued.
        duringCheck = { wakes.removeFirst().run() }
        assertFalse("work handed from the delay to its task is never quiet", dispatcher.isQuiet())
        assertEquals("the resumed task is queued", 1, queue.queued.size)
        assertFalse("a queued task is work", dispatcher.isQuiet())

        queue.runAll()
        assertTrue(resumed)
        assertTrue("nothing is left once the task has run", dispatcher.isQuiet())
    }

    @Test
    fun `a cancelled delay stops counting once its coroutine has unwound`() {
        val job = CoroutineScope(dispatcher).launch { delay(1_000) }
        queue.runAll()
        assertFalse(dispatcher.isQuiet())

        job.cancel()
        assertTrue("the cancel withdraws the wake", wakes.isEmpty())
        assertFalse("the cancelled coroutine is queued to unwind", dispatcher.isQuiet())
        queue.runAll()
        assertTrue(job.isCancelled && job.isCompleted)
        assertTrue(dispatcher.isQuiet())
        dispatcher.awaitQuiet("a quiet dispatcher is quiet")
    }
}
