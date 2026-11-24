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
package com.automatethethings.xkey.media

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Test
import java.util.concurrent.atomic.AtomicInteger

/**
 * One capture delivers a burst of MediaStore events (insert, pending
 * cleared, rescan). The automatic signer must sign it once: one signature,
 * one audit row, never two writers on one file.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class AutoSignQueueTest {

    private val uri = "content://media/external/images/media/42"

    @Test
    fun `three events within 100 ms for one capture sign it once`() = runTest {
        val scope = TestScope(StandardTestDispatcher(testScheduler))
        val signs = AtomicInteger()
        val auditRows = AtomicInteger()
        val queue = AutoSignQueue(scope, delayMs = 500) {
            signs.incrementAndGet()
            auditRows.incrementAndGet()
            AutoSignQueue.Outcome.DONE
        }

        queue.submit(uri)
        scope.advanceTimeBy(40)
        queue.submit(uri)
        scope.advanceTimeBy(40)
        queue.submit(uri)
        scope.advanceUntilIdle()

        assertEquals("one capture must be signed once", 1, signs.get())
        assertEquals("one capture must write one audit row", 1, auditRows.get())
    }

    @Test
    fun `a skipped capture is released so a later event retries it`() = runTest {
        val scope = TestScope(StandardTestDispatcher(testScheduler))
        val attempts = AtomicInteger()
        val queue = AutoSignQueue(scope, delayMs = 500) {
            if (attempts.incrementAndGet() == 1) AutoSignQueue.Outcome.RETRY else AutoSignQueue.Outcome.DONE
        }

        queue.submit(uri)
        scope.advanceUntilIdle()
        queue.submit(uri)
        scope.advanceUntilIdle()
        queue.submit(uri)
        scope.advanceUntilIdle()

        assertEquals("a retry must be attempted once more, then the URI is done", 2, attempts.get())
    }

    @Test
    fun `a capture whose signing throws is released`() = runTest {
        val scope = TestScope(StandardTestDispatcher(testScheduler))
        val attempts = AtomicInteger()
        val queue = AutoSignQueue(scope, delayMs = 500) {
            if (attempts.incrementAndGet() == 1) throw IllegalStateException("not readable yet")
            AutoSignQueue.Outcome.DONE
        }

        queue.submit(uri)
        scope.advanceUntilIdle()
        queue.submit(uri)
        scope.advanceUntilIdle()

        assertEquals(2, attempts.get())
    }
}
