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

import java.io.File
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The tracked scope holds its timers (#252): a wait on it ends on the event
 * it waits for, or when the test moves the scope's clock past its timer,
 * never because the wall clock ran on. The GATT server tests decide
 * "promptly" by that, not by a wall-clock bound a loaded runner misses.
 */
class ScopeDrainTest {

    /** Stands in for the owner whose `scope` field the tests replace. */
    private class Owner {
        val scope: CoroutineScope = CoroutineScope(SupervisorJob())
    }

    private lateinit var owner: Owner
    private lateinit var signals: TrackingDispatcher

    @Before
    fun setUp() {
        owner = Owner()
        signals = trackScope(owner)
    }

    @After
    fun tearDown() {
        owner.scope.cancel()
        awaitScopeFinished(owner)
    }

    @Test
    fun aTimeoutExpiresOnlyWhenTheClockReachesIt() {
        val result = CompletableDeferred<String?>()
        owner.scope.launch {
            result.complete(withTimeoutOrNull(600) { CompletableDeferred<String>().await() })
        }
        signals.awaitIdle("the wait has started")
        assertEquals("the wait holds one timer", 1, signals.pendingTimers)

        signals.advanceTimeBy(599)
        assertFalse("the wait goes on before its timeout", result.isCompleted)

        signals.advanceTimeBy(1)
        assertTrue("the wait expires at its timeout, and awaitIdle saw its end", result.isCompleted)
        assertEquals(null, runBlocking { result.await() })
        assertEquals(600L, signals.now)
        assertEquals(0, signals.pendingTimers)
    }

    @Test
    fun aShortTimeoutDoesNotExpireOnTheWallClock() {
        val result = CompletableDeferred<String?>()
        owner.scope.launch {
            result.complete(withTimeoutOrNull(1) { CompletableDeferred<String>().await() })
        }
        signals.awaitIdle("the wait has started")
        // Long past the 1 ms timeout on the wall clock: still waiting.
        assertThrows(AssertionError::class.java) {
            signals.eventually("the 1 ms wait expires on its own", 200) { result.isCompleted }
        }
        signals.advanceTimeBy(1)
        assertTrue(result.isCompleted)
    }

    @Test
    fun workADelayResumesIsIdleOnlyOnceItHasRun() {
        val steps = AtomicInteger()
        owner.scope.launch {
            delay(100)
            steps.incrementAndGet()
            owner.scope.launch { steps.incrementAndGet() }
        }
        signals.awaitIdle("the delay has started")
        assertEquals(0, steps.get())

        signals.advanceTimeBy(100)
        assertEquals("the resumed step and the one it launched have run", 2, steps.get())
    }

    @Test
    fun aCancelledDelayLetsGoOfItsTimer() {
        val job = owner.scope.launch { delay(100) }
        signals.awaitIdle("the delay has started")
        assertEquals(1, signals.pendingTimers)

        job.cancel()
        signals.awaitIdle("the cancel is handled")
        assertEquals(0, signals.pendingTimers)
        assertTrue(job.isCancelled)
    }

    /**
     * A test on the tracked scope decides what happened by the events it
     * delivered and the scope's clock: it neither sleeps nor times the
     * server on the wall clock.
     */
    @Test
    fun noTrackedScopeTestWaitsOnTheWallClock() {
        val dir = File("src/test/kotlin/com/automatethethings/xkey/ble")
        val users = dir.listFiles { f -> f.name.endsWith("Test.kt") && f.name != "ScopeDrainTest.kt" }!!
            .filter { it.readText().contains("trackScope(") }
        assertTrue("the GATT server tests use the tracked scope: ${users.map { it.name }}", users.size >= 5)
        val wallClock = listOf("Thread.sleep", "System.currentTimeMillis", "System.nanoTime", "PROMPTLY_MS")
        users.forEach { file ->
            val text = file.readText()
            wallClock.forEach { call ->
                assertFalse("${file.name} waits on the wall clock with $call", text.contains(call))
            }
        }
    }
}
