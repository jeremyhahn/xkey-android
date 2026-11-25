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

package com.automatethethings.xkey.ble

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * [LifecycleGeneration]: a start publishes only while no stop or destroy has
 * run since it took its token, and a stop or destroy never interleaves with a
 * publish in progress.
 */
class LifecycleGenerationTest {

    private val generation = LifecycleGeneration()

    @Test
    fun `begin returns the current token until a stop`() {
        val first = generation.begin()
        assertNotNull(first)
        assertEquals(first, generation.begin())
        generation.advance()
        val second = generation.begin()
        assertNotNull(second)
        assertNotEquals(first, second)
    }

    @Test
    fun `begin returns null after end, and a later stop does not revive it`() {
        generation.end()
        assertNull(generation.begin())
        generation.advance()
        assertNull(generation.begin())
        generation.end()
        assertNull(generation.begin())
    }

    @Test
    fun `advance makes an earlier token stale and the new one current`() {
        val stale = generation.begin()!!
        assertTrue(generation.isCurrent(stale))
        generation.advance()
        assertFalse(generation.isCurrent(stale))
        assertTrue(generation.isCurrent(generation.begin()!!))
    }

    @Test
    fun `no token is current after end, not even the latest`() {
        val stale = generation.begin()!!
        generation.advance()
        val latest = generation.begin()!!
        generation.end()
        assertFalse(generation.isCurrent(stale))
        assertFalse(generation.isCurrent(latest))
    }

    @Test
    fun `a token never taken is not current`() {
        val token = generation.begin()!!
        assertFalse(generation.isCurrent(token + 1))
        assertFalse(generation.isCurrent(token - 1))
    }

    @Test
    fun `publish runs its block for a current token and reports that it ran`() {
        val token = generation.begin()!!
        var runs = 0
        assertTrue(generation.publish(token) { runs++ })
        assertEquals(1, runs)
        // The token stays current: publishing does not advance it.
        assertTrue(generation.isCurrent(token))
    }

    @Test
    fun `publish does not run its block for a stale token`() {
        val token = generation.begin()!!
        generation.advance()
        var runs = 0
        assertFalse(generation.publish(token) { runs++ })
        assertEquals(0, runs)
    }

    @Test
    fun `publish does not run its block after end`() {
        val token = generation.begin()!!
        generation.end()
        var runs = 0
        assertFalse(generation.publish(token) { runs++ })
        assertEquals(0, runs)
    }

    @Test(timeout = 10_000)
    fun `a stop during a publish waits for the block, and the token is stale after it`() =
        assertWaitsForPublish("advance") { generation.advance() }

    @Test(timeout = 10_000)
    fun `a destroy during a publish waits for the block, and nothing begins after it`() {
        assertWaitsForPublish("end") { generation.end() }
        assertNull(generation.begin())
    }

    @Test(timeout = 10_000)
    fun `a start whose stop lands first does not publish`() {
        val token = generation.begin()!!
        val stopper = Thread { generation.advance() }
        stopper.start()
        stopper.join()
        var runs = 0
        assertFalse(generation.publish(token) { runs++ })
        assertEquals(0, runs)
    }

    /**
     * Holds a publish inside its block, runs [stop] on another thread, and
     * checks [stop] blocks on the lock until the block returns.
     */
    private fun assertWaitsForPublish(name: String, stop: () -> Unit) {
        val token = generation.begin()!!
        val events = CopyOnWriteArrayList<String>()
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        var published = false

        val starter = Thread {
            published = generation.publish(token) {
                events += "block start"
                entered.countDown()
                release.await()
                events += "block end"
            }
        }
        starter.start()
        assertTrue(entered.await(5, TimeUnit.SECONDS))

        val stopper = Thread {
            stop()
            events += name
        }
        stopper.start()
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (stopper.state != Thread.State.BLOCKED && System.nanoTime() < deadline) Thread.sleep(1)
        assertEquals("$name waits on the lock the publish holds", Thread.State.BLOCKED, stopper.state)
        assertEquals(listOf("block start"), events.toList())

        release.countDown()
        starter.join()
        stopper.join()

        assertTrue(published)
        assertEquals(listOf("block start", "block end", name), events.toList())
        assertFalse(generation.isCurrent(token))
    }
}
