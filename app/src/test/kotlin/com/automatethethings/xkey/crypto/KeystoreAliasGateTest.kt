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

package com.automatethethings.xkey.crypto

import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The per-alias gate of [KeystoreManager.withAliasGate] is shared by every
 * user of an alias, and keeps no entry for an alias nobody holds or waits on:
 * FileEncryptor takes it under a fresh alias for every file, and a paired
 * caller can name any number of key ids.
 */
class KeystoreAliasGateTest {

    @Test
    fun `many distinct aliases leave no entry behind`() {
        val before = KeystoreManager.aliasGateCount()
        repeat(10_000) { KeystoreManager.withAliasGate("churn-${UUID.randomUUID()}") { } }
        assertEquals(before, KeystoreManager.aliasGateCount())
    }

    @Test
    fun `aliases churned from many threads leave no entry behind`() {
        val before = KeystoreManager.aliasGateCount()
        val pool = Executors.newFixedThreadPool(8)
        try {
            val start = CyclicBarrier(8)
            val done = CountDownLatch(8)
            repeat(8) { t ->
                pool.execute {
                    start.await()
                    repeat(2_000) { i ->
                        // Half of them share an alias, so entries are dropped
                        // and recreated while others wait on them.
                        val alias = if (i % 2 == 0) "churn-shared-${i % 16}" else "churn-$t-$i"
                        KeystoreManager.withAliasGate(alias) { }
                    }
                    done.countDown()
                }
            }
            assertTrue(done.await(30, TimeUnit.SECONDS))
        } finally {
            pool.shutdownNow()
        }
        assertEquals(before, KeystoreManager.aliasGateCount())
    }

    @Test
    fun `two users of one alias exclude each other`() {
        val alias = "shared-${UUID.randomUUID()}"
        val inside = AtomicInteger(0)
        val maxInside = AtomicInteger(0)
        val pool = Executors.newFixedThreadPool(8)
        try {
            val start = CyclicBarrier(8)
            val done = CountDownLatch(8)
            repeat(8) {
                pool.execute {
                    start.await()
                    repeat(500) {
                        KeystoreManager.withAliasGate(alias) {
                            val now = inside.incrementAndGet()
                            maxInside.accumulateAndGet(now, ::maxOf)
                            Thread.yield()
                            inside.decrementAndGet()
                        }
                    }
                    done.countDown()
                }
            }
            assertTrue(done.await(30, TimeUnit.SECONDS))
        } finally {
            pool.shutdownNow()
        }
        assertEquals(1, maxInside.get())
    }

    @Test
    fun `a user waiting on an alias shares the holder's gate`() {
        val alias = "held-${UUID.randomUUID()}"
        val held = CountDownLatch(1)
        val release = CountDownLatch(1)
        val waiterIn = CountDownLatch(1)
        val holder = Thread {
            KeystoreManager.withAliasGate(alias) {
                held.countDown()
                release.await(10, TimeUnit.SECONDS)
            }
        }
        holder.start()
        assertTrue(held.await(10, TimeUnit.SECONDS))
        val waiter = Thread { KeystoreManager.withAliasGate(alias) { waiterIn.countDown() } }
        waiter.start()
        // While the holder holds it, the waiter cannot get in.
        assertTrue(!waiterIn.await(200, TimeUnit.MILLISECONDS))
        release.countDown()
        assertTrue(waiterIn.await(10, TimeUnit.SECONDS))
        holder.join(10_000)
        waiter.join(10_000)
    }

    @Test
    fun `a block that throws leaves no entry and frees the gate`() {
        val alias = "throws-${UUID.randomUUID()}"
        val before = KeystoreManager.aliasGateCount()
        val thrown = runCatching { KeystoreManager.withAliasGate(alias) { error("boom") } }
        assertTrue(thrown.isFailure)
        assertEquals(before, KeystoreManager.aliasGateCount())
        val other = Thread { KeystoreManager.withAliasGate(alias) { } }
        other.start()
        other.join(10_000)
        assertTrue(!other.isAlive)
    }

    @Test
    fun `the gate is reentrant for its holder`() {
        val alias = "reentrant-${UUID.randomUUID()}"
        val before = KeystoreManager.aliasGateCount()
        val value = KeystoreManager.withAliasGate(alias) { KeystoreManager.withAliasGate(alias) { 42 } }
        assertEquals(42, value)
        assertEquals(before, KeystoreManager.aliasGateCount())
    }
}
