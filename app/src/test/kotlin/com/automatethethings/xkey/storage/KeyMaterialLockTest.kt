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

package com.automatethethings.xkey.storage

import com.automatethethings.xkey.storage.dao.KeyPolicyDao
import io.mockk.coEvery
import io.mockk.mockk
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.UUID

/**
 * Each key id's material lock lives only while it has a holder or a waiter
 * (#255 review): key ids can come from a peer, so a map that kept a lock
 * per id ever used would grow without bound. The lock still excludes: a
 * second user of the same id waits until the first is done.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class KeyMaterialLockTest {

    private val dao = mockk<KeyPolicyDao>(relaxed = true)
    private val store = KeyPolicyStore(
        dao,
        object : KeyPolicyStore.Transactor {
            override suspend fun <T> run(block: suspend () -> T): T = block()
        }
    )

    @Test
    fun peerChosenIdsLeaveNoLockBehind() = runTest {
        val before = KeyPolicyStore.liveMaterialLocks()
        val ids = List(1_000) { "peer-${UUID.randomUUID()}" }
        for (id in ids) store.lockKeyMaterial(id) { }
        // A block that throws releases its lock too.
        for (id in ids.take(10)) runCatching { store.lockKeyMaterial(id) { error("refused") } }

        assertEquals(before, KeyPolicyStore.liveMaterialLocks())
        assertTrue(ids.all { KeyPolicyStore.materialLockUsers(it) == 0 })
    }

    @Test
    fun oneIdIsHeldByOneBlockAtATime() = runTest {
        val id = "same-${UUID.randomUUID()}"
        val release = CompletableDeferred<Unit>()
        var secondRan = false

        val first = async { store.lockKeyMaterial(id) { release.await() } }
        runCurrent()
        val second = async { store.lockKeyMaterial(id) { secondRan = true } }
        runCurrent()

        // The holder and the waiter both count, so the lock is not dropped
        // while the waiter still needs it.
        assertFalse("a second block of the same id ran while the first held it", secondRan)
        assertEquals(2, KeyPolicyStore.materialLockUsers(id))

        release.complete(Unit)
        first.await()
        second.await()
        assertTrue(secondRan)
        assertEquals(0, KeyPolicyStore.materialLockUsers(id))
    }

    /**
     * Crypto uses of one key run side by side; a delete waits until the
     * running use ends, and its tombstone then refuses the next use.
     */
    @Test
    fun usesShareTheKeyAndADeleteWaitsThemOut() = runTest {
        val id = "use-${UUID.randomUUID()}"
        coEvery { dao.deletion(id) } returns null
        val release = CompletableDeferred<Unit>()
        var secondUsed = false
        var deleteRan = false

        val first = async { store.withUsableKey(id) { release.await() } }
        runCurrent()
        store.withUsableKey(id) { secondUsed = true }
        assertTrue("a second use of the key waited for the first", secondUsed)

        val delete = async { store.lockKeyMaterial(id) { deleteRan = true } }
        runCurrent()
        assertFalse("a delete ran while a use of the key was running", deleteRan)

        release.complete(Unit)
        first.await()
        delete.await()
        assertTrue(deleteRan)
        assertEquals(0, KeyPolicyStore.materialLockUsers(id))
    }
}
