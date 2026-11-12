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

package com.automatethethings.xkey.settings

import android.util.Log
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.storage.dao.KeySharingPolicyDao
import com.automatethethings.xkey.storage.entity.KeySharingPolicy
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.confirmVerified
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.runs
import io.mockk.unmockkAll
import io.mockk.verify
import java.util.concurrent.CopyOnWriteArrayList
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test

/**
 * A desktop that stops being paired loses its per-key sharing grants (#174):
 * [PairedDeviceGrantCleanup], registered as a removal listener, deletes the
 * peer's `key_sharing_policies` rows for every removal path of
 * [PairedDeviceRepository] (unpair, eviction by a re-pairing under a new key,
 * and [PairedDeviceRepository.clear]), and only that peer's rows.
 *
 * The unit-test classpath has no Robolectric, so the DAO is backed by an
 * in-memory policy table whose DELETE matches the DAO's
 * `WHERE peer_public_key_hex = :peer`. The coroutine scope is unconfined, so
 * the cleanup has finished when the repository call returns.
 */
class PairedDeviceGrantCleanupTest {

    private companion object {
        val PEER_A = "a".repeat(64)
        val PEER_B = "b".repeat(64)
        val PEER_C = "c".repeat(64)
    }

    /** The `key_sharing_policies` table. */
    private val table = CopyOnWriteArrayList<KeySharingPolicy>()
    private lateinit var dao: KeySharingPolicyDao
    private lateinit var scope: CoroutineScope
    private lateinit var cleanup: PairedDeviceGrantCleanup
    private lateinit var repo: PairedDeviceRepository

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.e(any(), any<String>(), any()) } returns 0
        every { Log.i(any(), any<String>()) } returns 0
        mockkObject(AuditLogger)
        every { AuditLogger.logDeviceUnpaired(any(), any()) } just runs
        every { AuditLogger.logPeerGrantsDropped(any(), any()) } just runs

        dao = mockk()
        coEvery { dao.clearPoliciesForPeer(any()) } answers {
            val peer = firstArg<String>()
            val rows = table.filter { it.peerPublicKeyHex == peer }
            table.removeAll(rows.toSet())
            rows.size
        }

        // Peer A holds two SELECTED_PEERS grants, peer B one.
        table += KeySharingPolicy("k-1", PEER_A)
        table += KeySharingPolicy("k-2", PEER_A)
        table += KeySharingPolicy("k-1", PEER_B)

        scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
        cleanup = PairedDeviceGrantCleanup({ dao }, scope)
        PairedDeviceRepository.addRemovalListener(cleanup)
        repo = PairedDeviceRepository(InMemorySharedPreferences())
        repo.addDevice(PEER_A, "desktop-a")
        repo.addDevice(PEER_B, "desktop-b")
    }

    @After
    fun tearDown() {
        PairedDeviceRepository.removeRemovalListener(cleanup)
        scope.cancel()
        unmockkAll()
    }

    private fun peersWithGrants(): List<Pair<String, String>> =
        table.map { it.keyId to it.peerPublicKeyHex }

    @Test
    fun removeDeviceDropsOnlyThatPeersGrants() {
        repo.removeDevice(PEER_A)

        assertEquals(listOf("k-1" to PEER_B), peersWithGrants())
        verify(exactly = 1) { AuditLogger.logPeerGrantsDropped(PEER_A, 2) }
        coVerify(exactly = 1) { dao.clearPoliciesForPeer(PEER_A) }
        confirmVerified(dao)
    }

    /** A re-pairing under a new key evicts the old entry: the old key's grants go with it. */
    @Test
    fun evictionByRePairingDropsTheEvictedPeersGrants() {
        repo.addDevice(PEER_C, "desktop-a")

        assertEquals(listOf("k-1" to PEER_B), peersWithGrants())
        verify(exactly = 1) { AuditLogger.logPeerGrantsDropped(PEER_A, 2) }
        coVerify(exactly = 1) { dao.clearPoliciesForPeer(PEER_A) }
        confirmVerified(dao)
    }

    @Test
    fun clearDropsEveryPairedPeersGrants() {
        table += KeySharingPolicy("k-3", PEER_C)

        repo.clear()

        assertEquals(listOf("k-3" to PEER_C), peersWithGrants())
        verify(exactly = 1) { AuditLogger.logPeerGrantsDropped(PEER_A, 2) }
        verify(exactly = 1) { AuditLogger.logPeerGrantsDropped(PEER_B, 1) }
        coVerify(exactly = 1) { dao.clearPoliciesForPeer(PEER_A) }
        coVerify(exactly = 1) { dao.clearPoliciesForPeer(PEER_B) }
        confirmVerified(dao)
    }

    /** Re-pairing the same key is not a removal: its grants stay. */
    @Test
    fun reAddingTheSameKeyKeepsItsGrants() {
        repo.addDevice(PEER_A, "desktop-a")

        assertEquals(3, table.size)
        confirmVerified(dao)
    }

    /** A peer with no grants logs nothing. */
    @Test
    fun removingAPeerWithoutGrantsLogsNothing() {
        repo.removeDevice(PEER_C)

        assertEquals(3, table.size)
        verify(exactly = 0) { AuditLogger.logPeerGrantsDropped(any(), any()) }
    }

    /** A failing delete is logged and does not reach the caller. */
    @Test
    fun aFailingDeleteDoesNotReachTheCaller() {
        coEvery { dao.clearPoliciesForPeer(any()) } throws IllegalStateException("db closed")

        repo.removeDevice(PEER_A)

        assertEquals(3, table.size)
        verify(exactly = 0) { AuditLogger.logPeerGrantsDropped(any(), any()) }
    }
}
