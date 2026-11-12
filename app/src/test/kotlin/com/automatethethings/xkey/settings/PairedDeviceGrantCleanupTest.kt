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
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestCoroutineScheduler
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
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
 * `WHERE peer_public_key_hex = :peer`. In the first tests the coroutine scope
 * is unconfined, so the cleanup has finished when the repository call returns.
 * The durable-revocation tests run the cleanup on a [StandardTestDispatcher]
 * they advance by hand, so the delete can be held back, or never run.
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
    private val prefs = InMemorySharedPreferences()
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

        repo = PairedDeviceRepository(prefs)
        scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
        cleanup = PairedDeviceGrantCleanup({ dao }, { repo }, scope)
        PairedDeviceRepository.addRemovalListener(cleanup)
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

    // --- Durable revocation: a delete that never ran or failed is retried. ---

    private val scheduler = TestCoroutineScheduler()

    /** Swaps in a cleanup whose deletes run only when [scheduler] is advanced. */
    private fun heldCleanup(on: PairedDeviceRepository): PairedDeviceGrantCleanup {
        PairedDeviceRepository.removeRemovalListener(cleanup)
        scope.cancel()
        scope = CoroutineScope(SupervisorJob() + StandardTestDispatcher(scheduler))
        cleanup = PairedDeviceGrantCleanup({ dao }, { on }, scope)
        PairedDeviceRepository.addRemovalListener(cleanup)
        return cleanup
    }

    /**
     * A process restart: the old cleanup's coroutines are gone, a new
     * repository reads the same prefs, and the new cleanup replays what is
     * still pending.
     */
    private fun restart(): PairedDeviceRepository {
        val restarted = PairedDeviceRepository(prefs)
        heldCleanup(restarted).replayPending()
        scheduler.advanceUntilIdle()
        return restarted
    }

    private fun grantsOf(peer: String) = table.filter { it.peerPublicKeyHex == peer }

    /** The process dies before the delete runs: the restart drops the grants. */
    @Test
    fun aDeleteThatNeverRanIsReplayedAfterARestart() {
        heldCleanup(repo)
        repo.removeDevice(PEER_A)
        // The process dies: the delete never runs.
        assertEquals(2, grantsOf(PEER_A).size)

        val restarted = restart()
        restarted.addDevice(PEER_A, "desktop-a")

        assertEquals(emptyList<KeySharingPolicy>(), grantsOf(PEER_A))
        assertEquals(1, grantsOf(PEER_B).size)
        assertFalse(PEER_A in restarted.pendingRevocations())
    }

    /** The delete throws once: the restart retries it before the peer re-pairs. */
    @Test
    fun aFailedDeleteIsReplayedAfterARestart() {
        var failures = 1
        val delete = dao.clearPoliciesForPeerAnswer()
        coEvery { dao.clearPoliciesForPeer(any()) } answers {
            if (failures-- > 0) throw IllegalStateException("db closed") else delete(firstArg())
        }
        heldCleanup(repo)
        repo.removeDevice(PEER_A)
        scheduler.advanceUntilIdle()
        assertEquals(2, grantsOf(PEER_A).size)
        assertTrue(PEER_A in repo.pendingRevocations())

        val restarted = restart()
        restarted.addDevice(PEER_A, "desktop-a")

        assertEquals(emptyList<KeySharingPolicy>(), grantsOf(PEER_A))
        assertFalse(PEER_A in restarted.pendingRevocations())
        verify(exactly = 1) { AuditLogger.logPeerGrantsDropped(PEER_A, 2) }
    }

    /** The pending entry is written with the removal and cleared only once the delete commits. */
    @Test
    fun thePendingRevocationStaysRecordedUntilTheDeleteCommits() {
        heldCleanup(repo)
        repo.removeDevice(PEER_A)

        assertTrue(PEER_A in repo.pendingRevocations())
        assertTrue(PEER_A in PairedDeviceRepository(prefs).pendingRevocations())

        scheduler.advanceUntilIdle()

        assertEquals(emptyList<KeySharingPolicy>(), grantsOf(PEER_A))
        assertFalse(PEER_A in repo.pendingRevocations())
    }

    /** Eviction and clear() record their removed keys as pending too. */
    @Test
    fun evictionAndClearRecordPendingRevocations() {
        heldCleanup(repo)
        repo.addDevice(PEER_C, "desktop-a")
        assertEquals(setOf(PEER_A), repo.pendingRevocations())

        repo.clear()
        assertEquals(setOf(PEER_A, PEER_B, PEER_C), repo.pendingRevocations())

        scheduler.advanceUntilIdle()
        assertEquals(emptySet<String>(), repo.pendingRevocations())
        assertEquals(emptyList<KeySharingPolicy>(), table.toList())
    }

    /** Re-pairing a key whose revocation is still pending retries it, without a restart. */
    @Test
    fun rePairingAPendingKeyRetriesTheRevocation() {
        var failures = 1
        val delete = dao.clearPoliciesForPeerAnswer()
        coEvery { dao.clearPoliciesForPeer(any()) } answers {
            if (failures-- > 0) throw IllegalStateException("db closed") else delete(firstArg())
        }
        heldCleanup(repo)
        repo.removeDevice(PEER_A)
        scheduler.advanceUntilIdle()
        assertTrue(PEER_A in repo.pendingRevocations())

        repo.addDevice(PEER_A, "desktop-a")
        assertTrue(PEER_A in repo.pendingRevocations())
        scheduler.advanceUntilIdle()

        assertEquals(emptyList<KeySharingPolicy>(), grantsOf(PEER_A))
        assertFalse(PEER_A in repo.pendingRevocations())
        assertTrue(repo.isDeviceKnown(PEER_A))
    }

    /** The in-memory table's DELETE, for answers that wrap it. */
    private fun KeySharingPolicyDao.clearPoliciesForPeerAnswer(): (String) -> Int = { peer ->
        val rows = table.filter { it.peerPublicKeyHex == peer }
        table.removeAll(rows.toSet())
        rows.size
    }
}
