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

package com.automatethethings.xkey.ui

import android.util.Log
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.settings.InMemorySharedPreferences
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.storage.dao.KeySharingPolicyDao
import com.automatethethings.xkey.storage.entity.KeySharingPolicy
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.runs
import io.mockk.unmockkAll
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The key-sharing sheet's peer list while a re-paired peer's grant
 * revocation is still pending (#174): the peer is shown unselected and not
 * selectable, a grant for it is refused, and once the revocation completes
 * the list updates on its own and the peer can be granted again.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class KeySharingPeersTest {

    private companion object {
        const val KEY = "k-1"
        val PEER_A = "a".repeat(64)
        val PEER_B = "b".repeat(64)
        val PEER_C = "c".repeat(64)
    }

    /** The `key_sharing_policies` table; the DAO's Flow query re-emits on every change. */
    private val table = MutableStateFlow<List<KeySharingPolicy>>(emptyList())
    private lateinit var dao: KeySharingPolicyDao
    private lateinit var repo: PairedDeviceRepository

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.e(any(), any<String>(), any()) } returns 0
        every { Log.i(any(), any<String>()) } returns 0
        mockkObject(AuditLogger)
        every { AuditLogger.logDeviceUnpaired(any(), any()) } just runs

        dao = mockk()
        every { dao.getPoliciesForKey(any()) } answers {
            val keyId = firstArg<String>()
            table.map { rows -> rows.filter { it.keyId == keyId } }
        }
        coEvery { dao.setPolicy(any()) } answers { insert(firstArg()) }
        coEvery { dao.clearPoliciesForKey(any()) } answers {
            val before = table.value
            table.value = before.filterNot { it.keyId == firstArg<String>() }
            before.size - table.value.size
        }
        coEvery { dao.removePolicy(any(), any()) } answers {
            val before = table.value
            table.value = before.filterNot { it.keyId == firstArg<String>() && it.peerPublicKeyHex == secondArg<String>() }
            before.size - table.value.size
        }
        coEvery { dao.clearPoliciesForPeer(any()) } answers {
            val before = table.value
            table.value = before.filterNot { it.peerPublicKeyHex == firstArg<String>() }
            before.size - table.value.size
        }

        repo = PairedDeviceRepository(InMemorySharedPreferences())
        repo.addDevice(PEER_A, "desktop-a")
        repo.addDevice(PEER_B, "desktop-b")
        table.value = listOf(KeySharingPolicy(KEY, PEER_A), KeySharingPolicy(KEY, PEER_B))
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    /** The DAO's `INSERT OR REPLACE`. */
    private fun insert(row: KeySharingPolicy) {
        table.value = table.value.filterNot {
            it.keyId == row.keyId && it.peerPublicKeyHex == row.peerPublicKeyHex
        } + row
    }

    /** The list for [KEY], its writes run unconfined on the test scheduler. */
    private fun TestScope.peersOf() = KeySharingPeers(KEY, dao, repo, UnconfinedTestDispatcher(testScheduler))

    private fun List<KeySharingPeers.Peer>.of(peer: String) = single { it.device.publicKeyHex == peer }

    /** The request handler's SELECTED_PEERS check: refused while a revocation is pending, else the row decides. */
    private fun hasAccess(peer: String) =
        !repo.isRevocationPending(peer) && table.value.any { it.keyId == KEY && it.peerPublicKeyHex == peer && it.allowed }

    /** What the grant cleanup does for [peer]'s pending revocation: delete its rows, then acknowledge. */
    private suspend fun runCleanup(peer: String) {
        val generation = repo.pendingRevocationGeneration(peer) ?: return
        dao.clearPoliciesForPeer(peer)
        repo.completeRevocation(peer, generation)
    }

    @Test
    fun aRePairedPeerIsPendingAndUngrantableUntilItsRevocationCompletes() = runTest {
        // A is unpaired and re-paired; no cleanup has run, so its old row stays.
        repo.removeDevice(PEER_A)
        repo.addDevice(PEER_A, "desktop-a")
        assertTrue(repo.isRevocationPending(PEER_A))

        val peers = peersOf()
        val seen = mutableListOf<List<KeySharingPeers.Peer>>()
        backgroundScope.launch(UnconfinedTestDispatcher(testScheduler)) { peers.peers().toList(seen) }

        val pending = seen.last().of(PEER_A)
        assertFalse("the old row must not show as a grant", pending.allowed)
        assertFalse("a pending peer must not be selectable", pending.selectable)
        assertTrue(seen.last().of(PEER_B).allowed)
        assertTrue(seen.last().of(PEER_B).selectable)

        // The user taps it anyway: nothing is written.
        assertFalse(peers.setAllowed(PEER_A, true, repo.pairingGeneration(PEER_A)))
        coVerify(exactly = 0) { dao.setPolicy(any()) }

        // The cleanup deletes A's rows and then acknowledges the revocation.
        dao.clearPoliciesForPeer(PEER_A)
        assertFalse(seen.last().of(PEER_A).selectable)
        repo.completeRevocation(PEER_A, repo.pendingRevocationGeneration(PEER_A)!!)

        val done = seen.last().of(PEER_A)
        assertFalse(done.allowed)
        assertTrue("the list updates once the revocation completes", done.selectable)

        assertTrue(peers.setAllowed(PEER_A, true, repo.pairingGeneration(PEER_A)))
        assertTrue(seen.last().of(PEER_A).allowed)
        assertEquals(listOf(PEER_B, PEER_A), table.value.map { it.peerPublicKeyHex })
    }

    @Test
    fun aGrantPausedAcrossARevocationDoesNotAuthorizeTheNextPairing() = runTest {
        table.value = listOf(KeySharingPolicy(KEY, PEER_B))
        val gate = CompletableDeferred<Unit>()
        coEvery { dao.setPolicy(any()) } coAnswers {
            gate.await()
            val row = firstArg<KeySharingPolicy>()
            table.value = table.value.filterNot {
                it.keyId == row.keyId && it.peerPublicKeyHex == row.peerPublicKeyHex
            } + row
        }
        val peers = peersOf()

        // The grant passes its pending check and stops before its insert.
        val grant = async(UnconfinedTestDispatcher(testScheduler)) { peers.setAllowed(PEER_A, true, repo.pairingGeneration(PEER_A)) }
        assertFalse(grant.isCompleted)

        // Meanwhile A is unpaired, and its revocation is cleaned up and acknowledged.
        repo.removeDevice(PEER_A)
        runCleanup(PEER_A)
        assertNull("the revocation is acknowledged", repo.pendingRevocationGeneration(PEER_A))
        // A write checked against the ended pairing is still in flight.
        assertTrue(repo.isRevocationPending(PEER_A))

        // The insert lands after the revocation completed.
        gate.complete(Unit)
        assertFalse("a grant for an ended pairing does not stand", grant.await())

        // The same static key pairs again: the old grant must not authorize it.
        repo.addDevice(PEER_A, "desktop-a")
        assertFalse("a grant written for an older pairing authorized a newer one", hasAccess(PEER_A))

        // Once the cleanup has run, the row is gone and A is grantable again.
        runCleanup(PEER_A)
        assertFalse(repo.isRevocationPending(PEER_A))
        assertFalse(table.value.any { it.peerPublicKeyHex == PEER_A })
        assertFalse(hasAccess(PEER_A))
    }

    @Test
    fun aDevicePairedAfterSubscribingAppearsInTheList() = runTest {
        // The sheet subscribes when it opens, whatever the key's policy (PRIVATE
        // here: nothing in the table changes below), and shows this list as soon
        // as SELECTED_PEERS is chosen.
        val peers = peersOf()
        val seen = mutableListOf<List<KeySharingPeers.Peer>>()
        backgroundScope.launch(UnconfinedTestDispatcher(testScheduler)) { peers.peers().toList(seen) }
        assertEquals(setOf(PEER_A, PEER_B), seen.last().map { it.device.publicKeyHex }.toSet())

        // A new desktop pairs: no policy row and no revocation changes.
        repo.addDevice(PEER_C, "desktop-c")

        assertEquals(setOf(PEER_A, PEER_B, PEER_C), seen.last().map { it.device.publicKeyHex }.toSet())
        val added = seen.last().of(PEER_C)
        assertFalse(added.allowed)
        assertTrue(added.selectable)
    }

    @Test
    fun aPeerPairedBeforePairingGenerationsIsNotRevokingDuringItsOwnGrant() = runTest {
        // Upgrade state: A and B are in paired_devices, but no pairing_generations
        // entry exists yet (they were paired by a build before #174).
        val legacy = InMemorySharedPreferences()
        PairedDeviceRepository(legacy).apply {
            addDevice(PEER_A, "desktop-a")
            addDevice(PEER_B, "desktop-b")
        }
        legacy.edit().remove("pairing_generations").commit()
        repo = PairedDeviceRepository(legacy)
        table.value = listOf(KeySharingPolicy(KEY, PEER_B))

        val gate = CompletableDeferred<Unit>()
        var revokingDuringWrite: Boolean? = null
        coEvery { dao.setPolicy(any()) } coAnswers {
            revokingDuringWrite = repo.isRevocationPending(PEER_A)
            gate.await()
            val row = firstArg<KeySharingPolicy>()
            table.value = table.value.filterNot {
                it.keyId == row.keyId && it.peerPublicKeyHex == row.peerPublicKeyHex
            } + row
        }
        val peers = peersOf()
        val seen = mutableListOf<List<KeySharingPeers.Peer>>()
        backgroundScope.launch(UnconfinedTestDispatcher(testScheduler)) { peers.peers().toList(seen) }

        val grant = async(UnconfinedTestDispatcher(testScheduler)) { peers.setAllowed(PEER_A, true, repo.pairingGeneration(PEER_A)) }
        assertEquals("the write is under way", false, revokingDuringWrite)
        assertFalse("SELECTED_PEERS refused during the peer's own grant write", repo.isRevocationPending(PEER_A))

        gate.complete(Unit)
        assertTrue(grant.await())
        assertTrue(hasAccess(PEER_A))
        val after = seen.last().of(PEER_A)
        assertTrue("the sheet keeps the peer selectable", after.selectable)
        assertTrue(after.allowed)
    }

    // #193: edits of a key's peer rows land in the order the user made them.

    @Test
    fun aWithdrawalAfterAGrantStillWaitingEndsWithdrawn() = runTest {
        table.value = listOf(KeySharingPolicy(KEY, PEER_B))
        val gate = CompletableDeferred<Unit>()
        coEvery { dao.setPolicy(any()) } coAnswers {
            gate.await()
            insert(firstArg())
        }
        val peers = peersOf()

        // The user grants A, then withdraws it before the grant is written.
        val grant = async(UnconfinedTestDispatcher(testScheduler)) {
            peers.setAllowed(PEER_A, true, repo.pairingGeneration(PEER_A))
        }
        val withdrawal = async(UnconfinedTestDispatcher(testScheduler)) {
            peers.setAllowed(PEER_A, false, repo.pairingGeneration(PEER_A))
        }
        assertFalse(grant.isCompleted)
        assertFalse("the withdrawal waits for the grant made before it", withdrawal.isCompleted)

        gate.complete(Unit)
        assertTrue(grant.await())
        assertTrue(withdrawal.await())
        assertFalse("a grant landed after its withdrawal", hasAccess(PEER_A))
        assertEquals(listOf(PEER_B), table.value.map { it.peerPublicKeyHex })
    }

    @Test
    fun leavingSelectedPeersForPrivateDuringAGrantLeavesNoPeerRow() = runTest {
        leaveSelectedPeersDuringAGrant(SharingPolicyType.PRIVATE)
    }

    @Test
    fun leavingSelectedPeersForAllPeersDuringAGrantLeavesNoPeerRow() = runTest {
        leaveSelectedPeersDuringAGrant(SharingPolicyType.ALL_PEERS)
    }

    /**
     * A grant is in flight when the user switches the key to [destination],
     * then back to SELECTED_PEERS: the clear runs after the grant, so no peer
     * row is left and the list shows no access.
     */
    private suspend fun TestScope.leaveSelectedPeersDuringAGrant(destination: SharingPolicyType) {
        table.value = listOf(KeySharingPolicy(KEY, PEER_B))
        var column = SharingPolicyType.SELECTED_PEERS
        val gate = CompletableDeferred<Unit>()
        coEvery { dao.setPolicy(any()) } coAnswers {
            gate.await()
            insert(firstArg())
        }
        val peers = peersOf()
        val seen = mutableListOf<List<KeySharingPeers.Peer>>()
        backgroundScope.launch(UnconfinedTestDispatcher(testScheduler)) { peers.peers().toList(seen) }

        val grant = async(UnconfinedTestDispatcher(testScheduler)) {
            peers.setAllowed(PEER_A, true, repo.pairingGeneration(PEER_A))
        }
        val leave = async(UnconfinedTestDispatcher(testScheduler)) {
            peers.setSharingPolicy(selectedPeers = false) { column = destination }
        }
        assertFalse(grant.isCompleted)
        assertFalse("the clear waits for the grant made before it", leave.isCompleted)

        gate.complete(Unit)
        grant.await()
        leave.await()
        assertEquals(destination, column)
        assertTrue("a grant in flight outlived the key-wide clear", table.value.none { it.keyId == KEY })

        peers.setSharingPolicy(selectedPeers = true) { column = SharingPolicyType.SELECTED_PEERS }
        assertEquals(SharingPolicyType.SELECTED_PEERS, column)
        assertFalse(hasAccess(PEER_A))
        assertFalse(hasAccess(PEER_B))
        assertTrue("selected peers starts from nothing", seen.last().none { it.allowed })
    }

    @Test
    fun aGrantTappedBeforeAnUnpairAndRepairIsRefused() = runTest {
        table.value = emptyList()
        val gate = CompletableDeferred<Unit>()
        coEvery { dao.setPolicy(any()) } coAnswers {
            if (firstArg<KeySharingPolicy>().peerPublicKeyHex == PEER_B) gate.await()
            insert(firstArg())
        }
        val peers = peersOf()

        // B's grant is being written when the user taps A: A's grant waits its turn.
        val first = async(UnconfinedTestDispatcher(testScheduler)) {
            peers.setAllowed(PEER_B, true, repo.pairingGeneration(PEER_B))
        }
        val tapped = repo.pairingGeneration(PEER_A)
        val grant = async(UnconfinedTestDispatcher(testScheduler)) { peers.setAllowed(PEER_A, true, tapped) }
        assertFalse(grant.isCompleted)

        // Before it runs, A is unpaired, its revocation completes, and it pairs again.
        repo.removeDevice(PEER_A)
        runCleanup(PEER_A)
        repo.addDevice(PEER_A, "desktop-a")
        assertFalse(repo.isRevocationPending(PEER_A))

        gate.complete(Unit)
        assertTrue(first.await())
        assertFalse("a grant tapped for an ended pairing was written", grant.await())
        assertTrue(table.value.none { it.peerPublicKeyHex == PEER_A })
        assertFalse(hasAccess(PEER_A))
    }

    @Test
    fun aRefusedGrantDoesNotRedrawASheetDismissedWhileItWaited() = runTest {
        table.value = emptyList()
        val gate = CompletableDeferred<Unit>()
        coEvery { dao.setPolicy(any()) } coAnswers {
            if (firstArg<KeySharingPolicy>().peerPublicKeyHex == PEER_B) gate.await()
            insert(firstArg())
        }
        val peers = peersOf()
        var attached = true
        var redraws = 0

        // B's grant is being written when the user taps A: A's grant waits its turn.
        val first = async(UnconfinedTestDispatcher(testScheduler)) {
            peers.setAllowed(PEER_B, true, repo.pairingGeneration(PEER_B))
        }
        val tapped = repo.pairingGeneration(PEER_A)
        val tap = launch(UnconfinedTestDispatcher(testScheduler)) {
            peers.setAllowedOrRedraw(
                PEER_A,
                true,
                tapped,
                attached = { attached },
                // What requireContext() does once the sheet is detached.
                redraw = { check(attached) { "redrew a detached sheet" }; redraws++ }
            )
        }
        assertFalse(tap.isCompleted)

        // A is unpaired, then the sheet is dismissed, before the queue drains.
        repo.removeDevice(PEER_A)
        attached = false
        tap.cancel()

        gate.complete(Unit)
        assertTrue(first.await())
        tap.join()
        assertEquals("a detached sheet was redrawn", 0, redraws)
        assertTrue(table.value.none { it.peerPublicKeyHex == PEER_A })
        assertFalse(hasAccess(PEER_A))
        // The refused grant left the queue: the next edit of the key runs at once.
        assertTrue(peers.setAllowed(PEER_B, false, null))
    }

    @Test
    fun theGrantWriteDoesNotRunOnTheCallingDispatcher() = runTest {
        table.value = emptyList()
        val caller = Thread.currentThread()
        val writer = AtomicReference<Thread>()
        coEvery { dao.setPolicy(any()) } answers {
            writer.set(Thread.currentThread())
            insert(firstArg())
        }
        // The production dispatcher.
        val peers = KeySharingPeers(KEY, dao, repo)

        assertTrue(peers.setAllowed(PEER_A, true, repo.pairingGeneration(PEER_A)))

        assertNotNull(writer.get())
        assertNotSame("the grant was written on the calling thread", caller, writer.get())
        assertTrue(hasAccess(PEER_A))
    }
}
