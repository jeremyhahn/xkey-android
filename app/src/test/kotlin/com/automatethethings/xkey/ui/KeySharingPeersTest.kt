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
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
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
        coEvery { dao.setPolicy(any()) } answers {
            val row = firstArg<KeySharingPolicy>()
            table.value = table.value.filterNot {
                it.keyId == row.keyId && it.peerPublicKeyHex == row.peerPublicKeyHex
            } + row
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

        val peers = KeySharingPeers(KEY, dao, repo)
        val seen = mutableListOf<List<KeySharingPeers.Peer>>()
        backgroundScope.launch(UnconfinedTestDispatcher(testScheduler)) { peers.peers().toList(seen) }

        val pending = seen.last().of(PEER_A)
        assertFalse("the old row must not show as a grant", pending.allowed)
        assertFalse("a pending peer must not be selectable", pending.selectable)
        assertTrue(seen.last().of(PEER_B).allowed)
        assertTrue(seen.last().of(PEER_B).selectable)

        // The user taps it anyway: nothing is written.
        assertFalse(peers.setAllowed(PEER_A, true))
        coVerify(exactly = 0) { dao.setPolicy(any()) }

        // The cleanup deletes A's rows and then acknowledges the revocation.
        dao.clearPoliciesForPeer(PEER_A)
        assertFalse(seen.last().of(PEER_A).selectable)
        repo.completeRevocation(PEER_A, repo.pendingRevocationGeneration(PEER_A)!!)

        val done = seen.last().of(PEER_A)
        assertFalse(done.allowed)
        assertTrue("the list updates once the revocation completes", done.selectable)

        assertTrue(peers.setAllowed(PEER_A, true))
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
        val peers = KeySharingPeers(KEY, dao, repo)

        // The grant passes its pending check and stops before its insert.
        val grant = async(UnconfinedTestDispatcher(testScheduler)) { peers.setAllowed(PEER_A, true) }
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
        val peers = KeySharingPeers(KEY, dao, repo)
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
        val peers = KeySharingPeers(KEY, dao, repo)
        val seen = mutableListOf<List<KeySharingPeers.Peer>>()
        backgroundScope.launch(UnconfinedTestDispatcher(testScheduler)) { peers.peers().toList(seen) }

        val grant = async(UnconfinedTestDispatcher(testScheduler)) { peers.setAllowed(PEER_A, true) }
        assertEquals("the write is under way", false, revokingDuringWrite)
        assertFalse("SELECTED_PEERS refused during the peer's own grant write", repo.isRevocationPending(PEER_A))

        gate.complete(Unit)
        assertTrue(grant.await())
        assertTrue(hasAccess(PEER_A))
        val after = seen.last().of(PEER_A)
        assertTrue("the sheet keeps the peer selectable", after.selectable)
        assertTrue(after.allowed)
    }
}
