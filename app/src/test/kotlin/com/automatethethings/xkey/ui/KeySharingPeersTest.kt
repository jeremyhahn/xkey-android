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

import android.content.SharedPreferences
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
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.newSingleThreadContext
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
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
@OptIn(ExperimentalCoroutinesApi::class, DelicateCoroutinesApi::class)
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
        coEvery { dao.clearPoliciesForKey(any()) } answers {
            val before = table.value
            table.value = before.filterNot { it.keyId == firstArg<String>() }
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

        val peers = KeySharingPeers(KEY, dao, repo, UnconfinedTestDispatcher(testScheduler))
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
        val peers = KeySharingPeers(KEY, dao, repo, UnconfinedTestDispatcher(testScheduler))

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
        val peers = KeySharingPeers(KEY, dao, repo, UnconfinedTestDispatcher(testScheduler))
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
        val peers = KeySharingPeers(KEY, dao, repo, UnconfinedTestDispatcher(testScheduler))
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

    @Test
    fun aGrantFromTheMainThreadCommitsOnTheIoDispatcher() = runTest {
        // Every prefs commit, with the thread it ran on.
        val commits = mutableListOf<String>()
        val store = InMemorySharedPreferences()
        val prefs = object : SharedPreferences by store {
            override fun edit(): SharedPreferences.Editor {
                val inner = store.edit()
                return object : SharedPreferences.Editor by inner {
                    override fun putString(key: String, value: String?) = also { inner.putString(key, value) }
                    override fun putStringSet(key: String, values: Set<String>?) = also { inner.putStringSet(key, values) }
                    override fun putLong(key: String, value: Long) = also { inner.putLong(key, value) }
                    override fun remove(key: String) = also { inner.remove(key) }
                    override fun commit(): Boolean {
                        // Without the " @coroutine#n" suffix debug mode adds.
                        synchronized(commits) { commits += Thread.currentThread().name.substringBefore(" @") }
                        return inner.commit()
                    }
                }
            }
        }
        repo = PairedDeviceRepository(prefs)
        repo.addDevice(PEER_A, "desktop-a")
        synchronized(commits) { commits.clear() }

        newSingleThreadContext("ui-main").use { main ->
            newSingleThreadContext("grant-io").use { io ->
                val peers = KeySharingPeers(KEY, dao, repo, io)
                // The sheet calls setAllowed from lifecycleScope, on Main.
                assertTrue(withContext(main) { peers.setAllowed(PEER_A, true) })
            }
        }

        // The marker commit and finishGrantWrite's commit, both off the caller's thread.
        assertEquals(listOf("grant-io", "grant-io"), synchronized(commits) { commits.toList() })
        assertTrue(hasAccess(PEER_A))
    }

    @Test
    fun aWithdrawalAfterAHeldGrantLeavesThePeerWithoutAccess() = runTest {
        table.value = listOf(KeySharingPolicy(KEY, PEER_B))
        val gate = CompletableDeferred<Unit>()
        coEvery { dao.setPolicy(any()) } coAnswers {
            gate.await()
            val row = firstArg<KeySharingPolicy>()
            table.value = table.value.filterNot {
                it.keyId == row.keyId && it.peerPublicKeyHex == row.peerPublicKeyHex
            } + row
        }
        val peers = KeySharingPeers(KEY, dao, repo, UnconfinedTestDispatcher(testScheduler))

        // The user checks A; the grant is held before its insert.
        val grant = async(UnconfinedTestDispatcher(testScheduler)) { peers.setAllowed(PEER_A, true) }
        assertFalse(grant.isCompleted)

        // The user unchecks A; the withdrawal gets as far as it can.
        val withdrawal = async(UnconfinedTestDispatcher(testScheduler)) { peers.setAllowed(PEER_A, false) }

        // The grant lands, then the withdrawal: the last action wins.
        gate.complete(Unit)
        assertTrue(grant.await())
        assertTrue(withdrawal.await())
        assertFalse("an earlier grant overwrote a later withdrawal", hasAccess(PEER_A))
        assertFalse(table.value.any { it.peerPublicKeyHex == PEER_A })
    }

    @Test
    fun aKeyWideClearAfterAHeldGrantLeavesThePeerWithoutAccess() = runTest {
        for (leaving in listOf(SharingPolicyType.PRIVATE, SharingPolicyType.ALL_PEERS)) {
            table.value = listOf(KeySharingPolicy(KEY, PEER_B))
            val gate = CompletableDeferred<Unit>()
            coEvery { dao.setPolicy(any()) } coAnswers {
                gate.await()
                val row = firstArg<KeySharingPolicy>()
                table.value = table.value.filterNot {
                    it.keyId == row.keyId && it.peerPublicKeyHex == row.peerPublicKeyHex
                } + row
            }
            val stored = mutableListOf<SharingPolicyType>()
            val peers = KeySharingPeers(KEY, dao, repo, UnconfinedTestDispatcher(testScheduler))

            // The user checks A; the grant is held before its insert.
            val grant = async(UnconfinedTestDispatcher(testScheduler)) { peers.setAllowed(PEER_A, true) }
            assertFalse(grant.isCompleted)

            // The user leaves SELECTED_PEERS; the key-wide clear gets as far as it can.
            val leave = async(UnconfinedTestDispatcher(testScheduler)) { peers.setKeyPolicy(leaving) { stored += leaving } }

            // The grant lands, then the clear; the user returns to SELECTED_PEERS.
            gate.complete(Unit)
            assertTrue(grant.await())
            leave.await()
            peers.setKeyPolicy(SharingPolicyType.SELECTED_PEERS) { stored += SharingPolicyType.SELECTED_PEERS }

            assertEquals(listOf(leaving, SharingPolicyType.SELECTED_PEERS), stored)
            assertFalse("$leaving: an earlier grant survived the key-wide clear", hasAccess(PEER_A))
            assertFalse(peers.peers().first().of(PEER_A).allowed)
            assertTrue("$leaving: selecting peers again starts from nothing", table.value.none { it.keyId == KEY })
        }
    }

    @Test
    fun aQueuedGrantForAPeerRePairedMeanwhileIsRefused() = runTest {
        table.value = emptyList()
        val gate = CompletableDeferred<Unit>()
        coEvery { dao.setPolicy(any()) } coAnswers {
            val row = firstArg<KeySharingPolicy>()
            if (row.peerPublicKeyHex == PEER_B) gate.await()
            table.value = table.value.filterNot {
                it.keyId == row.keyId && it.peerPublicKeyHex == row.peerPublicKeyHex
            } + row
        }
        val peers = KeySharingPeers(KEY, dao, repo, UnconfinedTestDispatcher(testScheduler))

        // The user checks B; its grant is held before its insert.
        val first = async(UnconfinedTestDispatcher(testScheduler)) { peers.setAllowed(PEER_B, true) }
        assertFalse(first.isCompleted)

        // The user checks A, approving A's current pairing; the grant queues behind B's.
        val queued = async(UnconfinedTestDispatcher(testScheduler)) { peers.setAllowed(PEER_A, true) }
        assertFalse(queued.isCompleted)

        // A is unpaired, its cleanup completes, and the same static key pairs again.
        repo.removeDevice(PEER_A)
        runCleanup(PEER_A)
        repo.addDevice(PEER_A, "desktop-a")
        assertFalse(repo.isRevocationPending(PEER_A))

        // B's grant lands; A's queued grant runs against the new pairing.
        gate.complete(Unit)
        assertTrue(first.await())
        assertFalse("a grant approved for the old pairing was written for the new one", queued.await())
        assertFalse(hasAccess(PEER_A))
        assertFalse(table.value.any { it.peerPublicKeyHex == PEER_A })
        coVerify(exactly = 0) { dao.setPolicy(match { it.peerPublicKeyHex == PEER_A }) }
    }

    @Test
    fun aWithdrawalQueuedBehindAGrantSurvivesTheSheetsDismissal() = runTest {
        table.value = listOf(KeySharingPolicy(KEY, PEER_A))
        val gate = holdGrants()
        val peers = KeySharingPeers(KEY, dao, repo, UnconfinedTestDispatcher(testScheduler), editScope = this)

        // Another grant holds the edits lock.
        val grant = async(UnconfinedTestDispatcher(testScheduler)) { peers.setAllowed(PEER_B, true) }
        assertFalse(grant.isCompleted)

        // The sheet withdraws A, already authorized, and is dismissed while that waits.
        val sheet = CoroutineScope(Job() + UnconfinedTestDispatcher(testScheduler))
        sheet.launch { peers.setAllowed(PEER_A, false) }
        sheet.cancel()

        gate.complete(Unit)
        assertTrue(grant.await())
        advanceUntilIdle()

        assertFalse("a withdrawal accepted before dismissal was dropped", hasAccess(PEER_A))
        assertFalse(peers.peers().first().of(PEER_A).allowed)
    }

    @Test
    fun aPrivatePolicyQueuedBehindAGrantSurvivesTheSheetsDismissal() = runTest {
        table.value = listOf(KeySharingPolicy(KEY, PEER_A))
        val gate = holdGrants()
        val stored = mutableListOf<SharingPolicyType>()
        val peers = KeySharingPeers(KEY, dao, repo, UnconfinedTestDispatcher(testScheduler), editScope = this)

        val grant = async(UnconfinedTestDispatcher(testScheduler)) { peers.setAllowed(PEER_B, true) }
        assertFalse(grant.isCompleted)

        // The sheet selects Private and is dismissed while that waits.
        val sheet = CoroutineScope(Job() + UnconfinedTestDispatcher(testScheduler))
        sheet.launch { peers.setKeyPolicy(SharingPolicyType.PRIVATE) { stored += SharingPolicyType.PRIVATE } }
        sheet.cancel()

        gate.complete(Unit)
        assertTrue(grant.await())
        advanceUntilIdle()

        assertEquals("the Private policy accepted before dismissal was dropped", listOf(SharingPolicyType.PRIVATE), stored)
        assertFalse(hasAccess(PEER_A))
        assertTrue(table.value.none { it.keyId == KEY })
    }

    @Test
    fun aDetachedWithdrawalThatFailsDeniesThePeerAndIsRetried() = runTest {
        table.value = listOf(KeySharingPolicy(KEY, PEER_A))
        val gate = holdGrants()
        var failing = true
        coEvery { dao.removePolicy(any(), any()) } answers {
            if (failing) throw IllegalStateException("disk I/O error")
            val before = table.value
            table.value = before.filterNot { it.keyId == firstArg<String>() && it.peerPublicKeyHex == secondArg<String>() }
            before.size - table.value.size
        }
        val peers = KeySharingPeers(KEY, dao, repo, UnconfinedTestDispatcher(testScheduler), editScope = this)

        val grant = async(UnconfinedTestDispatcher(testScheduler)) { peers.setAllowed(PEER_B, true) }
        val sheet = CoroutineScope(Job() + UnconfinedTestDispatcher(testScheduler))
        sheet.launch { peers.setAllowed(PEER_A, false) }
        sheet.cancel()

        // The queued withdrawal runs with nobody awaiting it, and fails.
        gate.complete(Unit)
        assertTrue(grant.await())
        runCurrent()

        assertTrue("the failed withdrawal's row is still stored", table.value.any { it.peerPublicKeyHex == PEER_A })
        assertFalse("a failed withdrawal left the peer authorized", hasAccess(PEER_A))
        assertFalse(peers.peers().first().of(PEER_A).allowed)

        // The store recovers: a retry lands the withdrawal.
        failing = false
        advanceUntilIdle()

        assertTrue("the withdrawal was not retried", table.value.none { it.peerPublicKeyHex == PEER_A })
        assertFalse(hasAccess(PEER_A))
        assertTrue(hasAccess(PEER_B))
        coVerify(atLeast = 2) { dao.removePolicy(KEY, PEER_A) }
    }

    @Test
    fun aDetachedPrivatePolicyThatFailsDeniesEveryPeerAndIsRetried() = runTest {
        table.value = listOf(KeySharingPolicy(KEY, PEER_A))
        val gate = holdGrants()
        var failing = true
        val stored = mutableListOf<SharingPolicyType>()
        val peers = KeySharingPeers(KEY, dao, repo, UnconfinedTestDispatcher(testScheduler), editScope = this)

        val grant = async(UnconfinedTestDispatcher(testScheduler)) { peers.setAllowed(PEER_B, true) }
        val sheet = CoroutineScope(Job() + UnconfinedTestDispatcher(testScheduler))
        sheet.launch {
            peers.setKeyPolicy(SharingPolicyType.PRIVATE) {
                if (failing) throw IllegalStateException("disk I/O error")
                stored += SharingPolicyType.PRIVATE
            }
        }
        sheet.cancel()

        gate.complete(Unit)
        assertTrue(grant.await())
        runCurrent()

        assertTrue(stored.isEmpty())
        assertFalse("a failed Private policy left a peer authorized", hasAccess(PEER_A))
        assertFalse(hasAccess(PEER_B))
        assertTrue(peers.peers().first().none { it.allowed })

        failing = false
        advanceUntilIdle()

        assertEquals("the Private policy was not retried", listOf(SharingPolicyType.PRIVATE), stored)
        assertTrue(table.value.none { it.keyId == KEY })
        assertFalse(hasAccess(PEER_A))
    }

    @Test
    fun aGrantAfterAFailedWithdrawalIsNotUndoneByItsRetry() = runTest {
        table.value = listOf(KeySharingPolicy(KEY, PEER_A))
        var failing = true
        coEvery { dao.removePolicy(any(), any()) } answers {
            if (failing) throw IllegalStateException("disk I/O error")
            val before = table.value
            table.value = before.filterNot { it.keyId == firstArg<String>() && it.peerPublicKeyHex == secondArg<String>() }
            before.size - table.value.size
        }
        val peers = KeySharingPeers(KEY, dao, repo, UnconfinedTestDispatcher(testScheduler), editScope = this)

        assertTrue(peers.setAllowed(PEER_A, false))
        runCurrent()
        assertFalse(hasAccess(PEER_A))

        // The user grants A again before any retry: that later choice stands.
        assertTrue(peers.setAllowed(PEER_A, true))
        failing = false
        advanceUntilIdle()

        assertTrue("a retry undid the later grant", hasAccess(PEER_A))
        assertTrue(peers.peers().first().of(PEER_A).allowed)
    }

    /** Holds every grant before its insert until the returned gate completes. */
    private fun holdGrants(): CompletableDeferred<Unit> {
        val gate = CompletableDeferred<Unit>()
        coEvery { dao.setPolicy(any()) } coAnswers {
            gate.await()
            val row = firstArg<KeySharingPolicy>()
            table.value = table.value.filterNot {
                it.keyId == row.keyId && it.peerPublicKeyHex == row.peerPublicKeyHex
            } + row
        }
        return gate
    }
}
