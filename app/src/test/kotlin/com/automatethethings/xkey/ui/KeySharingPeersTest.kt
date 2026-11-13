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
import com.automatethethings.xkey.storage.FakeKeyPolicyTables
import com.automatethethings.xkey.storage.KeyPolicyStore
import com.automatethethings.xkey.storage.entity.SharingPolicyType as StoredPolicy
import io.mockk.coVerify
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.runs
import io.mockk.spyk
import io.mockk.unmockkAll
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.newSingleThreadContext
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
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
@OptIn(ExperimentalCoroutinesApi::class, DelicateCoroutinesApi::class)
class KeySharingPeersTest {

    private companion object {
        const val KEY = "k-1"
        val PEER_A = "a".repeat(64)
        val PEER_B = "b".repeat(64)
        val PEER_C = "c".repeat(64)
    }

    /** The `keys`, `key_policies` and `key_sharing_policies` tables the store writes. */
    private val tables = FakeKeyPolicyTables()
    private val store: KeyPolicyStore = tables.store()
    private lateinit var repo: PairedDeviceRepository

    /** [KEY]'s key row, stored Selected Peers. */
    private var instance = 0L

    /** Grant writes started, held or not. */
    private var grantWrites = 0

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.e(any(), any<String>(), any()) } returns 0
        every { Log.e(any(), any<String>()) } returns 0
        every { Log.i(any(), any<String>()) } returns 0
        mockkObject(AuditLogger)
        every { AuditLogger.logDeviceUnpaired(any(), any()) } just runs

        tables.onPutGrant = { grantWrites++ }
        instance = tables.addKey(KEY, StoredPolicy.SELECTED_PEERS)

        repo = PairedDeviceRepository(InMemorySharedPreferences())
        repo.addDevice(PEER_A, "desktop-a")
        repo.addDevice(PEER_B, "desktop-b")
        rows(KEY to PEER_A, KEY to PEER_B)
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    /** The grant rows, as (key, peer), in the order they were written. */
    private val table get() = tables.grants.value

    /** Replaces every grant row. */
    private fun rows(vararg grants: Pair<String, String>) {
        tables.grants.value = grants.toSet()
    }

    /** Holds every grant before its insert until [gate] completes, or only [peer]'s if given. */
    private fun holdGrants(gate: CompletableDeferred<Unit> = CompletableDeferred(), peer: String? = null): CompletableDeferred<Unit> {
        tables.onPutGrant = {
            grantWrites++
            if (peer == null || it.peerPublicKeyHex == peer) gate.await()
        }
        return gate
    }

    /** The list for [KEY], its writes run unconfined on the test scheduler, its edits in the test scope. */
    private fun TestScope.peersOf() = KeySharingPeers(KEY, instance, store, repo, UnconfinedTestDispatcher(testScheduler), editScope = this)

    private fun List<KeySharingPeers.Peer>.of(peer: String) = single { it.device.publicKeyHex == peer }

    /** The request handler's check for [peer]: refused while a withdrawal or revocation is pending, else the enforced policy and the rows decide. */
    private fun hasAccess(peer: String, keyId: String = KEY) =
        !KeySharingPeers.isWithdrawalPending(keyId, peer) && !repo.isRevocationPending(peer) &&
            when (tables.enforced(keyId)) {
                StoredPolicy.ALL_PEERS -> true
                StoredPolicy.SELECTED_PEERS -> tables.isGranted(keyId, peer)
                else -> false
            }

    /** What the grant cleanup does for [peer]'s pending revocation: delete its rows, then acknowledge. */
    private fun runCleanup(peer: String) {
        val generation = repo.pendingRevocationGeneration(peer) ?: return
        tables.clearPeer(peer)
        repo.completeRevocation(peer, generation)
    }

    @Test
    fun aRePairedPeerIsPendingAndUngrantableUntilItsRevocationCompletes() = runTest {
        // A is unpaired and re-paired; no cleanup has run, so its old row stays.
        repo.removeDevice(PEER_A)
        repo.addDevice(PEER_A, "desktop-a")
        assertTrue(repo.isRevocationPending(PEER_A))

        val peers = KeySharingPeers(KEY, instance, store, repo, UnconfinedTestDispatcher(testScheduler))
        val seen = mutableListOf<List<KeySharingPeers.Peer>>()
        backgroundScope.launch(UnconfinedTestDispatcher(testScheduler)) { peers.peers().toList(seen) }

        val pending = seen.last().of(PEER_A)
        assertFalse("the old row must not show as a grant", pending.allowed)
        assertFalse("a pending peer must not be selectable", pending.selectable)
        assertTrue(seen.last().of(PEER_B).allowed)
        assertTrue(seen.last().of(PEER_B).selectable)

        // The user taps it anyway: nothing is written.
        assertFalse(peers.setAllowed(PEER_A, true, repo.pairingGeneration(PEER_A)))
        assertEquals(0, grantWrites)

        // The cleanup deletes A's rows and then acknowledges the revocation.
        tables.clearPeer(PEER_A)
        assertFalse(seen.last().of(PEER_A).selectable)
        repo.completeRevocation(PEER_A, repo.pendingRevocationGeneration(PEER_A)!!)

        val done = seen.last().of(PEER_A)
        assertFalse(done.allowed)
        assertTrue("the list updates once the revocation completes", done.selectable)

        assertTrue(peers.setAllowed(PEER_A, true, repo.pairingGeneration(PEER_A)))
        assertTrue(seen.last().of(PEER_A).allowed)
        assertEquals(listOf(PEER_B, PEER_A), table.map { it.second })
    }

    @Test
    fun aGrantPausedAcrossARevocationDoesNotAuthorizeTheNextPairing() = runTest {
        rows(KEY to PEER_B)
        val gate = holdGrants()
        val peers = KeySharingPeers(KEY, instance, store, repo, UnconfinedTestDispatcher(testScheduler))

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
        assertFalse(table.any { it.second == PEER_A })
        assertFalse(hasAccess(PEER_A))
    }

    @Test
    fun aDevicePairedAfterSubscribingAppearsInTheList() = runTest {
        // The sheet subscribes when it opens, whatever the key's policy (PRIVATE
        // here: nothing in the table changes below), and shows this list as soon
        // as SELECTED_PEERS is chosen.
        val peers = KeySharingPeers(KEY, instance, store, repo, UnconfinedTestDispatcher(testScheduler))
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
        rows(KEY to PEER_B)

        val gate = CompletableDeferred<Unit>()
        var revokingDuringWrite: Boolean? = null
        tables.onPutGrant = {
            revokingDuringWrite = repo.isRevocationPending(PEER_A)
            gate.await()
        }
        val peers = KeySharingPeers(KEY, instance, store, repo, UnconfinedTestDispatcher(testScheduler))
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

    @Test
    fun aGrantFromTheMainThreadCommitsOnTheIoDispatcher() = runTest {
        // Every prefs commit, with the thread it ran on.
        val commits = mutableListOf<String>()
        val backing = InMemorySharedPreferences()
        val prefs = object : SharedPreferences by backing {
            override fun edit(): SharedPreferences.Editor {
                val inner = backing.edit()
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
                val peers = KeySharingPeers(KEY, instance, store, repo, io)
                // The sheet calls setAllowed from lifecycleScope, on Main.
                assertTrue(withContext(main) { peers.setAllowed(PEER_A, true, repo.pairingGeneration(PEER_A)) })
            }
        }

        // The marker commit and finishGrantWrite's commit, both off the caller's thread.
        assertEquals(listOf("grant-io", "grant-io"), synchronized(commits) { commits.toList() })
        assertTrue(hasAccess(PEER_A))
    }

    @Test
    fun aWithdrawalAfterAHeldGrantLeavesThePeerWithoutAccess() = runTest {
        rows(KEY to PEER_B)
        val gate = holdGrants()
        val peers = KeySharingPeers(KEY, instance, store, repo, UnconfinedTestDispatcher(testScheduler))

        // The user checks A; the grant is held before its insert.
        val grant = async(UnconfinedTestDispatcher(testScheduler)) { peers.setAllowed(PEER_A, true, repo.pairingGeneration(PEER_A)) }
        assertFalse(grant.isCompleted)

        // The user unchecks A; the withdrawal gets as far as it can.
        val withdrawal = async(UnconfinedTestDispatcher(testScheduler)) { peers.setAllowed(PEER_A, false, repo.pairingGeneration(PEER_A)) }

        // The grant lands, then the withdrawal: the last action wins.
        gate.complete(Unit)
        assertTrue(grant.await())
        assertTrue(withdrawal.await())
        assertFalse("an earlier grant overwrote a later withdrawal", hasAccess(PEER_A))
        assertFalse(table.any { it.second == PEER_A })
    }

    @Test
    fun aKeyWideClearAfterAHeldGrantLeavesThePeerWithoutAccess() = runTest {
        for (leaving in listOf(SharingPolicyType.PRIVATE, SharingPolicyType.ALL_PEERS)) {
            rows(KEY to PEER_B)
            val gate = holdGrants()
            val peers = KeySharingPeers(KEY, instance, store, repo, UnconfinedTestDispatcher(testScheduler))

            // The user checks A; the grant is held before its insert.
            val grant = async(UnconfinedTestDispatcher(testScheduler)) { peers.setAllowed(PEER_A, true, repo.pairingGeneration(PEER_A)) }
            assertFalse(grant.isCompleted)

            // The user leaves SELECTED_PEERS; the key-wide clear gets as far as it can.
            val leave = async(UnconfinedTestDispatcher(testScheduler)) { peers.setKeyPolicy(leaving, instance) }

            // The grant lands, then the clear; the user returns to SELECTED_PEERS.
            gate.complete(Unit)
            assertTrue(grant.await())
            assertTrue(leave.await())
            assertEquals(StoredPolicy.valueOf(leaving.name), tables.keyPolicy(KEY))
            assertTrue(peers.setKeyPolicy(SharingPolicyType.SELECTED_PEERS, instance))

            assertEquals(StoredPolicy.SELECTED_PEERS, tables.keyPolicy(KEY))
            assertFalse("$leaving: an earlier grant survived the key-wide clear", hasAccess(PEER_A))
            assertFalse(peers.peers().first().of(PEER_A).allowed)
            assertTrue("$leaving: selecting peers again starts from nothing", table.none { it.first == KEY })
        }
    }

    @Test
    fun aQueuedGrantForAPeerRePairedMeanwhileIsRefused() = runTest {
        rows()
        val gate = holdGrants(peer = PEER_B)
        val peers = KeySharingPeers(KEY, instance, store, repo, UnconfinedTestDispatcher(testScheduler))

        // The user checks B; its grant is held before its insert.
        val first = async(UnconfinedTestDispatcher(testScheduler)) { peers.setAllowed(PEER_B, true, repo.pairingGeneration(PEER_B)) }
        assertFalse(first.isCompleted)

        // The user checks A, approving A's current pairing; the grant queues behind B's.
        val queued = async(UnconfinedTestDispatcher(testScheduler)) { peers.setAllowed(PEER_A, true, repo.pairingGeneration(PEER_A)) }
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
        assertFalse(table.any { it.second == PEER_A })
    }

    @Test
    fun aWithdrawalQueuedBehindAGrantSurvivesTheSheetsDismissal() = runTest {
        rows(KEY to PEER_A)
        val gate = holdGrants()
        val peers = KeySharingPeers(KEY, instance, store, repo, UnconfinedTestDispatcher(testScheduler), editScope = this)

        // Another grant holds the edits lock.
        val grant = async(UnconfinedTestDispatcher(testScheduler)) { peers.setAllowed(PEER_B, true, repo.pairingGeneration(PEER_B)) }
        assertFalse(grant.isCompleted)

        // The sheet withdraws A, already authorized, and is dismissed while that waits.
        val sheet = CoroutineScope(Job() + UnconfinedTestDispatcher(testScheduler))
        sheet.launch { peers.setAllowed(PEER_A, false, repo.pairingGeneration(PEER_A)) }
        sheet.cancel()

        gate.complete(Unit)
        assertTrue(grant.await())
        advanceUntilIdle()

        assertFalse("a withdrawal accepted before dismissal was dropped", hasAccess(PEER_A))
        assertFalse(peers.peers().first().of(PEER_A).allowed)
    }

    @Test
    fun aPrivatePolicyQueuedBehindAGrantSurvivesTheSheetsDismissal() = runTest {
        rows(KEY to PEER_A)
        val gate = holdGrants()
        val peers = KeySharingPeers(KEY, instance, store, repo, UnconfinedTestDispatcher(testScheduler), editScope = this)

        val grant = async(UnconfinedTestDispatcher(testScheduler)) { peers.setAllowed(PEER_B, true, repo.pairingGeneration(PEER_B)) }
        assertFalse(grant.isCompleted)

        // The sheet selects Private and is dismissed while that waits.
        val sheet = CoroutineScope(Job() + UnconfinedTestDispatcher(testScheduler))
        sheet.launch { peers.setKeyPolicy(SharingPolicyType.PRIVATE, instance) }
        sheet.cancel()

        gate.complete(Unit)
        assertTrue(grant.await())
        advanceUntilIdle()

        assertEquals("the Private policy accepted before dismissal was dropped", StoredPolicy.PRIVATE, tables.keyPolicy(KEY))
        assertFalse(hasAccess(PEER_A))
        assertTrue(table.none { it.first == KEY })
    }

    @Test
    fun aDetachedWithdrawalThatFailsDeniesThePeerAndIsRetried() = runTest {
        rows(KEY to PEER_A)
        val gate = holdGrants()
        var removals = 0
        tables.onDeleteGrant = { _, _ -> removals++ }
        tables.failing += "deleteGrant"
        val peers = KeySharingPeers(KEY, instance, store, repo, UnconfinedTestDispatcher(testScheduler), editScope = this)

        val grant = async(UnconfinedTestDispatcher(testScheduler)) { peers.setAllowed(PEER_B, true, repo.pairingGeneration(PEER_B)) }
        val sheet = CoroutineScope(Job() + UnconfinedTestDispatcher(testScheduler))
        sheet.launch { peers.setAllowed(PEER_A, false, repo.pairingGeneration(PEER_A)) }
        sheet.cancel()

        // The queued withdrawal runs with nobody awaiting it, and fails.
        gate.complete(Unit)
        assertTrue(grant.await())
        runCurrent()

        assertTrue("the failed withdrawal's row is still stored", table.any { it.second == PEER_A })
        assertFalse("a failed withdrawal left the peer authorized", hasAccess(PEER_A))
        assertFalse(peers.peers().first().of(PEER_A).allowed)

        // The store recovers: a retry lands the withdrawal.
        tables.failing.clear()
        advanceUntilIdle()

        assertTrue("the withdrawal was not retried", table.none { it.second == PEER_A })
        assertFalse(hasAccess(PEER_A))
        assertFalse("the clear the failed withdrawal owes was not enforced", hasAccess(PEER_B))
        assertTrue("the withdrawal was not retried", removals >= 2)
    }

    /**
     * A Private change whose write fails is refused, not retried (#193): its
     * denial and its owed grant clear stay in the key's policy row, so every
     * peer is denied, after a restart too, until a later change lands; that
     * change clears the old grants first.
     */
    @Test
    fun aDetachedPrivatePolicyThatFailsDeniesEveryPeerUntilALaterChangeLands() = runTest {
        rows(KEY to PEER_A)
        val gate = holdGrants()
        tables.failing += "setKeyPolicy"
        val peers = KeySharingPeers(KEY, instance, store, repo, UnconfinedTestDispatcher(testScheduler), editScope = this)

        val grant = async(UnconfinedTestDispatcher(testScheduler)) { peers.setAllowed(PEER_B, true, repo.pairingGeneration(PEER_B)) }
        val sheet = CoroutineScope(Job() + UnconfinedTestDispatcher(testScheduler))
        sheet.launch { peers.setKeyPolicy(SharingPolicyType.PRIVATE, instance) }
        sheet.cancel()

        gate.complete(Unit)
        assertTrue(grant.await())
        runCurrent()

        assertEquals(StoredPolicy.SELECTED_PEERS, tables.keyPolicy(KEY))
        assertFalse("a failed Private policy left a peer authorized", hasAccess(PEER_A))
        assertFalse(hasAccess(PEER_B))
        assertTrue(peers.peers().first().none { it.allowed })

        // The store recovers: nothing is retried, and the denial holds.
        tables.failing.clear()
        advanceUntilIdle()
        assertEquals("a failed Private policy was retried", StoredPolicy.SELECTED_PEERS, tables.keyPolicy(KEY))
        assertFalse(hasAccess(PEER_A))
        assertEquals(setOf(PEER_A, PEER_B), tables.grantsOf(KEY))

        // The user's next choice lands, the owed clear first.
        assertTrue(peers.setKeyPolicy(SharingPolicyType.SELECTED_PEERS, instance))
        assertTrue(table.none { it.first == KEY })
        assertFalse(hasAccess(PEER_A))
        assertFalse(hasAccess(PEER_B))
    }

    @Test
    fun aGrantAfterAFailedWithdrawalIsNotUndoneByItsRetry() = runTest {
        rows(KEY to PEER_A)
        tables.failing += "deleteGrant"
        val peers = KeySharingPeers(KEY, instance, store, repo, UnconfinedTestDispatcher(testScheduler), editScope = this)

        assertTrue(peers.setAllowed(PEER_A, false, repo.pairingGeneration(PEER_A)))
        runCurrent()
        assertFalse(hasAccess(PEER_A))

        // The failed withdrawal owes the key's grant clear: a grant waits for it.
        assertFalse("a grant landed under an owed clear", peers.setAllowed(PEER_A, true, repo.pairingGeneration(PEER_A)))

        // The user's policy write lands the clear; then A is granted again before
        // any retry: that later choice stands.
        assertTrue(peers.setKeyPolicy(SharingPolicyType.SELECTED_PEERS, instance))
        assertTrue(peers.setAllowed(PEER_A, true, repo.pairingGeneration(PEER_A)))
        tables.failing.clear()
        advanceUntilIdle()

        assertTrue("a retry undid the later grant", hasAccess(PEER_A))
        assertTrue(peers.peers().first().of(PEER_A).allowed)
    }

    /**
     * Finding (2): a withdrawal whose grant delete fails is acknowledged only
     * once the grant clear it owes is in the key's policy row: after a
     * restart, with no in-memory retry left, the peer is still denied, and
     * the next policy write deletes the grant.
     */
    @Test
    fun aFailedWithdrawalIsRecordedDurablyBeforeItIsAcknowledged() = runTest {
        rows(KEY to PEER_A)
        tables.failing += "deleteGrant"
        val peers = peersOf()

        assertTrue(peers.setAllowed(PEER_A, false, repo.pairingGeneration(PEER_A)))
        runCurrent()

        val row = tables.rows.value[KEY]!!
        assertTrue("a failed withdrawal was acknowledged with no durable record", row.clearGrants)
        assertEquals("a restart would authorize the withdrawn peer", StoredPolicy.PRIVATE, tables.enforced(KEY))

        tables.failing.clear()
        advanceUntilIdle()
        assertTrue(peers.setKeyPolicy(SharingPolicyType.SELECTED_PEERS, instance))
        assertTrue(table.none { it.first == KEY })
    }

    /**
     * A withdrawal whose grant delete fails and whose denial cannot be
     * written either is not reported done: the denial is only held in the
     * process, which a restart loses, so the caller is told the withdrawal
     * did not stand (#193 r6, ruling 554).
     */
    @Test
    fun aWithdrawalWhoseDenialIsNotDurableIsNotReportedDone() = runTest {
        rows(KEY to PEER_A)
        tables.failing += setOf("deleteGrant", "putPolicyRow")
        val peers = peersOf()

        assertFalse(
            "a withdrawal was reported done with no durable denial",
            peers.setAllowed(PEER_A, false, repo.pairingGeneration(PEER_A))
        )
        runCurrent()
        assertEquals("the held denial was dropped", StoredPolicy.PRIVATE, store.enforcedPolicy(tables.key(KEY)!!))

        tables.failing.clear()
        advanceUntilIdle()
        assertTrue(peers.setKeyPolicy(SharingPolicyType.SELECTED_PEERS, instance))
        assertTrue(table.none { it.first == KEY })
    }

    /**
     * The Private write fails while the stored policy stays Selected Peers,
     * so the reopened sheet shows Selected Peers. A grant then is refused
     * while the failed change's clear is owed, so no approved grant is ever
     * deleted by it; the user's next choice clears the old rows, and a grant
     * after it stands.
     */
    @Test
    fun aGrantUnderAFailedPrivateIsRefusedUntilALaterChangeLands() = runTest {
        val key = "k-failed-private"
        val keyInstance = tables.addKey(key, StoredPolicy.SELECTED_PEERS)
        rows(key to PEER_A)
        tables.failing += "setKeyPolicy"
        val peers = KeySharingPeers(key, keyInstance, store, repo, UnconfinedTestDispatcher(testScheduler), editScope = this)

        assertFalse("a failed Private was reported stored", peers.setKeyPolicy(SharingPolicyType.PRIVATE, keyInstance))
        tables.failing.clear()
        runCurrent()

        assertFalse("a grant was accepted under a failed Private", peers.setAllowed(PEER_B, true, repo.pairingGeneration(PEER_B)))
        assertTrue(table.none { it.first == key && it.second == PEER_B })
        assertTrue(peers.peers().first().none { it.selectable || it.allowed })

        advanceUntilIdle()
        assertEquals("a failed Private was retried", StoredPolicy.SELECTED_PEERS, tables.keyPolicy(key))

        // Once the user chooses Selected Peers again, a grant stands and survives.
        assertTrue(peers.setKeyPolicy(SharingPolicyType.SELECTED_PEERS, keyInstance))
        assertTrue(table.none { it.first == key })
        assertTrue(peers.setAllowed(PEER_B, true, repo.pairingGeneration(PEER_B)))
        advanceUntilIdle()
        assertTrue(table.any { it.first == key && it.second == PEER_B })
        assertTrue(peers.peers().first().of(PEER_B).allowed)
    }

    /**
     * A key-wide policy written outside the sheet (local.setKeyPolicy) goes
     * through the companion [KeySharingPeers.setKeyPolicy]; the sheet's
     * older failed change was refused, not queued, so it never lands over it.
     */
    @Test
    fun aFailedSheetPolicyNeverLandsOverALaterWriteOutsideTheSheet() = runTest {
        val key = "k-rpc-supersedes"
        val keyInstance = tables.addKey(key, StoredPolicy.SELECTED_PEERS)
        rows(key to PEER_A)
        tables.failing += "setKeyPolicy"
        val peers = KeySharingPeers(key, keyInstance, store, repo, UnconfinedTestDispatcher(testScheduler), editScope = this)

        assertFalse(peers.setKeyPolicy(SharingPolicyType.ALL_PEERS, keyInstance))
        tables.failing.clear()
        assertTrue(KeySharingPeers.setKeyPolicy(key, store, SharingPolicyType.PRIVATE, keyInstance, editScope = this))
        assertEquals(StoredPolicy.PRIVATE, tables.keyPolicy(key))

        advanceUntilIdle()
        assertEquals("the older All Peers landed over the later Private", StoredPolicy.PRIVATE, tables.keyPolicy(key))
        assertTrue(table.none { it.first == key })
    }

    /** A grant queued while its key is deleted and generated again under its id is refused on the new key (#193). */
    @Test
    fun aQueuedGrantNeverLandsOnAKeyGeneratedAgainUnderItsId() = runTest {
        val heldKey = "k-held"
        val held = KeySharingPeers(heldKey, tables.addKey(heldKey, StoredPolicy.SELECTED_PEERS), store, repo, UnconfinedTestDispatcher(testScheduler), editScope = this)
        val gate = holdGrants(peer = PEER_B)
        val first = async(UnconfinedTestDispatcher(testScheduler)) { held.setAllowed(PEER_B, true, repo.pairingGeneration(PEER_B)) }
        val peers = peersOf()
        val queued = async(UnconfinedTestDispatcher(testScheduler)) { peers.setAllowed(PEER_A, true, repo.pairingGeneration(PEER_A)) }
        assertFalse(queued.isCompleted)

        // The key is deleted and generated again while the grant waits.
        tables.deleteKey(KEY)
        val recreated = tables.addKey(KEY, StoredPolicy.SELECTED_PEERS)
        assertTrue(recreated != instance)
        gate.complete(Unit)

        assertTrue(first.await())
        assertFalse("a grant made for the deleted key was reported stored", queued.await())
        assertFalse("a grant made for the deleted key authorizes on its replacement", tables.isGranted(KEY, PEER_A))
    }

    /** An edit bound to a key row deleted and generated again under its id is refused and writes nothing (#193). */
    @Test
    fun aPolicyChangeForAReplacedKeyIsRefused() = runTest {
        val peers = peersOf()
        assertTrue(KeySharingPeers.forgetKey(KEY, instance, store))
        val recreated = tables.addKey(KEY, StoredPolicy.SELECTED_PEERS)
        rows(KEY to PEER_A)

        assertFalse(peers.setKeyPolicy(SharingPolicyType.PRIVATE, instance))
        assertEquals(StoredPolicy.SELECTED_PEERS, tables.keyPolicy(KEY))
        assertEquals(setOf(PEER_A), tables.grantsOf(KEY))
        assertTrue(peers.setKeyPolicy(SharingPolicyType.PRIVATE, recreated))
        assertTrue(table.none { it.first == KEY })
    }

    // #193: edits of a key's peer rows land in the order the user made them.

    @Test
    fun aWithdrawalAfterAGrantStillWaitingEndsWithdrawn() = runTest {
        rows(KEY to PEER_B)
        val gate = holdGrants()
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
        assertEquals(listOf(PEER_B), table.map { it.second })
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
        rows(KEY to PEER_B)
        val gate = holdGrants()
        val peers = peersOf()
        val seen = mutableListOf<List<KeySharingPeers.Peer>>()
        backgroundScope.launch(UnconfinedTestDispatcher(testScheduler)) { peers.peers().toList(seen) }

        val grant = async(UnconfinedTestDispatcher(testScheduler)) {
            peers.setAllowed(PEER_A, true, repo.pairingGeneration(PEER_A))
        }
        val leave = async(UnconfinedTestDispatcher(testScheduler)) {
            peers.setKeyPolicy(destination, instance)
        }
        assertFalse(grant.isCompleted)
        assertFalse("the clear waits for the grant made before it", leave.isCompleted)

        gate.complete(Unit)
        grant.await()
        assertTrue(leave.await())
        assertEquals(StoredPolicy.valueOf(destination.name), tables.keyPolicy(KEY))
        assertTrue("a grant in flight outlived the key-wide clear", table.none { it.first == KEY })

        assertTrue(peers.setKeyPolicy(SharingPolicyType.SELECTED_PEERS, instance))
        assertEquals(StoredPolicy.SELECTED_PEERS, tables.keyPolicy(KEY))
        assertFalse(hasAccess(PEER_A))
        assertFalse(hasAccess(PEER_B))
        assertTrue("selected peers starts from nothing", seen.last().none { it.allowed })
    }

    @Test
    fun aGrantTappedBeforeAnUnpairAndRepairIsRefused() = runTest {
        rows()
        val gate = holdGrants(peer = PEER_B)
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
        assertTrue(table.none { it.second == PEER_A })
        assertFalse(hasAccess(PEER_A))
    }

    @Test
    fun aRefusedGrantDoesNotRedrawASheetDismissedWhileItWaited() = runTest {
        rows()
        val gate = holdGrants(peer = PEER_B)
        repo = spyk(repo)
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
        advanceUntilIdle()
        assertEquals("a detached sheet was redrawn", 0, redraws)
        // The cancelled tap's grant still took its turn, and was refused there.
        coVerify(exactly = 1) { repo.writeGrant(PEER_A, tapped!!, any()) }
        assertTrue(table.none { it.second == PEER_A })
        assertFalse(hasAccess(PEER_A))
        // The refused grant left the queue: the next edit of the key runs at once.
        assertTrue(peers.setAllowed(PEER_B, false, null))
    }

    @Test
    fun aKeyWideClearQueuedBehindAGrantSurvivesTheSheetsDismissal() = runTest {
        val gate = holdGrants()
        val peers = peersOf()

        // B's grant is being written when the user leaves selected peers: the clear waits its turn.
        val grant = async(UnconfinedTestDispatcher(testScheduler)) {
            peers.setAllowed(PEER_B, true, repo.pairingGeneration(PEER_B))
        }
        val leave = launch(UnconfinedTestDispatcher(testScheduler)) {
            peers.setKeyPolicy(SharingPolicyType.PRIVATE, instance)
        }
        assertFalse(leave.isCompleted)

        // The sheet is dismissed before the queue drains.
        leave.cancel()
        gate.complete(Unit)
        assertTrue(grant.await())
        leave.join()
        advanceUntilIdle()
        assertEquals(StoredPolicy.PRIVATE, tables.keyPolicy(KEY))
        assertTrue("a dismissed sheet discarded a queued key-wide clear", table.none { it.first == KEY })
    }

    @Test
    fun theGrantWriteDoesNotRunOnTheCallingDispatcher() = runTest {
        rows()
        val caller = Thread.currentThread()
        val writer = AtomicReference<Thread>()
        tables.onPutGrant = { writer.set(Thread.currentThread()) }
        // The production dispatcher.
        val peers = KeySharingPeers(KEY, instance, store, repo)

        assertTrue(peers.setAllowed(PEER_A, true, repo.pairingGeneration(PEER_A)))

        assertNotNull(writer.get())
        assertNotSame("the grant was written on the calling thread", caller, writer.get())
        assertTrue(hasAccess(PEER_A))
    }
}
