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

import android.app.KeyguardManager
import android.app.NotificationManager
import android.content.Context
import android.content.SharedPreferences
import android.os.Looper
import android.util.Log
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.KeySharingPolicyDao
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.storage.entity.KeySharingPolicy
import com.automatethethings.xkey.storage.entity.SharingPolicyType
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
import kotlin.concurrent.thread
import kotlin.coroutines.Continuation
import kotlin.coroutines.EmptyCoroutineContext
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestCoroutineScheduler
import org.junit.After
import org.junit.Assert.assertEquals
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertNotEquals
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
        // The delete fails; the process dies before the backoff ends.
        scheduler.runCurrent()
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
        // The delete fails; the re-pairing comes before the backoff ends.
        scheduler.runCurrent()
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

    // --- r3: one lock for every repository, and generation-checked cleanup. ---

    /**
     * A second view of the same prefs, as another repository instance in the
     * process holds. [afterNextStringSetRead] runs once, right after a read of
     * the pending set, while the reader may still mean to write it back.
     */
    private class HookedPrefs(private val backing: SharedPreferences) : SharedPreferences by backing {
        @Volatile var afterNextStringSetRead: (() -> Unit)? = null

        override fun getStringSet(key: String, defValues: Set<String>?): Set<String>? {
            val value = backing.getStringSet(key, defValues)
            afterNextStringSetRead?.let {
                afterNextStringSetRead = null
                it()
            }
            return value
        }
    }

    /**
     * The cleanup completes A through its own repository while the UI's
     * repository removes B in between the cleanup's read and its write of the
     * pending set. B must stay pending.
     */
    @Test
    fun completingOneRevocationKeepsAnotherInstancesNewPendingEntry() {
        val hooked = HookedPrefs(prefs)
        val cleanupRepo = PairedDeviceRepository(hooked)
        heldCleanup(cleanupRepo)
        repo.removeDevice(PEER_A)
        // B's removal only has to land in the pending set; no job for it.
        PairedDeviceRepository.removeRemovalListener(cleanup)

        var other: Thread? = null
        hooked.afterNextStringSetRead = {
            val t = thread { repo.removeDevice(PEER_B) }
            other = t
            // Either it runs to the end (no shared lock) or it waits on the lock.
            while (t.state != Thread.State.BLOCKED && t.state != Thread.State.TERMINATED) {
                Thread.yield()
            }
        }
        scheduler.advanceUntilIdle()
        other!!.join()

        assertEquals(emptyList<KeySharingPolicy>(), grantsOf(PEER_A))
        assertEquals(setOf(PEER_B), repo.pendingRevocations())
        assertEquals(setOf(PEER_B), cleanupRepo.pendingRevocations())
    }

    /**
     * Remove, re-pair while the cleanup is still queued, and approve a fresh
     * grant once the revocation has completed: no later cleanup job (the one
     * the re-pairing queued, a replay, a stray retry) may delete it.
     */
    @Test
    fun aGrantApprovedAfterTheRevocationCompletedSurvivesLaterCleanupJobs() {
        val fresh = KeySharingPolicy("k-9", PEER_A)
        var deletes = 0
        val delete = dao.clearPoliciesForPeerAnswer()
        coEvery { dao.clearPoliciesForPeer(any()) } answers {
            // A second delete for A runs after the first one completed the
            // revocation: by then the user has approved a fresh grant.
            if (deletes++ == 1 && fresh !in table) {
                assertFalse(PEER_A in repo.pendingRevocations())
                table += fresh
            }
            delete(firstArg())
        }
        heldCleanup(repo)
        repo.removeDevice(PEER_A)
        repo.addDevice(PEER_A, "desktop-a")
        scheduler.advanceUntilIdle()
        assertFalse(PEER_A in repo.pendingRevocations())
        if (fresh !in table) table += fresh

        // Delayed duplicates of the finished revocation.
        cleanup.replayPending()
        cleanup.onRevocationPending(PEER_A)
        cleanup.onDeviceRemoved(PEER_A)
        scheduler.advanceUntilIdle()

        assertEquals(listOf(fresh), grantsOf(PEER_A))
        assertEquals(1, grantsOf(PEER_B).size)
    }

    /**
     * The peer is re-paired while its revocation is held, so its old rows are
     * still in the table: a SELECTED_PEERS share request for it is refused.
     * Fails if canShareKeyWithPeer stops checking the pending set.
     */
    @Test
    fun aRePairedPeerIsRefusedSelectedPeersWhileItsRevocationIsPending() {
        heldCleanup(repo)
        repo.removeDevice(PEER_A)
        repo.addDevice(PEER_A, "desktop-a")
        assertEquals(2, grantsOf(PEER_A).size)
        assertTrue(PEER_A in repo.pendingRevocations())

        val handler = requestHandlerOver(repo)
        val key = KeyEntity(
            keyId = "k-1",
            keyType = "signing",
            algorithm = "ES256",
            label = "L",
            keySizeBits = 256,
            source = "local",
            sharingPolicy = SharingPolicyType.SELECTED_PEERS
        )

        assertFalse(canShareKeyWithPeer(handler, key, PEER_A))
        // Control: B's grant still authorizes B.
        assertTrue(canShareKeyWithPeer(handler, key, PEER_B))

        scheduler.advanceUntilIdle()
        assertFalse(canShareKeyWithPeer(handler, key, PEER_A))
    }

    private fun requestHandlerOver(paired: PairedDeviceRepository): RequestHandler {
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.d(any(), any<String>()) } returns 0
        every { Log.v(any(), any<String>()) } returns 0
        every { Log.e(any(), any<String>()) } returns 0
        mockkStatic(Looper::class)
        every { Looper.getMainLooper() } returns mockk(relaxed = true)
        coEvery { dao.isKeySharedWithPeer(any(), any()) } answers {
            val keyId = firstArg<String>()
            val peer = secondArg<String>()
            table.any { it.keyId == keyId && it.peerPublicKeyHex == peer }
        }
        val database = mockk<XKeyDatabase>(relaxed = true)
        every { database.keySharingPolicyDao() } returns dao
        mockkObject(XKeyDatabase.Companion)
        every { XKeyDatabase.getInstance(any()) } returns database
        val context = mockk<Context>(relaxed = true)
        every { context.getSystemService(Context.KEYGUARD_SERVICE) } returns
            mockk<KeyguardManager>(relaxed = true)
        every { context.getSystemService(NotificationManager::class.java) } returns
            mockk<NotificationManager>(relaxed = true)
        return RequestHandler(
            context = context,
            keystoreManager = mockk(relaxed = true),
            biometricLauncher = null,
            sessionAuthManager = null,
            pairedDeviceRepository = paired
        )
    }

    // --- r4: a durable acknowledgment, and a retry for a request made in flight. ---

    /**
     * Prefs with a disk under them: [apply] changes memory only, [commit]
     * also writes the whole of memory to disk, as Android's does.
     * [afterCrash] is a fresh process's view: what reached disk, nothing else.
     */
    private class DiskPrefs(
        private val memory: InMemorySharedPreferences = InMemorySharedPreferences()
    ) : SharedPreferences by memory {
        private var disk: Map<String, *> = emptyMap<String, Any>()

        /** The next this many commit() calls fail, changing nothing. */
        @Volatile var failCommits = 0

        fun flush() {
            disk = memory.all
        }

        fun afterCrash(): DiskPrefs {
            val restored = InMemorySharedPreferences()
            val editor = restored.edit()
            @Suppress("UNCHECKED_CAST")
            for ((key, value) in disk) {
                when (value) {
                    is String -> editor.putString(key, value)
                    is Long -> editor.putLong(key, value)
                    is Set<*> -> editor.putStringSet(key, value as Set<String>)
                    else -> error("unexpected $key")
                }
            }
            editor.commit()
            return DiskPrefs(restored).also { it.flush() }
        }

        override fun edit(): SharedPreferences.Editor {
            val inner = memory.edit()
            return object : SharedPreferences.Editor by inner {
                override fun putString(key: String, value: String?) = also { inner.putString(key, value) }
                override fun putStringSet(key: String, values: Set<String>?) = also { inner.putStringSet(key, values) }
                override fun putInt(key: String, value: Int) = also { inner.putInt(key, value) }
                override fun putLong(key: String, value: Long) = also { inner.putLong(key, value) }
                override fun putFloat(key: String, value: Float) = also { inner.putFloat(key, value) }
                override fun putBoolean(key: String, value: Boolean) = also { inner.putBoolean(key, value) }
                override fun remove(key: String) = also { inner.remove(key) }
                override fun clear() = also { inner.clear() }
                override fun apply() {
                    inner.commit()
                }
                override fun commit(): Boolean {
                    if (failCommits > 0) {
                        failCommits--
                        return false
                    }
                    return inner.commit().also { flush() }
                }
            }
        }
    }

    /**
     * A re-paired peer's revocation completes and the user approves a fresh
     * grant, which Room commits. The process then dies before prefs written
     * with apply() reach disk. The replay at the next start must not delete
     * the fresh grant: the acknowledgment has to be on disk before anyone can
     * see the revocation as done.
     */
    @Test
    fun aGrantApprovedAfterCompletionSurvivesACrashBeforeThePrefsFlush() {
        val disk = DiskPrefs()
        val before = PairedDeviceRepository(disk)
        heldCleanup(before)
        before.addDevice(PEER_A, "desktop-a")
        before.removeDevice(PEER_A)
        before.addDevice(PEER_A, "desktop-a")
        disk.flush()
        assertTrue(PEER_A in PairedDeviceRepository(disk.afterCrash()).pendingRevocations())

        scheduler.advanceUntilIdle()
        assertFalse(PEER_A in before.pendingRevocations())
        val fresh = KeySharingPolicy("k-9", PEER_A)
        table += fresh

        val after = PairedDeviceRepository(disk.afterCrash())
        heldCleanup(after).replayPending()
        scheduler.advanceUntilIdle()

        assertEquals(listOf(fresh), grantsOf(PEER_A))
        assertFalse(PEER_A in after.pendingRevocations())
    }

    /**
     * The peer re-pairs while its delete is suspended, and that delete then
     * fails. The re-pairing's request must not be lost with it: a later
     * attempt clears the pending entry, and a new SELECTED_PEERS grant works
     * without another re-pairing or a restart.
     */
    @Test
    fun aRePairingDuringAFailingDeleteStillGetsTheRevocationDone() {
        val held = CompletableDeferred<Unit>()
        var calls = 0
        val delete = dao.clearPoliciesForPeerAnswer()
        coEvery { dao.clearPoliciesForPeer(any()) } coAnswers {
            if (calls++ == 0) {
                held.await()
                throw IllegalStateException("db closed")
            }
            delete(firstArg())
        }
        heldCleanup(repo)
        repo.removeDevice(PEER_A)
        scheduler.runCurrent()
        assertEquals(1, calls)

        repo.addDevice(PEER_A, "desktop-a")
        held.complete(Unit)
        scheduler.advanceUntilIdle()

        assertEquals(emptyList<KeySharingPolicy>(), grantsOf(PEER_A))
        assertFalse(PEER_A in repo.pendingRevocations())

        table += KeySharingPolicy("k-9", PEER_A)
        val key = KeyEntity(
            keyId = "k-9",
            keyType = "signing",
            algorithm = "ES256",
            label = "L",
            keySizeBits = 256,
            source = "local",
            sharingPolicy = SharingPolicyType.SELECTED_PEERS
        )
        assertTrue(canShareKeyWithPeer(requestHandlerOver(repo), key, PEER_A))
    }

    // --- r5: the audit count across acknowledgment retries, and an atomic worker exit. ---

    /**
     * The delete drops A's two rows but the acknowledgment's commit fails
     * once. The retry deletes nothing, yet the security event for the two
     * dropped grants must still be recorded, exactly once.
     */
    @Test
    fun aFailedAcknowledgmentKeepsTheDroppedGrantsAuditEvent() {
        val disk = DiskPrefs()
        val paired = PairedDeviceRepository(disk)
        heldCleanup(paired)
        paired.addDevice(PEER_A, "desktop-a")
        disk.failCommits = 1

        paired.removeDevice(PEER_A)
        scheduler.advanceUntilIdle()

        assertEquals(emptyList<KeySharingPolicy>(), grantsOf(PEER_A))
        assertFalse(PEER_A in paired.pendingRevocations())
        coVerify(exactly = 2) { dao.clearPoliciesForPeer(PEER_A) }
        verify(exactly = 1) { AuditLogger.logPeerGrantsDropped(any(), any()) }
        verify(exactly = 1) { AuditLogger.logPeerGrantsDropped(PEER_A, 2) }
    }

    /**
     * Every attempt fails until the worker gives up. Its last attempt leaves
     * a child coroutine behind, so the worker has returned but its job has
     * not completed: the window between its decision to stop and its
     * removal from the job map in the old code. A re-pairing in that window
     * must still get the revocation done.
     */
    @Test
    fun aRePairingWhileAnExhaustedWorkerExitsIsNotLost() {
        // The worker gives up after its ninth failure in a row (MAX_FAILURES = 8).
        val attempts = 9
        val exiting = CompletableDeferred<Unit>()
        var calls = 0
        val delete = dao.clearPoliciesForPeerAnswer()
        coEvery { dao.clearPoliciesForPeer(any()) } coAnswers {
            calls++
            if (calls <= attempts) {
                if (calls == attempts) {
                    CoroutineScope(currentCoroutineContext()).launch { exiting.await() }
                }
                throw IllegalStateException("db closed")
            }
            delete(firstArg())
        }
        heldCleanup(repo)
        repo.removeDevice(PEER_A)
        scheduler.advanceUntilIdle()
        assertEquals(attempts, calls)
        assertTrue(PEER_A in repo.pendingRevocations())

        repo.addDevice(PEER_A, "desktop-a")
        exiting.complete(Unit)
        scheduler.advanceUntilIdle()

        assertEquals(emptyList<KeySharingPolicy>(), grantsOf(PEER_A))
        assertFalse(PEER_A in repo.pendingRevocations())
    }

    // --- r6: a request that wakes the worker from backoff resets its failure budget. ---

    /**
     * The worker fails eight times in a row, one short of giving up, and is
     * backing off. The peer re-pairs during that backoff, the next attempt
     * fails once more, and the one after succeeds: the revocation must still
     * complete, since the re-pairing renewed the worker's budget.
     */
    @Test
    fun aRequestDuringTheLastBackoffRenewsTheFailureBudget() {
        // MAX_FAILURES = 8: a ninth failure in a row would end the worker.
        val shortOfTheLimit = 8
        var calls = 0
        val delete = dao.clearPoliciesForPeerAnswer()
        coEvery { dao.clearPoliciesForPeer(any()) } answers {
            calls++
            if (calls <= shortOfTheLimit + 1) throw IllegalStateException("db closed")
            delete(firstArg())
        }
        heldCleanup(repo)
        repo.removeDevice(PEER_A)
        while (calls < shortOfTheLimit) {
            scheduler.advanceTimeBy(1_000)
            scheduler.runCurrent()
        }
        // The eighth attempt failed; the worker is now in its backoff.
        assertEquals(shortOfTheLimit, calls)

        repo.addDevice(PEER_A, "desktop-a")
        scheduler.advanceUntilIdle()

        assertEquals(shortOfTheLimit + 2, calls)
        assertEquals(emptyList<KeySharingPolicy>(), grantsOf(PEER_A))
        assertFalse(PEER_A in repo.pendingRevocations())
    }

    /** Calls the private suspend check; the faked DAO never suspends. */
    private fun canShareKeyWithPeer(handler: RequestHandler, key: KeyEntity, peer: String): Boolean {
        val method = RequestHandler::class.java.getDeclaredMethod(
            "canShareKeyWithPeer", KeyEntity::class.java, String::class.java, Continuation::class.java
        )
        method.isAccessible = true
        val noResume = Continuation<Any?>(EmptyCoroutineContext) { error("suspended") }
        return method.invoke(handler, key, peer, noResume) as Boolean
    }

    // --- r8: grant writes a previous process left unfinished. ---

    /** Persists a grant-write marker as an ended process left it: none of this process's writes holds it. */
    private fun seedGrantWrite(peer: String, generation: Long) {
        prefs.edit().putStringSet("grant_writes", setOf("$peer@$generation")).commit()
    }

    /**
     * The process died after a grant's insert committed and before its marker
     * was cleared, and the pairing that grant was checked against had ended.
     * The replay at the next start revokes the key, so the stale row goes.
     */
    @Test
    fun anInterruptedGrantWriteForAnEndedPairingIsRevokedAtRestart() {
        val ended = repo.pairingGeneration(PEER_A)!!
        repo.removeDevice(PEER_A)
        assertTrue(grantsOf(PEER_A).isEmpty())
        repo.addDevice(PEER_A, "desktop-a")
        assertNotEquals(ended, repo.pairingGeneration(PEER_A))
        // The insert of the interrupted write, and its marker.
        table += KeySharingPolicy("k-9", PEER_A)
        seedGrantWrite(PEER_A, ended)

        val restarted = restart()

        assertTrue("the stale grant is removed", grantsOf(PEER_A).isEmpty())
        assertFalse(PEER_A in restarted.pendingRevocations())
        assertTrue(prefs.getStringSet("grant_writes", null).isNullOrEmpty())
        assertEquals(listOf("k-1" to PEER_B), peersWithGrants())
    }

    /** The same, but the pairing is still the one the write was checked against: the grant stands. */
    @Test
    fun anInterruptedGrantWriteForTheCurrentPairingStandsAtRestart() {
        val current = repo.pairingGeneration(PEER_A)!!
        table += KeySharingPolicy("k-9", PEER_A)
        seedGrantWrite(PEER_A, current)

        val restarted = restart()

        assertEquals(listOf("k-1", "k-2", "k-9"), grantsOf(PEER_A).map { it.keyId }.sorted())
        assertFalse(PEER_A in restarted.pendingRevocations())
        assertTrue(prefs.getStringSet("grant_writes", null).isNullOrEmpty())
    }

    /** The marker never reached disk: the grant is not written, and nothing is left for a restart. */
    @Test
    fun aFailedGrantMarkerPersistenceLeavesNoGrant() = runTest {
        val disk = DiskPrefs()
        val paired = PairedDeviceRepository(disk)
        paired.addDevice(PEER_C, "desktop-c")
        disk.flush()
        disk.failCommits = 1
        var wrote = false

        assertFalse(paired.writeGrant(PEER_C) { wrote = true; table += KeySharingPolicy("k-9", PEER_C) })

        assertFalse(wrote)
        assertTrue(grantsOf(PEER_C).isEmpty())
        assertFalse(paired.isRevocationPending(PEER_C))
        val after = PairedDeviceRepository(disk.afterCrash())
        after.recoverInterruptedGrantWrites()
        assertFalse(after.isRevocationPending(PEER_C))
        assertTrue(after.pendingRevocations().isEmpty())
    }

    /** The compatibility overload binds the grant to the current pairing and answers as the three-argument one. */
    @Test
    fun theCompatibilityWriteGrantWritesForAPairedKey() = runTest {
        var wrote = false

        val result = repo.writeGrant(PEER_A) { wrote = true; table += KeySharingPolicy("k-9", PEER_A) }

        assertTrue(result)
        assertTrue(wrote)
        assertEquals(listOf("k-1", "k-2", "k-9"), grantsOf(PEER_A).map { it.keyId }.sorted())
        assertEquals(result, repo.writeGrant(PEER_A, repo.pairingOf(PEER_A)!!) {})
    }

    /** An unknown key has no pairing: the compatibility overload refuses without running the write. */
    @Test
    fun theCompatibilityWriteGrantRefusesAnUnknownKey() = runTest {
        var wrote = false

        assertFalse(repo.writeGrant(PEER_C) { wrote = true; table += KeySharingPolicy("k-9", PEER_C) })

        assertFalse(wrote)
        assertTrue(grantsOf(PEER_C).isEmpty())
        assertTrue(prefs.getStringSet("grant_writes", null).isNullOrEmpty())
    }
}
