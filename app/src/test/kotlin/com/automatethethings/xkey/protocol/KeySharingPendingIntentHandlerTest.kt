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

package com.automatethethings.xkey.protocol

import android.app.KeyguardManager
import android.app.NotificationManager
import android.content.Context
import android.os.Looper
import android.util.Log
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.settings.InMemorySharedPreferences
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.dao.KeySharingPolicyDao
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.storage.entity.KeySharingPolicy
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import com.automatethethings.xkey.ui.KeySharingPeers
import com.automatethethings.xkey.ui.SharingPolicyType as SheetPolicy
import io.mockk.coEvery
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.runs
import io.mockk.unmockkAll
import kotlin.coroutines.Continuation
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.coroutines.intrinsics.suspendCoroutineUninterceptedOrReturn
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.json.JSONObject
import org.junit.Test

/**
 * A sharing edit the sheet accepted fails closed in the production
 * [RequestHandler] while its detached write is failing (#174): the peers it
 * withdraws are refused by `canShareKeyWithPeer` itself, against surviving
 * grant rows and a stored All Peers policy, until a retry lands; then the
 * stored policy and rows decide again.
 *
 * Each test uses its own key: the pending intents live in the process.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class KeySharingPendingIntentHandlerTest {

    private companion object {
        const val OTHER_KEY = "k-other"
        val PEER_A = "a".repeat(64)
        val PEER_B = "b".repeat(64)
    }

    /** The `key_sharing_policies` table; the DAO's Flow query re-emits on every change. */
    private val table = MutableStateFlow<List<KeySharingPolicy>>(emptyList())

    /** The `keys` table: each key's stored entity, read by the DAO's SQL and the handler. */
    private val keys = mutableMapOf<String, KeyEntity>()
    private lateinit var dao: KeySharingPolicyDao
    private lateinit var repo: PairedDeviceRepository
    private lateinit var prefs: InMemorySharedPreferences
    private lateinit var keyDao: KeyDao
    private lateinit var context: Context
    private lateinit var handler: RequestHandler

    /** Throws from the matching DAO write while set. */
    private var removeFails = false
    private var clearFails = false

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.e(any(), any<String>(), any()) } returns 0
        every { Log.e(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.i(any(), any<String>()) } returns 0
        every { Log.d(any(), any<String>()) } returns 0
        every { Log.v(any(), any<String>()) } returns 0
        mockkObject(AuditLogger)
        every { AuditLogger.logDeviceUnpaired(any(), any()) } just runs

        dao = mockk()
        every { dao.getPoliciesForKey(any()) } answers {
            val keyId = firstArg<String>()
            table.map { rows -> rows.filter { it.keyId == keyId } }
        }
        coEvery { dao.setPolicy(any()) } answers { put(firstArg()) }
        coEvery { dao.removePolicy(any(), any()) } answers {
            if (removeFails) throw IllegalStateException("disk I/O error")
            val before = table.value
            table.value = before.filterNot { it.keyId == firstArg<String>() && it.peerPublicKeyHex == secondArg<String>() }
            before.size - table.value.size
        }
        coEvery { dao.clearPoliciesForKey(any()) } answers {
            if (clearFails) throw IllegalStateException("disk I/O error")
            val before = table.value
            table.value = before.filterNot { it.keyId == firstArg<String>() }
            before.size - table.value.size
        }
        // The real SQL: All Peers stored authorizes every peer, whatever the rows.
        coEvery { dao.isKeySharedWithPeer(any(), any()) } answers {
            when (keys[firstArg()]?.sharingPolicy) {
                SharingPolicyType.ALL_PEERS -> true
                SharingPolicyType.SELECTED_PEERS -> granted(firstArg(), secondArg())
                else -> false
            }
        }
        coEvery { dao.isPeerGranted(any(), any()) } answers { granted(firstArg(), secondArg()) }
        keyDao = mockk()
        coEvery { keyDao.getByKeyId(any()) } answers { keys[firstArg()] }
        coEvery { keyDao.updateSharingPolicy(any(), any()) } answers { store(firstArg(), secondArg()) }

        coEvery { keyDao.deleteByKeyId(any()) } answers { if (keys.remove(firstArg<String>()) != null) 1 else 0 }

        prefs = InMemorySharedPreferences()
        repo = PairedDeviceRepository(prefs)
        repo.addDevice(PEER_A, "desktop-a")
        repo.addDevice(PEER_B, "desktop-b")

        mockkStatic(Looper::class)
        every { Looper.getMainLooper() } returns mockk(relaxed = true)
        val database = mockk<XKeyDatabase>(relaxed = true)
        every { database.keySharingPolicyDao() } returns dao
        every { database.keyDao() } returns keyDao
        mockkObject(XKeyDatabase.Companion)
        every { XKeyDatabase.getInstance(any()) } returns database
        context = mockk(relaxed = true)
        every { context.getSystemService(Context.KEYGUARD_SERVICE) } returns
            mockk<KeyguardManager>(relaxed = true)
        every { context.getSystemService(NotificationManager::class.java) } returns
            mockk<NotificationManager>(relaxed = true)
        handler = newHandler()
    }

    /** A handler as the service builds it, over [repo]. */
    private fun newHandler() = RequestHandler(
        context = context,
        keystoreManager = mockk(relaxed = true),
        biometricLauncher = null,
        sessionAuthManager = null,
        pairedDeviceRepository = repo
    )

    @After
    fun tearDown() {
        unmockkAll()
    }

    private fun put(row: KeySharingPolicy) {
        table.value = table.value.filterNot {
            it.keyId == row.keyId && it.peerPublicKeyHex == row.peerPublicKeyHex
        } + row
    }

    private fun granted(keyId: String, peer: String): Boolean =
        table.value.any { it.keyId == keyId && it.peerPublicKeyHex == peer && it.allowed }

    /** Stores [keyId] with [stored] in the faked `keys` table, as row [id], and returns it. */
    private fun store(keyId: String, stored: SharingPolicyType, id: Long = keys[keyId]?.id ?: 0L): KeyEntity =
        KeyEntity(
            id = id,
            keyId = keyId,
            keyType = "signing",
            algorithm = "ES256",
            label = "L",
            keySizeBits = 256,
            source = "local",
            sharingPolicy = stored
        ).also { keys[keyId] = it }

    /** Invokes the handler's private suspend [name]; the faked DAOs never suspend. */
    private fun call(name: String, vararg args: Any, types: Array<Class<*>>): Any? {
        val method = RequestHandler::class.java.getDeclaredMethod(name, *types, Continuation::class.java)
        method.isAccessible = true
        val noResume = Continuation<Any?>(EmptyCoroutineContext) { error("suspended") }
        return method.invoke(handler, *args, noResume)
    }

    /**
     * The handler's own check, for [keyId] stored with [stored]: the gate
     * local.listFido2Credentials filters with and local.signFido2Assertion
     * refuses by.
     */
    private fun shares(keyId: String, stored: SharingPolicyType, peer: String): Boolean =
        call("canShareKeyWithPeer", store(keyId, stored), peer, types = arrayOf(KeyEntity::class.java, String::class.java)) as Boolean

    /** Runs local.setKeyPolicy through the handler, as a desktop's RPC does. */
    private suspend fun rpcSetShareable(keyId: String, shareable: Boolean) {
        assertEquals(null, rpcSetShareableResponse(keyId, shareable).error)
    }

    /** [rpcSetShareable]'s response, whatever it is. */
    private suspend fun rpcSetShareableResponse(keyId: String, shareable: Boolean): Response {
        val method = RequestHandler::class.java.getDeclaredMethod(
            "handleLocalSetKeyPolicy", Request::class.java, Continuation::class.java
        )
        method.isAccessible = true
        val request = Request(
            id = 1,
            method = MethodNames.LOCAL_SET_KEY_POLICY,
            params = JSONObject().put("keyId", keyId).put("shareable", shareable)
        )
        return suspendCoroutineUninterceptedOrReturn<Any?> { method.invoke(handler, request, it) } as Response
    }

    /** Runs local.deleteKey through the handler. */
    private suspend fun rpcDeleteKey(keyId: String) {
        val method = RequestHandler::class.java.getDeclaredMethod(
            "handleLocalDeleteKey", Request::class.java, Continuation::class.java
        )
        method.isAccessible = true
        val request = Request(id = 2, method = MethodNames.LOCAL_DELETE_KEY, params = JSONObject().put("keyId", keyId))
        val response = suspendCoroutineUninterceptedOrReturn<Any?> { method.invoke(handler, request, it) } as Response
        assertEquals(null, response.error)
    }

    /** The authorization key export runs: the stored key when [peer] may have it, else null. */
    private fun exports(keyId: String, peer: String): Boolean =
        call("authorizeShare", keyId, peer, types = arrayOf(String::class.java, String::class.java)) != null

    /**
     * Runs [edit] from a sheet dismissed while the edit waits behind another
     * key's held grant, so nobody awaits it when it runs and fails.
     */
    private fun TestScope.detached(edit: suspend () -> Unit) {
        val gate = CompletableDeferred<Unit>()
        coEvery { dao.setPolicy(any()) } coAnswers {
            gate.await()
            put(firstArg())
        }
        val other = KeySharingPeers(OTHER_KEY, dao, repo, UnconfinedTestDispatcher(testScheduler), editScope = this)
        val grant = async(UnconfinedTestDispatcher(testScheduler)) { other.setAllowed(PEER_B, true, repo.pairingGeneration(PEER_B)) }
        val sheet = CoroutineScope(Job() + UnconfinedTestDispatcher(testScheduler))
        sheet.launch { edit() }
        sheet.cancel()
        gate.complete(Unit)
        coEvery { dao.setPolicy(any()) } answers { put(firstArg()) }
        runCurrent()
        assertTrue(grant.isCompleted)
    }

    @Test
    fun aFailedDetachedNarrowingToSelectedPeersDeniesUngrantedPeersUntilItLands() = runTest {
        val key = "k-narrow"
        var stored = SharingPolicyType.ALL_PEERS
        var failing = true
        val peers = KeySharingPeers(key, dao, repo, UnconfinedTestDispatcher(testScheduler), editScope = this)
        assertTrue(shares(key, stored, PEER_A))

        detached {
            peers.setKeyPolicy(SheetPolicy.SELECTED_PEERS) {
                if (failing) throw IllegalStateException("disk I/O error")
                stored = SharingPolicyType.SELECTED_PEERS
            }
        }

        assertEquals(SharingPolicyType.ALL_PEERS, stored)
        assertFalse("a failed Selected Peers left All Peers authorizing an ungranted peer", shares(key, stored, PEER_A))
        assertFalse(shares(key, stored, PEER_B))

        // A grant the user makes meanwhile stands, and authorizes only its peer.
        assertTrue(peers.setAllowed(PEER_B, true, repo.pairingGeneration(PEER_B)))
        assertTrue(shares(key, stored, PEER_B))
        assertFalse(shares(key, stored, PEER_A))

        failing = false
        advanceUntilIdle()

        assertEquals("the Selected Peers policy was not retried", SharingPolicyType.SELECTED_PEERS, stored)
        assertFalse(shares(key, stored, PEER_A))
        assertTrue("the retry dropped the later grant", shares(key, stored, PEER_B))
    }

    @Test
    fun aPendingSelectedPeersOverStoredAllPeersAuthorizesOnlyGrantedPeers() = runTest {
        val key = "k-pending-selected"
        table.value = listOf(KeySharingPolicy(key, PEER_B))
        store(key, SharingPolicyType.ALL_PEERS)
        var failing = true
        val peers = KeySharingPeers(key, dao, repo, UnconfinedTestDispatcher(testScheduler), editScope = this)
        assertTrue(exports(key, PEER_A))

        // All Peers -> Selected Peers fails to persist; the old rows are
        // cleared, then PEER_B is granted again.
        detached {
            peers.setKeyPolicy(SheetPolicy.SELECTED_PEERS) {
                if (failing) throw IllegalStateException("disk I/O error")
                store(key, SharingPolicyType.SELECTED_PEERS)
            }
        }
        assertTrue(peers.setAllowed(PEER_B, true, repo.pairingGeneration(PEER_B)))
        assertEquals(SharingPolicyType.ALL_PEERS, keys.getValue(key).sharingPolicy)

        // Listing and signing share canShareKeyWithPeer; export runs authorizeShare.
        assertFalse("an ungranted desktop could list or sign through stored All Peers", shares(key, SharingPolicyType.ALL_PEERS, PEER_A))
        assertFalse("an ungranted desktop could export through stored All Peers", exports(key, PEER_A))
        assertTrue(shares(key, SharingPolicyType.ALL_PEERS, PEER_B))
        assertTrue(exports(key, PEER_B))

        failing = false
        advanceUntilIdle()

        assertEquals(SharingPolicyType.SELECTED_PEERS, keys.getValue(key).sharingPolicy)
        assertFalse(exports(key, PEER_A))
        assertTrue(exports(key, PEER_B))
    }

    @Test
    fun aLaterPrivateRpcSupersedesAnOlderSheetPolicyRetry() = runTest {
        val key = "k-rpc-private"
        table.value = listOf(KeySharingPolicy(key, PEER_B))
        store(key, SharingPolicyType.SELECTED_PEERS)
        var failing = true
        val peers = KeySharingPeers(key, dao, repo, UnconfinedTestDispatcher(testScheduler), editScope = this)

        // The sheet's Selected Peers -> All Peers fails to persist and queues a retry.
        peers.setKeyPolicy(SheetPolicy.ALL_PEERS) {
            if (failing) throw IllegalStateException("disk I/O error")
            store(key, SharingPolicyType.ALL_PEERS)
        }
        assertEquals(SharingPolicyType.SELECTED_PEERS, keys.getValue(key).sharingPolicy)

        // A desktop then makes the key Private, and that write succeeds.
        rpcSetShareable(key, shareable = false)
        assertEquals(SharingPolicyType.PRIVATE, keys.getValue(key).sharingPolicy)

        failing = false
        advanceUntilIdle()

        assertEquals("the older All Peers retry overwrote the later Private", SharingPolicyType.PRIVATE, keys.getValue(key).sharingPolicy)
        assertFalse(exports(key, PEER_A))
        assertFalse(exports(key, PEER_B))
    }

    @Test
    fun aSelectedPeersAfterAFailedPrivateClearsTheOldGrantsBeforeTheDenialLifts() = runTest {
        val key = "k-reselect"
        table.value = listOf(KeySharingPolicy(key, PEER_A), KeySharingPolicy(key, PEER_B))
        var stored = SharingPolicyType.SELECTED_PEERS
        var privateFails = true
        clearFails = true
        val peers = KeySharingPeers(key, dao, repo, UnconfinedTestDispatcher(testScheduler), editScope = this)

        detached {
            peers.setKeyPolicy(SheetPolicy.PRIVATE) {
                if (privateFails) throw IllegalStateException("disk I/O error")
                stored = SharingPolicyType.PRIVATE
            }
        }
        assertFalse(shares(key, stored, PEER_A))

        // Back to Selected Peers while the old rows still cannot be cleared.
        peers.setKeyPolicy(SheetPolicy.SELECTED_PEERS) { stored = SharingPolicyType.SELECTED_PEERS }
        assertEquals(2, table.value.count { it.keyId == key })
        assertFalse("Selected Peers lifted the denial over the old grants", shares(key, stored, PEER_A))
        assertFalse(shares(key, stored, PEER_B))

        privateFails = false
        clearFails = false
        advanceUntilIdle()

        assertTrue("the old grants were never cleared", table.value.none { it.keyId == key })
        assertEquals("the older Private retry overwrote the newer policy", SharingPolicyType.SELECTED_PEERS, stored)
        assertFalse("a previously granted peer regained access without approval", shares(key, stored, PEER_A))
        assertFalse(shares(key, stored, PEER_B))

        // A fresh approval stands.
        assertTrue(peers.setAllowed(PEER_A, true, repo.pairingGeneration(PEER_A)))
        advanceUntilIdle()
        assertTrue(shares(key, stored, PEER_A))
    }

    @Test
    fun aFailedDetachedWithdrawalIsDeniedByTheHandlerUntilItsRetryLands() = runTest {
        val key = "k-withdraw"
        table.value = listOf(KeySharingPolicy(key, PEER_A), KeySharingPolicy(key, PEER_B))
        val stored = SharingPolicyType.SELECTED_PEERS
        removeFails = true
        val peers = KeySharingPeers(key, dao, repo, UnconfinedTestDispatcher(testScheduler), editScope = this)

        detached { peers.setAllowed(PEER_A, false, repo.pairingGeneration(PEER_A)) }

        assertTrue(table.value.any { it.keyId == key && it.peerPublicKeyHex == PEER_A })
        assertFalse("a failed withdrawal left its peer authorized", shares(key, stored, PEER_A))
        assertTrue(shares(key, stored, PEER_B))

        removeFails = false
        advanceUntilIdle()

        assertTrue(table.value.none { it.keyId == key && it.peerPublicKeyHex == PEER_A })
        assertFalse(shares(key, stored, PEER_A))
        assertTrue(shares(key, stored, PEER_B))
    }

    @Test
    fun aFailedPrivateWriteDeniesGrantedAndAllPeersAccessUntilItLands() = runTest {
        val selectedKey = "k-private-selected"
        val allKey = "k-private-all"
        table.value = listOf(KeySharingPolicy(selectedKey, PEER_A))
        var selectedStored = SharingPolicyType.SELECTED_PEERS
        var allStored = SharingPolicyType.ALL_PEERS
        var failing = true
        clearFails = true
        val selected = KeySharingPeers(selectedKey, dao, repo, UnconfinedTestDispatcher(testScheduler), editScope = this)
        val all = KeySharingPeers(allKey, dao, repo, UnconfinedTestDispatcher(testScheduler), editScope = this)

        detached {
            selected.setKeyPolicy(SheetPolicy.PRIVATE) {
                if (failing) throw IllegalStateException("disk I/O error")
                selectedStored = SharingPolicyType.PRIVATE
            }
        }
        detached {
            all.setKeyPolicy(SheetPolicy.PRIVATE) {
                if (failing) throw IllegalStateException("disk I/O error")
                allStored = SharingPolicyType.PRIVATE
            }
        }

        assertFalse("a failed Private left a surviving grant authorizing", shares(selectedKey, selectedStored, PEER_A))
        assertFalse("a failed Private left All Peers authorizing", shares(allKey, allStored, PEER_A))
        assertFalse(shares(allKey, allStored, PEER_B))

        failing = false
        clearFails = false
        advanceUntilIdle()

        assertEquals(SharingPolicyType.PRIVATE, selectedStored)
        assertEquals(SharingPolicyType.PRIVATE, allStored)
        assertFalse(shares(selectedKey, selectedStored, PEER_A))
        assertFalse(shares(allKey, allStored, PEER_A))

        // Once resolved, the next choice decides again.
        all.setKeyPolicy(SheetPolicy.ALL_PEERS) { allStored = SharingPolicyType.ALL_PEERS }
        assertTrue(shares(allKey, allStored, PEER_A))
        assertTrue(shares(allKey, allStored, PEER_B))
    }
}
