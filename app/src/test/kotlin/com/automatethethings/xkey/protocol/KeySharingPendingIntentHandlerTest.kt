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
import com.automatethethings.xkey.storage.FakeKeyPolicyTables
import com.automatethethings.xkey.storage.KeyPolicyStore
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.dao.KeySharingPolicyDao
import com.automatethethings.xkey.storage.entity.KeyEntity
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
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.json.JSONObject
import org.junit.Test

/**
 * A sharing edit whose write fails is refused and fails closed in the
 * production [RequestHandler] (#174, #193): a failed narrowing's denial is
 * kept in the key's policy row, so `canShareKeyWithPeer` refuses the peers
 * it withdraws, after a restart too, until a later change lands. Nothing is
 * retried in memory but a single peer's withdrawal.
 *
 * Each test uses its own key: pending withdrawals live in the process.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class KeySharingPendingIntentHandlerTest {

    private companion object {
        const val OTHER_KEY = "k-other"
        val PEER_A = "a".repeat(64)
        val PEER_B = "b".repeat(64)
    }

    /** The `keys`, `key_policies` and `key_sharing_policies` tables. */
    private val tables = FakeKeyPolicyTables()
    private val store get() = tables.store()
    private lateinit var dao: KeySharingPolicyDao
    private lateinit var repo: PairedDeviceRepository
    private lateinit var prefs: InMemorySharedPreferences
    private lateinit var keyDao: KeyDao
    private lateinit var context: Context
    private lateinit var handler: RequestHandler
    private var otherInstance = 0L

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.e(any(), any<String>(), any()) } returns 0
        every { Log.e(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>(), any()) } returns 0
        every { Log.i(any(), any<String>()) } returns 0
        every { Log.d(any(), any<String>()) } returns 0
        every { Log.v(any(), any<String>()) } returns 0
        mockkObject(AuditLogger)
        every { AuditLogger.logDeviceUnpaired(any(), any()) } just runs

        otherInstance = tables.addKey(OTHER_KEY, SharingPolicyType.SELECTED_PEERS)
        dao = mockk()
        coEvery { dao.isPeerGranted(any(), any()) } answers { tables.isGranted(firstArg(), secondArg()) }
        keyDao = mockk()
        coEvery { keyDao.getByKeyId(any()) } answers { tables.key(firstArg()) }

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
        mockkObject(KeyPolicyStore.Companion)
        every { KeyPolicyStore.of(any()) } answers { tables.store() }
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

    /** Invokes the handler's private suspend [name]; the faked tables never suspend. */
    private fun call(name: String, vararg args: Any, types: Array<Class<*>>): Any? {
        val method = RequestHandler::class.java.getDeclaredMethod(name, *types, Continuation::class.java)
        method.isAccessible = true
        val noResume = Continuation<Any?>(EmptyCoroutineContext) { error("suspended") }
        return method.invoke(handler, *args, noResume)
    }

    /**
     * The handler's own check for [keyId]'s stored key row: the gate
     * local.listFido2Credentials filters with and local.signFido2Assertion
     * refuses by.
     */
    private fun shares(keyId: String, peer: String): Boolean =
        call("canShareKeyWithPeer", tables.key(keyId)!!, peer, types = arrayOf(KeyEntity::class.java, String::class.java)) as Boolean

    /** The authorization key export runs: the stored key when [peer] may have it, else null. */
    private fun exports(keyId: String, peer: String): Boolean =
        call("authorizeShare", keyId, peer, types = arrayOf(String::class.java, String::class.java)) != null

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

    /** Runs local.deleteKey through the handler, as a desktop's RPC does. */
    private suspend fun rpcDeleteKey(keyId: String): Response {
        val method = RequestHandler::class.java.getDeclaredMethod(
            "handleLocalDeleteKey", Request::class.java, Continuation::class.java
        )
        method.isAccessible = true
        val request = Request(id = 2, method = MethodNames.LOCAL_DELETE_KEY, params = JSONObject().put("keyId", keyId))
        return suspendCoroutineUninterceptedOrReturn<Any?> { method.invoke(handler, request, it) } as Response
    }

    /**
     * A process restart: [KeySharingPeers]' pending withdrawals are gone, and
     * their retries with them; the tables stay.
     */
    @Suppress("UNCHECKED_CAST")
    private fun restartProcess() {
        val field = KeySharingPeers::class.java.getDeclaredField("pendingWithdrawals").apply { isAccessible = true }
        (field.get(null) as MutableStateFlow<Map<Any, Any>>).value = emptyMap()
        repo = PairedDeviceRepository(prefs)
        handler = newHandler()
    }

    /**
     * Runs [edit] from a sheet dismissed while the edit waits behind another
     * key's held grant, so nobody awaits it when it runs and fails.
     */
    private fun TestScope.detached(edit: suspend () -> Unit) {
        val gate = CompletableDeferred<Unit>()
        tables.onPutGrant = { if (it.keyId == OTHER_KEY) gate.await() }
        val other = KeySharingPeers(OTHER_KEY, otherInstance, store, repo, UnconfinedTestDispatcher(testScheduler), editScope = this)
        val grant = async(UnconfinedTestDispatcher(testScheduler)) { other.setAllowed(PEER_B, true, repo.pairingGeneration(PEER_B)) }
        val sheet = CoroutineScope(Job() + UnconfinedTestDispatcher(testScheduler))
        sheet.launch { edit() }
        sheet.cancel()
        gate.complete(Unit)
        tables.onPutGrant = {}
        runCurrent()
        assertTrue(grant.isCompleted)
    }

    @Test
    fun aFailedDetachedNarrowingToSelectedPeersDeniesUngrantedPeersUntilALaterChangeLands() = runTest {
        val key = "k-narrow"
        val instance = tables.addKey(key, SharingPolicyType.ALL_PEERS)
        val peers = KeySharingPeers(key, instance, store, repo, UnconfinedTestDispatcher(testScheduler), editScope = this)
        assertTrue(shares(key, PEER_A))
        assertTrue(exports(key, PEER_A))

        tables.failing += "setKeyPolicy"
        detached { peers.setKeyPolicy(SheetPolicy.SELECTED_PEERS, instance) }
        tables.failing.clear()

        assertEquals(SharingPolicyType.ALL_PEERS, tables.keyPolicy(key))
        // Listing and signing share canShareKeyWithPeer; export runs authorizeShare.
        assertFalse("a failed Selected Peers left All Peers authorizing an ungranted peer", shares(key, PEER_A))
        assertFalse("an ungranted desktop could export through stored All Peers", exports(key, PEER_A))
        assertFalse(shares(key, PEER_B))

        // A grant the user makes meanwhile stands, and authorizes only its peer.
        assertTrue(peers.setAllowed(PEER_B, true, repo.pairingGeneration(PEER_B)))
        assertTrue(shares(key, PEER_B))
        assertTrue(exports(key, PEER_B))
        assertFalse(shares(key, PEER_A))

        // Nothing is retried, and the denial holds across a restart.
        advanceUntilIdle()
        restartProcess()
        assertEquals("a failed Selected Peers was retried", SharingPolicyType.ALL_PEERS, tables.keyPolicy(key))
        assertFalse(shares(key, PEER_A))
        assertTrue(shares(key, PEER_B))

        // The user's next choice lands and keeps the later grant.
        assertTrue(peers.setKeyPolicy(SheetPolicy.SELECTED_PEERS, instance))
        assertEquals(SharingPolicyType.SELECTED_PEERS, tables.keyPolicy(key))
        assertFalse(exports(key, PEER_A))
        assertTrue("the later grant was dropped", exports(key, PEER_B))
    }

    @Test
    fun aFailedSheetPolicyNeverLandsOverALaterPrivateRpc() = runTest {
        val key = "k-rpc-private"
        val instance = tables.addKey(key, SharingPolicyType.SELECTED_PEERS)
        tables.grant(key, PEER_B)
        val peers = KeySharingPeers(key, instance, store, repo, UnconfinedTestDispatcher(testScheduler), editScope = this)

        // The sheet's Selected Peers -> All Peers fails, and is refused.
        tables.failing += "setKeyPolicy"
        assertFalse(peers.setKeyPolicy(SheetPolicy.ALL_PEERS, instance))
        tables.failing.clear()
        assertEquals(SharingPolicyType.SELECTED_PEERS, tables.keyPolicy(key))

        // A desktop then makes the key Private, and that write succeeds.
        rpcSetShareable(key, shareable = false)
        assertEquals(SharingPolicyType.PRIVATE, tables.keyPolicy(key))

        advanceUntilIdle()

        assertEquals("the older All Peers landed over the later Private", SharingPolicyType.PRIVATE, tables.keyPolicy(key))
        assertFalse(exports(key, PEER_A))
        assertFalse(exports(key, PEER_B))
    }

    @Test
    fun aSelectedPeersAfterAFailedPrivateClearsTheOldGrantsBeforeTheDenialLifts() = runTest {
        val key = "k-reselect"
        val instance = tables.addKey(key, SharingPolicyType.SELECTED_PEERS)
        tables.grant(key, PEER_A)
        tables.grant(key, PEER_B)
        tables.failing += "deleteGrants"
        val peers = KeySharingPeers(key, instance, store, repo, UnconfinedTestDispatcher(testScheduler), editScope = this)

        detached { peers.setKeyPolicy(SheetPolicy.PRIVATE, instance) }
        assertFalse(shares(key, PEER_A))

        // Back to Selected Peers while the old rows still cannot be cleared: refused.
        assertFalse(peers.setKeyPolicy(SheetPolicy.SELECTED_PEERS, instance))
        assertEquals(setOf(PEER_A, PEER_B), tables.grantsOf(key))
        assertFalse("Selected Peers lifted the denial over the old grants", shares(key, PEER_A))
        assertFalse(shares(key, PEER_B))

        tables.failing.clear()
        advanceUntilIdle()
        assertFalse("the old grants authorize again with nothing landed", shares(key, PEER_A))

        // The next Selected Peers clears the old grants first.
        assertTrue(peers.setKeyPolicy(SheetPolicy.SELECTED_PEERS, instance))
        assertTrue("the old grants were never cleared", tables.grantsOf(key).isEmpty())
        assertEquals(SharingPolicyType.SELECTED_PEERS, tables.keyPolicy(key))
        assertFalse("a previously granted peer regained access without approval", shares(key, PEER_A))
        assertFalse(shares(key, PEER_B))

        // A fresh approval stands.
        assertTrue(peers.setAllowed(PEER_A, true, repo.pairingGeneration(PEER_A)))
        advanceUntilIdle()
        assertTrue(shares(key, PEER_A))
    }

    @Test
    fun aFailedDetachedWithdrawalIsDeniedByTheHandlerUntilItsRetryLands() = runTest {
        val key = "k-withdraw"
        val instance = tables.addKey(key, SharingPolicyType.SELECTED_PEERS)
        tables.grant(key, PEER_A)
        tables.grant(key, PEER_B)
        tables.failing += "deleteGrant"
        val peers = KeySharingPeers(key, instance, store, repo, UnconfinedTestDispatcher(testScheduler), editScope = this)

        detached { peers.setAllowed(PEER_A, false, repo.pairingGeneration(PEER_A)) }

        assertTrue(tables.isGranted(key, PEER_A))
        assertFalse("a failed withdrawal left its peer authorized", shares(key, PEER_A))
        assertTrue(shares(key, PEER_B))

        tables.failing.clear()
        advanceUntilIdle()

        assertFalse(tables.isGranted(key, PEER_A))
        assertFalse(shares(key, PEER_A))
        assertTrue(shares(key, PEER_B))
    }

    @Test
    fun aFailedPrivateWriteDeniesGrantedAndAllPeersAccessUntilALaterChangeLands() = runTest {
        val selectedKey = "k-private-selected"
        val allKey = "k-private-all"
        val selectedInstance = tables.addKey(selectedKey, SharingPolicyType.SELECTED_PEERS)
        val allInstance = tables.addKey(allKey, SharingPolicyType.ALL_PEERS)
        tables.grant(selectedKey, PEER_A)
        tables.failing += "setKeyPolicy"
        val selected = KeySharingPeers(selectedKey, selectedInstance, store, repo, UnconfinedTestDispatcher(testScheduler), editScope = this)
        val all = KeySharingPeers(allKey, allInstance, store, repo, UnconfinedTestDispatcher(testScheduler), editScope = this)

        detached { selected.setKeyPolicy(SheetPolicy.PRIVATE, selectedInstance) }
        detached { all.setKeyPolicy(SheetPolicy.PRIVATE, allInstance) }
        tables.failing.clear()

        assertFalse("a failed Private left a surviving grant authorizing", shares(selectedKey, PEER_A))
        assertFalse("a failed Private left All Peers authorizing", shares(allKey, PEER_A))
        assertFalse(shares(allKey, PEER_B))

        advanceUntilIdle()
        restartProcess()

        assertEquals(SharingPolicyType.SELECTED_PEERS, tables.keyPolicy(selectedKey))
        assertEquals(SharingPolicyType.ALL_PEERS, tables.keyPolicy(allKey))
        assertFalse(shares(selectedKey, PEER_A))
        assertFalse(shares(allKey, PEER_A))

        // The next choice decides again.
        assertTrue(all.setKeyPolicy(SheetPolicy.ALL_PEERS, allInstance))
        assertTrue(shares(allKey, PEER_A))
        assertTrue(shares(allKey, PEER_B))
    }

    @Test
    fun aFailedRpcRevocationIsNotReportedAndSurvivesARestart() = runTest {
        val key = "k-rpc-restart"
        tables.addKey(key, SharingPolicyType.ALL_PEERS)
        tables.grant(key, PEER_A)
        tables.failing += "setKeyPolicy"

        // A desktop makes the key private; the write fails.
        val response = rpcSetShareableResponse(key, false)
        assertFalse(response.result?.optBoolean("updated") == true)
        assertNotNull(response.error)
        tables.failing.clear()

        // The process dies and starts again over the same disk.
        restartProcess()

        assertEquals(SharingPolicyType.ALL_PEERS, tables.keyPolicy(key))
        assertFalse(shares(key, PEER_A))
        assertFalse(exports(key, PEER_A))
    }

    @Test
    fun aFailedRpcWideningIsNotRetriedOverAKeyDeletedAndReused() = runTest {
        val key = "k-rpc-reuse"
        val first = tables.addKey(key, SharingPolicyType.PRIVATE)
        tables.failing += "setKeyPolicy"

        // A desktop shares the key with all peers; the write fails and is refused.
        assertNotNull(rpcSetShareableResponse(key, true).error)
        tables.failing.clear()

        // The key is deleted (as the key screens do) and generated again
        // under its id, not shareable, and granted to a peer.
        assertTrue(KeySharingPeers.forgetKey(key, first, store))
        val second = tables.addKey(key, SharingPolicyType.PRIVATE)
        tables.grant(key, PEER_A)
        advanceUntilIdle()

        assertTrue(second != first)
        assertEquals(SharingPolicyType.PRIVATE, tables.keyPolicy(key))
        assertTrue(tables.isGranted(key, PEER_A))

        // An edit still bound to the deleted key row is refused and writes nothing.
        assertFalse(KeySharingPeers.setKeyPolicy(key, store, SheetPolicy.ALL_PEERS, first, editScope = this))
        assertEquals(SharingPolicyType.PRIVATE, tables.keyPolicy(key))
        assertTrue(tables.isGranted(key, PEER_A))
    }

    /**
     * A local.deleteKey that waits behind another edit while its key is
     * deleted and generated again under its id deletes nothing of the new
     * key: it is bound to the key row it read (#193).
     */
    @Test
    fun aDelayedDeleteNeverRemovesAKeyGeneratedAgainUnderItsId() = runTest {
        val key = "k-delete-reuse"
        // The software key store's cipher opens the platform keystore.
        mockkStatic(java.security.KeyStore::class)
        every { java.security.KeyStore.getInstance(any<String>()) } returns mockk(relaxed = true)
        val first = tables.addKey(key, SharingPolicyType.SELECTED_PEERS)
        val gate = CompletableDeferred<Unit>()
        tables.onPutGrant = { if (it.keyId == OTHER_KEY) gate.await() }
        val other = KeySharingPeers(OTHER_KEY, otherInstance, store, repo, UnconfinedTestDispatcher(testScheduler), editScope = this)
        val held = async(UnconfinedTestDispatcher(testScheduler)) { other.setAllowed(PEER_B, true, repo.pairingGeneration(PEER_B)) }
        val delete = async(UnconfinedTestDispatcher(testScheduler)) { rpcDeleteKey(key) }
        assertFalse(delete.isCompleted)

        // The key is deleted elsewhere and generated again while the delete waits.
        tables.deleteKey(key)
        val second = tables.addKey(key, SharingPolicyType.SELECTED_PEERS)
        tables.grant(key, PEER_A)
        assertTrue(second != first)
        gate.complete(Unit)
        assertTrue(held.await())
        delete.await()

        assertEquals("the delayed delete removed the new key's metadata", second, tables.key(key)?.id)
        assertTrue(tables.isGranted(key, PEER_A))
    }
}
