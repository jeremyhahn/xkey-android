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

import com.automatethethings.xkey.storage.materialDelete
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

    /** The Android Keystore side of a key: its material. */
    private val keystore = mockk<com.automatethethings.xkey.crypto.KeystoreManager>(relaxed = true)

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
        // No Keystore alias unless a test gives its key one.
        every { keystore.resolveKeystoreAlias(any()) } returns null
        handler = newHandler()
    }

    /** A handler as the service builds it, over [repo]. */
    private fun newHandler() = RequestHandler(
        context = context,
        keystoreManager = keystore,
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
        // A refusal the handler throws is answered as an error, as
        // handleRequest answers it.
        return try {
            suspendCoroutineUninterceptedOrReturn<Any?> { method.invoke(handler, request, it) } as Response
        } catch (e: java.lang.reflect.InvocationTargetException) {
            val refusal = e.cause as? ProtocolException ?: throw e
            Response.error(request.id, refusal.errorCode, refusal.message ?: "")
        }
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
        val field = KeySharingPeers::class.java.getDeclaredField("pendingObligations").apply { isAccessible = true }
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
        // It owes the key's grant clear (#193): every peer is denied until the next policy write.
        assertFalse(shares(key, PEER_B))

        tables.failing.clear()
        advanceUntilIdle()

        assertFalse(tables.isGranted(key, PEER_A))
        assertFalse(shares(key, PEER_A))
        assertFalse(shares(key, PEER_B))

        assertTrue(peers.setKeyPolicy(com.automatethethings.xkey.ui.SharingPolicyType.SELECTED_PEERS, instance))
        assertFalse("the owed clear left a grant", tables.isGranted(key, PEER_B))
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

    /**
     * A local.deleteKey cancelled while it waits behind another edit still
     * deletes the key's material once its queued row delete lands: the row
     * delete outlives the caller, so the material delete is part of it, never
     * left behind on a cancel (#193 r6, ruling 554).
     */
    @Test
    fun aCancelledQueuedDeleteStillDeletesTheKeyMaterial() = runTest {
        val key = "k-delete-cancel"
        fakeSoftwareKeyStore(java.nio.file.Files.createTempDirectory("software-keys").toFile().apply { deleteOnExit() })
        tables.addKey(key, SharingPolicyType.SELECTED_PEERS)
        // The key's Keystore alias, gone once deleted.
        val alias = "xkey_key_$key"
        var aliasHeld = true
        every { keystore.resolveKeystoreAlias(key) } answers { alias.takeIf { aliasHeld } }
        every { keystore.userKeyGeneration(key) } answers { if (aliasHeld) mapOf("keystore:$alias" to "1") else emptyMap() }
        every { keystore.deleteUserKeyGeneration(key, any()) } answers { aliasHeld = false; emptyMap() }
        val gate = CompletableDeferred<Unit>()
        tables.onPutGrant = { if (it.keyId == OTHER_KEY) gate.await() }
        val other = KeySharingPeers(OTHER_KEY, otherInstance, store, repo, UnconfinedTestDispatcher(testScheduler), editScope = this)
        val held = async(UnconfinedTestDispatcher(testScheduler)) { other.setAllowed(PEER_B, true, repo.pairingGeneration(PEER_B)) }
        val delete = async(UnconfinedTestDispatcher(testScheduler)) { rpcDeleteKey(key) }
        assertFalse(delete.isCompleted)

        // The desktop's request is cancelled while the delete is queued.
        delete.cancel()
        gate.complete(Unit)
        assertTrue(held.await())

        // The queued delete lands in the edits' own scope, off the test's clock.
        io.mockk.verify(timeout = 5_000) { keystore.deleteUserKeyGeneration(key, mapOf("keystore:$alias" to "1")) }
        assertEquals("the queued row delete did not land", null, tables.key(key))
    }

    /**
     * Round 11 (1): local.deleteKey of an internal key (the seal store's,
     * listed by the key sync under its raw alias) is refused and deletes
     * neither its rows nor its material.
     */
    @Test
    fun aDeleteOfAnInternalKeyIsRefusedOnTheRpcPath() = runTest {
        val internal = "xkey_seal_store_key"
        every { keystore.resolveKeystoreAlias(internal) } returns internal
        every { keystore.deleteByAlias(any()) } returns true
        tables.addKey(internal, SharingPolicyType.PRIVATE)

        val response = rpcDeleteKey(internal)

        assertEquals(ErrorCodes.OPERATION_DENIED, response.error?.code)
        io.mockk.verify(exactly = 0) { keystore.deleteByAlias(internal) }
        io.mockk.verify(exactly = 0) { keystore.deleteUserKeyGeneration(any(), any()) }
        assertNotNull("the internal key's row was deleted", tables.key(internal))
        assertFalse("a tombstone for an internal key", store.isDeletionPending(internal))
    }

    /**
     * Round 11 (1): a tombstone for an internal key (left by an older
     * build) is replayed without deleting the key, and is dropped.
     */
    @Test
    fun aDeleteOfAnInternalKeyIsRefusedOnTheReplayPath() = runTest {
        val internal = "xkey_seal_store_key"
        every { keystore.resolveKeystoreAlias(internal) } returns internal
        every { keystore.deleteByAlias(any()) } returns true
        val store = store
        assertTrue(store.deleteMaterial(internal, materialDelete { false }))
        assertTrue(store.isDeletionPending(internal))

        com.automatethethings.xkey.storage.replayKeyDeletions(context, store, keystore)

        io.mockk.verify(exactly = 0) { keystore.deleteByAlias(internal) }
        io.mockk.verify(exactly = 0) { keystore.deleteUserKeyGeneration(any(), any()) }
        assertFalse("the refused replay kept its tombstone", store.isDeletionPending(internal))
    }

    /**
     * Round 11 (1): a user key whose id is also an internal alias loses
     * only its user-key aliases; the internal key stays.
     */
    @Test
    fun aUserKeyDeleteNeverReachesAnInternalAliasOfTheSameName() = runTest {
        val id = "xkey_seal_store_key"
        val userAlias = "xkey_key_$id"
        var userHeld = true
        every { keystore.resolveKeystoreAlias(id) } answers { if (userHeld) userAlias else id }
        every { keystore.userKeyGeneration(id) } answers { if (userHeld) mapOf("keystore:$userAlias" to "1") else emptyMap() }
        every { keystore.deleteUserKeyGeneration(id, any()) } answers { userHeld = false; emptyMap() }
        every { keystore.deleteByAlias(any()) } returns true
        fakeSoftwareKeyStore(java.nio.file.Files.createTempDirectory("software-keys").toFile().apply { deleteOnExit() })
        tables.addKey(id, SharingPolicyType.PRIVATE)

        assertEquals(null, rpcDeleteKey(id).error)

        io.mockk.verify { keystore.deleteUserKeyGeneration(id, mapOf("keystore:$userAlias" to "1")) }
        io.mockk.verify(exactly = 0) { keystore.deleteByAlias(any()) }
    }

    /**
     * Round 12 (4): every key delete records one key-deletion audit event:
     * local.deleteKey of a key row, of material with no row, and the legacy
     * deleteKey.
     */
    @Test
    fun everyRpcKeyDeleteIsAuditedOnce() = runTest {
        every { AuditLogger.logKeyDeleted(any(), any(), any()) } just runs
        fakeSoftwareKeyStore(java.nio.file.Files.createTempDirectory("software-keys").toFile().apply { deleteOnExit() })
        val held = mutableSetOf("k-row", "k-bare", "k-legacy")
        for (id in held.toList()) {
            every { keystore.resolveKeystoreAlias(id) } answers { "xkey_credential_$id".takeIf { id in held } }
            every { keystore.keyExists(id) } answers { id in held }
            every { keystore.userKeyGeneration(id) } answers { if (id in held) mapOf("keystore:xkey_credential_$id" to "1") else emptyMap() }
            every { keystore.deleteUserKeyGeneration(id, any()) } answers { held -= id; emptyMap() }
        }
        tables.addKey("k-row", SharingPolicyType.PRIVATE)

        assertEquals(null, rpcDeleteKey("k-row").error)
        assertEquals(null, rpcDeleteKey("k-bare").error)
        assertEquals(null, rpcLegacyDeleteKey("k-legacy").error)

        for (id in listOf("k-row", "k-bare", "k-legacy")) {
            io.mockk.verify(exactly = 1) { AuditLogger.logKeyDeleted(id, any(), any()) }
        }
        assertTrue("a delete left its material", held.isEmpty())
        // The legacy delete takes the store's path: its material is deleted
        // by its generation, never by a raw alias outside the store.
        io.mockk.verify(exactly = 0) { keystore.deleteKey(any()) }
    }

    /**
     * Round 12 (1): a delete that reported success while its material is
     * still owed (its tombstone pending) leaves the key unusable at once:
     * every RPC naming it is refused as a deleted key, before it reaches
     * the key's material.
     */
    @Test
    fun aKeyWithAPendingDeletionRefusesEveryOperation() = runTest {
        every { AuditLogger.logKeyDeleted(any(), any(), any()) } just runs
        fakeSoftwareKeyStore(java.nio.file.Files.createTempDirectory("software-keys").toFile().apply { deleteOnExit() })
        val id = "k-owed"
        every { keystore.resolveKeystoreAlias(id) } returns "xkey_key_$id"
        every { keystore.keyExists(id) } returns true
        every { keystore.generalKeyExists(id) } returns true
        every { keystore.userKeyGeneration(id) } returns mapOf("keystore:xkey_key_$id" to "1")
        val instance = tables.addKey(id, SharingPolicyType.SELECTED_PEERS)

        assertTrue(store.deleteKey(id, instance, owedDelete()))
        assertTrue("the delete's material is not owed", store.isDeletionPending(id))

        val data = java.util.Base64.getEncoder().encodeToString(ByteArray(32))
        val keyed = listOf(
            "sign", "loadKey",
            MethodNames.LOCAL_SIGN, MethodNames.LOCAL_DECRYPT, MethodNames.LOCAL_SYMMETRIC_ENCRYPT,
            MethodNames.LOCAL_SYMMETRIC_DECRYPT, MethodNames.LOCAL_HMAC, MethodNames.LOCAL_ECDH,
            MethodNames.LOCAL_GET_PUBLIC_KEY, MethodNames.LOCAL_GET_KEY_INFO, MethodNames.LOCAL_SET_KEY_POLICY,
            MethodNames.LOCAL_ATTEST_KEY, MethodNames.LOCAL_SIGN_FIDO2_ASSERTION, MethodNames.LOCAL_SHARE_SYMMETRIC,
            MethodNames.LOCAL_IMPORT_SHARED_KEY, MethodNames.COSIGN_REQUEST
        )
        for (method in keyed) {
            val params = JSONObject()
                .put("keyId", id).put("credentialId", id).put("key_id", id)
                .put("data", data).put("hash", "00".repeat(32)).put("shareable", true)
            val response = handler.handleRequest(Request(id = 9, method = method, params = params))
            assertEquals("$method answered ${response.error?.message}", ErrorCodes.KEY_NOT_FOUND, response.error?.code)
            assertTrue("$method was not refused as a deleted key: ${response.error?.message}", "was deleted" in response.error!!.message)
        }
    }

    /** Runs the legacy deleteKey through the handler. */
    private suspend fun rpcLegacyDeleteKey(credentialId: String): Response {
        val method = RequestHandler::class.java.getDeclaredMethod("handleDeleteKey", Request::class.java, Continuation::class.java)
        method.isAccessible = true
        val request = Request(id = 4, method = "deleteKey", params = JSONObject().put("credentialId", credentialId))
        return try {
            suspendCoroutineUninterceptedOrReturn<Any?> { method.invoke(handler, request, it) } as Response
        } catch (e: java.lang.reflect.InvocationTargetException) {
            val refusal = e.cause as? ProtocolException ?: throw e
            Response.error(request.id, refusal.errorCode, refusal.message ?: "")
        }
    }

    /** The app's deleter, recording the generation, whose delete does not confirm: the tombstone is owed. */
    private fun owedDelete(): com.automatethethings.xkey.storage.KeyMaterial =
        object : com.automatethethings.xkey.storage.KeyMaterial by com.automatethethings.xkey.storage.keyMaterialDeleter(context, keystore) {
            override suspend fun delete(
                held: com.automatethethings.xkey.storage.KeyPolicyStore.KeyMaterialHeld,
                tombstone: com.automatethethings.xkey.storage.entity.KeyDeletionEntity
            ) = false
        }

    /**
     * The software key store as a set of key ids, its files under [files]:
     * the platform keystore its cipher opens is a stub.
     */
    private fun fakeSoftwareKeyStore(files: java.io.File): MutableSet<String> {
        mockkStatic(java.security.KeyStore::class)
        every { java.security.KeyStore.getInstance(any<String>()) } returns mockk(relaxed = true)
        every { context.filesDir } returns files
        val software = mutableSetOf<String>()
        io.mockk.mockkConstructor(com.automatethethings.xkey.crypto.SoftwareKeyStore::class)
        every { anyConstructed<com.automatethethings.xkey.crypto.SoftwareKeyStore>().contains(any()) } answers { firstArg<String>() in software }
        every { anyConstructed<com.automatethethings.xkey.crypto.SoftwareKeyStore>().put(any()) } answers {
            software += firstArg<com.automatethethings.xkey.crypto.SoftwareKey>().keyId
        }
        every { anyConstructed<com.automatethethings.xkey.crypto.SoftwareKeyStore>().delete(any()) } answers { software -= firstArg<String>() }
        every { anyConstructed<com.automatethethings.xkey.crypto.SoftwareKeyStore>().generation(any()) } answers {
            firstArg<String>().takeIf { it in software }?.let { "g-$it" }
        }
        every { anyConstructed<com.automatethethings.xkey.crypto.SoftwareKeyStore>().deleteGeneration(any(), any()) } answers {
            if (secondArg<String>() == "g-${firstArg<String>()}") software -= firstArg<String>()
            true
        }
        return software
    }

    /**
     * Round 11 (3): a replay whose caller is cancelled (the key screen
     * closed) while it waits for a key's material lock still deletes the
     * material and drops the tombstone: the replay runs out of the
     * caller's cancellation.
     */
    @Test
    fun aCancelledReplayStillSettlesItsTombstones() = runTest {
        val key = "k-replay-cancel"
        val files = java.nio.file.Files.createTempDirectory("software-keys").toFile()
        val software = fakeSoftwareKeyStore(files)
        try {
            val store = store
            software += key
            assertTrue(store.deleteMaterial(key, owedDelete()))
            // A write of another key under the same id holds its lock.
            val gate = CompletableDeferred<Unit>()
            val holder = async(UnconfinedTestDispatcher(testScheduler)) { store.lockKeyMaterial(key) { gate.await() } }
            val replay = async(UnconfinedTestDispatcher(testScheduler)) {
                com.automatethethings.xkey.storage.replayKeyDeletions(context, store, keystore)
            }
            assertFalse(replay.isCompleted)

            replay.cancel()
            gate.complete(Unit)
            holder.await()
            advanceUntilIdle()

            assertFalse("the cancelled replay left the material", key in software)
            assertFalse("the cancelled replay left its tombstone", store.isDeletionPending(key))
        } finally {
            files.deleteRecursively()
        }
    }

    /**
     * Round 11 (2): a symmetric import accepted under the id of an earlier
     * delete whose tombstone is still owed survives that tombstone's
     * replay: the import settles the owed delete first, so the replay never
     * deletes a later generation under the id.
     */
    @Test
    fun anImportAfterATombstoneSurvivesTheReplay() = runTest {
        val key = "k-import"
        val files = java.nio.file.Files.createTempDirectory("software-keys").toFile()
        val software = fakeSoftwareKeyStore(files)
        try {
            // An earlier delete of the id whose material delete did not
            // confirm: its tombstone is owed.
            val store = store
            assertTrue(store.deleteMaterial(key, owedDelete()))
            assertTrue(store.isDeletionPending(key))

            handler.setConnectedDevicePublicKeyHex(PEER_A)
            val method = RequestHandler::class.java.getDeclaredMethod("handleShareSymmetric", Request::class.java, Continuation::class.java)
            method.isAccessible = true
            val request = Request(
                id = 3,
                method = MethodNames.LOCAL_SHARE_SYMMETRIC,
                params = JSONObject().put("wrapped_key", "AAAAAAAAAAAAAAAAAAAAAA==").put("label", key)
            )
            val response = suspendCoroutineUninterceptedOrReturn<Any?> { method.invoke(handler, request, it) } as Response
            assertEquals(null, response.error)
            assertTrue("the import was not written", key in software)

            com.automatethethings.xkey.storage.replayKeyDeletions(context, store, keystore)

            assertTrue("the replay deleted the import accepted after the tombstone", key in software)
            assertFalse(store.isDeletionPending(key))
        } finally {
            files.deleteRecursively()
        }
    }
}
