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

package com.automatethethings.xkey.ble

import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattServer
import android.content.Context
import android.util.Log
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.protocol.ErrorCodes
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.protocol.Response
import com.automatethethings.xkey.remote.BidirectionalMessageRouter
import com.automatethethings.xkey.remote.ConnectionChangedException
import com.automatethethings.xkey.remote.sendOnBoundSession
import com.automatethethings.xkey.settings.InMemorySharedPreferences
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.settings.PeerNotPairedException
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.runs
import io.mockk.unmockkAll
import io.mockk.verify
import java.lang.reflect.InvocationTargetException
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.coroutines.intrinsics.suspendCoroutineUninterceptedOrReturn
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

/**
 * A desktop that is already paired is confirmed when its reconnect handshake
 * completes, so the replies to the phone's own requests reach the response
 * router instead of being refused as unpaired (#59). An unknown
 * desktop stays gated until `pairing.confirm`, and a removal during the
 * handshake confirms nothing. A `pairing.confirm` on the adopted session is
 * answered confirmed without a prompt; an unknown desktop's still
 * asks the user, and a revoked session's is not answered.
 *
 * The handshake's last message is driven through the server's private
 * `handleHandshakeMessage`, and frames from the desktop through
 * `handleApplicationMessage`, as the GATT callbacks reach them; the rest of
 * the connection state is installed by reflection, as in
 * [GattServerSessionRaceTest].
 */
@Suppress("DEPRECATION")
class GattServerReconnectTest {

    private companion object {
        const val ADDRESS = "AA:BB:CC:DD:EE:FF"
        const val TIMEOUT_MS = 5_000L
        const val BACKUP_ID = 42L
        val BACKUP_REQUEST = """{"jsonrpc":"2.0","id":$BACKUP_ID,"method":"remote.backup.create","params":{}}"""
            .toByteArray()
        val BACKUP_RESPONSE = """{"jsonrpc":"2.0","id":$BACKUP_ID,"result":{"stored":true}}""".toByteArray()
        val GENERATE_KEY = """{"jsonrpc":"2.0","id":5,"method":"local.generateKey","params":{}}""".toByteArray()

        fun randomKey(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }

        fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }

        fun pairingConfirm(keyHex: String): ByteArray = JSONObject()
            .put("jsonrpc", "2.0")
            .put("id", 3)
            .put("method", "pairing.confirm")
            .put("params", JSONObject().put("deviceName", "desktop").put("publicKeyHex", keyHex))
            .toString()
            .toByteArray()
    }

    private lateinit var context: Context
    private lateinit var repo: PairedDeviceRepository
    private lateinit var requestHandler: RequestHandler
    private lateinit var router: BidirectionalMessageRouter
    private lateinit var callback: PairingConfirmationCallback
    private lateinit var gatt: BluetoothGattServer
    private lateinit var device: BluetoothDevice
    private lateinit var server: GattServer

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.v(any(), any<String>()) } returns 0
        every { Log.d(any(), any<String>()) } returns 0
        every { Log.i(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.e(any(), any<String>()) } returns 0
        every { Log.d(any(), any<String>(), any()) } returns 0
        every { Log.i(any(), any<String>(), any()) } returns 0
        every { Log.w(any(), any<String>(), any()) } returns 0
        every { Log.e(any(), any<String>(), any()) } returns 0
        mockkObject(AuditLogger)
        every { AuditLogger.logDeviceUnpaired(any(), any()) } just runs
        every { AuditLogger.logPairingApproved(any(), any(), any()) } just runs

        context = mockk(relaxed = true)
        repo = PairedDeviceRepository(InMemorySharedPreferences())
        requestHandler = mockk(relaxed = true)
        coEvery { requestHandler.handleRawRequest(any<ByteArray>()) } returns
            """{"jsonrpc":"2.0","id":5,"result":{"ok":true}}""".toByteArray()
        router = BidirectionalMessageRouter(requestHandler)
        callback = mockk()
        gatt = mockk(relaxed = true)
        every { gatt.notifyCharacteristicChanged(any(), any(), any()) } returns true
        every { gatt.notifyCharacteristicChanged(any(), any(), any(), any<ByteArray>()) } returns 0
        device = mockk(relaxed = true)
        every { device.address } returns ADDRESS
        every { device.name } returns "desktop"
        server = GattServer(
            context,
            requestHandler,
            messageRouter = router,
            pairingCallback = callback,
            pairedDeviceRepository = repo
        )
        setField("gattServer", gatt)
        setField("responseCharacteristic", mockk<BluetoothGattCharacteristic>(relaxed = true))
    }

    @After
    fun tearDown() {
        server.destroy()
        awaitScopeFinished(server)
        unmockkAll()
    }

    /**
     * The finding: a paired desktop reconnects, the phone sends it a backup
     * request, and the desktop's reply completes that request instead of
     * being refused as coming from an unpaired peer.
     */
    @Test
    fun aPairedDesktopThatReconnectsHasItsReplyDeliveredToTheRouter() = runBlocking<Unit> {
        val desktop = NoiseInitiatorSession(randomKey())
        val keyHex = desktop.getLocalStaticPublicKey().hex()
        repo.addDevice(keyHex, "desktop")

        reconnect(desktop, claimedPeerKeyHex = keyHex)

        assertEquals(true, getField<Boolean>("pairingConfirmed"))
        assertEquals(ConnectionState.Connected("desktop", ADDRESS), server.connectionState.value)
        verify { requestHandler.setConnectedDevicePublicKeyHex(keyHex) }

        val pending = CompletableDeferred<Response>()
        router.registerPendingResponse(BACKUP_ID, pending)
        server.sendOnBoundSession(BACKUP_REQUEST)
        call("handleApplicationMessage", device, desktop.encrypt(BACKUP_RESPONSE))

        val response = withTimeout(TIMEOUT_MS) { pending.await() }
        assertEquals(BACKUP_ID, response.id)
        assertEquals(true, response.result?.getBoolean("stored"))
        coVerify(exactly = 0) { requestHandler.handleRawRequest(any<ByteArray>()) }
    }

    /**
     * An unknown desktop that completes a handshake is not confirmed: its
     * requests are refused and the phone sends it nothing, until the user
     * approves its `pairing.confirm`.
     */
    @Test
    fun anUnknownDesktopStaysGatedUntilPairingConfirm() = runBlocking<Unit> {
        coEvery { callback.onPairingConfirmationRequired(any(), any(), any()) } returns true
        val desktop = NoiseInitiatorSession(randomKey())
        val keyHex = desktop.getLocalStaticPublicKey().hex()
        val fragments = captureFragments()

        reconnect(desktop, claimedPeerKeyHex = keyHex)

        assertEquals(false, getField<Boolean>("pairingConfirmed"))
        verify(exactly = 0) { requestHandler.setConnectedDevicePublicKeyHex(keyHex) }
        call("handleApplicationMessage", device, desktop.encrypt(GENERATE_KEY))
        coVerify(exactly = 0) { requestHandler.handleRawRequest(any<ByteArray>()) }
        val refusal = JSONObject(String(desktop.decrypt(reassemble(fragments).single())))
        assertEquals(ErrorCodes.PAIRING_REQUIRED, refusal.getJSONObject("error").getInt("code"))
        try {
            server.sendOnBoundSession(BACKUP_REQUEST)
            fail("a send to an unconfirmed desktop must be refused")
        } catch (e: PeerNotPairedException) {
            assertEquals(keyHex, e.publicKeyHex)
        }

        call("handleApplicationMessage", device, desktop.encrypt(pairingConfirm(keyHex)))
        assertEquals(true, getField<Boolean>("pairingConfirmed"))
        call("handleApplicationMessage", device, desktop.encrypt(GENERATE_KEY))
        coVerify(exactly = 1) { requestHandler.handleRawRequest(any<ByteArray>()) }
    }

    /**
     * A desktop paired through another transport while its BLE session is
     * unconfirmed is not sent a request on that session: its reply would be
     * refused as unpaired, so the send is refused before encryption.
     */
    @Test
    fun aDesktopPairedInTheStoreButUnconfirmedOnTheSessionIsSentNothing() = runBlocking<Unit> {
        val desktop = NoiseInitiatorSession(randomKey())
        val keyHex = desktop.getLocalStaticPublicKey().hex()
        val session = reconnect(desktop, claimedPeerKeyHex = keyHex)
        repo.addDevice(keyHex, "desktop")
        val nonce = session.sendNonceForTest()

        try {
            server.sendOnBoundSession(BACKUP_REQUEST)
            fail("a send to an unconfirmed desktop must be refused")
        } catch (e: PeerNotPairedException) {
            assertEquals(keyHex, e.publicKeyHex)
        }

        assertEquals("a refused send must consume no nonce", nonce, session.sendNonceForTest())
        assertNoNotification()
    }

    /**
     * The paired desktop is removed while its reconnect handshake is in
     * progress: the session is not confirmed, the desktop is not adopted as
     * the connected peer, and no connected state is published.
     */
    @Test
    fun aRemovalDuringTheReconnectHandshakeAdoptsNothing() = runBlocking<Unit> {
        val desktop = NoiseInitiatorSession(randomKey())
        val keyHex = desktop.getLocalStaticPublicKey().hex()
        repo.addDevice(keyHex, "desktop")
        val session = startHandshake(desktop, claimedPeerKeyHex = keyHex)
        session.afterSplitForTest = { repo.removeDevice(keyHex) }

        call("handleHandshakeMessage", device, desktop.createHandshakeMessage3())

        assertEquals(false, getField<Boolean>("pairingConfirmed"))
        verify(exactly = 0) { requestHandler.setConnectedDevicePublicKeyHex(keyHex) }
        assertNotEquals(ConnectionState.Connected("desktop", ADDRESS), server.connectionState.value)
        verify(timeout = TIMEOUT_MS) { gatt.cancelConnection(device) }
        eventually("the session is torn down") { server.connectionState.value == ConnectionState.Disconnected }
        assertFalse(server.isSessionEstablished())
        assertNoNotification()
    }

    /**
     * A paired desktop that reconnects is confirmed at handshake
     * completion, and a later `pairing.confirm` (rerunning `xkey device
     * pair`) is answered confirmed with its own id, as StreamPairingSession
     * answers it, instead of reaching RequestHandler and METHOD_NOT_FOUND.
     * Nothing is prompted and the paired store is unchanged.
     */
    @Test
    fun aPairedDesktopThatReconnectsThenConfirmsIsAnsweredConfirmed() = runBlocking<Unit> {
        val desktop = NoiseInitiatorSession(randomKey())
        val keyHex = desktop.getLocalStaticPublicKey().hex()
        repo.addDevice(keyHex, "desktop")
        val stored = repo.getAllDevices()
        reconnect(desktop, claimedPeerKeyHex = keyHex)
        val fragments = captureFragments()

        call("handleApplicationMessage", device, desktop.encrypt(pairingConfirm(keyHex)))

        val answer = JSONObject(String(desktop.decrypt(reassemble(fragments).single())))
        assertFalse("pairing.confirm must not be refused: $answer", answer.has("error"))
        assertEquals(3, answer.getInt("id"))
        assertEquals(true, answer.getJSONObject("result").getBoolean("confirmed"))
        assertEquals(true, getField<Boolean>("pairingConfirmed"))
        coVerify(exactly = 0) { callback.onPairingConfirmationRequired(any(), any(), any()) }
        coVerify(exactly = 0) { requestHandler.handleRawRequest(any<ByteArray>()) }
        assertEquals(stored, repo.getAllDevices())
    }

    /**
     * An unknown desktop's `pairing.confirm` still goes to the user: a
     * refusal is answered PAIRING_REJECTED and leaves the desktop unknown
     * and the session unconfirmed.
     */
    @Test
    fun anUnknownDesktopsPairingConfirmStillAsksTheUser() = runBlocking<Unit> {
        every { AuditLogger.logPairingDenied(any(), any(), any()) } just runs
        coEvery { callback.onPairingConfirmationRequired(any(), any(), any()) } returns false
        val desktop = NoiseInitiatorSession(randomKey())
        val keyHex = desktop.getLocalStaticPublicKey().hex()
        reconnect(desktop, claimedPeerKeyHex = keyHex)
        val fragments = captureFragments()

        call("handleApplicationMessage", device, desktop.encrypt(pairingConfirm(keyHex)))

        coVerify(exactly = 1) { callback.onPairingConfirmationRequired("desktop", any(), any()) }
        val answer = JSONObject(String(desktop.decrypt(reassemble(fragments).single())))
        assertEquals(ErrorCodes.PAIRING_REJECTED, answer.getJSONObject("error").getInt("code"))
        assertEquals(false, getField<Boolean>("pairingConfirmed"))
        assertFalse(repo.isDeviceKnown(keyHex))
        coVerify(exactly = 0) { requestHandler.handleRawRequest(any<ByteArray>()) }
    }

    /**
     * Once the paired desktop is removed, a `pairing.confirm` on its old
     * session is not answered confirmed: nothing is sent, prompted or routed.
     */
    @Test
    fun aRevokedSessionsPairingConfirmIsNotAnswered() = runBlocking<Unit> {
        val desktop = NoiseInitiatorSession(randomKey())
        val keyHex = desktop.getLocalStaticPublicKey().hex()
        repo.addDevice(keyHex, "desktop")
        reconnect(desktop, claimedPeerKeyHex = keyHex)
        val fragments = captureFragments()
        val confirm = desktop.encrypt(pairingConfirm(keyHex))

        repo.removeDevice(keyHex)
        call("handleApplicationMessage", device, confirm)

        assertEquals(false, getField<Boolean>("pairingConfirmed"))
        assertTrue("nothing is answered on a revoked session", fragments.isEmpty())
        coVerify(exactly = 0) { callback.onPairingConfirmationRequired(any(), any(), any()) }
        coVerify(exactly = 0) { requestHandler.handleRawRequest(any<ByteArray>()) }
        assertFalse(repo.isDeviceKnown(keyHex))
    }

    // ---------------------------------------------------------------------
    // Connection-scoped sends
    // ---------------------------------------------------------------------

    /**
     * A send scoped to the current confirmed connection goes out on that
     * connection's own session, and its desktop decrypts the request.
     */
    @Test
    fun aScopedSendOnTheCurrentConfirmedConnectionReachesItsDesktop() = runBlocking<Unit> {
        val desktop = NoiseInitiatorSession(randomKey())
        val keyHex = desktop.getLocalStaticPublicKey().hex()
        repo.addDevice(keyHex, "desktop")
        reconnect(desktop, claimedPeerKeyHex = keyHex)
        val confirmed = server.confirmedConnection() ?: error("the connection confirms no one")
        // The only scoped send path: a sender bound to this connection.
        val bound = server.boundSender()?.second ?: error("no bound sender")
        assertEquals(keyHex, confirmed.peerPublicKeyHex)
        val fragments = captureFragments()

        bound.sendEncryptedMessageOn(confirmed, BACKUP_REQUEST)

        val request = JSONObject(String(desktop.decrypt(reassemble(fragments).single())))
        assertEquals("remote.backup.create", request.getString("method"))
    }

    /**
     * Another paired desktop reconnects on the same transport before the
     * send: the send scoped to the first desktop's connection is refused and
     * nothing is encrypted to the new one.
     */
    @Test
    fun aScopedSendAfterAnotherDesktopReconnectedIsRefused() = runBlocking<Unit> {
        val first = NoiseInitiatorSession(randomKey())
        val firstHex = first.getLocalStaticPublicKey().hex()
        repo.addDevice(firstHex, "desktop")
        reconnect(first, claimedPeerKeyHex = firstHex)
        val confirmed = server.confirmedConnection() ?: error("the connection confirms no one")
        // The only scoped send path: a sender bound to this connection.
        val bound = server.boundSender()?.second ?: error("no bound sender")

        val second = NoiseInitiatorSession(randomKey())
        val secondHex = second.getLocalStaticPublicKey().hex()
        repo.addDevice(secondHex, "second desktop")
        val replacement = reconnect(second, claimedPeerKeyHex = secondHex)
        val nonce = replacement.sendNonceForTest()

        val outcome = runCatching { bound.sendEncryptedMessageOn(confirmed, BACKUP_REQUEST) }

        assertTrue("got $outcome", outcome.exceptionOrNull() is ConnectionChangedException)
        assertEquals("nothing is encrypted to the new desktop", nonce, replacement.sendNonceForTest())
        assertNoNotification()
    }

    /**
     * The reconnect lands after the early check and before encryption:
     * admission itself refuses the send, and the desktop that reconnected
     * receives nothing.
     */
    @Test
    fun aScopedSendReplacedAfterTheEarlyCheckIsRefusedAtAdmission() = runBlocking<Unit> {
        val first = NoiseInitiatorSession(randomKey())
        val firstHex = first.getLocalStaticPublicKey().hex()
        repo.addDevice(firstHex, "desktop")
        reconnect(first, claimedPeerKeyHex = firstHex)
        val confirmed = server.confirmedConnection() ?: error("the connection confirms no one")
        // The only scoped send path: a sender bound to this connection.
        val bound = server.boundSender()?.second ?: error("no bound sender")

        val second = NoiseInitiatorSession(randomKey())
        val secondHex = second.getLocalStaticPublicKey().hex()
        repo.addDevice(secondHex, "second desktop")
        var replacement: NoiseSession? = null
        var nonce = -1L
        server.beforeAdmissionForTest = {
            if (replacement == null) {
                replacement = reconnect(second, claimedPeerKeyHex = secondHex)
                nonce = replacement!!.sendNonceForTest()
            }
        }

        val outcome = runCatching {
            withTimeout(TIMEOUT_MS) { bound.sendEncryptedMessageOn(confirmed, BACKUP_REQUEST) }
        }
        server.beforeAdmissionForTest = null

        val late = replacement ?: error("the second desktop never reconnected")
        assertTrue("got $outcome", outcome.exceptionOrNull() is ConnectionChangedException)
        assertEquals("nothing is encrypted to the new desktop", nonce, late.sendNonceForTest())
        assertNoNotification()
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    /**
     * Runs msg1 and msg2 of a handshake with [desktop] on a fresh responder
     * and installs it as the connecting session, as the identity exchange
     * leaves it.
     */
    private suspend fun startHandshake(desktop: NoiseInitiatorSession, claimedPeerKeyHex: String): NoiseSession {
        val session = NoiseSession().also { it.loadStaticKey(context) }
        val msg2 = session.processHandshakeMessage(desktop.createHandshakeMessage1())
            ?: throw AssertionError("the responder produced no msg2")
        desktop.processHandshakeMessage2(msg2)
        setField("connectedDevice", device)
        setField("noiseSession", session)
        setField("remotePublicKeyHex", claimedPeerKeyHex)
        setField("authenticatedPeerKeyHex", null)
        setField("identityExchangeComplete", true)
        setField("pairingConfirmed", false)
        getField<ConcurrentHashMap<String, Int>>("deviceMtu")[ADDRESS] = 247
        getField<ConcurrentHashMap<String, Boolean>>("notificationEnabled")[ADDRESS] = true
        getField<ConcurrentHashMap<String, CompletableDeferred<Unit>>>("notificationReady")[ADDRESS] =
            CompletableDeferred(Unit)
        getField<MutableStateFlow<ConnectionState>>("_connectionState").value = ConnectionState.Connecting
        return session
    }

    /** Completes a handshake with [desktop], its msg3 through the server, and returns the responder. */
    private suspend fun reconnect(desktop: NoiseInitiatorSession, claimedPeerKeyHex: String): NoiseSession {
        val session = startHandshake(desktop, claimedPeerKeyHex)
        call("handleHandshakeMessage", device, desktop.createHandshakeMessage3())
        desktop.finalizeHandshake()
        assertTrue("the handshake completed", server.isSessionEstablished())
        return session
    }

    /** Records every fragment written to the response characteristic, in order. */
    private fun captureFragments(): List<ByteArray> {
        val fragments = CopyOnWriteArrayList<ByteArray>()
        val characteristic = mockk<BluetoothGattCharacteristic>(relaxed = true)
        every { characteristic.setValue(any<ByteArray>()) } answers {
            fragments.add(firstArg<ByteArray>().copyOf())
            true
        }
        setField("responseCharacteristic", characteristic)
        return fragments
    }

    /** Reassembles [fragments] into the frames they carried. */
    private fun reassemble(fragments: List<ByteArray>): List<ByteArray> {
        val reassembler = FragmentReassembler()
        return fragments.mapNotNull { reassembler.addFragment(it) }
    }

    /** Calls the private suspend member [name] of the server, as its GATT callbacks do. */
    private suspend fun call(name: String, vararg args: Any?): Any? =
        suspendCoroutineUninterceptedOrReturn { continuation ->
            val method = GattServer::class.java.declaredMethods
                .single { it.name == name && it.parameterCount == args.size + 1 }
                .apply { isAccessible = true }
            try {
                method.invoke(server, *args, continuation)
            } catch (e: InvocationTargetException) {
                throw e.targetException
            }
        }

    private fun assertNoNotification() {
        verify(exactly = 0) { gatt.notifyCharacteristicChanged(any(), any(), any()) }
        verify(exactly = 0) { gatt.notifyCharacteristicChanged(any(), any(), any(), any<ByteArray>()) }
    }

    private fun eventually(what: String, check: () -> Boolean) {
        val deadline = System.currentTimeMillis() + TIMEOUT_MS
        while (!check()) {
            if (System.currentTimeMillis() > deadline) fail("timed out waiting until $what")
            Thread.sleep(10)
        }
    }

    private fun setField(name: String, value: Any?) {
        GattServer::class.java.getDeclaredField(name).apply { isAccessible = true }.set(server, value)
    }

    @Suppress("UNCHECKED_CAST")
    private fun <T> getField(name: String): T =
        GattServer::class.java.getDeclaredField(name).apply { isAccessible = true }.get(server) as T
}
