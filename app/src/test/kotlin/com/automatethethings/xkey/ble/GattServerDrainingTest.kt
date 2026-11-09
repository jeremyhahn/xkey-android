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
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothProfile
import android.content.Context
import android.util.Log
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.protocol.Response
import com.automatethethings.xkey.remote.BidirectionalMessageRouter
import com.automatethethings.xkey.settings.InMemorySharedPreferences
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.settings.PeerNotPairedException
import io.mockk.coEvery
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.runs
import io.mockk.spyk
import io.mockk.unmockkAll
import io.mockk.verify
import java.io.IOException
import java.security.SecureRandom
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Once a connection's disconnect is seen, its queued events still drain and
 * its session still decrypts the replies among them, but nothing more is
 * sent on it: a send is refused at admission, before anything is encrypted,
 * and a frame the stack refuses while it drains ends nothing early. The same
 * holds for every frame the phone sends unencrypted: the identity
 * acknowledgement, the handshake reply and the status notification.
 *
 * A CCCD read answers with the latest CCCD write of the connection that took
 * it, before its consumer has published the connection and while a reconnect
 * waits for the previous consumer to drain.
 */
@Suppress("DEPRECATION")
class GattServerDrainingTest {

    private companion object {
        const val ADDRESS = "AA:BB:CC:DD:EE:FF"
        const val MTU = 247
        const val TIMEOUT_MS = 5_000L

        // Long enough for a coroutine to reach the lock it waits on, or for a
        // send that was let through to have gone out. The wait is the check,
        // not a stand-in for a signal: a Mutex shows no waiter, and "nothing
        // is sent" has no event to await.
        const val SETTLE_MS = 300L

        val ENABLE = byteArrayOf(0x01, 0x00)
        val DISABLE = byteArrayOf(0x00, 0x00)

        fun randomKey(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }

        fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }

        fun result(id: Long): ByteArray =
            """{"jsonrpc":"2.0","id":$id,"result":{"ok":true}}""".toByteArray()

        fun request(id: Long, method: String): ByteArray =
            """{"jsonrpc":"2.0","id":$id,"method":"$method","params":{}}""".toByteArray()
    }

    private lateinit var context: Context
    private lateinit var repo: PairedDeviceRepository
    private lateinit var requestHandler: RequestHandler
    private lateinit var router: BidirectionalMessageRouter
    private lateinit var gatt: BluetoothGattServer
    private lateinit var device: BluetoothDevice
    private lateinit var controlPoint: BluetoothGattCharacteristic
    private lateinit var status: BluetoothGattCharacteristic
    private lateinit var cccd: BluetoothGattDescriptor
    private lateinit var server: GattServer
    private lateinit var desktop: NoiseInitiatorSession
    private val fragments = Collections.synchronizedList(mutableListOf<ByteArray>())

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

        context = mockk(relaxed = true)
        repo = spyk(PairedDeviceRepository(InMemorySharedPreferences()))
        requestHandler = mockk(relaxed = true)
        router = BidirectionalMessageRouter(requestHandler)
        gatt = mockk(relaxed = true)
        every { gatt.notifyCharacteristicChanged(any(), any(), any()) } returns true
        every { gatt.notifyCharacteristicChanged(any(), any(), any(), any<ByteArray>()) } returns 0
        device = mockk(relaxed = true)
        every { device.address } returns ADDRESS
        controlPoint = mockk(relaxed = true)
        every { controlPoint.uuid } returns GattServer.CONTROL_POINT_UUID
        status = mockk(relaxed = true)
        every { status.uuid } returns GattServer.STATUS_UUID
        cccd = mockk(relaxed = true)
        every { cccd.uuid } returns GattServer.CCCD_UUID
        val response = mockk<BluetoothGattCharacteristic>(relaxed = true)
        every { response.setValue(any<ByteArray>()) } answers {
            fragments.add(firstArg<ByteArray>().copyOf())
            true
        }

        server = GattServer(
            context,
            requestHandler,
            messageRouter = router,
            pairingCallback = mockk(),
            pairedDeviceRepository = repo,
        )
        setField("gattServer", gatt)
        setField("responseCharacteristic", response)
        setField("statusCharacteristic", status)
        desktop = NoiseInitiatorSession(randomKey())
    }

    @After
    fun tearDown() {
        server.beforeAdmissionForTest = null
        server.afterAdmissionForTest = null
        server.destroy()
        awaitScopeFinished(server)
        unmockkAll()
    }

    // ---------------------------------------------------------------------
    // Finding 1: no new sends once a connection drains
    // ---------------------------------------------------------------------

    /**
     * The case: notifications enabled, the desktop's reply queued,
     * then the disconnect. A phone-initiated send while the reply drains is
     * refused at admission: it encrypts nothing and notifies nothing, and the
     * reply still reaches its caller.
     */
    @Test
    fun aSendWhileTheConnectionDrainsIsRefusedAndTheQueuedReplyDelivered() = runBlocking<Unit> {
        val session = install()
        val answered = pending(7)
        val reply = desktop.encrypt(result(7))
        val atAdmission = CompletableDeferred<Unit>()
        server.beforeAdmissionForTest = { atAdmission.complete(Unit) }

        withStateHeld {
            val send = withNoiseHeld {
                onThread { write(reply) }
                onThread { disconnect() }
                // The consumer waits on the Noise lock to decrypt the reply.
                Thread.sleep(SETTLE_MS)
                val send = async(Dispatchers.Default) {
                    runCatching { server.sendEncryptedMessage(request(9, "remote.sign")) }
                }
                withTimeout(TIMEOUT_MS) { atAdmission.await() }
                // The send waits on the Noise lock behind the consumer.
                Thread.sleep(SETTLE_MS)
                send
            }
            val refused = withTimeout(TIMEOUT_MS) { send.await() }.exceptionOrNull()
            assertTrue("the send is refused: $refused", refused is IOException && refused !is PeerNotPairedException)
            assertTrue("it is refused as closing: ${refused?.message}", refused?.message?.contains("closing") == true)

            val response = withTimeout(TIMEOUT_MS) { answered.await() }
            assertNull("the reply reaches its caller: ${response.error}", response.error)
            assertEquals(true, response.result?.getBoolean("ok"))
        }

        eventually("the drain finishes") { getField<NoiseSession?>("noiseSession") == null }
        assertNoNotification()
        // Nothing was encrypted for the refused send: the session's next frame
        // is the next one the desktop expects.
        val probe = "probe".toByteArray()
        assertArrayEquals(probe, desktop.decrypt(session.encrypt(probe)))
    }

    /**
     * A send admitted before the disconnect, whose notification the stack
     * refuses once the connection drains, does not end the session early:
     * the request whose reply is queued is not settled as lost, and the
     * reply still reaches it.
     */
    @Test
    fun aNotificationRefusedWhileDrainingCancelsNoQueuedReply() = runBlocking<Unit> {
        install()
        every { gatt.notifyCharacteristicChanged(any(), any(), any()) } returns false
        every { gatt.notifyCharacteristicChanged(any(), any(), any(), any<ByteArray>()) } returns 1
        val answered = pending(7)
        val reply = desktop.encrypt(result(7))
        val noise = getField<Mutex>("noiseMutex")
        server.afterAdmissionForTest = {
            // Encrypted, not yet delivered: the reply arrives, then the
            // disconnect, and neither is handled until the lock is let go.
            noise.lock()
            onThread { write(reply) }
            onThread { disconnect() }
        }

        val failed = runCatching { server.sendEncryptedMessage(request(9, "remote.sign")) }.exceptionOrNull()
        server.afterAdmissionForTest = null
        try {
            assertTrue("the undelivered frame fails its send: $failed", failed is IOException)
            Thread.sleep(SETTLE_MS)
            assertFalse("the queued reply's request is not settled as lost", answered.isCompleted)
        } finally {
            noise.unlock()
        }

        val response = withTimeout(TIMEOUT_MS) { answered.await() }
        assertNull("the reply reaches its caller: ${response.error}", response.error)
        assertEquals(true, response.result?.getBoolean("ok"))
        eventually("the drain finishes") { getField<NoiseSession?>("noiseSession") == null }
    }

    /**
     * The answer to a desktop request, built while the connection was open,
     * is refused at admission when the disconnect lands after the answer was
     * built: nothing is written to a peer that has gone.
     */
    @Test
    fun anAnswerWhoseDisconnectLandsBeforeAdmissionIsNotSent() = runBlocking<Unit> {
        install()
        coEvery { requestHandler.handleRawRequest(any<ByteArray>()) } returns result(9)
        val atAdmission = CountDownLatch(1)
        server.beforeAdmissionForTest = {
            onThread { disconnect() }
            atAdmission.countDown()
        }

        withStateHeld {
            onThread { write(desktop.encrypt(request(9, "local.ping"))) }
            assertTrue("the answer reaches admission", atAdmission.await(TIMEOUT_MS, TimeUnit.MILLISECONDS))
            Thread.sleep(SETTLE_MS)
        }

        eventually("the drain finishes") { getField<NoiseSession?>("noiseSession") == null }
        assertNoNotification()
    }

    /** An identity acknowledgement whose disconnect lands while it is built is not sent. */
    @Test
    fun anIdentityAcknowledgementAfterTheDisconnectIsNotSent() {
        connect()
        cccdWrite(ENABLE)
        val lookingUp = CountDownLatch(1)
        val release = CountDownLatch(1)
        every { repo.getDevice(any()) } answers {
            lookingUp.countDown()
            release.await(TIMEOUT_MS, TimeUnit.MILLISECONDS)
            callOriginal()
        }

        write(byteArrayOf(0x01) + desktop.getLocalStaticPublicKey())
        assertTrue("the identity frame is being handled", lookingUp.await(TIMEOUT_MS, TimeUnit.MILLISECONDS))
        disconnect()
        release.countDown()

        eventually("the drain finishes") { getField<NoiseSession?>("noiseSession") == null }
        Thread.sleep(SETTLE_MS)
        assertEquals("nothing is sent for the ended connection", 0, messages().size)
    }

    /** A handshake reply whose disconnect lands while the handshake runs is not sent. */
    @Test
    fun aHandshakeReplyAfterTheDisconnectIsNotSent() = runBlocking<Unit> {
        connect()
        cccdWrite(ENABLE)
        setField("identityExchangeComplete", true)

        withNoiseHeld {
            onThread { write(desktop.createHandshakeMessage1()) }
            // The consumer waits on the Noise lock to process the handshake.
            Thread.sleep(SETTLE_MS)
            onThread { disconnect() }
        }

        eventually("the drain finishes") { getField<NoiseSession?>("noiseSession") == null }
        Thread.sleep(SETTLE_MS)
        assertEquals("nothing is sent for the ended connection", 0, messages().size)
    }

    /** A handshake completed while its connection drains sends no status notification. */
    @Test
    fun aHandshakeCompletedAfterTheDisconnectNotifiesNoStatus() = runBlocking<Unit> {
        connect()
        cccdWrite(ENABLE)
        setField("identityExchangeComplete", true)
        write(desktop.createHandshakeMessage1())
        eventually("the handshake reply is sent") { messages().isNotEmpty() }
        desktop.processHandshakeMessage2(messages()[0])

        withNoiseHeld {
            onThread { write(desktop.createHandshakeMessage3()) }
            Thread.sleep(SETTLE_MS)
            onThread { disconnect() }
        }

        eventually("the drain finishes") { getField<NoiseSession?>("noiseSession") == null }
        Thread.sleep(SETTLE_MS)
        verify(exactly = 0) { gatt.notifyCharacteristicChanged(device, status, any()) }
        verify(exactly = 0) { gatt.notifyCharacteristicChanged(device, status, any(), any<ByteArray>()) }
    }

    // ---------------------------------------------------------------------
    // Finding 2: the CCCD read comes from the connection that took the write
    // ---------------------------------------------------------------------

    /**
     * A CCCD enable written before the consumer has published its connection
     * reads back enabled, and so does every later read until a disable.
     */
    @Test
    fun aCccdEnableWrittenBeforePublicationReadsEnabled() {
        withStateHeld {
            callback.onConnectionStateChange(device, 0, BluetoothProfile.STATE_CONNECTED)
            assertCccdRead(DISABLE, requestId = 3)
            cccdWrite(ENABLE, requestId = 4, responseNeeded = true)
            verify { gatt.sendResponse(device, 4, BluetoothGatt.GATT_SUCCESS, 0, null) }
            assertNull("the enable is not yet published", published()[ADDRESS])
            assertCccdRead(ENABLE, requestId = 5)
        }

        eventually("the connect is handled") { getField<NoiseSession?>("noiseSession") != null }
        assertCccdRead(ENABLE, requestId = 6)
        cccdWrite(DISABLE)
        assertCccdRead(DISABLE, requestId = 7)
    }

    /**
     * A reconnect while the previous consumer drains: a read answers with
     * the new connection's CCCD state, never the previous connection's.
     */
    @Test
    fun aReconnectWhileTheOldConsumerDrainsReadsItsOwnCccd() {
        connect()
        cccdWrite(ENABLE)
        eventually("the enable is published") { published()[ADDRESS] == true }
        assertCccdRead(ENABLE, requestId = 3)
        val first = getField<NoiseSession?>("noiseSession")

        withStateHeld {
            disconnect()
            callback.onConnectionStateChange(device, 0, BluetoothProfile.STATE_CONNECTED)
            assertEquals("the previous connection's enable is still published", true, published()[ADDRESS])
            assertCccdRead(DISABLE, requestId = 4)
            cccdWrite(ENABLE)
            assertCccdRead(ENABLE, requestId = 5)
            cccdWrite(DISABLE)
            assertCccdRead(DISABLE, requestId = 6)
        }

        eventually("the reconnect is handled") {
            getField<NoiseSession?>("noiseSession").let { it != null && it !== first }
        }
        assertCccdRead(DISABLE, requestId = 7)
        cccdWrite(ENABLE)
        assertCccdRead(ENABLE, requestId = 8)
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    /**
     * Installs a confirmed session with a paired desktop on a connection the
     * stack's connect opened, notifications enabled, and returns the session.
     */
    private suspend fun install(): NoiseSession {
        val keyHex = desktop.getLocalStaticPublicKey().hex()
        repo.addDevice(keyHex, "desktop")
        val session = NoiseSession().also { it.loadStaticKey(context) }
        val msg2 = session.processHandshakeMessage(desktop.createHandshakeMessage1())
            ?: throw AssertionError("the responder produced no msg2")
        desktop.processHandshakeMessage2(msg2)
        session.processHandshakeMessage(desktop.createHandshakeMessage3())
        desktop.finalizeHandshake()

        connect()
        cccdWrite(ENABLE)
        setField("noiseSession", session)
        setField("establishedSession", session)
        setField("remotePublicKeyHex", keyHex)
        setField("authenticatedPeerKeyHex", keyHex)
        setField("identityExchangeComplete", true)
        setField("pairingConfirmed", true)
        getField<MutableStateFlow<ConnectionState>>("_connectionState").value =
            ConnectionState.Connected("desktop", ADDRESS)
        return session
    }

    /** A phone-initiated request [id] waiting on the desktop, as RemoteKeyClient registers one. */
    private fun pending(id: Long): CompletableDeferred<Response> =
        CompletableDeferred<Response>().also { router.registerPendingResponse(id, it) }

    /** Holds the Noise lock while [block] runs, so no queued frame can be decrypted. */
    private suspend fun <T> withNoiseHeld(block: suspend () -> T): T {
        val noise = getField<Mutex>("noiseMutex")
        noise.lock()
        try {
            return block()
        } finally {
            noise.unlock()
        }
    }

    /** Holds the state lock while [block] runs, so a consumer cannot settle a connect or a disconnect. */
    private inline fun <T> withStateHeld(block: () -> T): T {
        val state = getField<Mutex>("stateMutex")
        runBlocking { state.lock() }
        try {
            return block()
        } finally {
            state.unlock()
        }
    }

    /** Runs [block] on a thread of its own, as the binder delivers a callback, and waits for it to return. */
    private fun onThread(block: () -> Unit) {
        var failure: Throwable? = null
        val thread = Thread { runCatching(block).onFailure { failure = it } }
        thread.start()
        thread.join(TIMEOUT_MS)
        failure?.let { throw it }
    }

    private val callback: BluetoothGattServerCallback
        get() = getField("gattCallback")

    private fun connect() {
        callback.onConnectionStateChange(device, 0, BluetoothProfile.STATE_CONNECTED)
        callback.onMtuChanged(device, MTU)
        eventually("the connect is handled") {
            getField<BluetoothDevice?>("connectedDevice") != null && getField<NoiseSession?>("noiseSession") != null
        }
    }

    private fun disconnect() {
        callback.onConnectionStateChange(device, 0, BluetoothProfile.STATE_DISCONNECTED)
    }

    private fun cccdWrite(value: ByteArray, requestId: Int = 1, responseNeeded: Boolean = false) {
        callback.onDescriptorWriteRequest(device, requestId, cccd, false, responseNeeded, 0, value)
    }

    /** The CCCD state published for a waiting send, which a descriptor read no longer answers from. */
    private fun published(): ConcurrentHashMap<String, Boolean> = getField("notificationEnabled")

    /** Reads the CCCD as request [requestId] and checks it is answered with [expected]. */
    private fun assertCccdRead(expected: ByteArray, requestId: Int) {
        callback.onDescriptorReadRequest(device, requestId, 0, cccd)
        verify {
            gatt.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, match { it.contentEquals(expected) })
        }
    }

    /** Writes [frame] to the control point, fragment by fragment. */
    private fun write(frame: ByteArray) {
        Fragmenter(200).fragment(frame).forEach {
            callback.onCharacteristicWriteRequest(device, 1, controlPoint, false, false, 0, it)
        }
    }

    /** The whole messages notified on the response characteristic so far, reassembled. */
    private fun messages(): List<ByteArray> {
        val reassembler = FragmentReassembler()
        return synchronized(fragments) { fragments.toList() }.mapNotNull { reassembler.addFragment(it) }
    }

    private fun assertNoNotification() {
        verify(exactly = 0) { gatt.notifyCharacteristicChanged(any(), any(), any()) }
        verify(exactly = 0) { gatt.notifyCharacteristicChanged(any(), any(), any(), any<ByteArray>()) }
    }

    private fun eventually(what: String, check: () -> Boolean) {
        val deadline = System.currentTimeMillis() + TIMEOUT_MS
        while (!check()) {
            if (System.currentTimeMillis() > deadline) throw AssertionError("timed out waiting until $what")
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
