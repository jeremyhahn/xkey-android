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
import io.mockk.coEvery
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.runs
import io.mockk.unmockkAll
import io.mockk.verify
import java.security.SecureRandom
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test

/**
 * Each connection's GATT events are handled in the order they arrived (#63).
 * A write carrying the desktop's answer to a phone-initiated request, then a
 * disconnect, delivers the answer: the disconnect settles only what is still
 * unanswered, after the write is drained.
 *
 * The events go through the server's own GATT callback, each from its own
 * thread. The Noise lock is held while they are delivered, so neither can be
 * handled until both are queued; the old per-callback coroutines let the
 * disconnect settle every pending request in that window.
 */
@Suppress("DEPRECATION")
class GattServerEventOrderTest {

    private companion object {
        const val ADDRESS = "AA:BB:CC:DD:EE:FF"
        const val TIMEOUT_MS = 5_000L

        // Long enough for a disconnect handled out of order to have settled
        // the pending requests. The window is the check: the consumer waits
        // on the Noise lock, which shows no waiter, and "not settled" has no
        // event to await.
        const val SETTLE_MS = 300L

        // GattServer.EVENT_QUEUE_CAPACITY.
        const val EVENT_QUEUE_CAPACITY = 1024

        fun randomKey(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }

        fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }

        fun result(id: Long): ByteArray =
            """{"jsonrpc":"2.0","id":$id,"result":{"ok":true}}""".toByteArray()

        fun error(id: Long, message: String): ByteArray =
            """{"jsonrpc":"2.0","id":$id,"error":{"code":-32000,"message":"$message"}}""".toByteArray()
    }

    private lateinit var context: Context
    private lateinit var repo: PairedDeviceRepository
    private lateinit var requestHandler: RequestHandler
    private lateinit var router: BidirectionalMessageRouter
    private lateinit var gatt: BluetoothGattServer
    private lateinit var device: BluetoothDevice
    private lateinit var controlPoint: BluetoothGattCharacteristic
    private lateinit var server: GattServer
    private lateinit var desktop: NoiseInitiatorSession
    private lateinit var keyHex: String

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
        repo = PairedDeviceRepository(InMemorySharedPreferences())
        requestHandler = mockk(relaxed = true)
        router = BidirectionalMessageRouter(requestHandler)
        gatt = mockk(relaxed = true)
        every { gatt.notifyCharacteristicChanged(any(), any(), any()) } returns true
        every { gatt.notifyCharacteristicChanged(any(), any(), any(), any<ByteArray>()) } returns 0
        device = mockk(relaxed = true)
        every { device.address } returns ADDRESS
        controlPoint = mockk(relaxed = true)
        every { controlPoint.uuid } returns GattServer.CONTROL_POINT_UUID
        server = GattServer(
            context,
            requestHandler,
            messageRouter = router,
            pairingCallback = mockk(),
            pairedDeviceRepository = repo,
        )
        setField("gattServer", gatt)
        setField("responseCharacteristic", mockk<BluetoothGattCharacteristic>(relaxed = true))

        desktop = NoiseInitiatorSession(randomKey())
        keyHex = desktop.getLocalStaticPublicKey().hex()
        repo.addDevice(keyHex, "desktop")
        runBlocking { install(handshake(desktop)) }
    }

    @After
    fun tearDown() {
        server.destroy()
        awaitScopeFinished(server)
        unmockkAll()
    }

    /**
     * The #63 regression: the desktop writes its answer to a phone-initiated
     * `remote.*` request and disconnects. The caller gets the desktop's
     * result, not "Connection lost", and the request left unanswered is
     * settled only after it.
     */
    @Test
    fun aResultWrittenBeforeTheDisconnectReachesItsCaller() = runBlocking<Unit> {
        val settled = Collections.synchronizedList(mutableListOf<Long>())
        val answered = pending(7, settled)
        val unanswered = pending(8, settled)
        val frame = desktop.encrypt(result(7))

        withNoiseHeld {
            onThread { write(frame) }
            onThread { disconnect() }
            Thread.sleep(SETTLE_MS)
            assertFalse("nothing settles before the write is handled", answered.isCompleted)
            assertFalse("nothing settles before the write is handled", unanswered.isCompleted)
        }

        val response = withTimeout(TIMEOUT_MS) { answered.await() }
        assertNull("the caller gets the desktop's result: ${response.error}", response.error)
        assertEquals(true, response.result?.getBoolean("ok"))
        val lost = withTimeout(TIMEOUT_MS) { unanswered.await() }
        assertEquals("Connection lost", lost.error?.message)
        assertEquals("the unanswered request settles after the answer", listOf(7L, 8L), settled.toList())
        eventually("the disconnect is handled") { server.connectionState.value == ConnectionState.Disconnected }
        assertNoNotification()
    }

    /** A result and then an error, both before the disconnect: each caller gets the desktop's own. */
    @Test
    fun aResultAndAnErrorBeforeTheDisconnectBothReachTheirCallers() = runBlocking<Unit> {
        val first = pending(7)
        val second = pending(8)
        val frames = listOf(desktop.encrypt(result(7)), desktop.encrypt(error(8, "desktop refused")))

        withNoiseHeld {
            onThread { frames.forEach { write(it) } }
            onThread { disconnect() }
            Thread.sleep(SETTLE_MS)
        }

        val ok = withTimeout(TIMEOUT_MS) { first.await() }
        assertNull(ok.error)
        assertEquals(true, ok.result?.getBoolean("ok"))
        val refused = withTimeout(TIMEOUT_MS) { second.await() }
        assertNull(refused.result)
        assertEquals("desktop refused", refused.error?.message)
        assertEquals(-32000, refused.error?.code)
        assertNoNotification()
    }

    /**
     * A `local.verifyUser` prompt waits when the result to the phone's request
     * arrives, then the desktop disconnects: the result is delivered, the
     * prompt is cancelled with no user input, and nothing is written.
     */
    @Test
    fun aResultWhileAPromptWaitsIsDeliveredAndThePromptCancelled() = runBlocking<Unit> {
        val prompted = CompletableDeferred<Unit>()
        val cancelled = AtomicBoolean(false)
        coEvery { requestHandler.handleRawRequest(any<ByteArray>()) } coAnswers {
            prompted.complete(Unit)
            try {
                awaitCancellation()
            } finally {
                cancelled.set(true)
            }
        }
        val answered = pending(7)
        val verifyUser = desktop.encrypt(
            """{"jsonrpc":"2.0","id":9,"method":"local.verifyUser","params":{}}""".toByteArray()
        )
        val frame = desktop.encrypt(result(7))

        onThread { write(verifyUser) }
        withTimeout(TIMEOUT_MS) { prompted.await() }
        withNoiseHeld {
            onThread { write(frame) }
            onThread { disconnect() }
            Thread.sleep(SETTLE_MS)
            assertFalse("the prompt waits until the disconnect is handled", cancelled.get())
        }

        val response = withTimeout(TIMEOUT_MS) { answered.await() }
        assertNull(response.error)
        assertEquals(true, response.result?.getBoolean("ok"))
        eventually("the prompt is cancelled") { cancelled.get() }
        assertNoNotification()
    }

    /** A revocation while the desktop's result is queued: nothing is delivered from the revoked session. */
    @Test
    fun aRevocationWithAResultQueuedDeliversNothing() = runBlocking<Unit> {
        val answered = pending(7)
        val frame = desktop.encrypt(result(7))

        withNoiseHeld {
            onThread { write(frame) }
            Thread.sleep(SETTLE_MS)
            repo.removeDevice(keyHex)
            eventually("the revocation settles the request") { answered.isCompleted }
        }

        verify(timeout = TIMEOUT_MS) { gatt.cancelConnection(device) }
        val response = withTimeout(TIMEOUT_MS) { answered.await() }
        assertNull("a revoked session's result is not delivered", response.result)
        assertNotNull(response.error)
        eventually("the session is torn down") { getField<NoiseSession?>("noiseSession") == null }
        // Its keys are zeroed under the Noise lock; let that finish before the mocks go.
        eventually("the session's keys are zeroed") {
            getField<NoiseSession?>("zeroedSession") != null && !getField<Mutex>("noiseMutex").isLocked
        }
        assertNoNotification()
    }

    /**
     * A peer that queues more events than the queue holds has its connection
     * ended, and the disconnect is still handled, though the queue was full.
     */
    @Test
    fun aFloodOfWritesEndsTheConnectionAndTheDisconnectIsStillSeen() = runBlocking<Unit> {
        val unanswered = pending(8)
        val frame = desktop.encrypt(result(7))

        withNoiseHeld {
            // The first write is taken by the consumer, which then waits on
            // the Noise lock while the rest fill the queue.
            onThread { write(frame) }
            Thread.sleep(SETTLE_MS)
            onThread { repeat(EVENT_QUEUE_CAPACITY + 1) { writeFragment(byteArrayOf(0)) } }
            verify(exactly = 1) { gatt.cancelConnection(device) }
            assertFalse(unanswered.isCompleted)
        }

        val lost = withTimeout(TIMEOUT_MS) { unanswered.await() }
        assertEquals("Connection lost", lost.error?.message)
        eventually("the disconnect is handled") {
            server.connectionState.value == ConnectionState.Disconnected &&
                getField<BluetoothDevice?>("connectedDevice") == null
        }

        // The stack's own disconnect, after the flood, changes nothing.
        onThread { disconnect() }
        assertNull(getField<NoiseSession?>("noiseSession"))
        assertNoNotification()
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    /** Completes a handshake between [desktop] and a fresh responder, and returns the responder. */
    private suspend fun handshake(desktop: NoiseInitiatorSession): NoiseSession {
        val session = NoiseSession().also { it.loadStaticKey(context) }
        val msg2 = session.processHandshakeMessage(desktop.createHandshakeMessage1())
            ?: throw AssertionError("the responder produced no msg2")
        desktop.processHandshakeMessage2(msg2)
        session.processHandshakeMessage(desktop.createHandshakeMessage3())
        desktop.finalizeHandshake()
        return session
    }

    /**
     * Installs a confirmed session with [keyHex]'s desktop, as a completed
     * connection leaves it, on a connection the stack's connect opened: only
     * a connect opens the queue the writes go to (Codex 7527).
     */
    private fun install(session: NoiseSession) {
        callback.onConnectionStateChange(device, 0, BluetoothProfile.STATE_CONNECTED)
        eventually("the connect is handled") { server.connectionState.value == ConnectionState.Connecting }
        setField("connectedDevice", device)
        setField("noiseSession", session)
        setField("establishedSession", session)
        setField("remotePublicKeyHex", keyHex)
        setField("authenticatedPeerKeyHex", keyHex)
        setField("identityExchangeComplete", true)
        setField("pairingConfirmed", true)
        getField<ConcurrentHashMap<String, Int>>("deviceMtu")[ADDRESS] = 247
        getField<ConcurrentHashMap<String, FragmentReassembler>>("fragmentBuffer")[ADDRESS] = FragmentReassembler()
        getField<ConcurrentHashMap<String, Boolean>>("notificationEnabled")[ADDRESS] = true
        getField<ConcurrentHashMap<String, CompletableDeferred<Unit>>>("notificationReady")[ADDRESS] =
            CompletableDeferred(Unit)
        getField<MutableStateFlow<ConnectionState>>("_connectionState").value =
            ConnectionState.Connected("desktop", ADDRESS)
    }

    /** A phone-initiated request [id] waiting on the desktop, as RemoteKeyClient registers one. */
    private fun pending(id: Long, settled: MutableList<Long>? = null): CompletableDeferred<Response> =
        CompletableDeferred<Response>().also { deferred ->
            settled?.let { order -> deferred.invokeOnCompletion { order.add(id) } }
            router.registerPendingResponse(id, deferred)
        }

    /** Holds the Noise lock while [block] runs, so no queued write can be decrypted. */
    private suspend fun withNoiseHeld(block: () -> Unit) {
        val noise = getField<Mutex>("noiseMutex")
        noise.lock()
        try {
            block()
        } finally {
            noise.unlock()
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

    /** Writes [frame] to the control point, fragment by fragment. */
    private fun write(frame: ByteArray) {
        Fragmenter(200).fragment(frame).forEach { writeFragment(it) }
    }

    private fun writeFragment(fragment: ByteArray) {
        callback.onCharacteristicWriteRequest(device, 1, controlPoint, false, false, 0, fragment)
    }

    private fun disconnect() {
        callback.onConnectionStateChange(device, 0, BluetoothProfile.STATE_DISCONNECTED)
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
