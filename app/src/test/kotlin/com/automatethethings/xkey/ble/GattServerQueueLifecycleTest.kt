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
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.settings.InMemorySharedPreferences
import com.automatethethings.xkey.settings.PairedDeviceRepository
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mockk.verify
import java.security.SecureRandom
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * A connection's event queue lives from its STATE_CONNECTED to its
 * disconnect, and no callback outlives it (Codex 7527 on #63).
 *
 * Only a connect opens a queue. A write, read, MTU or CCCD callback that
 * finds no open queue (after the disconnect, an overflow or `destroy()`) is
 * dropped, and one that expects a response is refused. Each test ends with
 * no queue and no coroutine left: a consumer that waited on a queue nobody
 * would end held its device until the server was destroyed.
 */
@Suppress("DEPRECATION")
class GattServerQueueLifecycleTest {

    private companion object {
        const val ADDRESS = "AA:BB:CC:DD:EE:FF"
        const val MTU = 247
        const val OTHER_MTU = 185
        const val TIMEOUT_MS = 5_000L

        // GattServer.EVENT_QUEUE_CAPACITY.
        const val EVENT_QUEUE_CAPACITY = 1024

        // GattServer.NOTIFICATION_READY_TIMEOUT_MS and DRAIN_DEADLINE_MS.
        const val NOTIFICATION_READY_TIMEOUT_MS = 5_000L

        // Well inside the five-second waits, so what happens in it was not
        // caused by one expiring.
        const val PROMPTLY_MS = 2_000L

        // Long enough for the consumer to reach a wait, or to have handled an
        // event. The wait is the check: a consumer blocked on a lock shows no
        // signal, and "nothing reopened" or "nothing sent" has no event to await.
        const val SETTLE_MS = 300L

        val ENABLE = byteArrayOf(0x01, 0x00)

        fun randomKey(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }
    }

    private lateinit var context: Context
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

        context = mockk(relaxed = true)
        gatt = mockk(relaxed = true)
        every { gatt.notifyCharacteristicChanged(any(), any(), any()) } returns true
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
            mockk<RequestHandler>(relaxed = true),
            pairingCallback = mockk(),
            pairedDeviceRepository = PairedDeviceRepository(InMemorySharedPreferences()),
        )
        setField("gattServer", gatt)
        setField("responseCharacteristic", response)
        desktop = NoiseInitiatorSession(randomKey())
    }

    @After
    fun tearDown() {
        server.destroy()
        awaitScopeFinished(server)
        unmockkAll()
    }

    /**
     * The Codex 7527 regression: a write callback that resumes after the
     * disconnect callback, while the consumer is still settling it, opens no
     * queue. It is refused, and once the consumer has settled the disconnect
     * nothing is left.
     */
    @Test
    fun aWriteThatResumesAfterTheDisconnectOpensNoQueue() {
        connect()
        mtu(MTU)

        withStateHeld {
            disconnect()
            writeFragment(byteArrayOf(0x01), requestId = 7, responseNeeded = true)
            verify { gatt.sendResponse(device, 7, BluetoothGatt.GATT_FAILURE, 0, null) }
        }

        assertNothingRetained()
        assertNull(getField<BluetoothDevice?>("connectedDevice"))
        verify(exactly = 0) { gatt.sendResponse(device, 7, BluetoothGatt.GATT_SUCCESS, any(), any()) }
    }

    /** The same for an MTU callback: it opens no queue and sets no MTU. */
    @Test
    fun anMtuThatResumesAfterTheDisconnectOpensNoQueue() {
        connect()
        mtu(MTU)

        withStateHeld {
            disconnect()
            mtu(OTHER_MTU)
        }

        assertNothingRetained()
        assertNull(getField<ConcurrentHashMap<String, Int>>("deviceMtu")[ADDRESS])
    }

    /** Every callback after the disconnect has settled is refused or dropped, and opens nothing. */
    @Test
    fun everyCallbackAfterTheDisconnectIsRefused() {
        connect()
        mtu(MTU)
        disconnect()
        assertNothingRetained()

        writeFragment(byteArrayOf(0x01), requestId = 1, responseNeeded = true)
        cccdWrite(ENABLE, requestId = 2, responseNeeded = true)
        callback.onCharacteristicReadRequest(device, 3, 0, status)
        callback.onDescriptorReadRequest(device, 4, 0, cccd)
        mtu(OTHER_MTU)

        for (requestId in 1..4) {
            verify { gatt.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, 0, null) }
        }
        verify(exactly = 0) { gatt.sendResponse(any(), any(), BluetoothGatt.GATT_SUCCESS, any(), any()) }
        assertNothingRetained()
        assertNull(getField<ConcurrentHashMap<String, Boolean>>("notificationEnabled")[ADDRESS])
    }

    /** After destroy(), a connect and everything after it open nothing and answer nothing. */
    @Test
    fun callbacksAfterDestroyOpenNothing() {
        connect()
        server.destroy()
        awaitScopeFinished(server)

        callback.onConnectionStateChange(device, 0, BluetoothProfile.STATE_CONNECTED)
        mtu(MTU)
        writeFragment(byteArrayOf(0x01), requestId = 1, responseNeeded = true)
        cccdWrite(ENABLE, requestId = 2, responseNeeded = true)
        Thread.sleep(SETTLE_MS)

        assertEquals("no queue opens after destroy()", 0, queueCount())
        assertEquals("no consumer starts after destroy()", 0, coroutineCount())
        assertNull(getField<BluetoothDevice?>("connectedDevice"))
        verify(exactly = 0) { gatt.sendResponse(any(), any(), BluetoothGatt.GATT_SUCCESS, any(), any()) }
    }

    /**
     * An overflow ends the connection's queue for good: the writes after it
     * are refused, none reopens a queue, and only the next connect opens one.
     */
    @Test
    fun anOverflowEndsTheQueueAndLaterWritesAreRefused() {
        withStateHeld {
            // The consumer takes the connect and waits on the state lock
            // while the writes fill the queue.
            callback.onConnectionStateChange(device, 0, BluetoothProfile.STATE_CONNECTED)
            Thread.sleep(SETTLE_MS)
            repeat(EVENT_QUEUE_CAPACITY + 1) { writeFragment(byteArrayOf(0)) }
            verify(exactly = 1) { gatt.cancelConnection(device) }

            writeFragment(byteArrayOf(0), requestId = 9, responseNeeded = true)
            verify { gatt.sendResponse(device, 9, BluetoothGatt.GATT_FAILURE, 0, null) }
            mtu(MTU)
            assertEquals("only the overflowed queue, draining", 1, queueCount())
        }

        assertNothingRetained()
        writeFragment(byteArrayOf(0), requestId = 10, responseNeeded = true)
        verify { gatt.sendResponse(device, 10, BluetoothGatt.GATT_FAILURE, 0, null) }
        // The stack's own disconnect, after the overflow, has no queue to end.
        disconnect()
        assertNothingRetained()
        verify(exactly = 1) { gatt.cancelConnection(device) }
        verify(exactly = 0) { gatt.sendResponse(any(), any(), BluetoothGatt.GATT_SUCCESS, any(), any()) }

        connect()
        assertEquals("the next connect opens a queue", 1, queueCount())
    }

    /**
     * A disconnect and a reconnect while the old consumer still settles the
     * disconnect: the reconnect's events go to its own queue, which is
     * handled after the old one, so the old disconnect clears nothing of
     * the new connection.
     */
    @Test
    fun aReconnectWhileTheOldConsumerDrainsGetsAQueueOfItsOwn() {
        connect()
        mtu(MTU)
        val first = getField<NoiseSession?>("noiseSession")
        assertNotNull(first)

        withStateHeld {
            disconnect()
            callback.onConnectionStateChange(device, 0, BluetoothProfile.STATE_CONNECTED)
            mtu(OTHER_MTU)
            cccdWrite(ENABLE, requestId = 11, responseNeeded = true)
            verify { gatt.sendResponse(device, 11, BluetoothGatt.GATT_SUCCESS, 0, null) }
            assertEquals("the reconnect's queue replaced the old one", 1, queueCount())
        }

        eventually("the reconnect is handled") {
            getField<NoiseSession?>("noiseSession").let { it != null && it !== first }
        }
        eventually("its MTU is handled") { getField<ConcurrentHashMap<String, Int>>("deviceMtu")[ADDRESS] == OTHER_MTU }
        assertEquals(true, getField<ConcurrentHashMap<String, Boolean>>("notificationEnabled")[ADDRESS])
        assertEquals(1, queueCount())
        eventually("only the reconnect's consumer runs") { coroutineCount() == 1 }

        disconnect()
        assertNothingRetained()
    }

    /**
     * A connect with no disconnect before it, while the old consumer waits
     * to send: the old connection ends at once, and its waiting send is not
     * released by the new connection's enable.
     */
    @Test
    fun aConnectBeforeTheOldConsumerHasFinishedEndsIt() {
        connect()
        mtu(MTU)
        val first = getField<NoiseSession?>("noiseSession")
        assertNotNull(first)
        write(identityFrame())
        Thread.sleep(SETTLE_MS)

        val reconnected = System.currentTimeMillis()
        callback.onConnectionStateChange(device, 0, BluetoothProfile.STATE_CONNECTED)
        eventually("the new connect is handled") {
            getField<NoiseSession?>("noiseSession").let { it != null && it !== first }
        }
        val waited = System.currentTimeMillis() - reconnected
        assertTrue("the old wait ended at the connect, not its timeout: $waited", waited < PROMPTLY_MS)
        assertNotSame(first, getField<NoiseSession?>("noiseSession"))
        assertEquals(1, queueCount())
        eventually("only the new consumer runs") { coroutineCount() == 1 }

        cccdWrite(ENABLE)
        Thread.sleep(SETTLE_MS)
        assertEquals("the old connection's acknowledgement is not sent on the new one", 0, messages().size)

        disconnect()
        assertNothingRetained()
    }

    /**
     * A disconnect while a send waits on the CCCD enable ends the wait, the
     * consumer and its drain deadline at once, and an enable after it is
     * refused and sends nothing.
     */
    @Test
    fun aDisconnectWhileASendWaitsOnTheEnableLeavesNothing() {
        connect()
        mtu(MTU)
        write(identityFrame())
        Thread.sleep(SETTLE_MS)

        val disconnected = System.currentTimeMillis()
        disconnect()
        assertNothingRetained(PROMPTLY_MS)
        val waited = System.currentTimeMillis() - disconnected
        assertTrue("nothing waited for the $NOTIFICATION_READY_TIMEOUT_MS ms timeout: $waited", waited < PROMPTLY_MS)

        cccdWrite(ENABLE, requestId = 12, responseNeeded = true)
        verify { gatt.sendResponse(device, 12, BluetoothGatt.GATT_FAILURE, 0, null) }
        Thread.sleep(SETTLE_MS)
        assertEquals("nothing is sent for the ended connection", 0, messages().size)
        assertNothingRetained()
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    private val callback: BluetoothGattServerCallback
        get() = getField("gattCallback")

    private fun connect() {
        callback.onConnectionStateChange(device, 0, BluetoothProfile.STATE_CONNECTED)
        // The session is the last thing the connect sets, so a test comparing
        // sessions across a reconnect starts from this connection's own.
        eventually("the connect is handled") {
            getField<BluetoothDevice?>("connectedDevice") != null && getField<NoiseSession?>("noiseSession") != null
        }
    }

    private fun disconnect() {
        callback.onConnectionStateChange(device, 0, BluetoothProfile.STATE_DISCONNECTED)
    }

    private fun mtu(mtu: Int) {
        callback.onMtuChanged(device, mtu)
    }

    private fun cccdWrite(value: ByteArray, requestId: Int = 1, responseNeeded: Boolean = false) {
        callback.onDescriptorWriteRequest(device, requestId, cccd, false, responseNeeded, 0, value)
    }

    /** A desktop the phone has not paired with, announcing its key. */
    private fun identityFrame(): ByteArray = byteArrayOf(0x01) + desktop.getLocalStaticPublicKey()

    /** Writes [frame] to the control point, fragment by fragment. */
    private fun write(frame: ByteArray) {
        Fragmenter(200).fragment(frame).forEach { writeFragment(it) }
    }

    private fun writeFragment(fragment: ByteArray, requestId: Int = 1, responseNeeded: Boolean = false) {
        callback.onCharacteristicWriteRequest(device, requestId, controlPoint, false, responseNeeded, 0, fragment)
    }

    /** The whole messages notified so far, reassembled. */
    private fun messages(): List<ByteArray> {
        val reassembler = FragmentReassembler()
        return synchronized(fragments) { fragments.toList() }.mapNotNull { reassembler.addFragment(it) }
    }

    /** Holds the state lock while [block] runs, so a consumer cannot settle a connect or a disconnect. */
    private fun withStateHeld(block: () -> Unit) {
        val state = getField<Mutex>("stateMutex")
        runBlocking { state.lock() }
        try {
            block()
        } finally {
            state.unlock()
        }
    }

    private fun queueCount(): Int =
        synchronized(getField<Any>("eventQueuesLock")) { getField<Map<String, Any>>("eventQueues").size }

    /** The coroutines running on the server's scope: consumers, drain deadlines, requests. */
    private fun coroutineCount(): Int =
        getField<CoroutineScope>("scope").coroutineContext[Job]!!.children.count()

    /** No queue, no consumer and no drain deadline is left, nor does one appear after. */
    private fun assertNothingRetained(timeoutMs: Long = TIMEOUT_MS) {
        eventually("no queue and no coroutine is left", timeoutMs) { queueCount() == 0 && coroutineCount() == 0 }
        Thread.sleep(SETTLE_MS)
        assertEquals("no queue reopened", 0, queueCount())
        assertEquals("no coroutine started", 0, coroutineCount())
    }

    private fun eventually(what: String, timeoutMs: Long = TIMEOUT_MS, check: () -> Boolean) {
        val deadline = System.currentTimeMillis() + timeoutMs
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
