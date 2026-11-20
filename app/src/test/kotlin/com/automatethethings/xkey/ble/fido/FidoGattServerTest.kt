/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
 *
 * This file is part of xKey.
 *
 * xKey is dual-licensed:
 *
 * 1. GNU Affero General Public License v3.0 (AGPL-3.0)
 *    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
 *
 * 2. Commercial License
 *    Contact licensing@automatethethings.com for commercial licensing options.
 */

package com.automatethethings.xkey.ble.fido

import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.BluetoothStatusCodes
import android.content.Context
import android.os.Build
import com.automatethethings.xkey.crypto.CborDecoder
import com.automatethethings.xkey.testing.ReleaseMocks
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

/**
 * [FidoGattServer] driven through the GATT callbacks a Bluetooth stack calls:
 * control point writes in, fidoStatus notifications out, one at a time as the
 * stack reports each sent. The stack itself is a fake; the service table,
 * session, authenticator and framing are the real ones.
 */
@RunWith(RobolectricTestRunner::class)
class FidoGattServerTest {

    /** Drops what MockK recorded here, so it does not outlive the test. */
    @get:Rule
    val releaseMocks = ReleaseMocks()

    private val context = mockk<Context>(relaxed = true)
    private val manager = mockk<BluetoothManager>()
    private val stack = mockk<BluetoothGattServer>(relaxed = true)
    private val device = mockk<BluetoothDevice>(relaxed = true)
    private val callback = slot<BluetoothGattServerCallback>()
    private val added = slot<BluetoothGattService>()

    /** Frames the stack accepted for notification, in order. */
    private val notified = Collections.synchronizedList(mutableListOf<ByteArray>())

    /** Responses to reads and writes: (status, value). */
    private val responses = Collections.synchronizedList(mutableListOf<Pair<Int, ByteArray?>>())

    private lateinit var server: FidoGattServer

    /** getInfo only: the backend is never reached for anything else here. */
    private val backend = object : FidoCredentialBackend {
        override val userVerificationAvailable = true
        override val strictUserVerification = true
        override suspend fun credentials(rpId: String) = emptyList<FidoCredential>()
        override suspend fun checkUser(rpId: String, registering: Boolean) = UserCheck.DECLINED
        override suspend fun chooseCredential(rpId: String, candidates: List<FidoCredential>): FidoCredential? = null
        override suspend fun sign(
            credential: FidoCredential,
            authenticatorData: (signCount: Long) -> ByteArray,
            clientDataHash: ByteArray
        ): SignedAssertion = error("not used")
        override suspend fun create(request: CredentialRequest): NewCredential = error("not used")
    }

    @Before
    fun setUp() {
        every { device.address } returns "02:00:00:00:00:01"
        every { context.getSystemService(Context.BLUETOOTH_SERVICE) } returns manager
        every { manager.openGattServer(context, capture(callback)) } returns stack
        every { stack.addService(capture(added)) } answers {
            callback.captured.onServiceAdded(BluetoothGatt.GATT_SUCCESS, added.captured)
            true
        }
        every { stack.notifyCharacteristicChanged(any(), any(), any(), any<ByteArray>()) } answers {
            notified += arg<ByteArray>(3)
            BluetoothStatusCodes.SUCCESS
        }
        every { stack.sendResponse(any(), any(), any(), any(), any()) } answers {
            responses += arg<Int>(2) to arg<ByteArray?>(4)
            true
        }
        server = FidoGattServer(context, Ctap2Authenticator(backend))
        assertTrue(server.start())
        callback.captured.onConnectionStateChange(device, BluetoothGatt.GATT_SUCCESS, BluetoothProfile.STATE_CONNECTED)
    }

    @After
    fun tearDown() = server.destroy()

    private fun characteristic(uuid: java.util.UUID) = added.captured.getCharacteristic(uuid)

    private fun subscribe() {
        val cccd = characteristic(FidoBle.STATUS_UUID).getDescriptor(FidoBle.CCCD_UUID)
        callback.captured.onDescriptorWriteRequest(
            device, 1, cccd, false, true, 0, BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
        )
    }

    private fun write(frame: ByteArray, uuid: java.util.UUID = FidoBle.CONTROL_POINT_UUID) =
        callback.captured.onCharacteristicWriteRequest(device, 2, characteristic(uuid), false, true, 0, frame)

    private fun send(command: Byte, data: ByteArray, frameSize: Int = 20) =
        FidoBle.fragment(command, data, frameSize).forEach { write(it) }

    /** Report each notification sent, as the stack does, until none is left. */
    private fun release() {
        var seen = -1
        while (seen != notified.size) {
            seen = notified.size
            callback.captured.onNotificationSent(device, BluetoothGatt.GATT_SUCCESS)
        }
    }

    /** Release notifications until a whole non-KEEPALIVE reply has arrived. */
    private fun awaitReply(timeoutMillis: Long = 5_000): FidoBleReassembler.Result.Complete {
        val deadline = System.currentTimeMillis() + timeoutMillis
        while (System.currentTimeMillis() < deadline) {
            release()
            val r = FidoBleReassembler()
            var result: FidoBleReassembler.Result = FidoBleReassembler.Result.Incomplete
            synchronized(notified) { notified.filter { it[0] != FidoBle.CMD_KEEPALIVE } }
                .forEach { result = r.accept(it) }
            if (result is FidoBleReassembler.Result.Complete) return result
            Thread.sleep(10)
        }
        throw AssertionError("no reply within $timeoutMillis ms; frames: ${notified.size}")
    }

    @Test
    fun `every FIDO characteristic needs an encrypted, MITM-protected link`() {
        val writes = characteristic(FidoBle.CONTROL_POINT_UUID).permissions
        assertEquals(BluetoothGattCharacteristic.PERMISSION_WRITE_ENCRYPTED_MITM, writes)
        assertEquals(
            BluetoothGattCharacteristic.PERMISSION_READ_ENCRYPTED_MITM,
            characteristic(FidoBle.CONTROL_POINT_LENGTH_UUID).permissions
        )
        val cccd = characteristic(FidoBle.STATUS_UUID).getDescriptor(FidoBle.CCCD_UUID)
        assertEquals(
            BluetoothGattDescriptor.PERMISSION_READ_ENCRYPTED_MITM or
                BluetoothGattDescriptor.PERMISSION_WRITE_ENCRYPTED_MITM,
            cccd.permissions
        )
        assertEquals(
            BluetoothGattCharacteristic.PERMISSION_READ_ENCRYPTED_MITM or
                BluetoothGattCharacteristic.PERMISSION_WRITE_ENCRYPTED_MITM,
            characteristic(FidoBle.SERVICE_REVISION_BITFIELD_UUID).permissions
        )
    }

    @Test
    fun `the control point length and the FIDO2-only revision are readable`() {
        callback.captured.onCharacteristicReadRequest(device, 3, 0, characteristic(FidoBle.CONTROL_POINT_LENGTH_UUID))
        callback.captured.onCharacteristicReadRequest(
            device, 4, 0, characteristic(FidoBle.SERVICE_REVISION_BITFIELD_UUID)
        )

        assertEquals(BluetoothGatt.GATT_SUCCESS, responses[0].first)
        // The default ATT MTU of 23 leaves 20 bytes for a write.
        assertArrayEquals(byteArrayOf(0x00, 20), responses[0].second)
        assertArrayEquals(byteArrayOf(FidoBle.SERVICE_REVISION_FIDO2), responses[1].second)
    }

    private fun readControlPointLength(): Int {
        callback.captured.onCharacteristicReadRequest(device, 5, 0, characteristic(FidoBle.CONTROL_POINT_LENGTH_UUID))
        val value = responses.last().second!!
        return ((value[0].toInt() and 0xFF) shl 8) or (value[1].toInt() and 0xFF)
    }

    @Test
    fun `the control point length follows the MTU this client negotiated`() {
        callback.captured.onMtuChanged(device, 185)
        assertEquals(182, readControlPointLength())

        callback.captured.onMtuChanged(device, 517)
        assertEquals("never more than 512", 512, readControlPointLength())
    }

    @Test
    fun `each client reads the control point length of its own MTU`() {
        val other = mockk<BluetoothDevice>(relaxed = true)
        every { other.address } returns "02:00:00:00:00:02"
        callback.captured.onConnectionStateChange(other, BluetoothGatt.GATT_SUCCESS, BluetoothProfile.STATE_CONNECTED)
        callback.captured.onMtuChanged(other, 247)

        assertEquals(20, readControlPointLength())
        callback.captured.onCharacteristicReadRequest(other, 6, 0, characteristic(FidoBle.CONTROL_POINT_LENGTH_UUID))
        assertArrayEquals(byteArrayOf(0x00, 244.toByte()), responses.last().second)
    }

    @Test
    fun `a device connected before the server starts is admitted at start`() {
        server.destroy()
        every { manager.getConnectedDevices(BluetoothProfile.GATT_SERVER) } returns listOf(device)
        server = FidoGattServer(context, Ctap2Authenticator(backend))
        assertTrue(server.start())

        assertEquals(1, clientCount())
        assertEquals(20, readControlPointLength())
    }

    @Test
    fun `a control point write longer than the advertised length is refused`() {
        write(ByteArray(21))

        assertEquals(BluetoothGatt.GATT_INVALID_ATTRIBUTE_LENGTH, responses.last().first)
    }

    @Test
    fun `a revision other than FIDO2 is refused`() {
        write(byteArrayOf(0x80.toByte()), FidoBle.SERVICE_REVISION_BITFIELD_UUID)
        write(byteArrayOf(FidoBle.SERVICE_REVISION_FIDO2), FidoBle.SERVICE_REVISION_BITFIELD_UUID)

        assertEquals(BluetoothGatt.GATT_REQUEST_NOT_SUPPORTED, responses[0].first)
        assertEquals(BluetoothGatt.GATT_SUCCESS, responses[1].first)
    }

    @Test
    fun `a PING written to the control point is echoed on fidoStatus`() {
        subscribe()

        send(FidoBle.CMD_PING, ByteArray(50) { it.toByte() })
        val echo = awaitReply()

        assertEquals(FidoBle.CMD_PING, echo.command)
        assertArrayEquals(ByteArray(50) { it.toByte() }, echo.data)
        assertTrue("frames fit the default ATT MTU", notified.all { it.size <= 20 })
    }

    @Test
    fun `authenticatorGetInfo goes from a control point write to fidoStatus notifications`() {
        subscribe()

        send(FidoBle.CMD_MSG, byteArrayOf(Ctap2.CMD_GET_INFO.toByte()))
        val msg = awaitReply()

        assertEquals(FidoBle.CMD_MSG, msg.command)
        assertEquals(Ctap2.OK.toByte(), msg.data[0])
        val info = CborDecoder.decode(msg.data.copyOfRange(1, msg.data.size)) as Map<*, *>
        assertEquals(listOf("FIDO_2_0"), info[1L])
        assertEquals(listOf("ble"), info[9L])
    }

    @Test
    fun `replies follow the MTU the client negotiated`() {
        callback.captured.onMtuChanged(device, 185)
        subscribe()

        send(FidoBle.CMD_PING, ByteArray(400) { 7 }, frameSize = 182)
        val echo = awaitReply()

        assertArrayEquals(ByteArray(400) { 7 }, echo.data)
        assertTrue(notified.all { it.size <= 182 })
        assertEquals(3, notified.size)
    }

    @Test
    fun `nothing is notified to a client that has not subscribed`() {
        send(FidoBle.CMD_PING, byteArrayOf(1, 2, 3))
        release()

        assertTrue(notified.isEmpty())
    }

    private fun unsubscribe() {
        val cccd = characteristic(FidoBle.STATUS_UUID).getDescriptor(FidoBle.CCCD_UUID)
        callback.captured.onDescriptorWriteRequest(
            device, 7, cccd, false, true, 0, BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE
        )
    }

    @Test
    fun `no frame of a fragmented reply is notified after the client unsubscribes`() {
        subscribe()

        send(FidoBle.CMD_PING, fiftyBytes)
        assertEquals("the first frame is in the stack", 1, notified.size)
        unsubscribe()
        // The stack still reports the frame in flight sent.
        release()

        assertEquals("nothing after the unsubscribe", 1, notified.size)
    }

    @Test
    fun `a notify retry pending at the unsubscribe sends nothing`() {
        subscribe()
        rejectNotify { it == 2 }

        send(FidoBle.CMD_PING, fiftyBytes)
        // The second frame is refused, so its retry waits.
        callback.captured.onNotificationSent(device, BluetoothGatt.GATT_SUCCESS)
        unsubscribe()
        Thread.sleep(300)
        release()

        assertEquals("nothing after the unsubscribe", 1, notified.size)
    }

    @Test
    fun `a client that subscribes again gets only new replies`() {
        subscribe()
        send(FidoBle.CMD_PING, fiftyBytes)
        unsubscribe()
        notified.clear()

        subscribe()
        send(FidoBle.CMD_PING, byteArrayOf(4, 5))
        val echo = awaitReply()

        assertArrayEquals(byteArrayOf(4, 5), echo.data)
        assertEquals("no frame of the old reply", 1, notified.size)
    }

    @Test
    fun `a client writing while notifications stall cannot grow the queue without bound`() {
        subscribe()

        // The stack never reports a notification sent, so every reply queues.
        repeat(5_000) { send(FidoBle.CMD_PING, byteArrayOf(it.toByte())) }
        release()

        assertTrue("queued ${notified.size} frames", notified.size <= MAX_EXPECTED_FRAMES)
        assertArrayEquals(FidoBle.errorFrame(FidoBle.ERR_OTHER), notified.last())
    }

    /** The stack refuses the notify calls [reject] picks (1-based), and accepts the rest. */
    private fun rejectNotify(reject: (call: Int) -> Boolean) {
        val calls = java.util.concurrent.atomic.AtomicInteger()
        every { stack.notifyCharacteristicChanged(any(), any(), any(), any<ByteArray>()) } answers {
            if (reject(calls.incrementAndGet())) {
                BluetoothStatusCodes.ERROR_GATT_WRITE_REQUEST_BUSY
            } else {
                notified += arg<ByteArray>(3)
                BluetoothStatusCodes.SUCCESS
            }
        }
    }

    private val fiftyBytes = ByteArray(50) { it.toByte() }

    @Test
    fun `a fragmented reply survives a notification the stack rejects once`() {
        subscribe()
        rejectNotify { it == 2 }

        send(FidoBle.CMD_PING, fiftyBytes)
        val echo = awaitReply()

        assertArrayEquals(fiftyBytes, echo.data)
        assertEquals("every frame once, none dropped", 3, notified.size)
    }

    @Test
    fun `a fragmented reply survives a notification whose completion fails`() {
        subscribe()

        send(FidoBle.CMD_PING, fiftyBytes)
        callback.captured.onNotificationSent(device, BluetoothGatt.GATT_SUCCESS)
        // The second frame did not reach the client.
        notified.removeAt(notified.lastIndex)
        callback.captured.onNotificationSent(device, BluetoothGatt.GATT_FAILURE)
        val echo = awaitReply()

        assertArrayEquals(fiftyBytes, echo.data)
        assertEquals(3, notified.size)
    }

    @Test
    fun `a frame the stack keeps rejecting ends the client's connection, not the message`() {
        subscribe()
        rejectNotify { it >= 2 }

        send(FidoBle.CMD_PING, fiftyBytes)
        callback.captured.onNotificationSent(device, BluetoothGatt.GATT_SUCCESS)

        verify(timeout = 5_000) { stack.cancelConnection(device) }
        val frames = notified.size
        send(FidoBle.CMD_PING, byteArrayOf(1))
        release()
        assertEquals("the first frame only; nothing after the failure", 1, frames)
        assertEquals("the session is over", frames, notified.size)
    }

    @Test
    fun `a frame whose completion keeps failing ends the client's connection, not the message`() {
        subscribe()

        send(FidoBle.CMD_PING, fiftyBytes)
        callback.captured.onNotificationSent(device, BluetoothGatt.GATT_SUCCESS)
        repeat(10) { callback.captured.onNotificationSent(device, BluetoothGatt.GATT_FAILURE) }

        verify(timeout = 5_000) { stack.cancelConnection(device) }
        val frames = notified.size
        send(FidoBle.CMD_PING, byteArrayOf(1))
        release()
        assertTrue("the third frame is never sent", notified.none { it[0] == 1.toByte() })
        assertEquals("the session is over", frames, notified.size)
    }

    @Test
    fun `below API 33 a frame for one client is never notified to another`() {
        // Below API 33 every client shares fidoStatus's one value: it is set,
        // then notified. Client B's reply is forced in while client A's
        // notification is still in the stack.
        server.destroy()
        server = FidoGattServer(context, Ctap2Authenticator(backend), sdkInt = Build.VERSION_CODES.S_V2)
        assertTrue(server.start())
        val other = mockk<BluetoothDevice>(relaxed = true)
        every { other.address } returns "02:00:00:00:00:02"
        val sent = Collections.synchronizedList(mutableListOf<Pair<String, ByteArray>>())
        val otherInStack = CountDownLatch(1)
        val forced = AtomicBoolean(false)
        var otherReply: Thread? = null
        every { stack.notifyCharacteristicChanged(any(), any(), any<Boolean>()) } answers {
            val to = arg<BluetoothDevice>(0)
            val status = arg<BluetoothGattCharacteristic>(1)
            if (to === device && forced.compareAndSet(false, true)) {
                otherReply = thread { pingFrom(other, 0x0B) }
                otherInStack.await(1, TimeUnit.SECONDS)
            } else if (to === other) {
                otherInStack.countDown()
            }
            @Suppress("DEPRECATION")
            sent += to.address to status.value.copyOf()
            true
        }
        for (d in listOf(device, other)) {
            callback.captured.onConnectionStateChange(d, BluetoothGatt.GATT_SUCCESS, BluetoothProfile.STATE_CONNECTED)
            subscribe(d)
        }

        pingFrom(device, 0x0A)
        otherReply!!.join(5_000)

        val toA = sent.filter { it.first == device.address }.map { it.second.toList() }
        val toB = sent.filter { it.first == other.address }.map { it.second.toList() }
        assertEquals(listOf(pingFrame(0x0A).toList()), toA)
        assertEquals(listOf(pingFrame(0x0B).toList()), toB)
    }

    /** A handler that records every request that reaches it: a prompt or a credential would start here. */
    private class RecordingHandler : FidoMessageHandler {
        val requests = Collections.synchronizedList(mutableListOf<ByteArray>())
        override suspend fun handle(request: ByteArray, onUserActionNeeded: () -> Unit): ByteArray {
            requests += request
            onUserActionNeeded()
            return byteArrayOf(0x00)
        }
    }

    /** Replaces the server under test with one whose handler records what reaches it. */
    private fun recordingServer(): RecordingHandler {
        server.destroy()
        val handler = RecordingHandler()
        server = FidoGattServer(context, handler)
        assertTrue(server.start())
        callback.captured.onConnectionStateChange(device, BluetoothGatt.GATT_SUCCESS, BluetoothProfile.STATE_CONNECTED)
        return handler
    }

    @Suppress("UNCHECKED_CAST")
    private fun clientCount(): Int {
        val field = FidoGattServer::class.java.getDeclaredField("clients").apply { isAccessible = true }
        return (field.get(server) as Map<String, *>).size
    }

    @Test
    fun `a stop between a write's validation and its dispatch starts no session`() {
        val handler = recordingServer()
        subscribe()
        // The stack takes the write response after the length check and
        // before the frame is dispatched: stop the server right there.
        every { stack.sendResponse(any(), any(), any(), any(), any()) } answers {
            server.stop()
            true
        }

        send(FidoBle.CMD_MSG, byteArrayOf(Ctap2.CMD_GET_INFO.toByte()))
        Thread.sleep(300)

        assertEquals("no client outlives stop()", 0, clientCount())
        assertTrue("no request reaches the handler after stop()", handler.requests.isEmpty())
        assertTrue("nothing is notified after stop()", notified.isEmpty())
    }

    @Test
    fun `a control point write that reaches the server after its disconnect starts no session`() {
        val handler = recordingServer()
        subscribe()
        // The disconnect is handled while this write's callback is still on
        // its way: its admission comes after the connection has ended.
        callback.captured.onConnectionStateChange(device, BluetoothGatt.GATT_SUCCESS, BluetoothProfile.STATE_DISCONNECTED)
        responses.clear()

        send(FidoBle.CMD_MSG, byteArrayOf(Ctap2.CMD_GET_INFO.toByte()))
        callback.captured.onMtuChanged(device, 185)
        Thread.sleep(300)

        assertEquals("no client outlives its disconnect", 0, clientCount())
        assertTrue("no request reaches the handler after the disconnect", handler.requests.isEmpty())
        assertTrue("nothing is notified after the disconnect", notified.isEmpty())
        assertTrue("the write is refused", responses.all { it.first == BluetoothGatt.GATT_FAILURE })
    }

    @Test
    fun `a control point write whose admission overlaps the disconnect starts no session`() {
        val handler = recordingServer()
        subscribe()
        // A second connection of the same device: its first callback, a
        // write, looks the client up while the first connection's
        // disconnect is being handled on another thread.
        val other = mockk<BluetoothDevice>(relaxed = true)
        val disconnecting = CountDownLatch(1)
        every { other.address } answers {
            if (disconnecting.count > 0) {
                disconnecting.countDown()
                thread {
                    callback.captured.onConnectionStateChange(
                        device, BluetoothGatt.GATT_SUCCESS, BluetoothProfile.STATE_DISCONNECTED
                    )
                }.join(200)
            }
            "02:00:00:00:00:01"
        }
        val cp = characteristic(FidoBle.CONTROL_POINT_UUID)
        FidoBle.fragment(FidoBle.CMD_MSG, byteArrayOf(Ctap2.CMD_GET_INFO.toByte()), 20).forEach {
            callback.captured.onCharacteristicWriteRequest(other, 2, cp, false, true, 0, it)
        }
        Thread.sleep(300)

        assertEquals("no client outlives its disconnect", 0, clientCount())
        // Whatever the write reached, the disconnect closed it: a later
        // frame on that connection reaches nothing.
        val before = handler.requests.size
        send(FidoBle.CMD_MSG, byteArrayOf(Ctap2.CMD_GET_INFO.toByte()))
        Thread.sleep(300)
        assertEquals("no request reaches the handler after the disconnect", before, handler.requests.size)
        assertEquals("no client outlives its disconnect", 0, clientCount())
    }

    @Test
    fun `no callback after stop creates a client or reaches the handler`() {
        val handler = recordingServer()
        val gatt = callback.captured
        server.stop()

        gatt.onMtuChanged(device, 185)
        gatt.onCharacteristicReadRequest(device, 3, 0, characteristic(FidoBle.CONTROL_POINT_LENGTH_UUID))
        subscribe()
        send(FidoBle.CMD_MSG, byteArrayOf(Ctap2.CMD_GET_INFO.toByte()))
        Thread.sleep(300)

        assertEquals(0, clientCount())
        assertTrue(handler.requests.isEmpty())
        assertTrue(notified.isEmpty())
    }

    private fun subscribe(to: BluetoothDevice) {
        val cccd = characteristic(FidoBle.STATUS_UUID).getDescriptor(FidoBle.CCCD_UUID)
        callback.captured.onDescriptorWriteRequest(
            to, 1, cccd, false, true, 0, BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
        )
    }

    private fun pingFrame(payload: Byte) = FidoBle.fragment(FidoBle.CMD_PING, byteArrayOf(payload), 20).single()

    private fun pingFrom(from: BluetoothDevice, payload: Byte) = callback.captured.onCharacteristicWriteRequest(
        from, 7, characteristic(FidoBle.CONTROL_POINT_UUID), false, true, 0, pingFrame(payload)
    )

    private companion object {
        /** One largest reply at the smallest frame size, with room to spare. */
        const val MAX_EXPECTED_FRAMES = 2 * (FidoBle.MAX_MESSAGE_SIZE / 17 + 2)
    }
}
