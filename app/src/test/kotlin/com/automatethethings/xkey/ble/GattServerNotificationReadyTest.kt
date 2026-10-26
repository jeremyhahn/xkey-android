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
import java.security.SecureRandom
import java.util.Collections
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * A send the event consumer makes never waits for an event queued behind it
 * (Codex 7477 on #63). The peer may write its identity frame before it
 * enables notifications: the consumer handling that frame waits for the
 * enable, so the enable has to signal readiness from its callback, not from
 * the consumer. Only the connection that owns the address now is signalled.
 *
 * Every event goes through the server's own GATT callback, from the
 * connect on, as the stack delivers them.
 */
@Suppress("DEPRECATION")
class GattServerNotificationReadyTest {

    private companion object {
        const val ADDRESS = "AA:BB:CC:DD:EE:FF"
        const val MTU = 247
        const val TIMEOUT_MS = 5_000L

        // GattServer.NOTIFICATION_READY_TIMEOUT_MS.
        const val NOTIFICATION_READY_TIMEOUT_MS = 5_000L

        // Well inside the five-second wait, so what arrives in it was not
        // released by the wait expiring.
        const val PROMPTLY_MS = 2_000L

        // Long enough for a send that was not waiting to have gone out.
        const val SETTLE_MS = 300L

        val ENABLE = byteArrayOf(0x01, 0x00)
        val DISABLE = byteArrayOf(0x00, 0x00)
        val IDENTITY_ACK_UNKNOWN = byteArrayOf(0x00)

        fun randomKey(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }
    }

    private lateinit var context: Context
    private lateinit var gatt: BluetoothGattServer
    private lateinit var device: BluetoothDevice
    private lateinit var controlPoint: BluetoothGattCharacteristic
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
     * The Codex 7477 regression: the identity frame, then the CCCD enable
     * within the wait. The acknowledgement goes out on the enable, not when
     * the wait expires, and the handshake goes on.
     */
    @Test
    fun anIdentityFrameBeforeTheCccdEnableIsAcknowledgedAndTheHandshakeProceeds() {
        connect()
        mtu(MTU)
        write(identityFrame())
        Thread.sleep(SETTLE_MS)
        assertEquals("nothing is sent before notifications are enabled", 0, messages().size)

        enableNotifications()
        eventually("the identity acknowledgement is sent", PROMPTLY_MS) { messages().isNotEmpty() }
        assertArrayEquals(IDENTITY_ACK_UNKNOWN, messages()[0])

        write(desktop.createHandshakeMessage1())
        eventually("the handshake's second message is sent") { messages().size == 2 }
        desktop.processHandshakeMessage2(messages()[1])
    }

    /**
     * The Codex 7498 regression: a CCCD disable, the identity frame, then an
     * enable within the wait. The latest write decides, so the enable
     * releases the acknowledgement although the consumer handled the disable
     * first and the enable is still behind the frame.
     */
    @Test
    fun anEnableAfterADisableReleasesTheWaitingAcknowledgement() {
        connect()
        mtu(MTU)
        disableNotifications()
        write(identityFrame())
        Thread.sleep(SETTLE_MS)
        assertEquals("nothing is sent while notifications are disabled", 0, messages().size)

        enableNotifications()
        eventually("the identity acknowledgement is sent", PROMPTLY_MS) { messages().isNotEmpty() }
        assertArrayEquals(IDENTITY_ACK_UNKNOWN, messages()[0])

        write(desktop.createHandshakeMessage1())
        eventually("the handshake's second message is sent") { messages().size == 2 }
        desktop.processHandshakeMessage2(messages()[1])
    }

    /**
     * An enable that arrives after one connection's disconnect, and before
     * the next one's connect, belongs to neither: the next connection's
     * acknowledgement still waits for its own.
     */
    @Test
    fun aCccdEnableFromAnEarlierConnectionCompletesNothingForTheNext() {
        connect()
        mtu(MTU)
        disconnect()
        enableNotifications()

        connect()
        mtu(MTU)
        write(identityFrame())
        Thread.sleep(SETTLE_MS)
        assertEquals("the earlier connection's enable released nothing", 0, messages().size)

        enableNotifications()
        eventually("this connection's own enable releases it", PROMPTLY_MS) { messages().isNotEmpty() }
        assertArrayEquals(IDENTITY_ACK_UNKNOWN, messages()[0])
    }

    /** With no enable at all, the wait expires and the acknowledgement is dropped, as before. */
    @Test
    fun withNoEnableTheWaitExpiresAndTheAcknowledgementIsDropped() {
        connect()
        mtu(MTU)
        val start = System.currentTimeMillis()
        write(identityFrame())

        eventually("the identity exchange gives up", NOTIFICATION_READY_TIMEOUT_MS + TIMEOUT_MS) {
            getField<Boolean>("identityExchangeComplete")
        }
        val waited = System.currentTimeMillis() - start
        assertTrue("it waited the full $NOTIFICATION_READY_TIMEOUT_MS ms: $waited", waited >= NOTIFICATION_READY_TIMEOUT_MS - 100)
        assertEquals("the acknowledgement is dropped", 0, messages().size)
    }

    /**
     * The MTU, too, may be reported behind the frame the consumer is
     * answering. The acknowledgement is fragmented at it, not at the 23-byte
     * default, which leaves no room for a fragment.
     */
    @Test
    fun anMtuReportedBehindTheIdentityFrameSizesItsAcknowledgement() {
        connect()
        write(identityFrame())
        mtu(MTU)
        enableNotifications()

        eventually("the identity acknowledgement is sent", PROMPTLY_MS) { messages().isNotEmpty() }
        assertArrayEquals(IDENTITY_ACK_UNKNOWN, messages()[0])
    }

    /**
     * A disconnect while the acknowledgement waits for notifications ends
     * the wait: the disconnect is handled at once, not after the wait
     * expires, and an enable after it sends nothing.
     */
    @Test
    fun aDisconnectWhileTheAcknowledgementWaitsEndsTheWait() {
        connect()
        mtu(MTU)
        write(identityFrame())
        Thread.sleep(SETTLE_MS)

        disconnect()
        eventually("the disconnect is handled", PROMPTLY_MS) {
            server.connectionState.value == ConnectionState.Disconnected &&
                getField<BluetoothDevice?>("connectedDevice") == null
        }

        enableNotifications()
        Thread.sleep(SETTLE_MS)
        assertEquals("nothing is sent for the ended connection", 0, messages().size)
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    private val callback: BluetoothGattServerCallback
        get() = getField("gattCallback")

    private fun connect() {
        callback.onConnectionStateChange(device, 0, BluetoothProfile.STATE_CONNECTED)
        eventually("the connect is handled") { getField<BluetoothDevice?>("connectedDevice") != null }
    }

    private fun disconnect() {
        callback.onConnectionStateChange(device, 0, BluetoothProfile.STATE_DISCONNECTED)
    }

    private fun mtu(mtu: Int) {
        callback.onMtuChanged(device, mtu)
    }

    private fun enableNotifications() {
        callback.onDescriptorWriteRequest(device, 1, cccd, false, false, 0, ENABLE)
    }

    private fun disableNotifications() {
        callback.onDescriptorWriteRequest(device, 1, cccd, false, false, 0, DISABLE)
    }

    /** A desktop the phone has not paired with, announcing its key. */
    private fun identityFrame(): ByteArray = byteArrayOf(0x01) + desktop.getLocalStaticPublicKey()

    /** Writes [frame] to the control point, fragment by fragment. */
    private fun write(frame: ByteArray) {
        Fragmenter(200).fragment(frame).forEach {
            callback.onCharacteristicWriteRequest(device, 1, controlPoint, false, false, 0, it)
        }
    }

    /** The whole messages notified so far, reassembled. */
    private fun messages(): List<ByteArray> {
        val reassembler = FragmentReassembler()
        return synchronized(fragments) { fragments.toList() }.mapNotNull { reassembler.addFragment(it) }
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
