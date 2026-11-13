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
import org.junit.runner.RunWith
import org.junit.runners.Parameterized

/**
 * The latest CCCD write decides a send that waits for notifications
 * (#63): every interleaving of up to three CCCD writes with the
 * identity frame, whose acknowledgement is the response, and a disconnect
 * at the points where one can change the outcome.
 *
 * A row is the order the stack delivers the events in, from a connect:
 *
 * - `E` / `D`: a CCCD write enabling / disabling notifications
 * - `I`: the identity frame; the consumer answers it and waits to send
 * - `X`: the disconnect; `C`: the next connection's connect
 * - `*`: the event that sends the acknowledgement. `*I` sends it as the
 *   frame is answered; `*E` sends it on that enable, not before.
 *
 * A row with no `*` drops the acknowledgement: at the disconnect when it has
 * one after `I`, otherwise when the notification-ready wait expires.
 *
 * The rule: the acknowledgement goes out the first moment, within the wait,
 * that the latest CCCD write of the frame's connection is an enable, and
 * never after that connection's disconnect. Each event after `I` waits
 * until the server has nothing left to run, so the waiting send sees each
 * one before the next lands.
 */
@Suppress("DEPRECATION")
@RunWith(Parameterized::class)
class GattServerCccdOrderTest(private val row: String) {

    companion object {
        private const val ADDRESS = "AA:BB:CC:DD:EE:FF"
        private const val MTU = 247
        private const val TIMEOUT_MS = 5_000L

        // The notification-ready wait this test gives the server, in place of
        // the production five seconds, so a row that waits it out costs
        // 0.6 s.
        private const val NOTIFICATION_READY_TIMEOUT_MS = 600L

        // Well inside the wait, so what happens in it was not caused by the
        // wait expiring.
        private const val PROMPTLY_MS = 300L

        private val ENABLE = byteArrayOf(0x01, 0x00)
        private val DISABLE = byteArrayOf(0x00, 0x00)
        private val IDENTITY_ACK_UNKNOWN = byteArrayOf(0x00)

        @JvmStatic
        @Parameterized.Parameters(name = "{0}")
        fun rows(): List<String> = listOf(
            // No CCCD write
            "I",
            // One
            "E *I",
            "D I",
            "I *E",
            "I D",
            // Two, both before the frame
            "E E *I",
            "E D I",
            "D E *I",
            "D D I",
            // Two, one before and one after
            "E *I E",
            "E *I D",
            "D I *E", // a disable before the frame: the ack waits for the later enable
            "D I D",
            // Two, both after
            "I *E E",
            "I *E D",
            "I D *E",
            "I D D",
            // Three, all before
            "E E E *I",
            "E E D I",
            "E D E *I",
            "E D D I",
            "D E E *I",
            "D E D I",
            "D D E *I",
            "D D D I",
            // Three, two before
            "E E *I E",
            "E E *I D",
            "E D I *E",
            "E D I D",
            "D E *I E",
            "D E *I D",
            "D D I *E",
            "D D I D",
            // Three, one before
            "E *I E E",
            "E *I E D",
            "E *I D E",
            "E *I D D",
            "D I *E E",
            "D I *E D",
            "D I D *E",
            "D I D D",
            // Three, all after
            "I *E E E",
            "I *E E D",
            "I *E D E",
            "I *E D D",
            "I D *E E",
            "I D *E D",
            "I D D *E",
            "I D D D",
            // A disconnect while the acknowledgement waits ends the wait
            "I X E",
            "D I X E",
            "E D I X E",
            "I D X E",
            // A disconnect after it was sent changes nothing
            "E *I X E",
            "I *E X",
            // A CCCD write from the earlier connection carries nothing over
            "E X C I *E",
            "E X C I",
            "E X E C I",
            "D X C E *I",
            "E X C D I *E",
        )

        private fun randomKey(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }
    }

    private lateinit var context: Context
    private lateinit var gatt: BluetoothGattServer
    private lateinit var device: BluetoothDevice
    private lateinit var controlPoint: BluetoothGattCharacteristic
    private lateinit var cccd: BluetoothGattDescriptor
    private lateinit var server: GattServer
    private lateinit var signals: TrackingDispatcher
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
            notificationReadyTimeoutMs = NOTIFICATION_READY_TIMEOUT_MS,
        )
        signals = trackScope(server)
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

    @Test
    fun theLatestCccdWriteDecidesTheAcknowledgement() {
        val tokens = row.split(" ")
        val frameAt = tokens.indexOfFirst { it.trimStart('*') == "I" }
        val releasedBy = tokens.indexOfFirst { it.startsWith("*") }
        val disconnectAt = tokens.withIndex().indexOfFirst { (i, t) -> i > frameAt && t == "X" }

        connect()
        var frameWritten = 0L
        tokens.forEachIndexed { i, token ->
            if (i == releasedBy && i != frameAt) {
                assertEquals("$row: nothing is sent before ${i + 1}", 0, messages().size)
            }
            when (token.trimStart('*')) {
                "E" -> cccdWrite(ENABLE)
                "D" -> cccdWrite(DISABLE)
                "I" -> {
                    frameWritten = System.currentTimeMillis()
                    write(identityFrame())
                }
                "X" -> disconnect()
                "C" -> connect()
                else -> throw AssertionError("$row: unknown event $token")
            }
            if (i == releasedBy) {
                eventually("$row: the acknowledgement is sent on event ${i + 1}", PROMPTLY_MS) {
                    messages().isNotEmpty()
                }
            } else if (frameAt in 0..i) {
                // The consumer has reached the wait, or the waiting send has
                // seen this event, and a send it released has gone out.
                signals.awaitIdle("$row: event ${i + 1} is handled")
            }
        }

        when {
            releasedBy >= 0 -> {
                signals.awaitIdle("$row: the rest of the row is handled")
                assertEquals("$row: one acknowledgement", 1, messages().size)
                assertArrayEquals(IDENTITY_ACK_UNKNOWN, messages()[0])
            }
            disconnectAt >= 0 -> assertEquals("$row: nothing is sent for the ended connection", 0, messages().size)
            else -> {
                eventually("$row: the identity exchange gives up", NOTIFICATION_READY_TIMEOUT_MS + TIMEOUT_MS) {
                    getField<Boolean>("identityExchangeComplete")
                }
                val waited = System.currentTimeMillis() - frameWritten
                assertTrue(
                    "$row: it waited the full $NOTIFICATION_READY_TIMEOUT_MS ms: $waited",
                    waited >= NOTIFICATION_READY_TIMEOUT_MS - 100
                )
                assertEquals("$row: the acknowledgement is dropped", 0, messages().size)
            }
        }
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    private val callback: BluetoothGattServerCallback
        get() = getField("gattCallback")

    private fun connect() {
        callback.onConnectionStateChange(device, 0, BluetoothProfile.STATE_CONNECTED)
        callback.onMtuChanged(device, MTU)
        eventually("the connect is handled") { getField<BluetoothDevice?>("connectedDevice") != null }
    }

    /** Disconnects, and checks the disconnect is handled at once, not when a wait expires. */
    private fun disconnect() {
        callback.onConnectionStateChange(device, 0, BluetoothProfile.STATE_DISCONNECTED)
        eventually("$row: the disconnect is handled", PROMPTLY_MS) {
            server.connectionState.value == ConnectionState.Disconnected &&
                getField<BluetoothDevice?>("connectedDevice") == null
        }
    }

    private fun cccdWrite(value: ByteArray) {
        callback.onDescriptorWriteRequest(device, 1, cccd, false, false, 0, value)
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

    private fun eventually(what: String, timeoutMs: Long = TIMEOUT_MS, check: () -> Boolean) =
        signals.eventually(what, timeoutMs, check)

    private fun setField(name: String, value: Any?) {
        GattServer::class.java.getDeclaredField(name).apply { isAccessible = true }.set(server, value)
    }

    @Suppress("UNCHECKED_CAST")
    private fun <T> getField(name: String): T =
        GattServer::class.java.getDeclaredField(name).apply { isAccessible = true }.get(server) as T
}
