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

import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.le.BluetoothLeScanner
import android.content.Context
import io.mockk.every
import io.mockk.mockk
import java.security.MessageDigest
import java.util.UUID
import kotlinx.coroutines.runBlocking

/**
 * A whole xKey desktop, in-process, behind a mocked Bluetooth stack.
 *
 * [BleClient] is the only xKey transport where the *phone* is the initiator,
 * and it is the only one with no counterpart in `go-xkms` to test it against —
 * the desktop is the responder there. Wiring a real [NoiseSession] responder to
 * the client through a mocked `BluetoothGatt` is therefore the only way to run
 * the client's whole path: connect, service discovery, MTU negotiation, CCCD
 * setup, the pre-handshake identity exchange, Noise XX as initiator, and the
 * fragmented encrypted request/response loop.
 *
 * The mock is faithful in the ways that matter. Every framework call the client
 * makes is answered the way the stack answers it — asynchronously, by invoking
 * the `BluetoothGattCallback` — so the client's `CompletableDeferred` handshakes
 * with the stack are genuinely exercised rather than stepped over. Bytes written
 * to the control point are reassembled with the real [FragmentReassembler] and
 * replies go back through the real [Fragmenter], so the wire format is under
 * test on both sides.
 *
 * `Build.VERSION.SDK_INT` reads as 0 off-device, so the client takes its
 * pre-Tiramisu branches: `connectGatt(context, autoConnect, callback)`,
 * `writeDescriptor(descriptor)` and `writeCharacteristic(characteristic)`.
 * Those are the branches this harness answers.
 *
 * Every knob below is a `var` so a test can break one step and assert on how
 * the client reports it. Defaults describe a healthy desktop.
 */
@Suppress("DEPRECATION")
class BleClientHarness(
    /** The MTU the stack reports back from `requestMtu`. */
    val mtu: Int = 247,
    val address: String = "AA:BB:CC:DD:EE:F0",
    val deviceName: String = "xKey Desktop"
) {

    // -----------------------------------------------------------------
    // Knobs
    // -----------------------------------------------------------------

    /** `false` makes `initializeBluetooth` report a disabled radio. */
    var bluetoothEnabled: Boolean = true

    /** `false` makes `connectGatt` return null, as a refused connection does. */
    var connectStarts: Boolean = true

    /** The `newState` the stack reports once `connectGatt` is called. */
    var connectionNewState: Int = BluetoothProfile.STATE_CONNECTED

    /** The status paired with [connectionNewState]. */
    var connectionStatus: Int = BluetoothGatt.GATT_SUCCESS

    var discoveryStarts: Boolean = true
    var discoveryStatus: Int = BluetoothGatt.GATT_SUCCESS

    /** `false` hides the xKey primary service from discovery. */
    var serviceIsPresent: Boolean = true

    /** `false` hides the control point characteristic. */
    var controlPointIsPresent: Boolean = true

    /** `false` hides the response characteristic. */
    var responseIsPresent: Boolean = true

    /** `false` hides the CCCD, so notifications can never be enabled. */
    var cccdIsPresent: Boolean = true

    var mtuRequestStarts: Boolean = true
    var mtuStatus: Int = BluetoothGatt.GATT_SUCCESS

    var notificationsEnable: Boolean = true
    var descriptorWriteStarts: Boolean = true
    var descriptorWriteStatus: Int = BluetoothGatt.GATT_SUCCESS

    var writeStarts: Boolean = true
    var writeStatus: Int = BluetoothGatt.GATT_SUCCESS

    /**
     * When set, the desktop answers the identity exchange as a *known* device
     * and binds the handshake to `SHA256(client_pub || fingerprint ||
     * "xkey-v1")`, which is what a previously paired desktop does.
     */
    var pinnedFingerprint: ByteArray? = null

    /** The desktop's reply to a decrypted request. */
    var responseFor: (ByteArray) -> ByteArray = {
        """{"jsonrpc":"2.0","id":1,"result":{"ok":true}}""".toByteArray()
    }

    // -----------------------------------------------------------------
    // Observations
    // -----------------------------------------------------------------

    /** Every plaintext request the desktop decrypted, in order. */
    val receivedRequests = mutableListOf<ByteArray>()

    /** The raw 33-byte identity frame the client opened with. */
    var receivedIdentity: ByteArray? = null
        private set

    /** How many characteristic writes the client issued, fragments included. */
    var writeCount: Int = 0
        private set

    // -----------------------------------------------------------------
    // The mocked stack
    // -----------------------------------------------------------------

    val context: Context = mockk(relaxed = true)
    val bluetoothManager: BluetoothManager = mockk(relaxed = true)
    val adapter: BluetoothAdapter = mockk(relaxed = true)
    val scanner: BluetoothLeScanner = mockk(relaxed = true)
    val device: BluetoothDevice = mockk(relaxed = true)
    val gatt: BluetoothGatt = mockk(relaxed = true)
    val service: BluetoothGattService = mockk(relaxed = true)
    val controlPoint: BluetoothGattCharacteristic = mockk(relaxed = true)
    val responseCharacteristic: BluetoothGattCharacteristic = mockk(relaxed = true)
    val statusCharacteristic: BluetoothGattCharacteristic = mockk(relaxed = true)
    val cccd: BluetoothGattDescriptor = mockk(relaxed = true)

    val client = BleClient(context)
    val probe = BleClientProbe(client)

    /** The desktop's Noise responder, so tests can assert on its identity. */
    val responder = NoiseSession()

    private val inbound = FragmentReassembler()
    private var lastControlPointWrite: ByteArray? = null
    private var identityDone = false

    init {
        runBlocking { responder.loadStaticKey(context) }

        every { context.getSystemService(Context.BLUETOOTH_SERVICE) } returns bluetoothManager
        every { bluetoothManager.adapter } returns adapter
        every { adapter.isEnabled } answers { bluetoothEnabled }
        every { adapter.bluetoothLeScanner } returns scanner
        every { adapter.getRemoteDevice(any<String>()) } answers {
            if (firstArg<String>() == address) device
            else throw IllegalArgumentException("not a well-formed address")
        }

        every { device.name } returns deviceName
        every { device.address } returns address
        every {
            device.connectGatt(any(), any(), any<BluetoothGattCallback>())
        } answers {
            if (!connectStarts) return@answers null
            probe.gattCallback.onConnectionStateChange(gatt, connectionStatus, connectionNewState)
            gatt
        }

        every { gatt.device } returns device
        every { gatt.discoverServices() } answers {
            if (!discoveryStarts) return@answers false
            probe.gattCallback.onServicesDiscovered(gatt, discoveryStatus)
            true
        }
        every { gatt.getService(GattServer.XKEY_SERVICE_UUID) } answers {
            if (serviceIsPresent) service else null
        }
        every { service.getCharacteristic(any<UUID>()) } answers {
            when (firstArg<UUID>()) {
                GattServer.CONTROL_POINT_UUID -> if (controlPointIsPresent) controlPoint else null
                GattServer.RESPONSE_UUID -> if (responseIsPresent) responseCharacteristic else null
                GattServer.STATUS_UUID -> statusCharacteristic
                else -> null
            }
        }

        every { gatt.requestMtu(any()) } answers {
            if (!mtuRequestStarts) return@answers false
            probe.gattCallback.onMtuChanged(gatt, mtu, mtuStatus)
            true
        }

        every { gatt.setCharacteristicNotification(any(), any()) } answers { notificationsEnable }
        every { responseCharacteristic.getDescriptor(GattServer.CCCD_UUID) } answers {
            if (cccdIsPresent) cccd else null
        }
        every { cccd.uuid } returns GattServer.CCCD_UUID
        every { gatt.writeDescriptor(any<BluetoothGattDescriptor>()) } answers {
            if (!descriptorWriteStarts) return@answers false
            probe.gattCallback.onDescriptorWrite(gatt, cccd, descriptorWriteStatus)
            true
        }

        every { controlPoint.setValue(any<ByteArray>()) } answers {
            lastControlPointWrite = firstArg()
            true
        }
        every { gatt.writeCharacteristic(any<BluetoothGattCharacteristic>()) } answers {
            if (!writeStarts) return@answers false
            writeCount++
            val fragment = lastControlPointWrite
                ?: throw AssertionError("the client wrote without setting a value")
            val reply = if (writeStatus == BluetoothGatt.GATT_SUCCESS) consume(fragment) else null
            probe.gattCallback.onCharacteristicWrite(gatt, controlPoint, writeStatus)
            reply?.let { deliver(it) }
            true
        }
    }

    // -----------------------------------------------------------------
    // The desktop
    // -----------------------------------------------------------------

    /**
     * Reassembles one control-point fragment and, once a whole message has
     * arrived, produces the desktop's reply — or null where the protocol has
     * the desktop stay silent (handshake message 3).
     */
    private fun consume(fragment: ByteArray): ByteArray? {
        val message = inbound.addFragment(fragment) ?: return null
        return runBlocking { desktopReply(message) }
    }

    private suspend fun desktopReply(message: ByteArray): ByteArray? = when {
        !identityDone -> {
            identityDone = true
            receivedIdentity = message
            check(message.size == 33 && message[0] == 0x01.toByte()) {
                "the client must open with a 33-byte versioned identity frame"
            }
            val clientStaticKey = message.copyOfRange(1, message.size)
            val fingerprint = pinnedFingerprint
            if (fingerprint == null) {
                byteArrayOf(0x00)
            } else {
                responder.setPrologue(prologueOf(clientStaticKey, fingerprint))
                responder.reset()
                byteArrayOf(0x01) + fingerprint
            }
        }

        !responder.isHandshakeComplete() -> responder.processHandshakeMessage(message)

        else -> {
            val plaintext = responder.decrypt(message)
            receivedRequests += plaintext
            responder.encrypt(responseFor(plaintext))
        }
    }

    /**
     * Notifies the client, one fragment at a time.
     *
     * The client dispatches every inbound fragment onto its own scope, so this
     * waits for each one to be buffered before sending the next: a reassembler
     * that sees fragment 0 *after* fragment 1 resets and drops everything, and
     * a test that raced would fail for a reason unrelated to what it asserts.
     */
    private fun deliver(message: ByteArray) {
        val payloadSize = maxOf(
            mtu - 3 - FragmentReassembler.HEADER_SIZE,
            Fragmenter.MIN_PAYLOAD_SIZE
        )
        val fragments = Fragmenter(payloadSize).fragment(message)
        for ((index, fragment) in fragments.withIndex()) {
            probe.gattCallback.onCharacteristicChanged(gatt, responseCharacteristic, fragment)
            if (index < fragments.size - 1) awaitBufferedFragments(index + 1)
        }
    }

    private fun awaitBufferedFragments(expected: Int) {
        val deadline = System.currentTimeMillis() + 5_000
        while (System.currentTimeMillis() < deadline) {
            if (probe.fragmentReassembler.getFragmentCount() >= expected) return
            Thread.sleep(2)
        }
        throw AssertionError("the client never buffered inbound fragment $expected")
    }

    // -----------------------------------------------------------------
    // Convenience
    // -----------------------------------------------------------------

    /** Connects with a fresh random static key and returns it. */
    suspend fun connect(expectedRemoteKey: ByteArray? = null): ByteArray {
        val staticKey = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        client.connect(address, staticKey, expectedRemoteKey)
        return staticKey
    }

    /** Releases the client. Safe to call more than once. */
    fun close() {
        runCatching { runBlocking { client.destroy() } }
    }

    companion object {
        /** The prologue formula the phone, the desktop and `go-xkms` all share. */
        fun prologueOf(publicKey: ByteArray, fingerprint: ByteArray): ByteArray =
            MessageDigest.getInstance("SHA-256").run {
                update(publicKey)
                update(fingerprint)
                update("xkey-v1".toByteArray(Charsets.UTF_8))
                digest()
            }
    }
}
