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
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.runBlocking
import org.json.JSONException
import org.json.JSONObject

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
    val deviceName: String = "xKey Desktop",
    /** What the client answers the desktop's own requests with. */
    inboundRequests: PhoneInitiatedRequestHandler? = null
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

    /**
     * Runs inside `connectGatt`, before the stack reports the dialled
     * connection's state: while the client is dialling and has no GATT
     * object for the connection yet.
     */
    @Volatile
    var whileDialling: (() -> Unit)? = null

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

    /**
     * When set, the desktop sends this request in reply to handshake message
     * 3 — before the client has even finished the write that carried it — as
     * go-xkms does with `local.attestDevice` on a phone-initiated session.
     */
    var requestOnHandshake: ByteArray? = null

    /**
     * When true, a desktop message sent in reply to a post-handshake write —
     * [requestOnHandshake] among them — is notified *before* the stack reports
     * that write complete. Notifications and write callbacks travel separately,
     * so a real stack can deliver them in that order. The write is then held
     * open for [writeAckHoldMs], as a slow acknowledgement would hold it, and
     * any write the client starts meanwhile is refused, as a busy GATT stack
     * refuses it, and counted in [overlappingWrites].
     */
    var replyBeforeWriteAck: Boolean = false

    /** How long [replyBeforeWriteAck] holds a write open, absent an overlap. */
    var writeAckHoldMs: Long = 500

    /**
     * When true, every write is acknowledged from a separate stack thread, one
     * ack at a time, and the completion the client installed does not *return*
     * until the client has started its next write — or [nextWriteWaitMs] has
     * passed, for the last write of a message. Resuming the writer is what lets
     * the next write begin, so a real stack can be inside the first callback
     * while the second writer installs its own. Each ack that returned only
     * after the next write began is counted in [acksOutlivedByTheNextWrite].
     */
    var ackAfterTheNextWriteStarts: Boolean = false

    /** How long [ackAfterTheNextWriteStarts] keeps a callback open for the next write. */
    var nextWriteWaitMs: Long = 1_000

    /**
     * When true, a write the stack takes is not acknowledged until
     * [releaseHeldWrites]: the client is left with a write outstanding, and
     * its completion installed, for as long as the test needs.
     */
    @Volatile
    var holdWrites: Boolean = false

    /** The desktop's reply to a decrypted request. */
    var responseFor: (ByteArray) -> ByteArray = {
        """{"jsonrpc":"2.0","id":1,"result":{"ok":true}}""".toByteArray()
    }

    // -----------------------------------------------------------------
    // Observations
    // -----------------------------------------------------------------

    /** Every plaintext request the desktop decrypted, in order. */
    val receivedRequests = mutableListOf<ByteArray>()

    /**
     * Every plaintext *response* the desktop decrypted — the client's answers
     * to [desktopSends]. Written from the client's scope, read by the test.
     */
    val receivedResponses = CopyOnWriteArrayList<ByteArray>()

    /** The raw 33-byte identity frame the client opened with. */
    var receivedIdentity: ByteArray? = null
        private set

    /** How many characteristic writes the client issued, fragments included. */
    var writeCount: Int = 0
        private set

    /** Writes the client started while an earlier one was still unacknowledged. */
    val overlappingWrites = AtomicInteger(0)

    /** Under [ackAfterTheNextWriteStarts], callbacks the next write began inside. */
    val acksOutlivedByTheNextWrite = AtomicInteger(0)

    /** Writes [holdWrites] is holding unacknowledged. */
    val heldWrites: Int
        get() = held.size

    /** The desktop's replies to the writes [holdWrites] holds, in write order; null where it stays silent. */
    val heldReplies: List<ByteArray?>
        get() = held.map { it.second }

    /** How many characteristic writes the client tried on [gatt], refused ones included. */
    fun writesOn(gatt: BluetoothGatt): Int = writes[gatt]?.get() ?: 0

    // -----------------------------------------------------------------
    // The mocked stack
    // -----------------------------------------------------------------

    val context: Context = mockk(relaxed = true)
    val bluetoothManager: BluetoothManager = mockk(relaxed = true)
    val adapter: BluetoothAdapter = mockk(relaxed = true)
    val scanner: BluetoothLeScanner = mockk(relaxed = true)
    val device: BluetoothDevice = mockk(relaxed = true)
    /** The first connection's GATT object; [nextConnection] dials others. */
    val gatt: BluetoothGatt = mockk(relaxed = true)

    /** The GATT object `connectGatt` hands out, and the only one the stack writes on. */
    @Volatile
    var dialledGatt: BluetoothGatt = gatt
        private set
    val service: BluetoothGattService = mockk(relaxed = true)
    val controlPoint: BluetoothGattCharacteristic = mockk(relaxed = true)
    val responseCharacteristic: BluetoothGattCharacteristic = mockk(relaxed = true)
    val statusCharacteristic: BluetoothGattCharacteristic = mockk(relaxed = true)
    val cccd: BluetoothGattDescriptor = mockk(relaxed = true)

    val client = BleClient(context, inboundRequests)
    val probe = BleClientProbe(client)

    /** The desktop's Noise responder, so tests can assert on its identity. */
    val responder = NoiseSession()

    private val inbound = FragmentReassembler()
    private var lastControlPointWrite: ByteArray? = null
    private var identityDone = false

    /** Set while [replyBeforeWriteAck] holds a write open; read from the client's threads. */
    @Volatile
    private var writeInFlight = false

    /** The stack thread [ackAfterTheNextWriteStarts] acknowledges on, in write order. */
    private val ackThread by lazy {
        Executors.newSingleThreadExecutor { task ->
            Thread(task, "gatt-write-ack").apply { isDaemon = true }
        }
    }

    /** Writes handed to [ackThread] so far. */
    private val writesAcked = AtomicInteger(0)

    /** Every characteristic write tried, by the GATT object it was tried on. */
    private val writes = ConcurrentHashMap<BluetoothGatt, AtomicInteger>()

    /** What [holdWrites] holds: the GATT object written on, and the desktop's reply. */
    private val held = CopyOnWriteArrayList<Pair<BluetoothGatt, ByteArray?>>()

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
            device.connectGatt(any<Context>(), any<Boolean>(), any<BluetoothGattCallback>())
        } answers {
            if (!connectStarts) return@answers null
            val dialled = dialledGatt
            whileDialling?.invoke()
            probe.gattCallback.onConnectionStateChange(dialled, connectionStatus, connectionNewState)
            dialled
        }

        every { service.getCharacteristic(any<UUID>()) } answers {
            when (firstArg<UUID>()) {
                GattServer.CONTROL_POINT_UUID -> if (controlPointIsPresent) controlPoint else null
                GattServer.RESPONSE_UUID -> if (responseIsPresent) responseCharacteristic else null
                GattServer.STATUS_UUID -> statusCharacteristic
                else -> null
            }
        }
        every { responseCharacteristic.getDescriptor(GattServer.CCCD_UUID) } answers {
            if (cccdIsPresent) cccd else null
        }
        every { cccd.uuid } returns GattServer.CCCD_UUID
        every { controlPoint.setValue(any<ByteArray>()) } answers {
            lastControlPointWrite = firstArg()
            true
        }

        stubGatt(gatt)
    }

    /**
     * Answers [gatt]'s calls as the stack answers them, with every callback
     * carrying [gatt]. A write on a GATT object other than [dialledGatt] is
     * one the client has moved on from: the stack refuses it, and it is
     * counted in [writesOn].
     */
    private fun stubGatt(gatt: BluetoothGatt) {
        every { gatt.device } returns device
        every { gatt.discoverServices() } answers {
            if (!discoveryStarts) return@answers false
            probe.gattCallback.onServicesDiscovered(gatt, discoveryStatus)
            true
        }
        every { gatt.getService(GattServer.XKEY_SERVICE_UUID) } answers {
            if (serviceIsPresent) service else null
        }

        every { gatt.requestMtu(any()) } answers {
            if (!mtuRequestStarts) return@answers false
            probe.gattCallback.onMtuChanged(gatt, mtu, mtuStatus)
            true
        }

        every { gatt.setCharacteristicNotification(any(), any()) } answers { notificationsEnable }
        every { gatt.writeDescriptor(any<BluetoothGattDescriptor>()) } answers {
            if (!descriptorWriteStarts) return@answers false
            probe.gattCallback.onDescriptorWrite(gatt, cccd, descriptorWriteStatus)
            true
        }

        every { gatt.writeCharacteristic(any<BluetoothGattCharacteristic>()) } answers {
            writes.getOrPut(gatt) { AtomicInteger(0) }.incrementAndGet()
            if (gatt !== dialledGatt) return@answers false
            if (!writeStarts) return@answers false
            if (writeInFlight) {
                // One outstanding write per connection: a busy stack says no.
                overlappingWrites.incrementAndGet()
                return@answers false
            }
            writeCount++
            val fragment = lastControlPointWrite
                ?: throw AssertionError("the client wrote without setting a value")
            val reply = if (writeStatus == BluetoothGatt.GATT_SUCCESS) consume(fragment) else null
            if (holdWrites) {
                held += gatt to reply
            } else if (ackAfterTheNextWriteStarts) {
                ackOnceTheNextWriteStarts(gatt, reply)
            } else if (reply != null && replyBeforeWriteAck && responder.isHandshakeComplete()) {
                writeInFlight = true
                try {
                    deliver(reply)
                    holdWriteOpen()
                } finally {
                    writeInFlight = false
                }
                probe.gattCallback.onCharacteristicWrite(gatt, controlPoint, writeStatus)
            } else {
                probe.gattCallback.onCharacteristicWrite(gatt, controlPoint, writeStatus)
                reply?.let { deliver(it) }
            }
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

        !responder.isHandshakeComplete() -> {
            val reply = responder.processHandshakeMessage(message)
            val opener = requestOnHandshake
            if (reply == null && opener != null && responder.isHandshakeComplete()) {
                // go-xkms: local.attestDevice the moment message 3 is read.
                responder.encrypt(opener)
            } else {
                reply
            }
        }

        else -> {
            val plaintext = responder.decrypt(message)
            if (isResponse(plaintext)) {
                // The client answering a request the desktop sent: nothing
                // goes back.
                receivedResponses += plaintext
                null
            } else {
                receivedRequests += plaintext
                responder.encrypt(responseFor(plaintext))
            }
        }
    }

    /** A JSON-RPC response: JSON with a result or an error and no method. */
    private fun isResponse(plaintext: ByteArray): Boolean = try {
        val json = JSONObject(String(plaintext, Charsets.UTF_8))
        !json.has("method") && (json.has("result") || json.has("error"))
    } catch (e: JSONException) {
        false
    }

    /**
     * The desktop sends [request] over the established session, as go-xkms
     * does with `local.attestDevice` right after the handshake.
     */
    fun desktopSends(request: ByteArray) {
        deliver(responder.encrypt(request))
    }

    /** Waits for the client's [count]th answer to a [desktopSends]. */
    fun awaitResponses(count: Int): List<ByteArray> {
        val deadline = System.currentTimeMillis() + 5_000
        while (System.currentTimeMillis() < deadline) {
            if (receivedResponses.size >= count) return receivedResponses.toList()
            Thread.sleep(5)
        }
        throw AssertionError("the client sent ${receivedResponses.size} of $count answers")
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
            probe.gattCallback.onCharacteristicChanged(dialledGatt, responseCharacteristic, fragment)
            if (index < fragments.size - 1) awaitBufferedFragments(index + 1)
        }
    }

    /**
     * Keeps the write open for [writeAckHoldMs], or until the client has
     * tried to write over it, whichever comes first.
     */
    private fun holdWriteOpen() {
        val deadline = System.currentTimeMillis() + writeAckHoldMs
        while (System.currentTimeMillis() < deadline && overlappingWrites.get() == 0) {
            Thread.sleep(2)
        }
    }

    /**
     * Queues the ack for the write the client just started, behind any ack
     * still running. The completion the client installed is wrapped so that,
     * once it has resumed its writer, it waits for the next write to be handed
     * over before it returns, as [ackAfterTheNextWriteStarts] describes.
     */
    private fun ackOnceTheNextWriteStarts(gatt: BluetoothGatt, reply: ByteArray?) {
        val completion = probe.writeCompletion.get()
            ?: throw AssertionError("the client wrote with no completion installed")
        val thisWrite = writesAcked.get() + 1
        val wrapped: (Int) -> Unit = { status ->
            completion(status)
            if (awaitWritesAcked(thisWrite + 1)) acksOutlivedByTheNextWrite.incrementAndGet()
        }
        probe.writeCompletion.set(wrapped)
        writesAcked.set(thisWrite)
        ackThread.execute {
            probe.gattCallback.onCharacteristicWrite(gatt, controlPoint, writeStatus)
            reply?.let { deliver(it) }
        }
    }

    /**
     * Acknowledges the writes [holdWrites] held, on the GATT object each was
     * written on, and stops holding.
     */
    fun releaseHeldWrites() {
        holdWrites = false
        val released = held.toList()
        held.clear()
        for ((gatt, reply) in released) {
            probe.gattCallback.onCharacteristicWrite(gatt, controlPoint, writeStatus)
            reply?.let { deliver(it) }
        }
    }

    /** True once [expected] writes have been handed over, false after [nextWriteWaitMs]. */
    private fun awaitWritesAcked(expected: Int): Boolean {
        val deadline = System.currentTimeMillis() + nextWriteWaitMs
        while (System.currentTimeMillis() < deadline) {
            if (writesAcked.get() >= expected) return true
            Thread.sleep(2)
        }
        return false
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

    /**
     * Readies the next connection, as a desktop the client reconnects to: a
     * new GATT object for `connectGatt` to hand out, and a desktop waiting
     * for a new identity frame and handshake. Writes on the previous GATT
     * object are refused from here on. Call after the client disconnected.
     */
    fun nextConnection(): BluetoothGatt {
        val next = mockk<BluetoothGatt>(relaxed = true)
        stubGatt(next)
        identityDone = false
        inbound.reset()
        responder.reset()
        dialledGatt = next
        return next
    }

    /**
     * Releases the client and waits for its coroutines to finish, so none
     * outlives the test's mocks. Safe to call more than once.
     */
    fun close() {
        runCatching { runBlocking { client.destroy() } }
        if (ackAfterTheNextWriteStarts) ackThread.shutdownNow()
        awaitScopeFinished(client)
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
