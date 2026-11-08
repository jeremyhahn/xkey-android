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
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.content.Context
import android.os.SystemClock
import com.automatethethings.xkey.auth.SessionAuthManager
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.remote.BidirectionalMessageRouter
import com.automatethethings.xkey.settings.AttestationBiometricPolicy
import com.automatethethings.xkey.settings.BiometricSettingsData
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.settings.UserVerificationPolicy
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Method
import java.security.SecureRandom
import kotlin.coroutines.Continuation
import kotlin.coroutines.intrinsics.suspendCoroutineUninterceptedOrReturn
import kotlinx.coroutines.flow.MutableStateFlow
import org.junit.Assume.assumeTrue

/**
 * Reflective access to the half of [GattServer] that only the Bluetooth stack
 * ever calls.
 *
 * [BleLoopbackHarness] deliberately enters the server at `interceptOrRoute`,
 * one layer *above* the radio, so everything the stack drives — the
 * `BluetoothGattServerCallback`, the connect/disconnect bookkeeping, the
 * pre-handshake identity exchange and the encrypted message loop — has no
 * coverage at all. None of it actually needs a radio:
 *
 *  - every outbound call goes through `sendResponse`, which returns early
 *    while `gattServer` is null, so a server that was never `start()`ed can be
 *    driven safely;
 *  - `BluetoothDevice`, `BluetoothGattCharacteristic`, `BluetoothGattDescriptor`
 *    and `BluetoothGattService` are ordinary objects that can be created
 *    without a connection.
 *
 * What is therefore *not* observable through this probe is anything whose only
 * outlet is a notification (handshake message 2, identity acknowledgements,
 * response bodies). Tests assert on the server's own state instead, and drive
 * the peer side of the Noise session directly — see [establishSession].
 *
 * Every accessor names the member it reaches and fails with a pointed message
 * if it disappears, so a rename shows up as "this seam moved" rather than as a
 * mystery `NoSuchMethodException`.
 */
class GattServerProbe(
    val context: Context,
    /** Pass null to build a server that has no notion of device approval. */
    val pairedDeviceRepository: PairedDeviceRepository? = PairedDeviceRepository(context),
    pairingCallback: PairingConfirmationCallback? = null,
    withMessageRouter: Boolean = true
) {

    val requestHandler: RequestHandler = RequestHandler(
        context = context,
        keystoreManager = KeystoreManager(context),
        biometricLauncher = null,
        sessionAuthManager = SessionAuthManager(),
        pairedDeviceRepository = pairedDeviceRepository ?: PairedDeviceRepository(context)
    ).apply {
        // No UI is attached, so gate nothing on biometrics — the posture the
        // rest of the protocol suites use.
        updateSettings(
            BiometricSettingsData(
                uvPolicy = UserVerificationPolicy.DISABLED,
                attestationBiometricPolicy = AttestationBiometricPolicy.NEVER
            )
        )
    }

    val messageRouter: BidirectionalMessageRouter? =
        if (withMessageRouter) BidirectionalMessageRouter(requestHandler) else null

    val server: GattServer = GattServer(
        context = context,
        requestHandler = requestHandler,
        messageRouter = messageRouter,
        pairingCallback = pairingCallback,
        pairedDeviceRepository = pairedDeviceRepository
    )

    /** The callback object the Bluetooth stack owns. */
    val gattCallback: BluetoothGattServerCallback
        get() = read("gattCallback") as BluetoothGattServerCallback

    val connectedDevice: BluetoothDevice?
        get() = read("connectedDevice") as BluetoothDevice?

    val noiseSession: NoiseSession?
        get() = read("noiseSession") as NoiseSession?

    val identityExchangeComplete: Boolean
        get() = read("identityExchangeComplete") as Boolean

    val pairingConfirmed: Boolean
        get() = read("pairingConfirmed") as Boolean

    val remotePublicKeyHex: String?
        get() = read("remotePublicKeyHex") as String?

    var authenticatedPeerKeyHex: String?
        get() = read("authenticatedPeerKeyHex") as String?
        set(value) {
            write("authenticatedPeerKeyHex", value)
        }

    /**
     * The open server handle every notification goes out on. Replacing it lets
     * a test stand in for a stack that accepts notifications without a peer.
     */
    var gattServerHandle: BluetoothGattServer?
        get() = read("gattServer") as BluetoothGattServer?
        set(value) {
            write("gattServer", value)
        }

    @Suppress("UNCHECKED_CAST")
    val deviceMtu: Map<String, Int>
        get() = read("deviceMtu") as Map<String, Int>

    @Suppress("UNCHECKED_CAST")
    val notificationEnabled: Map<String, Boolean>
        get() = read("notificationEnabled") as Map<String, Boolean>

    @Suppress("UNCHECKED_CAST")
    val fragmentBuffer: Map<String, FragmentReassembler>
        get() = read("fragmentBuffer") as Map<String, FragmentReassembler>

    val serviceAddedLatch: java.util.concurrent.CountDownLatch?
        get() = read("serviceAddedLatch") as java.util.concurrent.CountDownLatch?

    val flexKeyService: BluetoothGattService?
        get() = read("flexKeyService") as BluetoothGattService?

    val controlPointCharacteristic: BluetoothGattCharacteristic?
        get() = read("controlPointCharacteristic") as BluetoothGattCharacteristic?

    val responseCharacteristic: BluetoothGattCharacteristic?
        get() = read("responseCharacteristic") as BluetoothGattCharacteristic?

    val statusCharacteristic: BluetoothGattCharacteristic?
        get() = read("statusCharacteristic") as BluetoothGattCharacteristic?

    /** The backing flow of [GattServer.connectionState], writable for tests. */
    @Suppress("UNCHECKED_CAST")
    private val connectionStateFlow: MutableStateFlow<ConnectionState>
        get() = read("_connectionState") as MutableStateFlow<ConnectionState>

    var connectionState: ConnectionState
        get() = connectionStateFlow.value
        set(value) {
            connectionStateFlow.value = value
        }

    // -----------------------------------------------------------------
    // Private members under test
    // -----------------------------------------------------------------

    /** Builds the GATT service and characteristics; returns false with no server. */
    fun setupService(): Boolean = invoke(setupServiceMethod) as Boolean

    /** The one-byte status the STATUS characteristic reports. */
    fun statusValue(): ByteArray = invoke(getStatusValueMethod) as ByteArray

    fun adoptExistingPairing() {
        invoke(adoptPairingMethod)
    }

    fun rejectUnpaired(plaintext: ByteArray): ByteArray? =
        invoke(rejectUnpairedMethod, plaintext) as ByteArray?

    /**
     * Adopts [device] directly, on a fresh link with no CCCD write, outside
     * any event queue. Only for a test that then calls the server's methods
     * directly: the callbacks find no open queue for the device and drop or
     * refuse what it sends, so a test that drives [gattCallback] connects
     * with [connectThroughTheCallback] instead.
     */
    suspend fun handleDeviceConnected(device: BluetoothDevice) {
        callSuspend(handleConnectedMethod, device, linkConstructor.newInstance())
    }

    suspend fun handleDeviceDisconnected(device: BluetoothDevice) {
        callSuspend(handleDisconnectedMethod, device)
    }

    /**
     * Whether the server holds an event queue for [device]: one a connect
     * callback began and whose consumer has not yet finished.
     */
    fun hasEventQueue(device: BluetoothDevice): Boolean =
        synchronized(read("eventQueuesLock")!!) {
            (read("eventQueues") as Map<*, *>).containsKey(device.address)
        }

    /**
     * Connects [device] the way the stack does, on a started server: the
     * connect callback begins the device's event queue with the connect at its
     * head, and every later callback is queued behind it or recorded on its
     * link. A callback from a device without an open queue is dropped.
     *
     * Returns once the queue has handled the connect, so the device is adopted
     * and its link published: from then on a CCCD write shows in
     * [notificationEnabled] as it is made, and a queued MTU change is awaited
     * with [awaitMtu]. Skips the test where the local stack will not open a
     * GATT server.
     */
    fun connectThroughTheCallback(device: BluetoothDevice) {
        assumeTrue("the local stack would not open a GATT server", server.start())
        gattCallback.onConnectionStateChange(
            device, BluetoothGatt.GATT_SUCCESS, BluetoothProfile.STATE_CONNECTED
        )
        awaitUntil("the device to be adopted") {
            connectedDevice?.address == device.address &&
                server.connectionState.value == ConnectionState.Connecting
        }
    }

    /**
     * Returns once [device]'s event queue has applied an MTU change to
     * [expected]. The connect records the default MTU, so a test that awaits
     * the default after a connect awaits it after another value.
     */
    fun awaitMtu(device: BluetoothDevice, expected: Int, why: String = "the negotiated MTU") {
        awaitUntil("the MTU to become $expected: $why") { deviceMtu[device.address] == expected }
    }

    suspend fun processIncomingData(device: BluetoothDevice, data: ByteArray) {
        callSuspend(processIncomingMethod, device, data)
    }

    suspend fun handleApplicationMessage(device: BluetoothDevice, encrypted: ByteArray) {
        callSuspend(handleApplicationMethod, device, encrypted)
    }

    suspend fun interceptOrRoute(plaintext: ByteArray): ByteArray? =
        callSuspend(interceptOrRouteMethod, plaintext) as ByteArray?

    // -----------------------------------------------------------------
    // Session installation
    // -----------------------------------------------------------------

    /**
     * Completes a Noise XX handshake against the server's own session and
     * installs the result exactly as `handleHandshakeMessage` does, so the
     * encrypted message loop can be driven afterwards.
     *
     * The server's replies are unreachable without a radio, so the responder is
     * driven directly rather than through `processIncomingData` — which is why
     * this bypasses the identity exchange. Tests that care about the identity
     * exchange drive [processIncomingData] instead.
     *
     * @return the desktop-side initiator, for encrypting requests.
     */
    suspend fun establishSession(device: BluetoothDevice): NoiseInitiatorSession {
        val initiator = NoiseInitiatorSession(ByteArray(32).also { SecureRandom().nextBytes(it) })
        val responder = NoiseSession().also { it.loadStaticKey(context) }

        val msg2 = responder.processHandshakeMessage(initiator.createHandshakeMessage1())
            ?: throw AssertionError("responder produced no handshake message 2")
        initiator.processHandshakeMessage2(msg2)
        check(responder.processHandshakeMessage(initiator.createHandshakeMessage3()) == null) {
            "responder replied to handshake message 3"
        }
        initiator.finalizeHandshake()
        check(responder.isHandshakeComplete()) { "responder handshake did not complete" }

        write("connectedDevice", device)
        write("noiseSession", responder)
        write("identityExchangeComplete", true)
        authenticatedPeerKeyHex = responder.getRemoteStaticKey()?.toHex()
        return initiator
    }

    fun close() = server.destroy()

    // -----------------------------------------------------------------
    // Reflection plumbing
    // -----------------------------------------------------------------

    private fun read(name: String): Any? = fieldOf(name).get(server)

    private fun write(name: String, value: Any?) = fieldOf(name).set(server, value)

    private fun invoke(method: Method, vararg args: Any?): Any? = try {
        method.invoke(server, *args)
    } catch (e: InvocationTargetException) {
        throw e.cause ?: e
    }

    private suspend fun callSuspend(method: Method, vararg args: Any?): Any? =
        suspendCoroutineUninterceptedOrReturn { continuation ->
            try {
                method.invoke(server, *(args.toList() + continuation).toTypedArray())
            } catch (e: InvocationTargetException) {
                throw e.cause ?: e
            }
        }

    private fun fieldOf(name: String) = try {
        GattServer::class.java.getDeclaredField(name).apply { isAccessible = true }
    } catch (e: NoSuchFieldException) {
        throw AssertionError("GattServer.$name is a seam these BLE tests drive", e)
    }

    companion object {
        private val setupServiceMethod = declaredMethod("setupService")
        private val getStatusValueMethod = declaredMethod("getStatusValue")
        private val adoptPairingMethod = declaredMethod("adoptExistingPairing")
        private val rejectUnpairedMethod = declaredMethod("rejectUnpaired", ByteArray::class.java)
        private val linkClass: Class<*> = try {
            Class.forName("${GattServer::class.java.name}\$Link")
        } catch (e: ClassNotFoundException) {
            throw AssertionError("GattServer.Link is a seam these BLE tests drive", e)
        }
        private val linkConstructor = linkClass.getDeclaredConstructor().apply { isAccessible = true }
        private val handleConnectedMethod = declaredMethod(
            "handleDeviceConnected", BluetoothDevice::class.java, linkClass, Continuation::class.java
        )
        private val handleDisconnectedMethod = declaredMethod(
            "handleDeviceDisconnected", BluetoothDevice::class.java, Continuation::class.java
        )
        private val processIncomingMethod = declaredMethod(
            "processIncomingData",
            BluetoothDevice::class.java,
            ByteArray::class.java,
            Continuation::class.java
        )
        private val handleApplicationMethod = declaredMethod(
            "handleApplicationMessage",
            BluetoothDevice::class.java,
            ByteArray::class.java,
            Continuation::class.java
        )
        private val interceptOrRouteMethod = declaredMethod(
            "interceptOrRoute", ByteArray::class.java, Continuation::class.java
        )

        private fun declaredMethod(name: String, vararg types: Class<*>): Method = try {
            GattServer::class.java.getDeclaredMethod(name, *types).apply { isAccessible = true }
        } catch (e: NoSuchMethodException) {
            throw AssertionError(
                "GattServer.$name is a seam these BLE tests drive; if it was renamed " +
                    "or resharped, update GattServerProbe",
                e
            )
        }

        /**
         * A remote device object for a fixed address. The address is never
         * dialled — it only has to be a well-formed peer identity.
         */
        fun remoteDevice(context: Context, address: String = "AA:BB:CC:DD:EE:F0"): BluetoothDevice? =
            context.getSystemService(BluetoothManager::class.java)
                ?.adapter
                ?.getRemoteDevice(address)

        /** Spins until [condition] holds, for state the server updates on its own scope. */
        fun awaitUntil(message: String, timeoutMs: Long = 10_000, condition: () -> Boolean) {
            val deadline = SystemClock.uptimeMillis() + timeoutMs
            while (SystemClock.uptimeMillis() < deadline) {
                if (condition()) return
                Thread.sleep(20)
            }
            throw AssertionError("timed out waiting for: $message")
        }

        fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
    }
}
