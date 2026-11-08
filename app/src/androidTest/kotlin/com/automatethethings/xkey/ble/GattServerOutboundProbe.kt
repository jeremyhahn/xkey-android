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
import com.automatethethings.xkey.ca.EnrollmentRefusal
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Method
import java.util.concurrent.atomic.AtomicLong
import kotlin.coroutines.Continuation
import kotlin.coroutines.intrinsics.suspendCoroutineUninterceptedOrReturn
import kotlinx.coroutines.CompletableDeferred
import org.json.JSONObject

/**
 * The half of [GattServer] that talks *outwards*, which [GattServerProbe] can
 * reach nothing of.
 *
 * That probe drives the server above the radio and is explicit that everything
 * whose only outlet is a notification is therefore invisible to it: `sendResponse`
 * returns at its first line while `gattServer` is null, so the MTU budget, the
 * subscription wait, the fragment loop, the status notification, the outbound
 * enrollment conversation and `sendEncryptedMessage` all stop before they begin.
 *
 * That is a large and load-bearing piece of the server. `sendResponse` is the
 * only way a desktop ever hears anything; it is also where an MTU too small to
 * carry a fragment has to be *refused* rather than allowed to throw from inside
 * a coroutine, and where a response too big for one ATT write is split.
 *
 * None of it needs a peer — only an open [BluetoothGattServer], which the local
 * adapter will hand out with no device in sight. Notifications to a device that
 * never connected are reported as undeliverable by the stack and are otherwise
 * inert, so the whole path runs for real up to the last framework call.
 *
 * This probe attaches to an existing [GattServer] — the one [GattServerProbe]
 * built, or one a test wired with the enrollment collaborators — and exposes the
 * seams that probe does not. Every accessor names the member it reaches and
 * fails with a pointed message if it disappears.
 */
class GattServerOutboundProbe(val server: GattServer) {

    // -----------------------------------------------------------------
    // State the outbound path reads
    // -----------------------------------------------------------------

    /** The open server handle; null until [GattServer.start] succeeds. */
    val bluetoothGattServer: BluetoothGattServer?
        get() = read("gattServer") as BluetoothGattServer?

    var isStarting: Boolean
        get() = read("isStarting") as Boolean
        set(value) = write("isStarting", value)

    var noiseSession: NoiseSession?
        get() = read("noiseSession") as NoiseSession?
        set(value) = write("noiseSession", value)

    var connectedDevice: BluetoothDevice?
        get() = read("connectedDevice") as BluetoothDevice?
        set(value) = write("connectedDevice", value)

    var identityExchangeComplete: Boolean
        get() = read("identityExchangeComplete") as Boolean
        set(value) = write("identityExchangeComplete", value)

    var pairingConfirmed: Boolean
        get() = read("pairingConfirmed") as Boolean
        set(value) = write("pairingConfirmed", value)

    var authenticatedPeerKeyHex: String?
        get() = read("authenticatedPeerKeyHex") as String?
        set(value) = write("authenticatedPeerKeyHex", value)

    @Suppress("UNCHECKED_CAST")
    val deviceMtu: MutableMap<String, Int>
        get() = read("deviceMtu") as MutableMap<String, Int>

    @Suppress("UNCHECKED_CAST")
    val notificationEnabled: MutableMap<String, Boolean>
        get() = read("notificationEnabled") as MutableMap<String, Boolean>

    @Suppress("UNCHECKED_CAST")
    val notificationReady: MutableMap<String, CompletableDeferred<Unit>>
        get() = read("notificationReady") as MutableMap<String, CompletableDeferred<Unit>>

    val responseCharacteristic: BluetoothGattCharacteristic?
        get() = read("responseCharacteristic") as BluetoothGattCharacteristic?

    /**
     * The id the next outbound enrollment request will carry. Enrollment ids
     * live in their own 3_000_000 range so they cannot collide with the
     * laptop's or with the other remote clients sharing the router.
     */
    val nextEnrollmentRequestId: Long
        get() = (read("enrollmentRequestId") as AtomicLong).get()

    // -----------------------------------------------------------------
    // The outbound path
    // -----------------------------------------------------------------

    suspend fun sendResponse(device: BluetoothDevice, response: ByteArray) {
        callSuspend(sendResponseMethod, device, response)
    }

    fun sendStatusNotification(device: BluetoothDevice) {
        invoke(sendStatusNotificationMethod, device)
    }

    fun sendNotification(
        device: BluetoothDevice,
        characteristic: BluetoothGattCharacteristic,
        data: ByteArray
    ) {
        invoke(sendNotificationMethod, device, characteristic, data)
    }

    suspend fun sendRequestAndWaitForResponse(method: String, params: JSONObject): JSONObject =
        callSuspend(sendRequestMethod, method, params) as JSONObject

    suspend fun performPostPairingEnrollment(publicKeyHex: String, deviceName: String) {
        callSuspend(enrollmentMethod, publicKeyHex, deviceName)
    }

    /**
     * Refuses an enrollment exactly as a verification step in the ceremony does.
     *
     * Every refusal site funnels through this one method, and none of them is
     * reachable above the radio: the ceremony's first request needs a Noise
     * session to encrypt with, so it fails in transport long before anything is
     * verified. Driving the funnel directly is the only way to see what a
     * refusal actually leaves behind — an audit row carrying the case, and a
     * record beside the enrollment list for the device's own screen to read.
     *
     * Always throws; the refusal is returned as the thrown exception so a
     * caller can assert on what it carries.
     */
    fun refuseEnrollment(
        deviceId: String,
        deviceName: String,
        refusal: EnrollmentRefusal
    ): Throwable = try {
        invoke(refuseMethod, deviceId, deviceName, refusal)
        throw AssertionError("GattServer.refuseEnrollment must never return")
    } catch (e: Throwable) {
        if (e is AssertionError) throw e
        e
    }

    // -----------------------------------------------------------------
    // The inbound seams this probe's suites also need
    // -----------------------------------------------------------------

    /**
     * Adopts [device] directly, on a fresh link with no CCCD write, outside
     * any event queue. Only for a test that then calls the server's methods
     * directly: the callbacks find no open queue for the device and drop or
     * refuse what it sends, so a test that drives the callback connects with
     * [GattServerProbe.connectThroughTheCallback] instead.
     */
    suspend fun handleDeviceConnected(device: BluetoothDevice) {
        callSuspend(handleConnectedMethod, device, linkConstructor.newInstance())
    }

    suspend fun handleDeviceDisconnected(device: BluetoothDevice) {
        callSuspend(handleDisconnectedMethod, device)
    }

    suspend fun processIncomingData(device: BluetoothDevice, data: ByteArray) {
        callSuspend(processIncomingMethod, device, data)
    }

    suspend fun handleHandshakeMessage(device: BluetoothDevice, message: ByteArray) {
        callSuspend(handleHandshakeMethod, device, message)
    }

    suspend fun handleApplicationMessage(device: BluetoothDevice, encrypted: ByteArray) {
        callSuspend(handleApplicationMethod, device, encrypted)
    }

    suspend fun interceptOrRoute(plaintext: ByteArray): ByteArray? =
        callSuspend(interceptOrRouteMethod, plaintext) as ByteArray?

    suspend fun handlePairingConfirmIfNeeded(plaintext: ByteArray): ByteArray? =
        callSuspend(pairingConfirmMethod, plaintext) as ByteArray?

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
        private val sendResponseMethod = declaredMethod(
            "sendResponse",
            BluetoothDevice::class.java,
            ByteArray::class.java,
            Continuation::class.java
        )
        private val sendStatusNotificationMethod =
            declaredMethod("sendStatusNotification", BluetoothDevice::class.java)
        private val sendNotificationMethod = declaredMethod(
            "sendNotification",
            BluetoothDevice::class.java,
            BluetoothGattCharacteristic::class.java,
            ByteArray::class.java
        )
        private val sendRequestMethod = declaredMethod(
            "sendRequestAndWaitForResponse",
            String::class.java,
            JSONObject::class.java,
            Continuation::class.java
        )
        private val enrollmentMethod = declaredMethod(
            "performPostPairingEnrollment",
            String::class.java,
            String::class.java,
            Continuation::class.java
        )
        private val refuseMethod = declaredMethod(
            "refuseEnrollment",
            String::class.java,
            String::class.java,
            EnrollmentRefusal::class.java
        )
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
        private val handleHandshakeMethod = declaredMethod(
            "handleHandshakeMessage",
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
        private val pairingConfirmMethod = declaredMethod(
            "handlePairingConfirmIfNeeded", ByteArray::class.java, Continuation::class.java
        )

        private fun declaredMethod(name: String, vararg types: Class<*>): Method = try {
            GattServer::class.java.getDeclaredMethod(name, *types).apply { isAccessible = true }
        } catch (e: NoSuchMethodException) {
            throw AssertionError(
                "GattServer.$name is a seam these BLE tests drive; if it was renamed " +
                    "or resharped, update GattServerOutboundProbe",
                e
            )
        }
    }
}
