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
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Method
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.Continuation
import kotlin.coroutines.intrinsics.suspendCoroutineUninterceptedOrReturn
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.MutableStateFlow

/**
 * Reflective access to the half of [BleClient] that only the Bluetooth stack
 * ever calls.
 *
 * [BleClient] is the phone acting as a *central*: it dials a desktop, walks
 * connect / discover / MTU / notifications, runs Noise XX as the initiator and
 * then carries encrypted JSON-RPC. Every one of those steps is a suspending
 * call parked on a [CompletableDeferred] that only a `BluetoothGattCallback`
 * ever completes, so none of it runs — and none of it is observable — unless
 * something plays the part of the stack.
 *
 * Nothing here needs a radio. The client never touches the framework except
 * through objects it was handed:
 *
 *  - the `BluetoothGatt`, `BluetoothDevice`, characteristics and descriptor all
 *    arrive from the adapter, so a mock is indistinguishable from the real one;
 *  - `gattCallback` and `scanCallback` are ordinary objects whose overrides are
 *    plain Kotlin — invoking them directly is exactly what the stack does.
 *
 * This probe exposes those two callbacks plus the private state they mutate.
 * [BleClientHarness] builds on it to run a whole desktop against the client
 * in-process; suites that only need one branch drive the seams here directly.
 *
 * Every accessor names the member it reaches and fails with a pointed message
 * if it disappears, so a rename reads as "this seam moved" rather than as a
 * mystery `NoSuchFieldException`.
 */
class BleClientProbe(val client: BleClient) {

    // -----------------------------------------------------------------
    // The two callbacks the stack owns
    // -----------------------------------------------------------------

    val gattCallback: BluetoothGattCallback
        get() = read("gattCallback") as BluetoothGattCallback

    val scanCallback: ScanCallback
        get() = read("scanCallback") as ScanCallback

    // -----------------------------------------------------------------
    // Connection state
    // -----------------------------------------------------------------

    var gattConnection: BluetoothGatt?
        get() = read("gattConnection") as BluetoothGatt?
        set(value) = write("gattConnection", value)

    var connectedDevice: BluetoothDevice?
        get() = read("connectedDevice") as BluetoothDevice?
        set(value) = write("connectedDevice", value)

    var controlPointCharacteristic: BluetoothGattCharacteristic?
        get() = read("controlPointCharacteristic") as BluetoothGattCharacteristic?
        set(value) = write("controlPointCharacteristic", value)

    var responseCharacteristic: BluetoothGattCharacteristic?
        get() = read("responseCharacteristic") as BluetoothGattCharacteristic?
        set(value) = write("responseCharacteristic", value)

    val statusCharacteristic: BluetoothGattCharacteristic?
        get() = read("statusCharacteristic") as BluetoothGattCharacteristic?

    var noiseSession: NoiseInitiatorSession?
        get() = read("noiseSession") as NoiseInitiatorSession?
        set(value) = write("noiseSession", value)

    var negotiatedMtu: Int
        get() = read("negotiatedMtu") as Int
        set(value) = write("negotiatedMtu", value)

    val fragmentReassembler: FragmentReassembler
        get() = read("fragmentReassembler") as FragmentReassembler

    @Suppress("UNCHECKED_CAST")
    val connectionStateFlow: MutableStateFlow<ClientConnectionState>
        get() = read("_connectionState") as MutableStateFlow<ClientConnectionState>

    // -----------------------------------------------------------------
    // Scanning
    // -----------------------------------------------------------------

    val isScanning: AtomicBoolean
        get() = read("isScanning") as AtomicBoolean

    @Suppress("UNCHECKED_CAST")
    val discoveredDevices: ConcurrentHashMap<String, ScanResult>
        get() = read("discoveredDevices") as ConcurrentHashMap<String, ScanResult>

    @Suppress("UNCHECKED_CAST")
    var scanDeferred: CompletableDeferred<List<ScanResult>>?
        get() = read("scanDeferred") as CompletableDeferred<List<ScanResult>>?
        set(value) = write("scanDeferred", value)

    // -----------------------------------------------------------------
    // The deferreds the callbacks complete
    // -----------------------------------------------------------------

    @Suppress("UNCHECKED_CAST")
    var connectionDeferred: CompletableDeferred<Unit>?
        get() = read("connectionDeferred") as CompletableDeferred<Unit>?
        set(value) = write("connectionDeferred", value)

    @Suppress("UNCHECKED_CAST")
    var servicesDiscoveredDeferred: CompletableDeferred<Unit>?
        get() = read("servicesDiscoveredDeferred") as CompletableDeferred<Unit>?
        set(value) = write("servicesDiscoveredDeferred", value)

    @Suppress("UNCHECKED_CAST")
    var mtuDeferred: CompletableDeferred<Int>?
        get() = read("mtuDeferred") as CompletableDeferred<Int>?
        set(value) = write("mtuDeferred", value)

    @Suppress("UNCHECKED_CAST")
    var notificationEnabledDeferred: CompletableDeferred<Unit>?
        get() = read("notificationEnabledDeferred") as CompletableDeferred<Unit>?
        set(value) = write("notificationEnabledDeferred", value)

    @Suppress("UNCHECKED_CAST")
    var pendingResponse: CompletableDeferred<ByteArray>?
        get() = read("pendingResponse") as CompletableDeferred<ByteArray>?
        set(value) = write("pendingResponse", value)

    /** True while a `sendCharacteristicWrite` is parked waiting for the stack. */
    val hasWriteInFlight: Boolean
        get() = read("writeCompletionCallback") != null

    // -----------------------------------------------------------------
    // Private methods under test
    // -----------------------------------------------------------------

    fun initializeBluetooth() {
        invoke(initializeBluetoothMethod)
    }

    fun stopScan() {
        invoke(stopScanMethod)
    }

    fun disconnectInternal() {
        invoke(disconnectInternalMethod)
    }

    fun handleCompleteMessage(message: ByteArray) {
        invoke(handleCompleteMessageMethod, message)
    }

    suspend fun sendFragmentedMessage(
        characteristic: BluetoothGattCharacteristic,
        message: ByteArray
    ) {
        callSuspend(sendFragmentedMessageMethod, characteristic, message)
    }

    // -----------------------------------------------------------------
    // Reflection plumbing
    // -----------------------------------------------------------------

    private fun read(name: String): Any? = fieldOf(name).get(client)

    private fun write(name: String, value: Any?) = fieldOf(name).set(client, value)

    private fun invoke(method: Method, vararg args: Any?): Any? = try {
        method.invoke(client, *args)
    } catch (e: InvocationTargetException) {
        throw e.cause ?: e
    }

    private suspend fun callSuspend(method: Method, vararg args: Any?): Any? =
        suspendCoroutineUninterceptedOrReturn { continuation ->
            try {
                method.invoke(client, *(args.toList() + continuation).toTypedArray())
            } catch (e: InvocationTargetException) {
                throw e.cause ?: e
            }
        }

    private fun fieldOf(name: String) = try {
        BleClient::class.java.getDeclaredField(name).apply { isAccessible = true }
    } catch (e: NoSuchFieldException) {
        throw AssertionError("BleClient.$name is a seam these BLE tests drive", e)
    }

    companion object {
        private val initializeBluetoothMethod = declaredMethod("initializeBluetooth")
        private val stopScanMethod = declaredMethod("stopScan")
        private val disconnectInternalMethod = declaredMethod("disconnectInternal")
        private val handleCompleteMessageMethod =
            declaredMethod("handleCompleteMessage", ByteArray::class.java)
        private val sendFragmentedMessageMethod = declaredMethod(
            "sendFragmentedMessage",
            BluetoothGattCharacteristic::class.java,
            ByteArray::class.java,
            Continuation::class.java
        )

        private fun declaredMethod(name: String, vararg types: Class<*>): Method = try {
            BleClient::class.java.getDeclaredMethod(name, *types).apply { isAccessible = true }
        } catch (e: NoSuchMethodException) {
            throw AssertionError(
                "BleClient.$name is a seam these BLE tests drive; if it was renamed " +
                    "or resharped, update BleClientProbe",
                e
            )
        }
    }
}
