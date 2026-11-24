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
import com.automatethethings.xkey.ca.EnrollmentRefusal
import kotlin.coroutines.Continuation
import org.json.JSONObject
import org.junit.Assert.fail
import org.junit.Test

/**
 * The private members of [GattServer] and [XKeyGattService] that the
 * instrumented BLE harnesses reach by reflection.
 *
 * Those harnesses live in `androidTest` and resolve their seams in a static
 * initializer, so a renamed or resharped member only shows up on a device, as
 * a `NoClassDefFoundError` for every test class that touches the harness. This
 * test resolves the same members on the JVM, so the drift fails here first.
 *
 * The two source sets share no code, so each list below is a copy of one
 * harness's lookups; its twin is named above it. Change both together.
 */
class GattServerSeamSignatureTest {

    private class Seam(val name: String, vararg val types: Class<*>)

    private val gattServer = GattServer::class.java

    private val link: Class<*> =
        Class.forName("${GattServer::class.java.name}\$Link", false, GattServer::class.java.classLoader)

    private val continuation = Continuation::class.java
    private val bytes = ByteArray::class.java
    private val device = BluetoothDevice::class.java
    private val string = String::class.java

    // Twin: androidTest ble/GattServerOutboundProbe.kt (companion and field accessors).
    private val outboundProbeMethods = listOf(
        Seam("sendResponse", device, bytes, continuation),
        Seam("sendStatusNotification", device),
        Seam("sendNotification", device, BluetoothGattCharacteristic::class.java, bytes),
        Seam("sendRequestAndWaitForResponse", NoiseSession::class.java, string, JSONObject::class.java, continuation),
        Seam("performPostPairingEnrollment", string, string, NoiseSession::class.java, continuation),
        Seam("refuseEnrollment", string, string, EnrollmentRefusal::class.java),
        Seam("handleDeviceConnected", device, link, continuation),
        Seam("handleDeviceDisconnected", device, continuation),
        Seam("processIncomingData", device, bytes, continuation),
        Seam("handleHandshakeMessage", device, bytes, continuation),
        Seam("handleApplicationMessage", device, bytes, continuation),
        Seam("interceptOrRoute", bytes, continuation),
        Seam("handlePairingConfirmIfNeeded", bytes, NoiseSession::class.java, continuation)
    )
    private val outboundProbeFields = listOf(
        "gattServer", "isStarting", "noiseSession", "connectedDevice", "identityExchangeComplete",
        "pairingConfirmed", "authenticatedPeerKeyHex", "deviceMtu", "notificationEnabled",
        "notificationReady", "responseCharacteristic", "enrollmentRequestId"
    )

    // Twin: androidTest ble/GattServerProbe.kt (companion and field accessors).
    private val probeMethods = listOf(
        Seam("setupService"),
        Seam("getStatusValue"),
        Seam("adoptExistingPairing"),
        Seam("rejectUnpaired", bytes),
        Seam("handleDeviceConnected", device, link, continuation),
        Seam("handleDeviceDisconnected", device, continuation),
        Seam("processIncomingData", device, bytes, continuation),
        Seam("handleApplicationMessage", device, bytes, continuation),
        Seam("interceptOrRoute", bytes, continuation)
    )
    private val probeFields = listOf(
        "gattCallback", "connectedDevice", "noiseSession", "establishedSession",
        "identityExchangeComplete", "pairingConfirmed", "remotePublicKeyHex",
        "authenticatedPeerKeyHex", "gattServer", "deviceMtu", "notificationEnabled",
        "fragmentBuffer", "serviceAddedLatch", "flexKeyService", "controlPointCharacteristic",
        "responseCharacteristic", "statusCharacteristic", "_connectionState",
        "eventQueuesLock", "eventQueues"
    )

    // Twin: androidTest ble/BleLoopbackHarness.kt (companion and connect()).
    private val loopbackMethods = listOf(
        Seam("interceptOrRoute", bytes, continuation),
        Seam("computePrologueFromIdentity", bytes, bytes)
    )
    private val loopbackFields = listOf(
        "noiseSession", "establishedSession", "authenticatedPeerKeyHex", "pairingConfirmed"
    )

    // Twin: androidTest ble/XKeyGattServiceProbe.kt (companion and field accessors).
    private val serviceMethods = listOf(
        Seam("initializeBluetooth"),
        Seam("handleConnectionStateChange", ConnectionState::class.java),
        Seam("handleAdvertisingStateChange", AdvertisingState::class.java),
        Seam("startTcpHsmServer"),
        Seam("stopTcpHsmServer"),
        Seam("createNotification"),
        Seam("acquireWakeLock"),
        Seam("releaseWakeLock")
    )
    private val serviceFields = listOf(
        "gattServer", "advertiser", "requestHandler", "bleMessageRouter", "tcpMessageRouter",
        "tcpHsmServer", "usbServerSlot", "pairedDeviceRepository", "bluetoothAdapter",
        "isStartingAdvertising", "wakeLock", "_serviceState"
    )

    @Test
    fun theOutboundProbeSeamsExist() = assertSeams("GattServerOutboundProbe", gattServer, outboundProbeMethods, outboundProbeFields)

    @Test
    fun theProbeSeamsExist() = assertSeams("GattServerProbe", gattServer, probeMethods, probeFields)

    @Test
    fun theLoopbackHarnessSeamsExist() = assertSeams("BleLoopbackHarness", gattServer, loopbackMethods, loopbackFields)

    @Test
    fun theLinkHasTheNoArgumentConstructorBothProbesUse() {
        try {
            link.getDeclaredConstructor()
        } catch (e: NoSuchMethodException) {
            fail("GattServer.Link() is a seam GattServerProbe and GattServerOutboundProbe build")
        }
    }

    @Test
    fun theServiceProbeSeamsExist() =
        assertSeams("XKeyGattServiceProbe", XKeyGattService::class.java, serviceMethods, serviceFields)

    /** Collects every missing member, so one stale seam does not hide the next. */
    private fun assertSeams(harness: String, target: Class<*>, methods: List<Seam>, fields: List<String>) {
        val missing = mutableListOf<String>()
        for (seam in methods) {
            try {
                target.getDeclaredMethod(seam.name, *seam.types)
            } catch (e: NoSuchMethodException) {
                missing += "${seam.name}(${seam.types.joinToString { it.simpleName }})"
            }
        }
        for (field in fields) {
            try {
                target.getDeclaredField(field)
            } catch (e: NoSuchFieldException) {
                missing += field
            }
        }
        if (missing.isNotEmpty()) {
            fail("$harness reflects on ${target.simpleName} members that no longer exist: $missing")
        }
    }
}
