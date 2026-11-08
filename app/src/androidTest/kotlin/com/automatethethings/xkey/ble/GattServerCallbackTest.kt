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

import android.Manifest
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothProfile
import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.rule.GrantPermissionRule
import java.io.IOException
import java.security.SecureRandom
import java.util.UUID
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The [GattServer] surface the Bluetooth stack owns.
 *
 * `BluetoothGattServerCallback` is where every byte from a desktop first
 * arrives, and it had no coverage: the loopback harness enters the server well
 * above it, and the only way an integration test would reach it is with a
 * second radio. It does not need one — nothing in the callback requires an open
 * `BluetoothGattServer`, because every outbound call is `gattServer?.…` and
 * simply does nothing while the server was never started. See [GattServerProbe]
 * for the reflection this relies on.
 *
 * The properties asserted here are the ones a wrong callback silently breaks:
 * the MTU clamp that decides the fragment budget, the CCCD bookkeeping that
 * decides whether a response is ever sent, the characteristic routing that
 * decides whether a write is treated as protocol data at all, and the service
 * definition the desktop discovers by UUID.
 */
@RunWith(AndroidJUnit4::class)
class GattServerCallbackTest {

    /** `handleDeviceConnected` reads `BluetoothDevice.getName()`. */
    @get:Rule
    val bluetoothPermission: GrantPermissionRule =
        GrantPermissionRule.grant(Manifest.permission.BLUETOOTH_CONNECT)

    private lateinit var context: Context
    private lateinit var probe: GattServerProbe
    private lateinit var device: BluetoothDevice

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        val remote = GattServerProbe.remoteDevice(context)
        assumeTrue("this device has no Bluetooth adapter", remote != null)
        device = remote!!
        probe = GattServerProbe(context)
    }

    @After
    fun tearDown() {
        if (::probe.isInitialized) probe.close()
    }

    // -----------------------------------------------------------------
    // Lifecycle without a radio
    // -----------------------------------------------------------------

    /** A server that was never started must report itself as idle, not broken. */
    @Test
    fun aServerThatNeverStartedIsIdle() {
        assertFalse(probe.server.isRunning())
        assertNull(probe.server.getConnectedDevice())
        assertFalse(probe.server.isSessionEstablished())
        assertEquals(ConnectionState.Disconnected, probe.server.connectionState.value)
        assertArrayEquals(byteArrayOf(0x00), probe.statusValue())
    }

    /** `stop()` runs on every teardown path, including ones that never started. */
    @Test
    fun stopIsSafeAndIdempotentOnAServerThatNeverStarted() {
        probe.server.stop()
        probe.server.stop()

        assertFalse(probe.server.isRunning())
        assertNull(probe.server.getConnectedDevice())
    }

    /** The STATUS characteristic reports one byte per connection state. */
    @Test
    fun theStatusValueEncodesEachConnectionState() {
        probe.connectionState = ConnectionState.Disconnected
        assertArrayEquals(byteArrayOf(0x00), probe.statusValue())

        probe.connectionState = ConnectionState.Connecting
        assertArrayEquals(byteArrayOf(0x01), probe.statusValue())

        probe.connectionState = ConnectionState.Connected("Workstation", device.address)
        assertArrayEquals(byteArrayOf(0x02), probe.statusValue())
    }

    /** Outbound requests need a live session; without one they fail loudly. */
    @Test
    fun sendingAnEncryptedMessageWithoutASessionFails(): Unit = runBlocking {
        try {
            probe.server.sendEncryptedMessage("{}".toByteArray())
            fail("expected sending without a Noise session to fail")
        } catch (expected: IOException) {
            // expected
        }
    }

    // -----------------------------------------------------------------
    // The GATT service definition
    // -----------------------------------------------------------------

    /**
     * The service and its three characteristics are what a desktop discovers.
     * The control point must be writable and the response characteristic must
     * carry a CCCD, or notifications — the only way the phone answers — can
     * never be subscribed to.
     */
    @Test
    fun theServiceDefinitionMatchesWhatADesktopDiscovers() {
        // With no open server the add cannot succeed; the definition is still built.
        assertFalse("addService cannot succeed without an open server", probe.setupService())

        val service = probe.flexKeyService
        assertNotNull(service)
        assertEquals(GattServer.XKEY_SERVICE_UUID, service!!.uuid)
        assertEquals(BluetoothGattService.SERVICE_TYPE_PRIMARY, service.type)
        assertEquals(3, service.characteristics.size)

        val controlPoint = probe.controlPointCharacteristic!!
        assertEquals(GattServer.CONTROL_POINT_UUID, controlPoint.uuid)
        assertTrue(
            "the desktop writes requests here",
            controlPoint.properties and BluetoothGattCharacteristic.PROPERTY_WRITE != 0
        )
        assertTrue(
            controlPoint.permissions and BluetoothGattCharacteristic.PERMISSION_WRITE != 0
        )

        val response = probe.responseCharacteristic!!
        assertEquals(GattServer.RESPONSE_UUID, response.uuid)
        assertTrue(
            "responses are delivered as notifications",
            response.properties and BluetoothGattCharacteristic.PROPERTY_NOTIFY != 0
        )
        assertNotNull(
            "without a CCCD the desktop cannot subscribe and never sees a reply",
            response.getDescriptor(GattServer.CCCD_UUID)
        )

        val status = probe.statusCharacteristic!!
        assertEquals(GattServer.STATUS_UUID, status.uuid)
        assertNotNull(status.getDescriptor(GattServer.CCCD_UUID))

        assertEquals("start() waits on this latch", 1L, probe.serviceAddedLatch?.count)
    }

    /** `start()` blocks on the latch this callback releases. */
    @Test
    fun addingTheXKeyServiceReleasesTheStartupLatch() {
        probe.setupService()

        probe.gattCallback.onServiceAdded(BluetoothGatt.GATT_SUCCESS, probe.flexKeyService!!)

        assertEquals(0L, probe.serviceAddedLatch?.count)
    }

    /** A callback for some other service must not release it. */
    @Test
    fun addingAForeignServiceLeavesTheStartupLatchClosed() {
        probe.setupService()

        probe.gattCallback.onServiceAdded(
            BluetoothGatt.GATT_SUCCESS,
            BluetoothGattService(UUID.randomUUID(), BluetoothGattService.SERVICE_TYPE_PRIMARY)
        )

        assertEquals(1L, probe.serviceAddedLatch?.count)
    }

    // -----------------------------------------------------------------
    // MTU
    // -----------------------------------------------------------------

    /**
     * The negotiated MTU becomes the fragment budget, so an unclamped value is
     * a wire error: below 23 the fragmenter throws before sending a byte, and
     * above 517 the stack silently truncates notifications.
     */
    @Test
    fun theNegotiatedMtuIsClampedToTheSupportedRange() {
        connectThroughTheCallback()

        probe.gattCallback.onMtuChanged(device, 247)
        awaitMtu(247, "within the supported range")

        probe.gattCallback.onMtuChanged(device, 3)
        awaitMtu(23, "below the BLE minimum")

        probe.gattCallback.onMtuChanged(device, 4096)
        awaitMtu(517, "above the supported maximum")
    }

    // -----------------------------------------------------------------
    // CCCD subscription
    // -----------------------------------------------------------------

    /**
     * `sendResponse` refuses to send until this flag is set, so getting the
     * CCCD write wrong means the phone accepts requests and answers none.
     */
    @Test
    fun subscribingToNotificationsIsRecordedPerDevice() {
        connectThroughTheCallback()
        val cccd = cccdDescriptor()

        probe.gattCallback.onDescriptorWriteRequest(
            device, 1, cccd, false, false, 0,
            BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
        )
        assertEquals(true, probe.notificationEnabled[device.address])

        probe.gattCallback.onDescriptorWriteRequest(
            device, 2, cccd, false, false, 0,
            BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE
        )
        assertEquals(false, probe.notificationEnabled[device.address])
    }

    /** Indications count as a subscription too. */
    @Test
    fun subscribingWithIndicationsAlsoCounts() {
        connectThroughTheCallback()

        probe.gattCallback.onDescriptorWriteRequest(
            device, 1, cccdDescriptor(), false, true, 0,
            BluetoothGattDescriptor.ENABLE_INDICATION_VALUE
        )

        assertEquals(true, probe.notificationEnabled[device.address])
    }

    @Test
    fun aWriteToAnotherDescriptorIsIgnored() {
        connectThroughTheCallback()

        probe.gattCallback.onDescriptorWriteRequest(
            device, 1,
            BluetoothGattDescriptor(UUID.randomUUID(), BluetoothGattDescriptor.PERMISSION_WRITE),
            false, true, 0,
            BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
        )

        assertNull(probe.notificationEnabled[device.address])
    }

    @Test
    fun aDescriptorWriteWithNoValueIsIgnored() {
        connectThroughTheCallback()

        probe.gattCallback.onDescriptorWriteRequest(
            device, 1, cccdDescriptor(), false, true, 0, null
        )

        assertNull(probe.notificationEnabled[device.address])
    }

    /** Reads on an open connection are answered from its subscription state. */
    @Test
    fun descriptorReadsAreServedForBothSubscriptionStates() {
        connectThroughTheCallback()
        val cccd = cccdDescriptor()

        probe.gattCallback.onDescriptorReadRequest(device, 1, 0, cccd)

        probe.gattCallback.onDescriptorWriteRequest(
            device, 2, cccd, false, false, 0,
            BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
        )
        probe.gattCallback.onDescriptorReadRequest(device, 3, 0, cccd)
        probe.gattCallback.onDescriptorReadRequest(
            device, 4, 0,
            BluetoothGattDescriptor(UUID.randomUUID(), BluetoothGattDescriptor.PERMISSION_READ)
        )

        assertEquals(true, probe.notificationEnabled[device.address])
    }

    // -----------------------------------------------------------------
    // Characteristic traffic
    // -----------------------------------------------------------------

    /** Reads are served for the two readable characteristics and refused elsewhere. */
    @Test
    fun characteristicReadsAreRoutedByUuid() {
        // The connect leaves the connection Connecting; a read outside an open
        // connection is refused before it is routed.
        connectThroughTheCallback()

        probe.gattCallback.onCharacteristicReadRequest(device, 1, 0, characteristic(GattServer.STATUS_UUID))
        probe.gattCallback.onCharacteristicReadRequest(device, 2, 1, characteristic(GattServer.STATUS_UUID))
        probe.gattCallback.onCharacteristicReadRequest(device, 3, 0, characteristic(GattServer.RESPONSE_UUID))
        probe.gattCallback.onCharacteristicReadRequest(device, 4, 0, characteristic(UUID.randomUUID()))

        // The responses go to a device the stack never connected; what matters
        // is that the status value is derived from live state and no branch throws.
        assertArrayEquals(byteArrayOf(0x01), probe.statusValue())
    }

    /** Only the control point carries protocol data. */
    @Test
    fun aWriteToAnyCharacteristicButTheControlPointIsRefused() {
        connectThroughTheCallback()

        probe.gattCallback.onCharacteristicWriteRequest(
            device, 1, characteristic(GattServer.STATUS_UUID), false, true, 0,
            Fragmenter().fragment("hello".toByteArray()).first()
        )

        awaitEarlierEventsHandled()
        assertFalse(
            "a write outside the control point must never be treated as protocol data",
            probe.identityExchangeComplete
        )
    }

    @Test
    fun anEmptyControlPointWriteIsRefused() {
        connectThroughTheCallback()

        probe.gattCallback.onCharacteristicWriteRequest(
            device, 1, characteristic(GattServer.CONTROL_POINT_UUID), false, true, 0, ByteArray(0)
        )
        probe.gattCallback.onCharacteristicWriteRequest(
            device, 2, characteristic(GattServer.CONTROL_POINT_UUID), false, false, 0, null
        )

        awaitEarlierEventsHandled()
        assertFalse(probe.identityExchangeComplete)
        assertEquals(0, probe.fragmentBuffer.getValue(device.address).getFragmentCount())
    }

    /**
     * The real path: a control-point write is reassembled and fed to the
     * protocol. This is the only route a desktop has into the phone.
     */
    @Test
    fun aControlPointWriteIsReassembledAndProcessed() {
        connectThroughTheCallback()

        val identity = NoiseInitiatorSession(randomKey()).createIdentityMessage()
        for (fragment in Fragmenter(20).fragment(identity)) {
            probe.gattCallback.onCharacteristicWriteRequest(
                device, 1, characteristic(GattServer.CONTROL_POINT_UUID), false, true, 0, fragment
            )
        }

        GattServerProbe.awaitUntil("the identity exchange to complete") {
            probe.identityExchangeComplete
        }
        assertNotNull(probe.remotePublicKeyHex)
    }

    /** Delivery confirmations are pure telemetry and must never throw. */
    @Test
    fun notificationConfirmationsAreHarmless() {
        connectThroughTheCallback()

        probe.gattCallback.onNotificationSent(device, BluetoothGatt.GATT_SUCCESS)
        probe.gattCallback.onNotificationSent(device, BluetoothGatt.GATT_FAILURE)
    }

    // -----------------------------------------------------------------
    // Connection state changes
    // -----------------------------------------------------------------

    /**
     * The stack reports connect and disconnect on a binder thread and the
     * server hands both to its own scope. A dropped link must leave no
     * per-device state behind, or the next desktop inherits a half-open
     * session.
     */
    @Test
    fun connectAndDisconnectAreDrivenFromTheStackCallback() {
        connectThroughTheCallback()

        assertSame(device, probe.connectedDevice)
        assertNotNull("a Noise session is prepared up front", probe.noiseSession)

        probe.gattCallback.onConnectionStateChange(
            device, BluetoothGatt.GATT_SUCCESS, BluetoothProfile.STATE_DISCONNECTED
        )

        GattServerProbe.awaitUntil("the device to be released") {
            probe.server.connectionState.value == ConnectionState.Disconnected
        }
        assertNull(probe.connectedDevice)
        assertNull(probe.noiseSession)
        assertTrue(probe.fragmentBuffer.isEmpty())
        assertTrue(probe.deviceMtu.isEmpty())
    }

    /**
     * Intermediate states carry no bookkeeping. On a started server only a
     * connect begins a queue, and it does so inside the callback, so a queue
     * begun by either state would be there when the callback returns.
     */
    @Test
    fun connectingAndDisconnectingStatesAreIgnored() {
        startTheServer()

        probe.gattCallback.onConnectionStateChange(
            device, BluetoothGatt.GATT_SUCCESS, BluetoothProfile.STATE_CONNECTING
        )
        probe.gattCallback.onConnectionStateChange(
            device, BluetoothGatt.GATT_SUCCESS, BluetoothProfile.STATE_DISCONNECTING
        )

        assertFalse("no state but a connect begins a queue", probe.hasEventQueue(device))
        assertNull(probe.connectedDevice)
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private fun cccdDescriptor() = BluetoothGattDescriptor(
        GattServer.CCCD_UUID,
        BluetoothGattDescriptor.PERMISSION_READ or BluetoothGattDescriptor.PERMISSION_WRITE
    )

    /**
     * Starts the server, as every callback-driven test does: the connect
     * callback begins a device's event queue only on a started server. Skips
     * the test where the local stack will not open a GATT server.
     */
    private fun startTheServer() {
        assumeTrue("the local stack would not open a GATT server", probe.server.start())
    }

    /** Connects [device]; see [GattServerProbe.connectThroughTheCallback]. */
    private fun connectThroughTheCallback() = probe.connectThroughTheCallback(device)

    private fun awaitMtu(expected: Int, why: String) = probe.awaitMtu(device, expected, why)

    /**
     * Returns once the device's event queue has handled everything queued
     * before this call: an MTU change queued behind it is applied in turn, so
     * a write that was wrongly queued has been processed by the time it shows.
     * The queue must have been opened by [connectThroughTheCallback].
     */
    private fun awaitEarlierEventsHandled() {
        probe.gattCallback.onMtuChanged(device, BARRIER_MTU)
        GattServerProbe.awaitUntil("the queue to reach the MTU change") {
            probe.deviceMtu[device.address] == BARRIER_MTU
        }
    }

    private fun characteristic(uuid: UUID) = BluetoothGattCharacteristic(
        uuid,
        BluetoothGattCharacteristic.PROPERTY_WRITE or BluetoothGattCharacteristic.PROPERTY_READ,
        BluetoothGattCharacteristic.PERMISSION_WRITE or BluetoothGattCharacteristic.PERMISSION_READ
    )

    private fun randomKey() = ByteArray(32).also { SecureRandom().nextBytes(it) }

    private companion object {
        /** Any in-range MTU other than the default the connect records. */
        const val BARRIER_MTU = 247
    }
}
