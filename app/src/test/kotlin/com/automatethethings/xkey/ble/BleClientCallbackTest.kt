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
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.util.Log
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mockk.verify
import java.util.UUID
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

/**
 * The half of [BleClient] the Bluetooth stack drives: the `ScanCallback`, the
 * `BluetoothGattCallback`, and the teardown paths.
 *
 * [BleClientConnectionTest] runs the happy ladder end to end. What it cannot
 * reach are the branches the stack only takes when something goes wrong —
 * a scan the controller refuses, an MTU the stack declines, a descriptor write
 * that belongs to somebody else's descriptor, a notification carrying garbage.
 * Every one of those is a silent failure in production: the client parks on a
 * `CompletableDeferred` and the user sees a spinner.
 *
 * These drive each seam directly, through [BleClientProbe]. Nothing here needs
 * a radio; see that class for why a mocked stack is faithful.
 */
class BleClientCallbackTest {

    private var harness: BleClientHarness? = null

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.v(any(), any<String>()) } returns 0
        every { Log.d(any(), any<String>()) } returns 0
        every { Log.i(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.e(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>(), any()) } returns 0
        every { Log.e(any(), any<String>(), any()) } returns 0
    }

    @After
    fun tearDown() {
        harness?.close()
        harness = null
        unmockkAll()
    }

    private fun harness(): BleClientHarness = BleClientHarness().also { harness = it }

    // -----------------------------------------------------------------
    // Bringing Bluetooth up
    // -----------------------------------------------------------------

    /** A device with no Bluetooth service at all must say so, not crash. */
    @Test
    fun aMissingBluetoothServiceIsReported() {
        val context = mockk<Context>(relaxed = true)
        every { context.getSystemService(Context.BLUETOOTH_SERVICE) } returns null
        val probe = BleClientProbe(BleClient(context))

        assertFailsWith("Bluetooth service not available") { probe.initializeBluetooth() }
    }

    @Test
    fun aMissingAdapterIsReported() {
        val manager = mockk<BluetoothManager>(relaxed = true)
        every { manager.adapter } returns null
        val probe = BleClientProbe(BleClient(contextWith(manager)))

        assertFailsWith("Bluetooth adapter not available") { probe.initializeBluetooth() }
    }

    @Test
    fun aDisabledAdapterIsReported() {
        val adapter = mockk<BluetoothAdapter>(relaxed = true)
        every { adapter.isEnabled } returns false
        val manager = mockk<BluetoothManager>(relaxed = true)
        every { manager.adapter } returns adapter
        val probe = BleClientProbe(BleClient(contextWith(manager)))

        assertFailsWith("Bluetooth is not enabled") { probe.initializeBluetooth() }
    }

    /** Plenty of chipsets can advertise but not scan. */
    @Test
    fun anAdapterWithoutAnLeScannerIsReported() {
        val adapter = mockk<BluetoothAdapter>(relaxed = true)
        every { adapter.isEnabled } returns true
        every { adapter.bluetoothLeScanner } returns null
        val manager = mockk<BluetoothManager>(relaxed = true)
        every { manager.adapter } returns adapter
        val probe = BleClientProbe(BleClient(contextWith(manager)))

        assertFailsWith("BLE scanner not available") { probe.initializeBluetooth() }
    }

    // -----------------------------------------------------------------
    // Scanning
    // -----------------------------------------------------------------

    /** Two scans at once would leak the first scan's callback registration. */
    @Test
    fun aSecondScanIsRefusedWhileOneIsRunning(): Unit = runBlocking {
        val h = harness()
        h.probe.isScanning.set(true)

        try {
            h.client.scan()
            fail("a concurrent scan must be refused")
        } catch (expected: BleClientException) {
            assertTrue(expected.message!!.contains("already in progress"))
        }
    }

    /** A BLE advertiser is seen many times a second; the UI wants one row. */
    @Test
    fun repeatedAdvertisementsFromOneDeviceCollapseToASingleResult() {
        val h = harness()
        val callback = h.probe.scanCallback

        callback.onScanResult(ScanSettings.CALLBACK_TYPE_ALL_MATCHES, scanResult("AA:BB:CC:DD:EE:01"))
        callback.onScanResult(ScanSettings.CALLBACK_TYPE_ALL_MATCHES, scanResult("AA:BB:CC:DD:EE:01"))
        callback.onScanResult(ScanSettings.CALLBACK_TYPE_ALL_MATCHES, scanResult("AA:BB:CC:DD:EE:02"))

        assertEquals(2, h.probe.discoveredDevices.size)
        assertTrue(h.probe.discoveredDevices.containsKey("AA:BB:CC:DD:EE:01"))
        assertTrue(h.probe.discoveredDevices.containsKey("AA:BB:CC:DD:EE:02"))
    }

    /**
     * Every code the controller can report has to reach the caller with a
     * reason. A scan that fails silently looks exactly like a desktop that is
     * switched off.
     */
    @Test
    fun everyScanFailureCodeIsSurfacedToTheCaller() {
        val expected = mapOf(
            ScanCallback.SCAN_FAILED_ALREADY_STARTED to "already started",
            ScanCallback.SCAN_FAILED_APPLICATION_REGISTRATION_FAILED to "registration failed",
            ScanCallback.SCAN_FAILED_INTERNAL_ERROR to "Internal error",
            ScanCallback.SCAN_FAILED_FEATURE_UNSUPPORTED to "unsupported"
        )

        for ((code, reason) in expected) {
            val h = BleClientHarness()
            try {
                val deferred = CompletableDeferred<List<ScanResult>>()
                h.probe.scanDeferred = deferred
                h.probe.isScanning.set(true)

                h.probe.scanCallback.onScanFailed(code)

                assertTrue("code $code must complete the scan", deferred.isCompleted)
                assertFalse("code $code must clear the scanning flag", h.probe.isScanning.get())
                val failure = deferred.getCompletionExceptionOrNull()!!
                assertTrue(
                    "code $code must explain itself: ${failure.message}",
                    failure.message!!.contains(reason)
                )
            } finally {
                h.close()
            }
        }
    }

    /** An unrecognised code still reaches the caller, with its raw value. */
    @Test
    fun anUnknownScanFailureCodeCarriesItsRawValue() {
        val h = harness()
        val deferred = CompletableDeferred<List<ScanResult>>()
        h.probe.scanDeferred = deferred

        h.probe.scanCallback.onScanFailed(4242)

        assertTrue(deferred.getCompletionExceptionOrNull()!!.message!!.contains("4242"))
    }

    /** Stopping hands the caller whatever was found and unregisters the scan. */
    @Test
    fun stoppingAScanReturnsWhatWasFoundAndUnregisters(): Unit = runBlocking {
        val h = harness()
        h.probe.initializeBluetooth()
        val deferred = CompletableDeferred<List<ScanResult>>()
        h.probe.scanDeferred = deferred
        h.probe.isScanning.set(true)
        h.probe.scanCallback.onScanResult(ScanSettings.CALLBACK_TYPE_ALL_MATCHES, scanResult("AA:BB:CC:DD:EE:03"))

        h.probe.stopScan()

        assertFalse(h.probe.isScanning.get())
        assertEquals(1, deferred.await().size)
        assertNull("the deferred must not be reused by the next scan", h.probe.scanDeferred)
        verify { h.scanner.stopScan(h.probe.scanCallback) }
    }

    /** A stop with nothing running must not touch the controller. */
    @Test
    fun stoppingAnIdleScanIsANoOp() {
        val h = harness()
        h.probe.initializeBluetooth()

        h.probe.stopScan()

        verify(exactly = 0) { h.scanner.stopScan(any<ScanCallback>()) }
    }

    // -----------------------------------------------------------------
    // The GATT callback
    // -----------------------------------------------------------------

    /** A disconnect must fail the connect that is waiting, not hang it. */
    @Test
    fun aDisconnectFailsTheConnectionThatIsWaitingForIt() {
        val h = harness()
        val deferred = CompletableDeferred<Unit>()
        h.probe.connectionDeferred = deferred

        h.probe.gattCallback.onConnectionStateChange(
            h.gatt, BluetoothGatt.GATT_FAILURE, BluetoothProfile.STATE_DISCONNECTED
        )

        assertTrue(deferred.isCompleted)
        assertTrue(
            deferred.getCompletionExceptionOrNull()!!.message!!.contains("status: 257")
        )
    }

    @Test
    fun aFailedServiceDiscoveryIsReportedToTheWaiter() {
        val h = harness()
        val deferred = CompletableDeferred<Unit>()
        h.probe.servicesDiscoveredDeferred = deferred

        h.probe.gattCallback.onServicesDiscovered(h.gatt, BluetoothGatt.GATT_FAILURE)

        assertTrue(
            deferred.getCompletionExceptionOrNull()!!.message!!.contains("Service discovery failed")
        )
    }

    /**
     * A declined MTU is *not* an error — the stack keeps the previous value and
     * the client falls back to the BLE minimum rather than failing the connect.
     */
    @Test
    fun aDeclinedMtuFallsBackToTheBleMinimum(): Unit = runBlocking {
        val h = harness()
        val deferred = CompletableDeferred<Int>()
        h.probe.mtuDeferred = deferred

        h.probe.gattCallback.onMtuChanged(h.gatt, 517, BluetoothGatt.GATT_FAILURE)

        assertEquals(23, deferred.await())
    }

    @Test
    fun anAcceptedMtuIsHandedToTheWaiter(): Unit = runBlocking {
        val h = harness()
        val deferred = CompletableDeferred<Int>()
        h.probe.mtuDeferred = deferred

        h.probe.gattCallback.onMtuChanged(h.gatt, 517, BluetoothGatt.GATT_SUCCESS)

        assertEquals(517, deferred.await())
    }

    /**
     * The client writes exactly one descriptor, but the stack reports every
     * descriptor write on the connection. Completing on somebody else's write
     * would let the connect proceed before notifications were live.
     */
    @Test
    fun aDescriptorWriteForAnotherDescriptorIsIgnored() {
        val h = harness()
        val deferred = CompletableDeferred<Unit>()
        h.probe.notificationEnabledDeferred = deferred
        val other = mockk<BluetoothGattDescriptor>(relaxed = true)
        every { other.uuid } returns UUID.fromString("0000dead-0000-1000-8000-00805f9b34fb")

        h.probe.gattCallback.onDescriptorWrite(h.gatt, other, BluetoothGatt.GATT_SUCCESS)

        assertFalse("only the CCCD write completes the wait", deferred.isCompleted)
    }

    @Test
    fun aFailedCccdWriteIsReportedToTheWaiter() {
        val h = harness()
        val deferred = CompletableDeferred<Unit>()
        h.probe.notificationEnabledDeferred = deferred

        h.probe.gattCallback.onDescriptorWrite(h.gatt, h.cccd, BluetoothGatt.GATT_FAILURE)

        assertTrue(
            deferred.getCompletionExceptionOrNull()!!.message!!.contains("Failed to enable notifications")
        )
    }

    /**
     * The write completion is a single-shot callback. Leaving it installed
     * would let the *next* stack event resume a coroutine that already
     * continued.
     */
    @Test
    fun aWriteCompletionIsClearedAfterItIsDelivered(): Unit = runBlocking {
        val h = harness()

        h.client.connect(h.address, ByteArray(32) { it.toByte() })

        assertFalse("no completion may outlive its write", h.probe.hasWriteInFlight)
    }

    // -----------------------------------------------------------------
    // Inbound notifications
    // -----------------------------------------------------------------

    /** An empty notification carries no fragment header and must be dropped. */
    @Test
    fun anEmptyNotificationIsIgnored() {
        val h = harness()

        h.probe.gattCallback.onCharacteristicChanged(h.gatt, h.responseCharacteristic, ByteArray(0))

        Thread.sleep(50)
        assertEquals(0, h.probe.fragmentReassembler.getFragmentCount())
    }

    /**
     * A malformed frame must be dropped, not thrown — it arrives on the
     * client's own scope, where an escaping exception would take the connection
     * down with no way to report it.
     */
    @Test
    fun aMalformedFragmentIsDroppedAndTheClientKeepsWorking() {
        val h = harness()

        h.probe.gattCallback.onCharacteristicChanged(
            h.gatt, h.responseCharacteristic, byteArrayOf(0x01, 0x02, 0x03)
        )
        Thread.sleep(50)
        assertEquals(0, h.probe.fragmentReassembler.getFragmentCount())

        h.probe.gattCallback.onCharacteristicChanged(
            h.gatt, h.responseCharacteristic, firstOfTwoFragments()
        )

        awaitUntil("the client to buffer a valid fragment") {
            h.probe.fragmentReassembler.getFragmentCount() == 1
        }
    }

    /**
     * Android 12 and below deliver notifications through the deprecated
     * overload that reads `characteristic.value`. minSdk is 28, so that is the
     * path most devices in the field take.
     */
    @Suppress("DEPRECATION")
    @Test
    fun theDeprecatedNotificationOverloadIsHandled() {
        val h = harness()
        every { h.responseCharacteristic.value } returns firstOfTwoFragments()

        h.probe.gattCallback.onCharacteristicChanged(h.gatt, h.responseCharacteristic)

        awaitUntil("the deprecated overload to buffer its fragment") {
            h.probe.fragmentReassembler.getFragmentCount() == 1
        }
    }

    /** Before the session exists, a whole message belongs to the handshake. */
    @Test
    fun aCompleteMessageBeforeTheHandshakeIsNotDeliveredAsAResponse() {
        val h = harness()
        val pending = CompletableDeferred<ByteArray>()
        h.probe.pendingResponse = pending

        h.probe.handleCompleteMessage("handshake".toByteArray())

        Thread.sleep(50)
        assertFalse(
            "handshake traffic must never be handed to a request waiter",
            pending.isCompleted
        )
    }

    /** Once the session is live, a whole message is the pending response. */
    @Test
    fun aCompleteMessageAfterTheHandshakeIsDeliveredAsTheResponse(): Unit = runBlocking {
        val h = harness()
        h.client.connect(h.address, ByteArray(32) { it.toByte() })
        val pending = CompletableDeferred<ByteArray>()
        h.probe.pendingResponse = pending
        val payload = "response".toByteArray()

        h.probe.handleCompleteMessage(payload)

        assertArrayEquals(payload, pending.await())
    }

    // -----------------------------------------------------------------
    // Teardown
    // -----------------------------------------------------------------

    @Test
    fun aFreshClientHasNoSession() {
        val h = harness()

        assertFalse(h.client.isConnected())
        assertNull(h.client.getRemoteStaticKey())
        assertEquals(ClientConnectionState.Disconnected, h.client.connectionState.value)
    }

    /**
     * `destroy` has to fail everything in flight before it cancels its scope.
     * The deferreds are awaited on the *caller's* coroutine, so leaving one
     * pending would keep an in-flight `connect` holding the state mutex until
     * its own 30-second timeout expired.
     */
    @Test
    fun destroyFailsEveryOperationInFlight(): Unit = runBlocking {
        val h = harness()
        val scan = CompletableDeferred<List<ScanResult>>()
        val connection = CompletableDeferred<Unit>()
        val discovery = CompletableDeferred<Unit>()
        val mtu = CompletableDeferred<Int>()
        val notifications = CompletableDeferred<Unit>()
        h.probe.scanDeferred = scan
        h.probe.connectionDeferred = connection
        h.probe.servicesDiscoveredDeferred = discovery
        h.probe.mtuDeferred = mtu
        h.probe.notificationEnabledDeferred = notifications

        h.client.destroy()

        for (deferred in listOf(scan, connection, discovery, mtu, notifications)) {
            assertTrue("every pending operation must be failed", deferred.isCompleted)
            assertTrue(
                deferred.getCompletionExceptionOrNull()!!.message!!.contains("destroyed")
            )
        }
        assertNull(h.probe.connectionDeferred)
        assertNull(h.probe.mtuDeferred)
        assertFalse(h.probe.hasWriteInFlight)
    }

    /** A teardown must not leave half a message for the next connection. */
    @Test
    fun disconnectingCancelsThePendingRequestAndResetsReassembly() {
        val h = harness()
        val pending = CompletableDeferred<ByteArray>()
        h.probe.pendingResponse = pending
        h.probe.fragmentReassembler.addFragment(firstOfTwoFragments())
        assertEquals(1, h.probe.fragmentReassembler.getFragmentCount())

        h.probe.disconnectInternal()

        assertTrue("a waiter must not be stranded", pending.isCancelled)
        assertNull(h.probe.pendingResponse)
        assertEquals(0, h.probe.fragmentReassembler.getFragmentCount())
        assertFalse(h.probe.fragmentReassembler.isInProgress())
    }

    @Test
    fun sendingWithoutAConnectionIsRefused(): Unit = runBlocking {
        val h = harness()

        try {
            h.probe.sendFragmentedMessage(h.controlPoint, "ping".toByteArray())
            fail("sending without a GATT connection must be refused")
        } catch (expected: BleClientException) {
            assertTrue(expected.message!!.contains("Not connected"))
        }
    }

    /** The identity the phone dials out under is the one it answers on. */
    @Test
    fun theClientReportsTheRemoteIdentityOnlyAfterTheHandshake(): Unit = runBlocking {
        val h = harness()
        assertNull(h.client.getRemoteStaticKey())

        h.client.connect(h.address, ByteArray(32) { (it + 1).toByte() })

        assertNotNull(h.client.getRemoteStaticKey())
        assertArrayEquals(h.responder.getStaticPublicKey(), h.client.getRemoteStaticKey())
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private fun contextWith(manager: BluetoothManager): Context =
        mockk<Context>(relaxed = true).also {
            every { it.getSystemService(Context.BLUETOOTH_SERVICE) } returns manager
        }

    private fun scanResult(address: String): ScanResult {
        val device = mockk<BluetoothDevice>(relaxed = true)
        every { device.address } returns address
        every { device.name } returns "xKey $address"
        return mockk<ScanResult>(relaxed = true).also {
            every { it.device } returns device
            every { it.rssi } returns -55
        }
    }

    /** Fragment 0 of a 2-fragment message: buffered, never completing. */
    private fun firstOfTwoFragments(): ByteArray =
        Fragmenter(Fragmenter.MIN_PAYLOAD_SIZE).fragment(ByteArray(40) { it.toByte() })[0]

    private fun assertFailsWith(fragment: String, block: () -> Unit) {
        try {
            block()
            fail("expected a BleClientException mentioning \"$fragment\"")
        } catch (expected: BleClientException) {
            assertTrue(
                "expected \"$fragment\" in: ${expected.message}",
                expected.message!!.contains(fragment)
            )
        }
    }

    private fun awaitUntil(message: String, timeoutMs: Long = 5_000, condition: () -> Boolean) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (condition()) return
            Thread.sleep(5)
        }
        throw AssertionError("timed out waiting for: $message")
    }
}
