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
import android.app.NotificationManager
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothManager
import android.content.Context
import androidx.fragment.app.FragmentActivity
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.rule.GrantPermissionRule
import com.automatethethings.xkey.remote.BidirectionalMessageRouter
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.usb.UsbAccessoryServer
import java.lang.ref.WeakReference
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.runBlocking
import org.junit.After
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
 * [XKeyGattService] as the app's transport arbiter and state machine.
 *
 * Three things live here and nowhere else:
 *
 *  - **transport selection.** `activeTransport()` is the single source every
 *    outbound `remote.*` client goes through. Picking the wrong one, or picking
 *    a transport whose router is missing, sends a request into a channel with
 *    nothing to correlate the reply — which surfaces as a sync that hangs.
 *  - **the state the UI reads.** `ConnectionState` and `AdvertisingState`
 *    arrive from two independent flows and are folded into one `ServiceState`.
 *    The folding rules are asymmetric on purpose: advertising must never demote
 *    a live connection, and a disconnect must fall back to advertising rather
 *    than to idle whenever the radio is still discoverable.
 *  - **the audit trail.** Connect and disconnect are the only two BLE events
 *    that reach the audit log, and they are written from here.
 *
 * None of it needs a radio, and none of it is reachable through the normal
 * entry points — see [XKeyGattServiceProbe] for how the service is stood up
 * without `onCreate`.
 */
@RunWith(AndroidJUnit4::class)
class XKeyGattServiceTest {

    /** `GattServerProbe.establishSession` reads `BluetoothDevice.getName()`. */
    @get:Rule
    val bluetoothPermission: GrantPermissionRule =
        GrantPermissionRule.grant(Manifest.permission.BLUETOOTH_CONNECT)

    private companion object {
        const val DEVICE_ADDRESS = "AA:BB:CC:DD:EE:F5"
        const val NOTIFICATION_ID = 1001
    }

    private lateinit var context: Context
    private lateinit var probe: XKeyGattServiceProbe
    private var gattProbe: GattServerProbe? = null

    /** Audit rows the service wrote for the test device; purged in teardown. */
    private var auditedDevice: String? = null

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        probe = XKeyGattServiceProbe(context)
    }

    @After
    fun tearDown() {
        probe.stopTcpHsmServer()
        probe.releaseWakeLock()
        gattProbe?.close()
        gattProbe = null
        auditedDevice?.let { purgeAuditRowsFor(it) }
        auditedDevice = null
        context.getSystemService(NotificationManager::class.java)?.cancel(NOTIFICATION_ID)
    }

    // -----------------------------------------------------------------
    // The state the UI reads
    // -----------------------------------------------------------------

    @Test
    fun aServiceThatHasNotStartedIsStopped() {
        assertEquals(ServiceState.Stopped, probe.serviceState)
        assertEquals("xKey" to "Service stopped", probe.notificationText())
    }

    /**
     * Every state has to say something different in the shade — it is the only
     * place the user can see what the service is doing while the app is closed.
     */
    @Test
    fun everyServiceStateHasItsOwnNotificationText() {
        val states = listOf(
            ServiceState.Stopped,
            ServiceState.Ready,
            ServiceState.Advertising,
            ServiceState.Connecting,
            ServiceState.Connected("Workstation", DEVICE_ADDRESS),
            ServiceState.Error("radio off")
        )

        val texts = states.map { state ->
            probe.serviceState = state
            probe.notificationText().second
        }

        assertEquals("every state needs its own wording", texts.size, texts.toSet().size)
        assertTrue(texts.any { it!!.contains("Workstation") })
        assertTrue(texts.any { it!!.contains("radio off") })
    }

    @Test
    fun advertisingPromotesAnIdleService() {
        probe.serviceState = ServiceState.Ready

        probe.handleAdvertisingStateChange(advertisingState())

        assertEquals(ServiceState.Advertising, probe.serviceState)
    }

    /**
     * Advertising continues while a desktop is connected, so its state change
     * must not overwrite the connection the user is looking at.
     */
    @Test
    fun advertisingNeverDemotesALiveConnection() {
        val connected = ServiceState.Connected("Workstation", DEVICE_ADDRESS)
        probe.serviceState = connected

        probe.handleAdvertisingStateChange(advertisingState())

        assertEquals(connected, probe.serviceState)
    }

    @Test
    fun advertisingNeverDemotesAConnectionInProgress() {
        probe.serviceState = ServiceState.Connecting

        probe.handleAdvertisingStateChange(advertisingState())

        assertEquals(ServiceState.Connecting, probe.serviceState)
    }

    @Test
    fun advertisingStoppedDemotesOnlyFromAdvertising() {
        probe.serviceState = ServiceState.Advertising
        probe.handleAdvertisingStateChange(AdvertisingState.Stopped)
        assertEquals(ServiceState.Ready, probe.serviceState)

        val connected = ServiceState.Connected("Workstation", DEVICE_ADDRESS)
        probe.serviceState = connected
        probe.handleAdvertisingStateChange(AdvertisingState.Stopped)
        assertEquals("a connection outlives the advertisement", connected, probe.serviceState)
    }

    /** An advertising failure is logged, but it is not the service's state. */
    @Test
    fun anAdvertisingErrorLeavesTheServiceStateAlone() {
        probe.serviceState = ServiceState.Ready

        probe.handleAdvertisingStateChange(
            AdvertisingState.Error(AdvertiseError.DATA_TOO_LARGE, "too large")
        )

        assertEquals(ServiceState.Ready, probe.serviceState)
    }

    @Test
    fun aConnectingDeviceIsShownAsConnecting() {
        probe.handleConnectionStateChange(ConnectionState.Connecting)

        assertEquals(ServiceState.Connecting, probe.serviceState)
    }

    /** A connection is the one BLE event the audit log has to carry. */
    @Test
    fun aConnectionIsPublishedAndAudited() {
        auditedDevice = DEVICE_ADDRESS

        probe.handleConnectionStateChange(
            ConnectionState.Connected("Workstation", DEVICE_ADDRESS)
        )

        assertEquals(
            ServiceState.Connected("Workstation", DEVICE_ADDRESS),
            probe.serviceState
        )
        assertTrue(
            "the audit log is the only record a desktop ever connected",
            awaitAuditRows(DEVICE_ADDRESS) >= 1
        )
    }

    /** Losing the desktop while still discoverable must return to Advertising. */
    @Test
    fun aDisconnectFallsBackToAdvertisingWhileStillDiscoverable() {
        auditedDevice = DEVICE_ADDRESS
        probe.advertiser = advertiserReportingAdvertising()
        probe.serviceState = ServiceState.Connected("Workstation", DEVICE_ADDRESS)

        probe.handleConnectionStateChange(ConnectionState.Disconnected)

        assertEquals(ServiceState.Advertising, probe.serviceState)
        assertTrue(
            "a closed connection has to be audited too",
            awaitAuditRows(DEVICE_ADDRESS) >= 1
        )
    }

    @Test
    fun aDisconnectFallsBackToReadyWhenNotAdvertising() {
        probe.advertiser = Advertiser(null)
        probe.serviceState = ServiceState.Advertising

        probe.handleConnectionStateChange(ConnectionState.Disconnected)

        assertEquals(ServiceState.Ready, probe.serviceState)
    }

    // -----------------------------------------------------------------
    // Transport selection
    // -----------------------------------------------------------------

    @Test
    fun noTransportIsActiveOnAServiceWithNothingConnected() {
        assertNull(probe.activeTransport())
    }

    /** BLE is the primary transport whenever its session is up. */
    @Test
    fun aLiveBleSessionIsTheActiveTransport(): Unit = runBlocking {
        val gatt = bleServerWithSession()
        probe.gattServer = gatt.server
        probe.bleMessageRouter = gatt.messageRouter

        val (sender, router) = probe.activeTransport()!!

        assertSame(gatt.server, sender)
        assertSame(gatt.messageRouter, router)
    }

    /**
     * A transport with no router can send but never correlate a reply, so it
     * must not be offered as the active transport at all.
     */
    @Test
    fun aBleSessionWithoutARouterIsNotOffered(): Unit = runBlocking {
        val gatt = bleServerWithSession()
        probe.gattServer = gatt.server
        probe.bleMessageRouter = null

        assertNull(probe.activeTransport())
    }

    /** A GATT server with no established session is not a transport. */
    @Test
    fun anIdleBleServerIsNotOffered() {
        val gatt = gattProbe()
        probe.gattServer = gatt.server
        probe.bleMessageRouter = gatt.messageRouter

        assertNull(probe.activeTransport())
    }

    @Test
    fun usbIsUsedWhenBleIsIdle() {
        val gatt = gattProbe()
        val usbRouter = BidirectionalMessageRouter(gatt.requestHandler)
        val usbServer = UsbAccessoryServer(gatt.requestHandler, usbRouter)
        probe.usbAccessoryServer = usbServer
        probe.usbMessageRouter = usbRouter

        val (sender, router) = probe.activeTransport()!!

        assertSame(usbServer, sender)
        assertSame(usbRouter, router)
    }

    /** The order is BLE, then TCP, then USB; a live BLE session always wins. */
    @Test
    fun bleWinsOverUsb(): Unit = runBlocking {
        val gatt = bleServerWithSession()
        val usbRouter = BidirectionalMessageRouter(gatt.requestHandler)
        probe.gattServer = gatt.server
        probe.bleMessageRouter = gatt.messageRouter
        probe.usbAccessoryServer = UsbAccessoryServer(gatt.requestHandler, usbRouter)
        probe.usbMessageRouter = usbRouter

        assertSame(gatt.server, probe.activeTransport()!!.first)
    }

    /** Sync has to fail fast and say why, not hang on a transport that is not there. */
    @Test
    fun syncIsRefusedWithNoDesktopConnected(): Unit = runBlocking {
        try {
            probe.service.syncNow()
            fail("syncing without a desktop must be refused")
        } catch (expected: IllegalStateException) {
            assertTrue(expected.message!!.contains("No desktop connected"))
        }
    }

    /** Attestation is only meaningful for the device currently on the wire. */
    @Test
    fun attestationIsRefusedForADeviceThatIsNotConnected(): Unit = runBlocking {
        assertFalse(probe.service.requestDeviceAttestation("00ff00ff"))
    }

    // -----------------------------------------------------------------
    // Advertising control
    // -----------------------------------------------------------------

    @Test
    fun startingWithoutComponentsReportsAnError() {
        probe.gattServer = null
        probe.advertiser = null

        probe.service.startAdvertising()

        assertEquals(ServiceState.Error("Components not initialized"), probe.serviceState)
        assertNull("nothing may hold a wake lock after a failed start", probe.wakeLock)
    }

    @Test
    fun startingWithoutBluetoothReportsAnError() {
        val gatt = gattProbe()
        probe.gattServer = gatt.server
        probe.advertiser = Advertiser(null)
        probe.bluetoothAdapter = null

        probe.service.startAdvertising()

        assertEquals(ServiceState.Error("Bluetooth not enabled"), probe.serviceState)
        assertNull(probe.wakeLock)
    }

    /**
     * `startAdvertising` hands the real work to a coroutine, so a second call
     * before the first finishes would start the GATT server twice.
     */
    @Test
    fun aConcurrentStartIsIgnored() {
        probe.serviceState = ServiceState.Ready
        probe.isStartingAdvertising = true

        probe.service.startAdvertising()

        assertEquals("the guard must not touch the state", ServiceState.Ready, probe.serviceState)
    }

    @Test
    fun stoppingReturnsTheServiceToReadyAndDropsTheWakeLock() {
        val gatt = gattProbe()
        probe.gattServer = gatt.server
        probe.advertiser = Advertiser(null)
        probe.acquireWakeLock()
        assertNotNull(probe.wakeLock)

        probe.service.stopAdvertising()

        assertEquals(ServiceState.Ready, probe.serviceState)
        assertNull("the radio must not be pinned awake while idle", probe.wakeLock)
    }

    /** The wake lock is not reference counted, so a second acquire is a no-op. */
    @Test
    fun theWakeLockIsAcquiredOnceAndReleasedOnce() {
        probe.acquireWakeLock()
        val held = probe.wakeLock
        probe.acquireWakeLock()

        assertSame("a second acquire must not replace the lock", held, probe.wakeLock)
        assertTrue(held!!.isHeld)

        probe.releaseWakeLock()

        assertNull(probe.wakeLock)
        assertFalse(held.isHeld)
        probe.releaseWakeLock()
    }

    // -----------------------------------------------------------------
    // The other transports
    // -----------------------------------------------------------------

    @Test
    fun theTcpServerIsNotStartedWithoutARequestHandler() {
        probe.requestHandler = null

        probe.startTcpHsmServer()

        assertNull(probe.tcpHsmServer)
        assertNull(probe.tcpMessageRouter)
    }

    @Test
    fun theTcpServerStartsWithItsOwnRouterAndStops() {
        probe.requestHandler = gattProbe().requestHandler

        probe.startTcpHsmServer()

        val started = probe.tcpHsmServer
        assertNotNull("the TCP transport must come up", started)
        assertNotNull("and bring its own correlation router", probe.tcpMessageRouter)

        probe.startTcpHsmServer()
        assertSame("starting twice must not replace the listener", started, probe.tcpHsmServer)

        probe.stopTcpHsmServer()

        assertNull(probe.tcpHsmServer)
        assertNull(probe.tcpMessageRouter)
    }

    @Test
    fun detachingTheUsbAccessoryClearsItsTransport() {
        val gatt = gattProbe()
        val usbRouter = BidirectionalMessageRouter(gatt.requestHandler)
        probe.usbAccessoryServer = UsbAccessoryServer(gatt.requestHandler, usbRouter)
        probe.usbMessageRouter = usbRouter

        probe.service.onUsbAccessoryDetached()

        assertNull(probe.usbAccessoryServer)
        assertNull(probe.usbMessageRouter)
        assertNull(probe.activeTransport())
    }

    // -----------------------------------------------------------------
    // Accessors and binding
    // -----------------------------------------------------------------

    /** Every accessor is read by the UI before the service has components. */
    @Test
    fun theAccessorsAreNullSafeBeforeAnythingIsInitialised() {
        assertFalse(probe.service.isAdvertising())
        assertFalse(probe.service.isConnected())
        assertNull(probe.service.getConnectionState())
        assertNull(probe.service.getCurrentSessionId())
        assertNull(probe.service.getPairedDeviceRepository())
        assertNull(probe.service.getConnectedDevicePublicKeyHex())
    }

    @Test
    fun theAccessorsReportTheLiveSession(): Unit = runBlocking {
        val gatt = bleServerWithSession()
        probe.gattServer = gatt.server
        probe.pairedDeviceRepository = gatt.pairedDeviceRepository

        assertTrue(probe.service.isConnected())
        assertEquals(DEVICE_ADDRESS, probe.service.getCurrentSessionId())
        assertNotNull(probe.service.getConnectionState())
        assertSame(gatt.pairedDeviceRepository, probe.service.getPairedDeviceRepository())
    }

    @Test
    fun theBinderHandsBackTheService() {
        val binder = probe.service.onBind(null)

        assertTrue(binder is XKeyGattService.LocalBinder)
        assertSame(probe.service, (binder as XKeyGattService.LocalBinder).getService())
    }

    /**
     * Detaching the activity must not leave a stale reference behind — the
     * service holds it only to raise the pairing dialog, and a reference to a
     * destroyed activity would leak it and raise the dialog on nothing.
     */
    @Test
    fun detachingTheActivityClearsTheReference() {
        val field = XKeyGattService::class.java.getDeclaredField("activityRef")
            .apply { isAccessible = true }
        field.set(probe.service, WeakReference<FragmentActivity>(null))
        assertNotNull(field.get(probe.service))

        probe.service.setActivity(null)

        assertNull(field.get(probe.service))
    }

    /**
     * With no activity bound there is nobody to approve a pairing, and the only
     * safe answer is no — an unattended phone must never pair itself.
     */
    @Test
    fun pairingIsRefusedWithNoActivityBound(): Unit = runBlocking {
        probe.service.setActivity(null)

        assertFalse(probe.service.onPairingConfirmationRequired("Workstation", "ab:cd:ef"))
    }

    /**
     * Bluetooth initialisation has to leave the service in a state the UI can
     * explain, whichever of the two the device happens to be in.
     */
    @Test
    fun bluetoothInitialisationReportsWhateverTheDeviceHas() {
        val adapter = context.getSystemService(BluetoothManager::class.java)?.adapter

        probe.initializeBluetooth()

        if (adapter != null && adapter.isEnabled) {
            assertNotNull(probe.bluetoothAdapter)
            assertFalse(
                "a working radio must not be reported as an error",
                probe.serviceState is ServiceState.Error
            )
        } else {
            assertTrue(
                "an unusable radio must be reported, not ignored",
                probe.serviceState is ServiceState.Error
            )
        }
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    /** A GATT server built the way the service builds one, reused per test. */
    private fun gattProbe(): GattServerProbe =
        gattProbe ?: GattServerProbe(context).also { gattProbe = it }

    /** A GATT server carrying a completed Noise session, as a live desktop leaves it. */
    private suspend fun bleServerWithSession(): GattServerProbe {
        val device = remoteDevice()
        return gattProbe().also { it.establishSession(device) }
    }

    private fun remoteDevice(): BluetoothDevice {
        val device = GattServerProbe.remoteDevice(context, DEVICE_ADDRESS)
        assumeTrue("this device has no Bluetooth adapter", device != null)
        return device!!
    }

    private fun advertisingState() =
        AdvertisingState.Advertising(connectable = true, txPowerLevel = 2, mode = 1)

    /** An advertiser that reports itself as running, without touching a radio. */
    private fun advertiserReportingAdvertising(): Advertiser =
        Advertiser(null).also {
            val field = Advertiser::class.java.getDeclaredField("isAdvertising")
                .apply { isAccessible = true }
            (field.get(it) as AtomicBoolean).set(true)
        }

    /**
     * Waits for the asynchronous audit write to land and returns how many rows
     * the device has.
     */
    private fun awaitAuditRows(deviceId: String): Int {
        val dao = XKeyDatabase.getInstance(context).auditLogDao()
        val deadline = System.currentTimeMillis() + 5_000
        while (System.currentTimeMillis() < deadline) {
            val rows = runBlocking { dao.getByDeviceId(deviceId) }
            if (rows.isNotEmpty()) return rows.size
            Thread.sleep(20)
        }
        return 0
    }

    /**
     * Removes the rows this suite caused. Other suites assert on live audit
     * counts, so nothing may be left behind. There is no DAO delete keyed on a
     * device, so this goes through the support database directly.
     */
    private fun purgeAuditRowsFor(deviceId: String) {
        awaitAuditRows(deviceId)
        XKeyDatabase.getInstance(context).openHelper.writableDatabase
            .delete("audit_logs", "device_id = ?", arrayOf(deviceId))
    }
}
