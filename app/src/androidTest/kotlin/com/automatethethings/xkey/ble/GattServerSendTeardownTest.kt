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
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothManager
import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.rule.GrantPermissionRule
import com.automatethethings.xkey.settings.PairedDeviceRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * What [GattServer] does when a teardown lands on a send that is already
 * running.
 *
 * [GattServerRadioTest] covers the outbound path when nothing goes wrong. This
 * suite covers the one moment where two of the server's own paths cross: a
 * response is being assembled and sent while `stop()` or a disconnect is
 * dismantling the connection underneath it.
 *
 * Both halves of that collision were broken. The subscription wait parks on a
 * `CompletableDeferred` that teardown *cancels*, and an await on a cancelled
 * deferred throws rather than returning null — `withTimeoutOrNull` only
 * swallows its own timeout. That `CancellationException` unwound into
 * `handleApplicationMessage`'s catch, which responded by trying to send an
 * error over the connection that had just gone away, and threw again. And the
 * fragment loop re-read the server handle for every fragment, so a teardown
 * midway silently dropped the remainder and left the peer holding half a
 * message with no end to wait for.
 *
 * Like [GattServerRadioTest] this needs the radio genuinely open — `sendResponse`
 * returns at its second line without a handle — but never a peer: notifications
 * to a device that never connected are reported undeliverable and are otherwise
 * inert.
 */
@RunWith(AndroidJUnit4::class)
class GattServerSendTeardownTest {

    /** Opening a GATT server and reading `BluetoothDevice.getName()`. */
    @get:Rule
    val bluetoothPermission: GrantPermissionRule =
        GrantPermissionRule.grant(Manifest.permission.BLUETOOTH_CONNECT)

    private lateinit var context: Context
    private lateinit var repository: PairedDeviceRepository
    private lateinit var probe: GattServerProbe
    private lateinit var outbound: GattServerOutboundProbe
    private lateinit var device: BluetoothDevice

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        val adapter: BluetoothAdapter? =
            context.getSystemService(BluetoothManager::class.java)?.adapter
        assumeTrue("this device has no Bluetooth adapter", adapter != null)
        assumeTrue("this device's Bluetooth adapter is off", adapter!!.isEnabled)
        device = adapter.getRemoteDevice(DEVICE_ADDRESS)

        repository = PairedDeviceRepository(context)
        probe = GattServerProbe(context, pairedDeviceRepository = repository)
        outbound = GattServerOutboundProbe(probe.server)

        assumeTrue("the local stack would not open a GATT server", probe.server.start())
    }

    @After
    fun tearDown() {
        if (::probe.isInitialized) probe.close()
    }

    // -----------------------------------------------------------------
    // The subscription wait
    // -----------------------------------------------------------------

    /**
     * The regression: a send whose readiness deferred is cancelled out from
     * under it must give up quietly, not throw.
     *
     * A cancelled — rather than removed — deferred is precisely the state
     * `stop()` leaves behind between cancelling every entry and clearing the
     * map, and the state `handleDeviceDisconnected` leaves for any send that
     * read the map before the removal landed.
     */
    @Test
    fun aSendWhoseSubscriptionWaitIsCancelledGivesUpQuietly(): Unit = runBlocking {
        outbound.handleDeviceConnected(device)
        probe.gattCallback.onMtuChanged(device, 247)
        // Subscribed, so nothing but the cancellation can decide this.
        outbound.notificationEnabled[device.address] = true
        outbound.notificationReady[device.address]!!.cancel()

        // Throwing here is the defect: it reaches handleApplicationMessage's
        // catch, which answers by sending again over the same dead connection.
        outbound.sendResponse(device, ByteArray(64) { 0x41 })

        assertTrue("a refused send must not take the server down", probe.server.isRunning())
    }

    /** A device that disconnected has no deferred at all; that is not an error. */
    @Test
    fun aSendToADeviceThatAlreadyDisconnectedGivesUpQuietly(): Unit = runBlocking {
        outbound.handleDeviceConnected(device)
        probe.gattCallback.onMtuChanged(device, 247)
        outbound.handleDeviceDisconnected(device)

        outbound.sendResponse(device, ByteArray(64) { 0x42 })

        assertTrue(probe.server.isRunning())
    }

    /**
     * The wait itself must still work. A desktop writes the CCCD a moment after
     * it connects, and a response prepared in that window has to be held rather
     * than dropped — the fix must not turn every wait into an early return.
     */
    @Test
    fun aSendWaitsForASubscriptionThatArrivesLate(): Unit = runBlocking {
        outbound.handleDeviceConnected(device)
        probe.gattCallback.onMtuChanged(device, 247)

        val send = async(Dispatchers.IO) { outbound.sendResponse(device, ByteArray(64) { 0x43 }) }
        delay(50)
        assertFalse("the send must still be parked on the subscription", send.isCompleted)

        writeCccd()
        send.await()

        assertEquals(true, outbound.notificationEnabled[device.address])
    }

    // -----------------------------------------------------------------
    // Teardown during fragmentation
    // -----------------------------------------------------------------

    /**
     * A `stop()` landing on a send in progress must end it, not fail it.
     *
     * The handle the fragments go out on is captured once, so a teardown can no
     * longer swap it midway and split a message across two of them — that part
     * has no expression from outside the server, since it needs a peer to
     * observe. What is checkable here is the consequence: the send terminates
     * and nothing is thrown into the coroutine that was doing it.
     */
    @Test
    fun aStopBetweenFragmentsEndsTheSendWithoutThrowing(): Unit = runBlocking {
        outbound.handleDeviceConnected(device)
        probe.gattCallback.onMtuChanged(device, 247)
        writeCccd()

        // Long enough to reach the paced branch, so the stop lands mid-message.
        val response = ByteArray(8192) { (it % 251).toByte() }
        val send = launch(Dispatchers.IO) { outbound.sendResponse(device, response) }
        delay(20)
        probe.server.stop()

        send.join()

        assertFalse(probe.server.isRunning())
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    /** Writes the CCCD the way a desktop does before it expects any reply. */
    private fun writeCccd() {
        probe.gattCallback.onDescriptorWriteRequest(
            device, 1,
            BluetoothGattDescriptor(
                GattServer.CCCD_UUID,
                BluetoothGattDescriptor.PERMISSION_READ or BluetoothGattDescriptor.PERMISSION_WRITE
            ),
            false, false, 0,
            BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
        )
        assertEquals(true, outbound.notificationEnabled[device.address])
    }

    private companion object {
        const val DEVICE_ADDRESS = "AA:BB:CC:DD:EE:F7"
    }
}
