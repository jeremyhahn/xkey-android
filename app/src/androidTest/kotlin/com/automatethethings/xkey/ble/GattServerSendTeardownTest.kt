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
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.BluetoothStatusCodes
import android.content.Context
import android.os.Build
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.rule.GrantPermissionRule
import com.automatethethings.xkey.settings.PairedDeviceRepository
import io.mockk.every
import io.mockk.mockk
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
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
 * inert. Where a send must get past its first fragment, the test swaps in an
 * [AcceptingServerHandle] that takes notifications as a subscribed peer's
 * server would.
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
        connectAtMtu247()
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
        connectAtMtu247()
        // The disconnect ends the queue; its consumer then releases the device.
        probe.gattCallback.onConnectionStateChange(
            device, BluetoothGatt.GATT_SUCCESS, BluetoothProfile.STATE_DISCONNECTED
        )
        GattServerProbe.awaitUntil("the device to be released") {
            probe.connectedDevice == null && outbound.notificationReady[device.address] == null
        }

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
        connectAtMtu247()

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
     * Without a peer the stack refuses the first notification, and the send
     * would end before any teardown could reach it. So the open handle is
     * replaced by [AcceptingServerHandle], which takes notifications until it
     * is closed, as an open server does for a subscribed peer. Its first
     * fragment is held until `stop()` has run, so the stop lands with every
     * later fragment still pending; the send must then end at the closed
     * handle rather than run the rest of the message into it.
     */
    @Test
    fun aStopBetweenFragmentsEndsTheSendWithoutThrowing(): Unit = runBlocking {
        assumeTrue(
            "mocking the final server handle needs API 28",
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.P
        )
        connectAtMtu247()
        writeCccd()
        val handle = AcceptingServerHandle(probe.gattServerHandle!!, probe.responseCharacteristic!!)
        probe.gattServerHandle = handle.server

        // Long enough to reach the paced branch, so the stop lands mid-message.
        val response = ByteArray(8192) { (it % 251).toByte() }
        val fragments = Fragmenter(247 - 3 - FragmentReassembler.HEADER_SIZE).fragment(response).size
        val send = launch(Dispatchers.IO) { outbound.sendResponse(device, response) }

        assertTrue(
            "the first fragment never reached the stack",
            handle.firstFragment.await(5, TimeUnit.SECONDS)
        )
        assertTrue("the send must still be running when stop lands", send.isActive)
        probe.server.stop()
        handle.stopped.countDown()

        send.join()

        val accepted = handle.accepted.get()
        assertTrue("stop must land after a fragment was sent", accepted >= 1)
        assertTrue(
            "stop must end the send before its last fragment ($accepted of $fragments sent)",
            accepted < fragments
        )
        assertTrue("the send must have tried the closed handle", handle.refused.get() >= 1)
        assertFalse(probe.server.isRunning())
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    /**
     * Connects [device] through the callback on the started server and
     * negotiates an MTU large enough to carry a fragment, awaited because the
     * change is queued behind the connect.
     */
    private fun connectAtMtu247() {
        probe.connectThroughTheCallback(device)
        probe.gattCallback.onMtuChanged(device, 247)
        probe.awaitMtu(device, 247)
    }

    /**
     * Writes the CCCD the way a desktop does before it expects any reply. On a
     * connection [connectAtMtu247] opened, the write is recorded as it is made.
     */
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

/**
 * A server handle that accepts response notifications until it is closed, the
 * way an open server does for a subscribed peer, and refuses them after.
 *
 * The first accepted fragment opens [firstFragment] and is then held until
 * [stopped] opens, so a test can tear the server down while the rest of the
 * message is still to be sent. Closing it closes [real], the handle the server
 * opened, so nothing outlives the test.
 */
private class AcceptingServerHandle(
    private val real: BluetoothGattServer,
    private val response: BluetoothGattCharacteristic
) {
    val firstFragment = CountDownLatch(1)
    val stopped = CountDownLatch(1)
    val accepted = AtomicInteger()
    val refused = AtomicInteger()

    @Volatile
    private var closed = false

    val server: BluetoothGattServer = mockk(relaxed = true)

    init {
        every { server.close() } answers {
            closed = true
            real.close()
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            every { server.notifyCharacteristicChanged(any(), any(), any(), any()) } answers {
                if (notify(secondArg())) {
                    BluetoothStatusCodes.SUCCESS
                } else {
                    BluetoothStatusCodes.ERROR_PROFILE_SERVICE_NOT_BOUND
                }
            }
        } else {
            @Suppress("DEPRECATION")
            every { server.notifyCharacteristicChanged(any(), any(), any()) } answers {
                notify(secondArg())
            }
        }
    }

    /** Whether the stack takes a notification on [characteristic]. */
    private fun notify(characteristic: BluetoothGattCharacteristic): Boolean {
        if (characteristic.uuid != response.uuid) return !closed
        if (closed) {
            refused.incrementAndGet()
            return false
        }
        if (accepted.incrementAndGet() == 1) {
            firstFragment.countDown()
            stopped.await(5, TimeUnit.SECONDS)
        }
        return true
    }
}
