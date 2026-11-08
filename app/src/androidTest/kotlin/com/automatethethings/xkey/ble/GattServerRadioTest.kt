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
import java.io.IOException
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * [GattServer] with the radio actually open.
 *
 * Every other BLE suite drives the server with `gattServer` null, which is
 * enough for the request path but stops the *outbound* half dead:
 * `sendResponse` returns at its second line, so the subscription wait, the MTU
 * budget, the fragment loop and the notification calls never run. That is the
 * only route a desktop has to hear anything back, and it contains the one
 * decision that has no other expression anywhere in the app — an MTU too small
 * to carry a fragment must be *refused* rather than allowed to throw from
 * inside a coroutine, because a throw there leaves the peer with neither a
 * reply nor an explanation.
 *
 * None of this needs a peer, only a local adapter willing to open a GATT
 * server. Notifications aimed at a device that never connected are reported
 * undeliverable by the stack and are otherwise inert, so the whole path runs
 * for real right up to the final framework call. Where a device *is* needed it
 * is a well-formed address that is never dialled.
 *
 * The suite skips itself where there is no usable adapter — see the
 * assumptions in [setUp].
 */
@RunWith(AndroidJUnit4::class)
class GattServerRadioTest {

    /** Opening a GATT server and reading `BluetoothDevice.getName()`. */
    @get:Rule
    val bluetoothPermission: GrantPermissionRule =
        GrantPermissionRule.grant(Manifest.permission.BLUETOOTH_CONNECT)

    private lateinit var context: Context
    private lateinit var repository: PairedDeviceRepository
    private lateinit var probe: GattServerProbe
    private lateinit var outbound: GattServerOutboundProbe
    private lateinit var device: BluetoothDevice

    /** Servers this test started beyond the main one; stopped in teardown. */
    private val extraProbes = mutableListOf<GattServerProbe>()

    /** Keys registered in the paired-device store; removed in teardown. */
    private val pairedKeys = mutableListOf<String>()

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
        extraProbes.forEach { it.close() }
        extraProbes.clear()
        pairedKeys.forEach { repository.removeDevice(it) }
        pairedKeys.clear()
    }

    // -----------------------------------------------------------------
    // Startup
    // -----------------------------------------------------------------

    /**
     * A started server publishes the service a desktop scans for. Without the
     * primary service registered under this exact UUID no xKey desktop can
     * discover the phone at all.
     */
    @Test
    fun aStartedServerPublishesTheXKeyService() {
        assertTrue(probe.server.isRunning())

        val services = outbound.bluetoothGattServer?.services
        assertNotNull("a running server must hold an open handle", services)
        val published = services!!.firstOrNull { it.uuid == GattServer.XKEY_SERVICE_UUID }
        assertNotNull("the xKey primary service must be registered", published)
        assertEquals(3, published!!.characteristics.size)
        assertNotNull(published.getCharacteristic(GattServer.CONTROL_POINT_UUID))
        assertNotNull(published.getCharacteristic(GattServer.RESPONSE_UUID))
        assertNotNull(published.getCharacteristic(GattServer.STATUS_UUID))
    }

    /**
     * The UI toggle can ask for a start that is already satisfied. Registering
     * the service a second time would be rejected by the stack, so a repeat
     * start has to be recognised and reported as already-running.
     */
    @Test
    fun startingAnAlreadyRunningServerIsANoOp() {
        val servicesBefore = outbound.bluetoothGattServer?.services?.size

        assertTrue("a second start must report success", probe.server.start())

        assertTrue(probe.server.isRunning())
        assertEquals(
            "the service must not be registered twice",
            servicesBefore,
            outbound.bluetoothGattServer?.services?.size
        )
    }

    /**
     * Two starts racing is a different case from one that already finished: the
     * second must back off rather than open a competing server handle and leak
     * the first.
     */
    @Test
    fun aStartThatRacesAnotherIsRefused() {
        val second = GattServerProbe(context, pairedDeviceRepository = repository)
        extraProbes += second
        GattServerOutboundProbe(second.server).isStarting = true

        assertFalse("a start already in flight must not be joined", second.server.start())
        assertFalse(second.server.isRunning())
    }

    /** Stopping releases the handle even while a session is live. */
    @Test
    fun stoppingWithALiveSessionReleasesEverything(): Unit = runBlocking {
        outbound.handleDeviceConnected(device)
        probe.establishSession(device)

        probe.server.stop()

        assertFalse(probe.server.isRunning())
        assertNull("the open handle must be released", outbound.bluetoothGattServer)
        assertNull(probe.connectedDevice)
        assertNull(probe.noiseSession)
        assertFalse(probe.server.isSessionEstablished())
    }

    // -----------------------------------------------------------------
    // The subscription gate
    // -----------------------------------------------------------------

    /**
     * Responses leave as notifications, so a desktop that has not written the
     * CCCD cannot receive one. Sending anyway would silently drop the reply; the
     * server has to notice and say so.
     */
    @Test
    fun aResponseIsWithheldFromADeviceThatNeverSubscribed(): Unit = runBlocking {
        outbound.handleDeviceConnected(device)
        // Released as if the subscription arrived, but the CCCD was never
        // written — the wait must not be what decides this.
        outbound.notificationReady[device.address]?.complete(Unit)

        outbound.sendResponse(device, ByteArray(64) { 0x41 })

        assertNull(
            "an unsubscribed device must not be recorded as subscribed",
            outbound.notificationEnabled[device.address]
        )
    }

    /**
     * The MTU decides the fragment budget, and at the BLE default of 23 the
     * arithmetic leaves 13 bytes — below the fragmenter's floor of
     * [Fragmenter.MIN_PAYLOAD_SIZE]. Building a fragmenter anyway throws, and it
     * would throw from inside the server's own coroutine where nothing can
     * answer the peer. The send is refused instead.
     */
    @Test
    fun aResponseIsRefusedWhenTheMtuCannotCarryAFragment(): Unit = runBlocking {
        connectAndSubscribe()
        assertEquals("the default MTU is what makes this case real", 23, outbound.deviceMtu[device.address])

        // Must return rather than throw; a throw here is the regression.
        outbound.sendResponse(device, ByteArray(128) { 0x42 })

        assertTrue("the session must survive a refused send", probe.server.isRunning())
    }

    /** A payload that fits one ATT write goes out as a single fragment. */
    @Test
    fun aShortResponseIsSentAsOneFragment(): Unit = runBlocking {
        connectAndSubscribe(mtu = 247)

        val response = ByteArray(32) { it.toByte() }
        assertEquals(1, Fragmenter(payloadBudgetFor(247)).fragment(response).size)

        outbound.sendResponse(device, response)
    }

    /**
     * A long response — a key listing, a sync payload — is split across many
     * notifications, and past ten fragments the server paces them so the BLE
     * stack's outbound queue cannot overflow.
     */
    @Test
    fun aLongResponseIsSplitAcrossManyPacedFragments(): Unit = runBlocking {
        connectAndSubscribe(mtu = 247)

        val response = ByteArray(4096) { (it % 251).toByte() }
        val fragments = Fragmenter(payloadBudgetFor(247)).fragment(response)
        assertTrue(
            "the payload must be big enough to reach the pacing branch",
            fragments.size > 10
        )

        outbound.sendResponse(device, response)
    }

    /** The status characteristic is notified with one byte per state. */
    @Test
    fun theStatusNotificationCarriesTheCurrentState(): Unit = runBlocking {
        connectAndSubscribe()
        probe.connectionState = ConnectionState.Connected("Workstation", device.address)

        outbound.sendStatusNotification(device)

        assertArrayEquals(byteArrayOf(0x02), probe.statusValue())
    }

    // -----------------------------------------------------------------
    // Outbound requests
    // -----------------------------------------------------------------

    /**
     * `sendEncryptedMessage` is how the phone *initiates* — enrollment, remote
     * key and sync clients all go out through it. It needs both halves of the
     * session, and it must leave the session usable afterwards: a Noise
     * cipherstate numbers each message, so a send that half-completed would
     * desynchronise every later frame.
     */
    @Test
    fun anOutboundMessageIsEncryptedAndLeavesTheSessionUsable(): Unit = runBlocking {
        probe.connectThroughTheCallback(device)
        val initiator = probe.establishSession(device)
        subscribe(mtu = 247)
        // The send revalidates pairing, so the fresh peer must be trusted first.
        adoptPairing()

        probe.server.sendEncryptedMessage("""{"id":1,"method":"remote.ping"}""".toByteArray())

        val probeFrame = """{"id":2,"method":"local.getCapabilities"}""".toByteArray()
        assertArrayEquals(
            "the inbound half of the session must be untouched by an outbound send",
            probeFrame,
            probe.noiseSession!!.decrypt(initiator.encrypt(probeFrame))
        )
    }

    /** Without a peer there is nowhere to send, and that must be an error. */
    @Test
    fun anOutboundMessageWithoutAPeerFails(): Unit = runBlocking {
        outbound.handleDeviceConnected(device)
        probe.establishSession(device)
        outbound.connectedDevice = null

        try {
            probe.server.sendEncryptedMessage("{}".toByteArray())
            fail("sending with no connected device must fail")
        } catch (expected: IOException) {
            // expected
        }
    }

    /**
     * The end-to-end shape: a paired desktop's request is decrypted, dispatched
     * and the reply encrypted and fragmented back out over the open server.
     */
    @Test
    fun aPairedRequestIsAnsweredOverTheRadio(): Unit = runBlocking {
        probe.connectThroughTheCallback(device)
        val initiator = probe.establishSession(device)
        subscribe(mtu = 247)
        adoptPairing()

        outbound.handleApplicationMessage(
            device,
            initiator.encrypt(request(1, "local.getCapabilities"))
        )

        // The reply was encrypted on the way out, so the send counter moved;
        // the receive half must still be exactly one frame ahead.
        val probeFrame = request(2, "local.listKeys")
        assertArrayEquals(
            probeFrame,
            probe.noiseSession!!.decrypt(initiator.encrypt(probeFrame))
        )
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    /** Max payload per fragment: the ATT value limit minus the 7-byte header. */
    private fun payloadBudgetFor(mtu: Int) =
        minOf(mtu - 3, 512) - FragmentReassembler.HEADER_SIZE

    private fun connectAndSubscribe(mtu: Int? = null) {
        probe.connectThroughTheCallback(device)
        subscribe(mtu)
    }

    /**
     * Negotiates [mtu], when given, and writes the CCCD the way a desktop does
     * before it expects any reply. [device] must have been connected with
     * [GattServerProbe.connectThroughTheCallback]: the MTU change is queued
     * behind the connect and awaited, and the CCCD write is recorded on the
     * published link as it is made.
     */
    private fun subscribe(mtu: Int? = null) {
        if (mtu != null) {
            probe.gattCallback.onMtuChanged(device, mtu)
            probe.awaitMtu(device, mtu)
        }
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

    /** Confirms the session the way a reconnect from a trusted desktop does. */
    private fun adoptPairing() {
        val peerKeyHex = probe.authenticatedPeerKeyHex!!
        repository.addDevice(peerKeyHex, "BleRadioTest ${peerKeyHex.take(8)}")
        pairedKeys += peerKeyHex
        probe.adoptExistingPairing()
        assertTrue(probe.pairingConfirmed)
    }

    private fun request(id: Long, method: String): ByteArray =
        JSONObject().put("id", id).put("method", method).put("params", JSONObject())
            .toString().toByteArray(Charsets.UTF_8)

    private companion object {
        const val DEVICE_ADDRESS = "AA:BB:CC:DD:EE:F6"
    }
}
