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

import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothProfile
import android.util.Log
import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mockk.verify
import java.security.SecureRandom
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
 * [BleClient] driven end to end against a real Noise responder, through a
 * mocked Bluetooth stack — see [BleClientHarness] for why that is faithful.
 *
 * This is the phone's *outbound* transport: the path it takes when it dials a
 * desktop instead of answering one. Nothing else in the app exercises it, and
 * every step of it is a suspending call parked on a `CompletableDeferred` that
 * only the Bluetooth stack completes, so an ordering mistake in connect,
 * discovery, MTU negotiation or CCCD setup is a permanent hang with no error to
 * read. These tests run the whole ladder and then assert on what the desktop
 * actually received.
 *
 * `runBlocking` rather than `runTest`: the client's internal scope is a real
 * `Dispatchers.Default` scope and its `withTimeout` guards are real, so virtual
 * time would fast-forward straight through them.
 */
class BleClientConnectionTest {

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

    /** Builds the harness and registers it for teardown. */
    private fun harness(mtu: Int = 247): BleClientHarness =
        BleClientHarness(mtu = mtu).also { harness = it }

    // -----------------------------------------------------------------
    // The connect ladder
    // -----------------------------------------------------------------

    /**
     * The whole outbound path in one assertion set: the client reaches a live
     * encrypted session, and both sides end up holding the other's
     * *authenticated* static key.
     */
    @Test
    fun connectingRunsTheWholeLadderAndAuthenticatesBothSides(): Unit = runBlocking {
        val h = harness()

        assertTrue(h.client.connect(h.address, randomKey()))

        assertTrue("the client must report a live session", h.client.isConnected())
        assertEquals(
            ClientConnectionState.Connected(h.deviceName, h.address),
            h.client.connectionState.value
        )
        assertArrayEquals(
            "the client must learn the desktop's own static key",
            h.responder.getStaticPublicKey(),
            h.client.getRemoteStaticKey()
        )
        assertArrayEquals(
            "the desktop must learn the client's own static key",
            h.probe.noiseSession!!.getLocalStaticPublicKey(),
            h.responder.getRemoteStaticKey()
        )
    }

    /**
     * Pins the outbound frame count. A connect is exactly three writes —
     * identity, `-> e`, `-> s, se` — and the identity frame is the versioned
     * 33-byte form `go-xkms` peeks for before it will speak Noise at all.
     */
    @Test
    fun aConnectIsTheIdentityFrameAndThreeHandshakeSteps(): Unit = runBlocking {
        val h = harness()

        h.client.connect(h.address, randomKey())

        assertEquals("identity, msg1, msg3", 3, h.writeCount)
        val identity = h.receivedIdentity!!
        assertEquals(33, identity.size)
        assertEquals("version byte", 0x01.toByte(), identity[0])
        assertArrayEquals(
            h.probe.noiseSession!!.getLocalStaticPublicKey(),
            identity.copyOfRange(1, identity.size)
        )
    }

    /** The stack's MTU is what the client records and fragments against. */
    @Test
    fun theNegotiatedMtuIsRecordedAndNotificationsAreEnabled(): Unit = runBlocking {
        val h = harness(mtu = 185)

        h.client.connect(h.address, randomKey())

        assertEquals(185, h.probe.negotiatedMtu)
        verify { h.gatt.setCharacteristicNotification(h.responseCharacteristic, true) }
        verify { h.gatt.writeDescriptor(h.cccd) }
    }

    /** Discovery must resolve all three characteristics, status included. */
    @Test
    fun discoveryResolvesEveryCharacteristic(): Unit = runBlocking {
        val h = harness()

        h.client.connect(h.address, randomKey())

        assertNotNull(h.probe.controlPointCharacteristic)
        assertNotNull(h.probe.responseCharacteristic)
        assertNotNull("status is optional but present here", h.probe.statusCharacteristic)
    }

    /**
     * A desktop the phone has paired with before answers the identity exchange
     * as a *known* device, which binds Noise to
     * `SHA256(client_pub || fingerprint || "xkey-v1")`. If the client derived it
     * differently the handshake would not authenticate, so a completed connect
     * is the proof.
     */
    @Test
    fun aKnownDeviceAckBindsTheHandshakeToThePinnedFingerprint(): Unit = runBlocking {
        val h = harness()
        h.pinnedFingerprint = ByteArray(32).also { SecureRandom().nextBytes(it) }

        assertTrue(h.client.connect(h.address, randomKey()))
        assertTrue(h.client.isConnected())
    }

    /** Pinning the desktop's key is what makes a relay detectable. */
    @Test
    fun anExpectedRemoteKeyThatMatchesIsAccepted(): Unit = runBlocking {
        val h = harness()

        assertTrue(h.client.connect(h.address, randomKey(), h.responder.getStaticPublicKey()))
    }

    @Test
    fun anExpectedRemoteKeyThatDiffersAbortsTheConnection(): Unit = runBlocking {
        val h = harness()

        val failure = assertConnectFails(h, expectedRemoteKey = randomKey())

        assertTrue(
            "the user has to be told this was a key mismatch: ${failure.message}",
            failure.message!!.contains("mismatch")
        )
        assertFalse(h.client.isConnected())
        assertEquals(ClientConnectionState.Disconnected, h.client.connectionState.value)
        assertNull("a rejected connection must not stay open", h.probe.gattConnection)
    }

    // -----------------------------------------------------------------
    // The encrypted request loop
    // -----------------------------------------------------------------

    @Test
    fun requestsRoundTripOverTheEncryptedSession(): Unit = runBlocking {
        val h = harness()
        h.client.connect(h.address, randomKey())
        val request = """{"jsonrpc":"2.0","id":1,"method":"local.getCapabilities"}""".toByteArray()

        val response = h.client.sendRequest(request)

        assertEquals(1, h.receivedRequests.size)
        assertArrayEquals("the desktop must decrypt exactly what was sent", request, h.receivedRequests[0])
        assertArrayEquals(h.responseFor(request), response)
    }

    /**
     * The transport nonce is a local monotonic counter with no replay window,
     * so several requests in a row are the only thing that proves the two
     * directions stay in step.
     */
    @Test
    fun consecutiveRequestsKeepBothNoncesInStep(): Unit = runBlocking {
        val h = harness()
        h.client.connect(h.address, randomKey())

        val responses = (1..4).map { h.client.sendRequest("""{"id":$it}""".toByteArray()) }

        assertEquals(4, h.receivedRequests.size)
        responses.forEachIndexed { index, response ->
            assertArrayEquals(h.responseFor(h.receivedRequests[index]), response)
        }
        assertEquals("""{"id":4}""", String(h.receivedRequests[3]))
    }

    /**
     * A payload larger than the MTU has to survive fragmentation in both
     * directions — the client fragments the request, the desktop fragments the
     * reply, and each side reassembles with the counterpart implementation.
     */
    @Test
    fun payloadsLargerThanTheMtuAreFragmentedBothWays(): Unit = runBlocking {
        val h = harness()
        h.client.connect(h.address, randomKey())
        val writesBefore = h.writeCount
        val request = ByteArray(4096).also { SecureRandom().nextBytes(it) }
        val reply = ByteArray(3072).also { SecureRandom().nextBytes(it) }
        h.responseFor = { reply }

        val response = h.client.sendRequest(request)

        assertArrayEquals(request, h.receivedRequests[0])
        assertArrayEquals(reply, response)
        assertTrue(
            "a 4 KB request cannot fit one 247-byte frame",
            h.writeCount - writesBefore > 1
        )
    }

    @Test
    fun aRequestBeforeConnectingIsRefused(): Unit = runBlocking {
        val h = harness()

        try {
            h.client.sendRequest("ping".toByteArray())
            fail("a request without a session must be refused")
        } catch (expected: BleClientException) {
            assertTrue(expected.message!!.contains("Not connected"))
        }
    }

    // -----------------------------------------------------------------
    // Teardown
    // -----------------------------------------------------------------

    @Test
    fun disconnectingClosesTheGattConnectionAndDropsTheSession(): Unit = runBlocking {
        val h = harness()
        h.client.connect(h.address, randomKey())

        h.probe.disconnectInternal()

        assertNull(h.probe.gattConnection)
        assertNull(h.probe.connectedDevice)
        assertNull(h.probe.controlPointCharacteristic)
        assertNull(h.probe.responseCharacteristic)
        assertNull("the session must not outlive the link", h.probe.noiseSession)
        assertFalse(h.client.isConnected())
        assertEquals("the MTU falls back to the BLE minimum", 23, h.probe.negotiatedMtu)
        verify { h.gatt.disconnect() }
        verify { h.gatt.close() }
    }

    /** `destroy` is what the service calls; it must leave nothing open. */
    @Test
    fun destroyReleasesTheConnectionAndReportsDisconnected(): Unit = runBlocking {
        val h = harness()
        h.client.connect(h.address, randomKey())

        h.client.destroy()

        assertFalse(h.client.isConnected())
        assertNull(h.probe.gattConnection)
        assertEquals(ClientConnectionState.Disconnected, h.client.connectionState.value)
        verify { h.gatt.close() }
    }

    // -----------------------------------------------------------------
    // Failure modes
    // -----------------------------------------------------------------

    /** Connecting twice would leak the first `BluetoothGatt`. */
    @Test
    fun aSecondConnectWhileConnectedIsRefused(): Unit = runBlocking {
        val h = harness()
        h.client.connect(h.address, randomKey())

        try {
            h.client.connect(h.address, randomKey())
            fail("a second connect must be refused")
        } catch (expected: BleClientException) {
            assertTrue(expected.message!!.contains("Already connected"))
        }
        assertTrue("the live session must survive the refusal", h.client.isConnected())
    }

    @Test
    fun aDisabledRadioIsReportedBeforeAnythingIsOpened(): Unit = runBlocking {
        val h = harness()
        h.bluetoothEnabled = false

        try {
            h.client.connect(h.address, randomKey())
            fail("connect must refuse a disabled radio")
        } catch (expected: BleClientException) {
            assertTrue(expected.message!!.contains("not enabled"))
        }
        assertNull(h.probe.gattConnection)
    }

    @Test
    fun anUnparseableAddressIsRejected(): Unit = runBlocking {
        val h = harness()

        try {
            h.client.connect("not-an-address", randomKey())
            fail("an invalid address must be rejected")
        } catch (expected: BleClientException) {
            assertTrue(expected.message!!.contains("Invalid device address"))
        }
    }

    /** Every step of the ladder must fail loudly rather than hang. */
    @Test
    fun aRefusedGattConnectionSurfaces(): Unit = runBlocking {
        val h = harness()
        h.connectStarts = false

        assertConnectFails(h)
        assertNull(h.probe.gattConnection)
    }

    @Test
    fun aDisconnectDuringConnectSurfaces(): Unit = runBlocking {
        val h = harness()
        h.connectionNewState = BluetoothProfile.STATE_DISCONNECTED
        h.connectionStatus = BluetoothGatt.GATT_FAILURE

        assertConnectFails(h)
        assertEquals(ClientConnectionState.Disconnected, h.client.connectionState.value)
    }

    @Test
    fun aServiceDiscoveryThatCannotStartSurfaces(): Unit = runBlocking {
        val h = harness()
        h.discoveryStarts = false

        assertConnectFails(h)
    }

    @Test
    fun aFailedServiceDiscoverySurfaces(): Unit = runBlocking {
        val h = harness()
        h.discoveryStatus = BluetoothGatt.GATT_FAILURE

        assertConnectFails(h)
    }

    /** A desktop without the xKey service is not an xKey desktop. */
    @Test
    fun aMissingXKeyServiceSurfaces(): Unit = runBlocking {
        val h = harness()
        h.serviceIsPresent = false

        val failure = assertConnectFails(h)
        assertTrue(failure.message!!.contains("service not found"))
    }

    @Test
    fun aMissingControlPointSurfaces(): Unit = runBlocking {
        val h = harness()
        h.controlPointIsPresent = false

        val failure = assertConnectFails(h)
        assertTrue(failure.message!!.contains("Control point"))
    }

    @Test
    fun aMissingResponseCharacteristicSurfaces(): Unit = runBlocking {
        val h = harness()
        h.responseIsPresent = false

        val failure = assertConnectFails(h)
        assertTrue(failure.message!!.contains("Response characteristic"))
    }

    @Test
    fun aMissingCccdSurfaces(): Unit = runBlocking {
        val h = harness()
        h.cccdIsPresent = false

        val failure = assertConnectFails(h)
        assertTrue(failure.message!!.contains("CCCD"))
    }

    @Test
    fun aRefusedNotificationRegistrationSurfaces(): Unit = runBlocking {
        val h = harness()
        h.notificationsEnable = false

        val failure = assertConnectFails(h)
        assertTrue(failure.message!!.contains("local notifications"))
    }

    @Test
    fun aFailedCccdWriteSurfaces(): Unit = runBlocking {
        val h = harness()
        h.descriptorWriteStatus = BluetoothGatt.GATT_FAILURE

        val failure = assertConnectFails(h)
        assertTrue(failure.message!!.contains("notifications"))
    }

    @Test
    fun aWriteTheStackRefusesToStartSurfaces(): Unit = runBlocking {
        val h = harness()
        h.writeStarts = false

        val failure = assertConnectFails(h)
        assertTrue(failure.message!!.contains("initiate write"))
    }

    @Test
    fun aWriteTheStackReportsAsFailedSurfaces(): Unit = runBlocking {
        val h = harness()
        h.writeStatus = BluetoothGatt.GATT_FAILURE

        val failure = assertConnectFails(h)
        assertTrue(failure.message!!.contains("Write failed"))
    }

    /**
     * Documents a real defect rather than a design choice.
     *
     * When MTU negotiation cannot start — or the stack refuses it — the client
     * falls back to the BLE minimum of 23. Its fragment budget is then
     * `min(23 - 3, 512) - 7 = 13` bytes, below [Fragmenter.MIN_PAYLOAD_SIZE],
     * so constructing the `Fragmenter` throws and *no message can ever be
     * sent*. The connection dies on the identity frame, before Noise starts.
     *
     * `GattServer` does not have this problem: it clamps the peer's MTU into
     * `[23, 517]` and fragments against the clamped value the same way, but it
     * is only ever reached with an MTU the desktop already negotiated upwards.
     */
    @Test
    fun aFailedMtuNegotiationLeavesTheClientUnableToSendAnything(): Unit = runBlocking {
        val h = harness()
        h.mtuRequestStarts = false

        assertConnectFails(h)

        assertEquals(0, h.writeCount)
        assertNull("no identity frame was ever sent", h.receivedIdentity)
    }

    /** The same dead end is reached when the stack reports an MTU failure. */
    @Test
    fun anMtuFailureStatusIsEquallyFatal(): Unit = runBlocking {
        val h = harness()
        h.mtuStatus = BluetoothGatt.GATT_FAILURE

        assertConnectFails(h)
        assertEquals(0, h.writeCount)
    }

    /** A failed connect must leave the client usable for a retry. */
    @Test
    fun aFailedConnectLeavesTheClientReusable(): Unit = runBlocking {
        val h = harness()
        h.serviceIsPresent = false
        assertConnectFails(h)

        h.serviceIsPresent = true
        // A retry dials a new GATT object, as connectGatt does: the client
        // treats the failed one's callbacks as stale from here on.
        h.nextConnection()
        assertTrue(h.client.connect(h.address, randomKey()))
        assertTrue(h.client.isConnected())
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private fun randomKey(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }

    private suspend fun assertConnectFails(
        h: BleClientHarness,
        expectedRemoteKey: ByteArray? = null
    ): BleClientException {
        try {
            h.client.connect(h.address, randomKey(), expectedRemoteKey)
        } catch (expected: BleClientException) {
            assertEquals(
                "a failed connect must not leave the UI showing a connection",
                ClientConnectionState.Disconnected,
                h.client.connectionState.value
            )
            return expected
        }
        fail("expected the connection to fail")
        error("unreachable")
    }
}
