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
import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.rule.GrantPermissionRule
import com.automatethethings.xkey.protocol.ErrorCodes
import com.automatethethings.xkey.settings.PairedDeviceRepository
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The message loop from the first byte off the radio to the dispatched request,
 * and the pairing gate's remaining refusals.
 *
 * `processIncomingData` is a three-way switch — identity exchange, handshake,
 * application message — and the existing suites only ever deliver one frame per
 * connection, so the two later branches were never taken through the real
 * entry point at all. Nor was the *completion* of the handshake: the server's
 * reply to message 2 goes to the radio, so a suite with no radio cannot get
 * message 3 back. Here the peer side is driven against a responder that is then
 * installed exactly as `handleHandshakeMessage` installs one, and message 3
 * arrives the way the stack delivers it — fragmented, through
 * `processIncomingData`.
 *
 * The refusals matter as much as the successes. A frame that fails to *decrypt*
 * is fatal in Noise and takes the session down; a frame that decrypts and is
 * merely garbage must not, or a paired desktop with one bad request would lose
 * a session it could still have used. Those two live one `catch` apart in the
 * same function and are asserted against each other here.
 */
@RunWith(AndroidJUnit4::class)
class GattServerMessageLoopTest {

    /** `handleDeviceConnected` reads `BluetoothDevice.getName()`. */
    @get:Rule
    val bluetoothPermission: GrantPermissionRule =
        GrantPermissionRule.grant(Manifest.permission.BLUETOOTH_CONNECT)

    private lateinit var context: Context
    private lateinit var repository: PairedDeviceRepository
    private lateinit var probe: GattServerProbe
    private lateinit var outbound: GattServerOutboundProbe
    private lateinit var device: BluetoothDevice

    /** Set when the app would have shown the user a pairing prompt. */
    private val promptShown = AtomicBoolean(false)

    /** Whether the simulated user approves. */
    private val userApproves = AtomicBoolean(true)

    /** Probes built by individual tests; closed in teardown. */
    private val extraProbes = mutableListOf<GattServerProbe>()

    /** Keys registered in the paired-device store; removed in teardown. */
    private val pairedKeys = mutableListOf<String>()

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        val remote = GattServerProbe.remoteDevice(context, DEVICE_ADDRESS)
        assumeTrue("this device has no Bluetooth adapter", remote != null)
        device = remote!!
        promptShown.set(false)
        userApproves.set(true)

        repository = PairedDeviceRepository(context)
        probe = GattServerProbe(
            context,
            pairedDeviceRepository = repository,
            pairingCallback = object : PairingConfirmationCallback {
                override suspend fun onPairingConfirmationRequired(
                    deviceName: String,
                    publicKeyFingerprint: String
                ): Boolean {
                    promptShown.set(true)
                    return userApproves.get()
                }
            }
        )
        outbound = GattServerOutboundProbe(probe.server)
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
    // Routing
    // -----------------------------------------------------------------

    /**
     * Fragments are reassembled per device. A frame from a device the server
     * never accepted has nowhere to be buffered and must be dropped rather than
     * be reassembled against somebody else's stream.
     */
    @Test
    fun aFrameFromAnUnacceptedDeviceIsDropped(): Unit = runBlocking {
        val stranger = GattServerProbe.remoteDevice(context, "AA:BB:CC:DD:EE:F9")!!
        probe.handleDeviceConnected(device)

        for (fragment in Fragmenter(20).fragment(randomKey())) {
            probe.processIncomingData(stranger, fragment)
        }

        assertFalse(
            "a stranger's frame must not advance the accepted device's exchange",
            probe.identityExchangeComplete
        )
        assertNull(probe.fragmentBuffer[stranger.address])
    }

    /** A frame that arrives after the session is gone is dropped, not decrypted. */
    @Test
    fun aFrameWithoutASessionIsDropped(): Unit = runBlocking {
        probe.handleDeviceConnected(device)
        outbound.noiseSession = null

        deliver(NoiseInitiatorSession(randomKey()).createIdentityMessage())

        assertFalse(probe.identityExchangeComplete)
    }

    /**
     * The handshake completing is what publishes the peer's identity and flips
     * the state the UI shows. Message 3 has to arrive the way the stack
     * delivers it, so this is the only place that path is taken end to end.
     */
    @Test
    fun theHandshakeCompletesThroughTheRealFramePath(): Unit = runBlocking {
        val initiator = beginConnection()

        completeHandshakeThroughTheWire(initiator)

        assertTrue(probe.server.isSessionEstablished())
        assertEquals(
            "the identity the server trusts comes from the transcript",
            initiator.getLocalStaticPublicKey().toHex(),
            probe.authenticatedPeerKeyHex
        )
        assertEquals(
            ConnectionState.Connected(device.name ?: "Unknown", device.address),
            probe.server.connectionState.value
        )
    }

    /**
     * And once it has, the same entry point routes encrypted traffic to the
     * application branch instead of the handshake one.
     */
    @Test
    fun anEncryptedRequestRoutesThroughTheApplicationBranch(): Unit = runBlocking {
        val initiator = beginConnection()
        completeHandshakeThroughTheWire(initiator)
        adoptPairing()

        deliver(initiator.encrypt(request(1, "local.getCapabilities")))

        val probeFrame = request(2, "local.listKeys")
        assertArrayEquals(
            "the frame must have been decrypted, consuming exactly one counter",
            probeFrame,
            probe.noiseSession!!.decrypt(initiator.encrypt(probeFrame))
        )
    }

    // -----------------------------------------------------------------
    // Malformed traffic
    // -----------------------------------------------------------------

    /**
     * A frame that decrypts but is not a JSON-RPC message is answered with an
     * internal error and the session is *kept*. Only a failed decryption is
     * fatal — see `anUndecryptableFrameTearsTheSessionDown` in
     * [GattServerSessionTest] for the other half of this pair. Tearing down here
     * too would let one malformed request cost a desktop its session.
     */
    @Test
    fun aDecryptableButUnparseableFrameLeavesTheSessionAlive(): Unit = runBlocking {
        val initiator = probe.establishSession(device)
        adoptPairing()

        probe.handleApplicationMessage(device, initiator.encrypt("<not json>".toByteArray()))

        assertNotNull("the session must survive a malformed request", probe.noiseSession)
        assertNotNull(probe.connectedDevice)
        assertTrue(probe.pairingConfirmed)

        val probeFrame = request(3, "local.getCapabilities")
        assertArrayEquals(
            "the receive half must still be in step",
            probeFrame,
            probe.noiseSession!!.decrypt(initiator.encrypt(probeFrame))
        )
    }

    // -----------------------------------------------------------------
    // Dispatch without a router
    // -----------------------------------------------------------------

    /**
     * A server built without a [com.automatethethings.xkey.remote.BidirectionalMessageRouter]
     * cannot correlate anything the phone sends, but it must still answer what
     * the desktop asks — it dispatches straight to the handler.
     */
    @Test
    fun aServerWithoutARouterDispatchesDirectly(): Unit = runBlocking {
        val direct = GattServerProbe(
            context,
            pairedDeviceRepository = null,
            withMessageRouter = false
        )
        extraProbes += direct
        direct.establishSession(device)

        val response = direct.interceptOrRoute(request(11, "local.getCapabilities"))

        assertNotNull("a request must still be answered", response)
        val json = JSONObject(String(response!!, Charsets.UTF_8))
        assertEquals(11L, json.getLong("id"))
        assertTrue("the handler must have produced a result", json.has("result"))
    }

    // -----------------------------------------------------------------
    // pairing.confirm, off the happy path
    // -----------------------------------------------------------------

    /** A confirm with no params is not a confirm; it falls through unanswered. */
    @Test
    fun aPairingConfirmWithoutParamsIsIgnored(): Unit = runBlocking {
        probe.establishSession(device)

        val response = outbound.handlePairingConfirmIfNeeded(
            JSONObject()
                .put("id", 1)
                .put("method", "pairing.confirm")
                .toString().toByteArray(Charsets.UTF_8)
        )

        assertNull(response)
        assertFalse(probe.pairingConfirmed)
    }

    /** Params that do not describe a device cannot be acted on either. */
    @Test
    fun aPairingConfirmWithUnreadableParamsIsIgnored(): Unit = runBlocking {
        probe.establishSession(device)

        val response = outbound.handlePairingConfirmIfNeeded(
            JSONObject()
                .put("id", 2)
                .put("method", "pairing.confirm")
                .put("params", JSONObject().put("unrelated", "value"))
                .toString().toByteArray(Charsets.UTF_8)
        )

        assertNull(response)
        assertFalse(probe.pairingConfirmed)
    }

    /** Any other method is left to normal routing. */
    @Test
    fun anotherMethodIsNotTreatedAsAPairingConfirm(): Unit = runBlocking {
        probe.establishSession(device)

        assertNull(outbound.handlePairingConfirmIfNeeded(request(3, "local.listKeys")))
    }

    /**
     * Pairing is granted to the key the Noise transcript authenticated. Without
     * one there is no identity to grant it to, and the request must be refused
     * rather than fall back to what the peer claims.
     */
    @Test
    fun pairingIsRefusedWhenTheTranscriptNamesNobody(): Unit = runBlocking {
        probe.establishSession(device)
        probe.authenticatedPeerKeyHex = null

        val response = outbound.handlePairingConfirmIfNeeded(
            confirmRequest(4, "Anonymous Laptop", "aa".repeat(32))
        )

        assertNotNull(response)
        val json = JSONObject(String(response!!, Charsets.UTF_8))
        assertEquals(ErrorCodes.PAIRING_REJECTED, json.getJSONObject("error").getInt("code"))
        assertFalse(probe.pairingConfirmed)
        assertFalse("nothing was asked of the user", promptShown.get())
    }

    /**
     * A declined pairing does not just return an error: the desktop is
     * disconnected shortly afterwards, so a peer the user refused cannot sit on
     * the connection and retry. The delay exists to let the rejection reach the
     * wire first.
     */
    @Test
    fun aDeclinedPeerIsDisconnectedAfterTheRejectionIsSent(): Unit = runBlocking {
        userApproves.set(false)
        probe.establishSession(device)
        val peerKeyHex = probe.authenticatedPeerKeyHex!!

        val response = outbound.handlePairingConfirmIfNeeded(
            confirmRequest(5, "Refused Laptop", peerKeyHex)
        )

        assertNotNull(response)
        val json = JSONObject(String(response!!, Charsets.UTF_8))
        assertEquals(ErrorCodes.PAIRING_REJECTED, json.getJSONObject("error").getInt("code"))
        assertTrue("the user must have been asked", promptShown.get())

        GattServerProbe.awaitUntil("the refused desktop to be disconnected") {
            probe.connectedDevice == null
        }
        assertNull(probe.noiseSession)
        assertFalse(probe.pairingConfirmed)
        assertFalse(
            "a refused desktop must not be persisted",
            repository.isDeviceKnown(peerKeyHex)
        )
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    /** Accepts a connection and runs the identity exchange for an unknown peer. */
    private suspend fun beginConnection(): NoiseInitiatorSession {
        probe.handleDeviceConnected(device)
        val initiator = NoiseInitiatorSession(randomKey())
        deliver(initiator.createIdentityMessage())
        assertTrue(probe.identityExchangeComplete)
        return initiator
    }

    /**
     * Runs Noise XX with message 3 delivered through `processIncomingData`.
     *
     * Messages 1 and 2 are exchanged against a responder built the same way the
     * server builds one, because the server's own reply to message 1 leaves
     * over the radio and cannot be recovered here. That responder is then
     * installed, so message 3 — the one that completes the handshake and
     * publishes the peer's identity — travels the real path.
     */
    private suspend fun completeHandshakeThroughTheWire(initiator: NoiseInitiatorSession) {
        val responder = NoiseSession().also { it.loadStaticKey(context) }
        val msg2 = responder.processHandshakeMessage(initiator.createHandshakeMessage1())
            ?: throw AssertionError("the responder produced no handshake message 2")
        initiator.processHandshakeMessage2(msg2)
        outbound.noiseSession = responder

        deliver(initiator.createHandshakeMessage3())
        initiator.finalizeHandshake()
    }

    /** Pushes a message through the real fragment path, as the radio would. */
    private suspend fun deliver(message: ByteArray) {
        for (fragment in Fragmenter(20).fragment(message)) {
            probe.processIncomingData(device, fragment)
        }
    }

    /** Confirms the session the way a reconnect from a trusted desktop does. */
    private fun adoptPairing() {
        val peerKeyHex = probe.authenticatedPeerKeyHex!!
        repository.addDevice(peerKeyHex, "BleLoopTest ${peerKeyHex.take(8)}")
        pairedKeys += peerKeyHex
        probe.adoptExistingPairing()
        assertTrue(probe.pairingConfirmed)
    }

    private fun confirmRequest(id: Long, deviceName: String, publicKeyHex: String): ByteArray =
        JSONObject()
            .put("id", id)
            .put("method", "pairing.confirm")
            .put(
                "params",
                JSONObject().put("deviceName", deviceName).put("publicKeyHex", publicKeyHex)
            )
            .toString().toByteArray(Charsets.UTF_8)

    private fun request(id: Long, method: String): ByteArray =
        JSONObject().put("id", id).put("method", method).put("params", JSONObject())
            .toString().toByteArray(Charsets.UTF_8)

    private fun randomKey() = ByteArray(32).also { SecureRandom().nextBytes(it) }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    private companion object {
        const val DEVICE_ADDRESS = "AA:BB:CC:DD:EE:F8"
    }
}
