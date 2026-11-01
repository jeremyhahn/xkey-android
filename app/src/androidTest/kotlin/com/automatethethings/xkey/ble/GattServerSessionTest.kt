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
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
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
 * The connection lifecycle a desktop actually walks through [GattServer]:
 * connect, the pre-handshake identity exchange, the encrypted message loop, and
 * disconnect.
 *
 * The identity exchange is the piece with the most to get wrong and the least
 * to notice: it decides the Noise *prologue*, and a prologue mismatch surfaces
 * only as an unexplained handshake failure with a previously paired laptop.
 * These tests prove the binding rather than assert on its inputs — the
 * responder the server prepared is driven to completion by an initiator that
 * derived the prologue independently, so any divergence fails the handshake.
 *
 * The server's own replies are unreachable without a radio (see
 * [GattServerProbe]), so wherever a reply is needed the peer side is driven
 * against the server's session object directly.
 */
@RunWith(AndroidJUnit4::class)
class GattServerSessionTest {

    /** `handleDeviceConnected` reads `BluetoothDevice.getName()`. */
    @get:Rule
    val bluetoothPermission: GrantPermissionRule =
        GrantPermissionRule.grant(Manifest.permission.BLUETOOTH_CONNECT)

    private lateinit var context: Context
    private lateinit var repository: PairedDeviceRepository
    private lateinit var probe: GattServerProbe
    private lateinit var device: BluetoothDevice

    /** Keys registered in the paired-device store; removed in teardown. */
    private val pairedKeys = mutableListOf<String>()

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        val remote = GattServerProbe.remoteDevice(context)
        assumeTrue("this device has no Bluetooth adapter", remote != null)
        device = remote!!
        repository = PairedDeviceRepository(context)
        probe = GattServerProbe(context, pairedDeviceRepository = repository)
    }

    @After
    fun tearDown() {
        if (::probe.isInitialized) probe.close()
        pairedKeys.forEach { repository.removeDevice(it) }
        pairedKeys.clear()
    }

    // -----------------------------------------------------------------
    // Connection bookkeeping
    // -----------------------------------------------------------------

    /** A connect prepares everything the session needs before the first byte. */
    @Test
    fun connectingPreparesTheSessionState(): Unit = runBlocking {
        probe.handleDeviceConnected(device)

        assertSame(device, probe.connectedDevice)
        assertNotNull("a Noise responder is created up front", probe.noiseSession)
        assertNotNull("each device gets its own reassembler", probe.fragmentBuffer[device.address])
        assertEquals("the BLE minimum until the MTU is negotiated", 23, probe.deviceMtu[device.address])
        assertFalse("a fresh connection starts unpaired", probe.pairingConfirmed)
        assertFalse(probe.identityExchangeComplete)
        assertNull(probe.authenticatedPeerKeyHex)
        assertEquals(ConnectionState.Connecting, probe.server.connectionState.value)
    }

    /**
     * The server serves one desktop at a time. A second connection must not
     * steal the session out from under the first.
     */
    @Test
    fun aSecondDeviceIsRefusedWhileOneIsConnected(): Unit = runBlocking {
        val other = GattServerProbe.remoteDevice(context, "AA:BB:CC:DD:EE:F1")!!

        probe.handleDeviceConnected(device)
        val session = probe.noiseSession
        probe.handleDeviceConnected(other)

        assertSame("the first device keeps the session", device, probe.connectedDevice)
        assertSame(session, probe.noiseSession)
    }

    /** A disconnect for some other device must not tear down the live one. */
    @Test
    fun aDisconnectForAnotherDeviceIsIgnored(): Unit = runBlocking {
        val other = GattServerProbe.remoteDevice(context, "AA:BB:CC:DD:EE:F2")!!

        probe.handleDeviceConnected(device)
        probe.handleDeviceDisconnected(other)

        assertSame(device, probe.connectedDevice)
        assertNotNull(probe.noiseSession)
    }

    /** Disconnecting must leave nothing behind for the next desktop to inherit. */
    @Test
    fun disconnectingClearsEveryPieceOfSessionState(): Unit = runBlocking {
        probe.handleDeviceConnected(device)
        probe.establishSession(device)

        probe.handleDeviceDisconnected(device)

        assertNull(probe.connectedDevice)
        assertNull(probe.noiseSession)
        assertNull("the authenticated identity must not survive", probe.authenticatedPeerKeyHex)
        assertNull(probe.remotePublicKeyHex)
        assertFalse(probe.identityExchangeComplete)
        assertFalse(probe.pairingConfirmed)
        assertTrue(probe.fragmentBuffer.isEmpty())
        assertTrue(probe.deviceMtu.isEmpty())
        assertEquals(ConnectionState.Disconnected, probe.server.connectionState.value)
    }

    // -----------------------------------------------------------------
    // The pre-handshake identity exchange
    // -----------------------------------------------------------------

    /** An unknown desktop is recorded but not bound to any fingerprint. */
    @Test
    fun anUnknownDeviceCompletesTheIdentityExchangeUnbound(): Unit = runBlocking {
        probe.handleDeviceConnected(device)
        val initiator = NoiseInitiatorSession(randomKey())

        deliver(initiator.createIdentityMessage())

        assertTrue(probe.identityExchangeComplete)
        assertEquals(initiator.getLocalStaticPublicKey().toHex(), probe.remotePublicKeyHex)

        // No prologue was set, so an unbound initiator must still complete.
        completeHandshake(initiator)
        assertArrayEquals(
            initiator.getLocalStaticPublicKey(),
            probe.noiseSession!!.getRemoteStaticKey()
        )
    }

    /**
     * The property the whole identity exchange exists for: a desktop the user
     * already paired is bound to the phone's attestation fingerprint, so a peer
     * holding only the desktop's key cannot complete the handshake without also
     * knowing the fingerprint the two sides agreed on.
     */
    @Test
    fun aKnownDeviceIsBoundToItsStoredFingerprint(): Unit = runBlocking {
        val initiator = NoiseInitiatorSession(randomKey())
        val publicKeyHex = initiator.getLocalStaticPublicKey().toHex()
        val fingerprint = randomKey()
        registerPairedDevice(publicKeyHex, fingerprint.toHex())

        probe.handleDeviceConnected(device)
        deliver(initiator.createIdentityMessage())

        assertTrue(probe.identityExchangeComplete)

        // The desktop learns the fingerprint from the acknowledgement; here it
        // is handed the same value the phone stored.
        initiator.processIdentityAck(byteArrayOf(0x01) + fingerprint)
        completeHandshake(initiator)

        assertArrayEquals(
            initiator.getLocalStaticPublicKey(),
            probe.noiseSession!!.getRemoteStaticKey()
        )
    }

    /** And the binding is real: the wrong fingerprint cannot complete it. */
    @Test
    fun aPeerWithTheWrongFingerprintCannotCompleteTheHandshake(): Unit = runBlocking {
        val initiator = NoiseInitiatorSession(randomKey())
        registerPairedDevice(initiator.getLocalStaticPublicKey().toHex(), randomKey().toHex())

        probe.handleDeviceConnected(device)
        deliver(initiator.createIdentityMessage())

        initiator.processIdentityAck(byteArrayOf(0x01) + randomKey())
        try {
            completeHandshake(initiator)
            fail("a peer that does not know the fingerprint must not authenticate")
        } catch (expected: Exception) {
            assertFalse(probe.noiseSession!!.isHandshakeComplete())
        }
    }

    /**
     * A device paired before attestation ran has no fingerprint to bind to.
     * It must fall back to the unbound handshake rather than binding to null.
     */
    @Test
    fun aKnownDeviceWithoutAFingerprintFallsBackToAnUnboundHandshake(): Unit = runBlocking {
        val initiator = NoiseInitiatorSession(randomKey())
        val publicKeyHex = initiator.getLocalStaticPublicKey().toHex()
        repository.addDevice(publicKeyHex, "Fingerprintless ${randomKey().toHex().take(8)}")
        pairedKeys += publicKeyHex

        probe.handleDeviceConnected(device)
        deliver(initiator.createIdentityMessage())

        assertTrue(probe.identityExchangeComplete)
        completeHandshake(initiator)
    }

    /**
     * Backwards compatibility: a desktop that opens with a Noise message rather
     * than an identity frame is still served — the frame is not 33 bytes, so it
     * falls through to the handshake.
     */
    @Test
    fun aPeerThatSkipsTheIdentityFrameFallsThroughToTheHandshake(): Unit = runBlocking {
        probe.handleDeviceConnected(device)
        val initiator = NoiseInitiatorSession(randomKey())

        deliver(initiator.createHandshakeMessage1())

        assertTrue("the exchange is marked done so the next frame routes correctly", probe.identityExchangeComplete)
        assertNull("no key was announced", probe.remotePublicKeyHex)
        assertFalse("msg1 alone does not complete a handshake", probe.noiseSession!!.isHandshakeComplete())
    }

    /**
     * An identity frame of the right length but an unknown version is not
     * something this protocol can interpret. It falls through to the handshake,
     * where 33 bytes is not a valid Noise message, and the connection is torn
     * down instead of being left half-open.
     */
    @Test
    fun anUnknownIdentityVersionTearsTheConnectionDown(): Unit = runBlocking {
        probe.handleDeviceConnected(device)

        deliver(byteArrayOf(0x02) + randomKey())

        assertNull("a frame this server cannot parse must not leave a live session", probe.connectedDevice)
        assertEquals(ConnectionState.Disconnected, probe.server.connectionState.value)
    }

    // -----------------------------------------------------------------
    // The encrypted message loop
    // -----------------------------------------------------------------

    /**
     * A frame that fails to decrypt must take the session down.
     *
     * Noise treats a failed decryption as fatal, and the implementation makes it
     * so: `decrypt` advances the receive nonce before authenticating, so once one
     * frame fails, every later frame is offset by one and fails too. Answering
     * with an error and staying connected therefore leaves a session that looks
     * alive but can never process another message — a worse and quieter denial of
     * service than dropping the connection and letting the peer re-handshake.
     */
    @Test
    fun anUndecryptableFrameTearsTheSessionDown(): Unit = runBlocking {
        probe.establishSession(device)
        adoptPairing()

        probe.handleApplicationMessage(device, randomKey() + randomKey())

        assertNull(probe.connectedDevice)
        assertNull(probe.noiseSession)
        assertFalse(probe.pairingConfirmed)
    }

    /** With no session there is nothing to decrypt, and nothing may throw. */
    @Test
    fun applicationMessagesWithoutASessionAreDropped(): Unit = runBlocking {
        probe.establishSession(device)
        probe.handleDeviceDisconnected(device)

        probe.handleApplicationMessage(device, randomKey())
    }

    // -----------------------------------------------------------------
    // The pairing gate around the message loop
    // -----------------------------------------------------------------

    /**
     * A reconnect from a desktop the user already approved must not re-prompt,
     * but approval still comes from the store — never from the peer.
     */
    @Test
    fun anAlreadyTrustedPeerIsAdoptedWithoutAPrompt(): Unit = runBlocking {
        probe.establishSession(device)
        val peerKeyHex = probe.authenticatedPeerKeyHex!!

        probe.adoptExistingPairing()
        assertFalse("an unknown peer must stay gated", probe.pairingConfirmed)

        registerPairedDevice(peerKeyHex, null)
        probe.adoptExistingPairing()
        assertTrue("a stored peer needs no second approval", probe.pairingConfirmed)
    }

    /** Adoption cannot happen at all before the transcript names a peer. */
    @Test
    fun adoptionIsImpossibleWithoutAnAuthenticatedPeer() {
        probe.authenticatedPeerKeyHex = null

        probe.adoptExistingPairing()

        assertFalse(probe.pairingConfirmed)
    }

    /** Requests from an unpaired peer are refused with the pairing error code. */
    @Test
    fun unpairedRequestsAreRefusedWithTheDocumentedCode() {
        val refusal = probe.rejectUnpaired(request(7, "local.sign"))

        assertNotNull(refusal)
        val json = JSONObject(String(refusal!!, Charsets.UTF_8))
        assertEquals(7L, json.getLong("id"))
        assertEquals(ErrorCodes.PAIRING_REQUIRED, json.getJSONObject("error").getInt("code"))
    }

    /**
     * A *response* to one of the phone's own outbound requests carries no
     * method and must not be answered — replying to it would put a stray error
     * frame into the correlation stream.
     */
    @Test
    fun repliesToOurOwnRequestsAreNotRefused() {
        val response = """{"id":42,"result":{"ok":true}}""".toByteArray()

        assertNull(probe.rejectUnpaired(response))
    }

    /** Anything unparseable is dropped silently rather than echoed back. */
    @Test
    fun unparseableFramesAreDroppedSilently() {
        assertNull(probe.rejectUnpaired("not json at all".toByteArray()))
        assertNull(probe.rejectUnpaired(ByteArray(0)))
    }

    /**
     * A server built without a paired-device store has no notion of approval,
     * so it cannot gate on one. This is the posture a transport with its own
     * out-of-band trust would use, and it must route rather than refuse.
     */
    @Test
    fun aServerWithoutAPairedDeviceStoreRoutesWithoutGating(): Unit = runBlocking {
        val ungated = GattServerProbe(context, pairedDeviceRepository = null)
        try {
            ungated.establishSession(device)

            val response = ungated.interceptOrRoute(request(1, "local.getCapabilities"))

            assertNotNull("an ungated server must answer", response)
            val json = JSONObject(String(response!!, Charsets.UTF_8))
            assertFalse(
                "the pairing gate cannot apply without a device store",
                json.has("error") &&
                    json.getJSONObject("error").getInt("code") == ErrorCodes.PAIRING_REQUIRED
            )
        } finally {
            ungated.close()
        }
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    /** Pushes a message through the real fragment path, as the radio would. */
    private suspend fun deliver(message: ByteArray) {
        for (fragment in Fragmenter(20).fragment(message)) {
            probe.processIncomingData(device, fragment)
        }
    }

    /** Drives Noise XX against the responder the server prepared. */
    private suspend fun completeHandshake(initiator: NoiseInitiatorSession) {
        val session = probe.noiseSession ?: throw AssertionError("the server has no responder")
        val msg2 = session.processHandshakeMessage(initiator.createHandshakeMessage1())
            ?: throw AssertionError("the responder produced no msg2")
        initiator.processHandshakeMessage2(msg2)
        assertNull(session.processHandshakeMessage(initiator.createHandshakeMessage3()))
        initiator.finalizeHandshake()
    }

    /** Confirms the session the way a reconnect from a trusted desktop does. */
    private fun adoptPairing() {
        registerPairedDevice(probe.authenticatedPeerKeyHex!!, null)
        probe.adoptExistingPairing()
        assertTrue("the peer must be adopted before the gate opens", probe.pairingConfirmed)
    }

    private fun registerPairedDevice(publicKeyHex: String, fingerprintHex: String?) {
        repository.addDevice(publicKeyHex, "BleSessionTest ${publicKeyHex.take(8)}")
        pairedKeys += publicKeyHex
        if (fingerprintHex != null) {
            repository.updateDeviceAttestation(
                publicKeyHex = publicKeyHex,
                bootHashHex = "00".repeat(32),
                securityLevel = "tee",
                bootStateVerified = true,
                deviceFingerprint = fingerprintHex
            )
        }
    }

    private fun request(id: Long, method: String): ByteArray =
        JSONObject().put("id", id).put("method", method).put("params", JSONObject())
            .toString().toByteArray(Charsets.UTF_8)

    private fun randomKey() = ByteArray(32).also { SecureRandom().nextBytes(it) }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}
