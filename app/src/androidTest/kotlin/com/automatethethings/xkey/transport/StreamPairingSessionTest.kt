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

package com.automatethethings.xkey.transport

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.auth.SessionAuthManager
import com.automatethethings.xkey.ble.NoiseInitiatorSession
import com.automatethethings.xkey.ble.PairingConfirmationCallback
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.protocol.ErrorCodes
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.remote.BidirectionalMessageRouter
import com.automatethethings.xkey.settings.AttestationBiometricPolicy
import com.automatethethings.xkey.settings.BiometricSettingsData
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.settings.UserVerificationPolicy
import com.automatethethings.xkey.tcp.TcpHsmServer
import com.automatethethings.xkey.tcp.TcpHsmState
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Branch coverage for [StreamPairingSession], the responder shared by the USB
 * and TCP transports, driven over a real socket through [TcpHsmServer].
 *
 * `ProtocolIntegrationTest` and `PairingSecurityTest` drive the happy path with
 * a well-behaved desktop initiator. This suite covers what a well-behaved peer
 * never does, and the two configurations the transports can be constructed in:
 *
 * - the **known-device identity exchange**, where the responder answers
 *   `[0x01|fingerprint(32)]` and both sides re-key the Noise handshake with
 *   `SHA256(initiatorPub || fingerprint || "xkey-v1")` as the prologue. Only
 *   the "new device" arm was reachable before, so the prologue binding — the
 *   thing that makes a reconnect cryptographically tied to the attested
 *   fingerprint — went unexercised.
 * - an initiator that **skips the identity exchange** and opens with Noise msg1.
 * - a frame that **fails to decrypt**. In Noise the receive nonce advances
 *   before authentication, so a failed decrypt is unrecoverable: the session
 *   must be torn down, never continued.
 * - **pre-pairing traffic** that is not a request at all, or a malformed
 *   `pairing.confirm`.
 * - a transport built **without a paired-device repository** (no approval UI,
 *   so nothing to gate on) and **without a message router**.
 *
 * Everything the suite persists is removed in [tearDown]; the server binds
 * loopback on a port unique to this suite.
 */
@RunWith(AndroidJUnit4::class)
class StreamPairingSessionTest {

    private companion object {
        /** Loopback port unique to this suite. */
        const val TEST_PORT = 18601

        /** Loopback port for the ungated (no repository) server. */
        const val UNGATED_PORT = 18602
    }

    private lateinit var context: Context
    private lateinit var pairedDevices: PairedDeviceRepository
    private lateinit var server: TcpHsmServer

    /** Set when the app would have prompted the user to approve a peer. */
    private val promptShown = AtomicBoolean(false)

    /** Peer keys this run registered, removed in [tearDown]. */
    private val registeredPeers = mutableSetOf<String>()

    private var ungatedServer: TcpHsmServer? = null

    @Before
    fun startServer() {
        context = ApplicationProvider.getApplicationContext()
        pairedDevices = PairedDeviceRepository(context)
        promptShown.set(false)
        registeredPeers.clear()

        val handler = headlessHandler(pairedDevices)
        server = TcpHsmServer(
            requestHandler = handler,
            messageRouter = BidirectionalMessageRouter(handler),
            pairingCallback = object : PairingConfirmationCallback {
                override suspend fun onPairingConfirmationRequired(
                    deviceName: String,
                    publicKeyFingerprint: String
                ): Boolean {
                    promptShown.set(true)
                    return true
                }
            },
            pairedDeviceRepository = pairedDevices
        )
        server.start(context, TEST_PORT)
        awaitListening(server)
    }

    @After
    fun tearDown() {
        ungatedServer?.stop()
        ungatedServer = null
        if (::server.isInitialized) server.stop()
        for (peer in registeredPeers) {
            runCatching { pairedDevices.removeDevice(peer) }
        }
    }

    // ------------------------------------------------------------------
    // Identity exchange
    // ------------------------------------------------------------------

    /**
     * Once a device has an attested fingerprint, the responder answers the
     * identity message with `[0x01|fingerprint]` and both sides mix that
     * fingerprint into the Noise prologue. A handshake that completes under
     * that prologue proves the peer agreed on the same fingerprint, so it is
     * the reconnect path the desktop uses after `xkey device attest`.
     */
    @Test
    fun aKnownDeviceWithAFingerprintReHandshakesUnderTheBoundPrologue() {
        val staticKey = randomStaticKey()
        lateinit var peerKeyHex: String

        // First contact: unknown device, plain prologue, user approves.
        RawStreamPeer(TEST_PORT, staticKey).use { first ->
            first.handshake()
            assertFalse("first contact must not be a known device", first.wasRecognised)
            peerKeyHex = first.publicKeyHex
            registeredPeers.add(peerKeyHex)
            assertTrue(first.confirmPairing("Fingerprint Desktop").optBoolean("confirmed"))
        }

        // The user attests the desktop, which records its fingerprint.
        val fingerprint = "ab".repeat(32)
        pairedDevices.updateDeviceAttestation(
            publicKeyHex = peerKeyHex,
            bootHashHex = "00".repeat(32),
            securityLevel = "hardware",
            bootStateVerified = true,
            deviceFingerprint = fingerprint
        )

        // Reconnect: the responder now recognises the key and binds the prologue.
        RawStreamPeer(TEST_PORT, staticKey).use { second ->
            second.handshake()
            assertTrue("a device with a fingerprint must be recognised", second.wasRecognised)
            assertEquals(
                "the responder must echo the stored fingerprint",
                fingerprint,
                second.acknowledgedFingerprintHex
            )
            // The handshake only completes if both sides derived the same
            // prologue from that fingerprint.
            assertNotNull(second.call("local.listKeys", JSONObject()).getJSONArray("keys"))
        }
    }

    /**
     * A fingerprint that is not 32 bytes of hex is not usable as a prologue
     * input, so the responder must fall back to the "new device" answer rather
     * than binding a prologue the initiator cannot reproduce.
     */
    @Test
    fun aMalformedStoredFingerprintFallsBackToTheNewDeviceAnswer() {
        val staticKey = randomStaticKey()
        lateinit var peerKeyHex: String
        RawStreamPeer(TEST_PORT, staticKey).use { first ->
            first.handshake()
            peerKeyHex = first.publicKeyHex
            registeredPeers.add(peerKeyHex)
            first.confirmPairing("Short Fingerprint Desktop")
        }

        pairedDevices.updateDeviceAttestation(
            publicKeyHex = peerKeyHex,
            bootHashHex = "00",
            securityLevel = "software",
            bootStateVerified = false,
            deviceFingerprint = "abcd" // far too short
        )

        RawStreamPeer(TEST_PORT, staticKey).use { second ->
            second.handshake()
            assertFalse(
                "an unusable fingerprint must not be echoed",
                second.wasRecognised
            )
            assertNotNull(second.call("local.listKeys", JSONObject()).getJSONArray("keys"))
        }
    }

    /**
     * go-xkms always performs the identity exchange, but the responder tolerates
     * an initiator that opens straight with Noise msg1 rather than hanging or
     * mis-reading 32 bytes of ephemeral key as an identity message.
     */
    @Test
    fun anInitiatorThatSkipsTheIdentityExchangeStillHandshakes() {
        RawStreamPeer(TEST_PORT, randomStaticKey()).use { peer ->
            peer.handshake(sendIdentity = false)
            registeredPeers.add(peer.publicKeyHex)

            assertTrue(peer.confirmPairing("No Identity Desktop").optBoolean("confirmed"))
            assertNotNull(peer.call("local.listKeys", JSONObject()).getJSONArray("keys"))
        }
    }

    // ------------------------------------------------------------------
    // Message loop
    // ------------------------------------------------------------------

    /**
     * A Noise transport cipherstate advances its receive nonce before the
     * ciphertext is authenticated, so a frame that fails to decrypt has already
     * desynchronised the session. Continuing would silently drop every
     * subsequent message; the session must end instead.
     */
    @Test
    fun aFrameThatFailsToDecryptEndsTheSession() {
        RawStreamPeer(TEST_PORT, randomStaticKey()).use { peer ->
            peer.handshake()
            registeredPeers.add(peer.publicKeyHex)
            peer.confirmPairing("Corrupting Desktop")

            // Well-formed frame, unauthenticatable contents.
            peer.writeRawFrame(ByteArray(64).also { SecureRandom().nextBytes(it) })

            assertThrows(
                "the responder must close the session after a failed decrypt",
                IOException::class.java
            ) { peer.readRawFrame(timeoutMs = 5000) }
        }
    }

    /**
     * A peer disconnecting mid-session is ordinary, not an error: the responder
     * returns to listening and serves the next connection.
     */
    @Test
    fun aPeerDisconnectingLeavesTheServerListening() {
        RawStreamPeer(TEST_PORT, randomStaticKey()).use { peer ->
            peer.handshake()
            registeredPeers.add(peer.publicKeyHex)
            peer.confirmPairing("Transient Desktop")
        }

        awaitListening(server)

        RawStreamPeer(TEST_PORT, randomStaticKey()).use { next ->
            next.handshake()
            registeredPeers.add(next.publicKeyHex)
            assertTrue(next.confirmPairing("Second Desktop").optBoolean("confirmed"))
        }
    }

    // ------------------------------------------------------------------
    // Pre-pairing traffic
    // ------------------------------------------------------------------

    /**
     * Only requests are refused before pairing. A frame that is not JSON at all
     * carries no method, so there is nobody to answer — it is dropped, and the
     * session stays usable.
     */
    @Test
    fun anUnparseablePrePairingFrameIsDroppedWithoutAReply() {
        RawStreamPeer(TEST_PORT, randomStaticKey()).use { peer ->
            peer.handshake()
            registeredPeers.add(peer.publicKeyHex)

            peer.sendEncrypted("this is not JSON".toByteArray(Charsets.UTF_8))
            assertNull("a dropped frame must not be answered", peer.pollFrame())

            // The session survives it.
            assertTrue(peer.confirmPairing("Noisy Desktop").optBoolean("confirmed"))
        }
    }

    /**
     * An inbound *response* (no `method`) belongs to the router, not to the
     * pairing gate, so it must not be answered with PAIRING_REQUIRED.
     */
    @Test
    fun aPrePairingResponseFrameIsNotRefused() {
        RawStreamPeer(TEST_PORT, randomStaticKey()).use { peer ->
            peer.handshake()
            registeredPeers.add(peer.publicKeyHex)

            peer.sendEncrypted(
                JSONObject().put("id", 99).put("result", JSONObject()).toString()
                    .toByteArray(Charsets.UTF_8)
            )
            assertNull("a response frame must not be answered", peer.pollFrame())

            assertTrue(peer.confirmPairing("Router Desktop").optBoolean("confirmed"))
        }
    }

    /**
     * `pairing.confirm` without params, or without the `publicKeyHex` the
     * responder cross-checks against the Noise transcript, cannot be honoured.
     * It falls through to the pairing gate rather than pairing anything.
     */
    @Test
    fun aMalformedPairingConfirmLeavesTheSessionUnpaired() {
        RawStreamPeer(TEST_PORT, randomStaticKey()).use { peer ->
            peer.handshake()
            registeredPeers.add(peer.publicKeyHex)

            val noParams = peer.callExpectingError("pairing.confirm", null)
            assertNotNull("pairing.confirm without params must not pair", noParams)
            assertEquals(ErrorCodes.PAIRING_REQUIRED, noParams!!.getInt("code"))

            val noKey = peer.callExpectingError(
                "pairing.confirm",
                JSONObject().put("deviceName", "Malformed Desktop")
            )
            assertNotNull("pairing.confirm without publicKeyHex must not pair", noKey)
            assertEquals(ErrorCodes.PAIRING_REQUIRED, noKey!!.getInt("code"))

            assertFalse("no prompt should have been shown", promptShown.get())
            assertFalse(pairedDevices.isDeviceKnown(peer.publicKeyHex))
        }
    }

    // ------------------------------------------------------------------
    // Transport configuration
    // ------------------------------------------------------------------

    /**
     * A transport with no paired-device repository has no notion of approval —
     * there is no store to record it in and no UI to ask. It cannot gate on
     * something it cannot express, so it routes directly to the request handler.
     * This is also the only configuration in which the router-less path runs.
     */
    @Test
    fun aTransportWithoutAPairedDeviceStoreCannotGateOnPairing() {
        val ungated = TcpHsmServer(requestHandler = headlessHandler(null))
        ungatedServer = ungated
        ungated.start(context, UNGATED_PORT)
        awaitListening(ungated)

        RawStreamPeer(UNGATED_PORT, randomStaticKey()).use { peer ->
            peer.handshake()
            // No pairing.confirm at all.
            assertNotNull(peer.call("local.listKeys", JSONObject()).getJSONArray("keys"))
            assertTrue(peer.call("ping").optBoolean("pong"))
        }
    }

    // ------------------------------------------------------------------
    // Outbound sends
    // ------------------------------------------------------------------

    /**
     * The transport is the [com.automatethethings.xkey.remote.MessageSender] the
     * outbound `remote.*` clients write through, so a phone-initiated request
     * must reach the connected desktop on the same encrypted session.
     */
    @Test
    fun aPhoneInitiatedRequestReachesTheConnectedPeer() {
        RawStreamPeer(TEST_PORT, randomStaticKey()).use { peer ->
            peer.handshake()
            registeredPeers.add(peer.publicKeyHex)
            peer.confirmPairing("Sync Desktop")

            val outbound = JSONObject()
                .put("id", 4242)
                .put("method", "remote.listBackends")
                .put("params", JSONObject())
            runBlocking {
                server.sendEncryptedMessage(outbound.toString().toByteArray(Charsets.UTF_8))
            }

            val received = peer.readFrame()
            assertEquals("remote.listBackends", received.getString("method"))
            assertEquals(4242L, received.getLong("id"))
        }
    }

    // ------------------------------------------------------------------
    // Fixtures
    // ------------------------------------------------------------------

    /** A handler with no UI attached, so no biometric prompt is reachable. */
    private fun headlessHandler(repository: PairedDeviceRepository?): RequestHandler =
        RequestHandler(
            context = context,
            keystoreManager = KeystoreManager(context),
            biometricLauncher = null,
            sessionAuthManager = SessionAuthManager(),
            pairedDeviceRepository = repository
        ).apply {
            updateSettings(
                BiometricSettingsData(
                    uvPolicy = UserVerificationPolicy.DISABLED,
                    attestationBiometricPolicy = AttestationBiometricPolicy.NEVER
                )
            )
        }

    private fun randomStaticKey(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }

    private fun awaitListening(target: TcpHsmServer) {
        runBlocking { withTimeout(5000) { target.state.first { it is TcpHsmState.Listening } } }
    }
}

/**
 * A desktop initiator with the framing left exposed, so a test can send frames
 * a conformant peer never would: no identity message, undecryptable ciphertext,
 * a bare response, a malformed `pairing.confirm`.
 *
 * `ProtocolTestClient` deliberately hides all of that behind a request/response
 * API; this peer is its lower-level sibling and lives only in this suite.
 */
private class RawStreamPeer(
    private val port: Int,
    staticKey: ByteArray
) : AutoCloseable {

    private val noise = NoiseInitiatorSession(staticKey)
    private lateinit var socket: Socket
    private lateinit var input: InputStream
    private lateinit var output: OutputStream
    private val nextId = AtomicLong(1)

    /** Hex of this peer's static public key, valid after [handshake]. */
    lateinit var publicKeyHex: String
        private set

    /** True when the responder answered the identity message with `[0x01|fp]`. */
    var wasRecognised: Boolean = false
        private set

    /** The fingerprint the responder echoed, or null for a new device. */
    var acknowledgedFingerprintHex: String? = null
        private set

    /**
     * Connects and completes the Noise XX handshake.
     *
     * @param sendIdentity false opens straight with msg1, as an initiator that
     *        does not implement the identity exchange would.
     */
    fun handshake(sendIdentity: Boolean = true, timeoutMs: Long = 5000) {
        val deadline = System.currentTimeMillis() + timeoutMs
        var lastError: IOException? = null
        while (System.currentTimeMillis() < deadline) {
            try {
                socket = Socket()
                socket.tcpNoDelay = true
                socket.connect(InetSocketAddress(InetAddress.getLoopbackAddress(), port), 1000)
                lastError = null
                break
            } catch (e: IOException) {
                lastError = e
                Thread.sleep(100)
            }
        }
        lastError?.let { throw it }

        input = socket.getInputStream()
        output = socket.getOutputStream()

        val identity = noise.createIdentityMessage()
        publicKeyHex = identity.copyOfRange(1, identity.size).toHex()

        if (sendIdentity) {
            StreamMessageFraming.writeMessage(output, identity)
            val ack = StreamMessageFraming.readMessage(input)
            wasRecognised = ack.isNotEmpty() && ack[0] == 0x01.toByte() && ack.size >= 33
            if (wasRecognised) {
                acknowledgedFingerprintHex = ack.copyOfRange(1, ack.size).toHex()
            }
            noise.processIdentityAck(ack)
        }

        StreamMessageFraming.writeMessage(output, noise.createHandshakeMessage1())
        noise.processHandshakeMessage2(StreamMessageFraming.readMessage(input))
        StreamMessageFraming.writeMessage(output, noise.createHandshakeMessage3())
        noise.finalizeHandshake()
        check(noise.isHandshakeComplete()) { "Noise handshake did not complete" }
    }

    fun confirmPairing(deviceName: String): JSONObject = call(
        "pairing.confirm",
        JSONObject().put("deviceName", deviceName).put("publicKeyHex", publicKeyHex)
    )

    /** Sends a request and returns its `result`, failing on an error response. */
    fun call(method: String, params: JSONObject? = null): JSONObject {
        val response = request(method, params)
        response.optJSONObject("error")?.let {
            throw IOException("$method failed: [${it.optInt("code")}] ${it.optString("message")}")
        }
        return response.getJSONObject("result")
    }

    /** Sends a request and returns its `error` object, or null on success. */
    fun callExpectingError(method: String, params: JSONObject?): JSONObject? =
        request(method, params).optJSONObject("error")

    private fun request(method: String, params: JSONObject?): JSONObject {
        val id = nextId.getAndIncrement()
        val body = JSONObject().apply {
            put("id", id)
            put("method", method)
            if (params != null) put("params", params)
        }
        sendEncrypted(body.toString().toByteArray(Charsets.UTF_8))

        while (true) {
            val frame = readFrame()
            if (frame.has("method")) continue
            if (frame.optLong("id", -1) != id) continue
            return frame
        }
    }

    /** Encrypts [plaintext] onto the session and frames it. */
    fun sendEncrypted(plaintext: ByteArray) {
        StreamMessageFraming.writeMessage(output, noise.encrypt(plaintext))
    }

    /** Writes [data] as a frame with no encryption, producing an undecryptable frame. */
    fun writeRawFrame(data: ByteArray) {
        StreamMessageFraming.writeMessage(output, data)
    }

    /** Reads and decrypts the next frame. */
    fun readFrame(): JSONObject =
        JSONObject(String(noise.decrypt(StreamMessageFraming.readMessage(input)), Charsets.UTF_8))

    /**
     * Reads the next frame without decrypting it, bounded by [timeoutMs] so a
     * responder that wrongly keeps the session open fails the test instead of
     * hanging it.
     */
    fun readRawFrame(timeoutMs: Int = 0): ByteArray {
        val previous = socket.soTimeout
        socket.soTimeout = timeoutMs
        return try {
            StreamMessageFraming.readMessage(input)
        } finally {
            runCatching { socket.soTimeout = previous }
        }
    }

    /**
     * Reads the next frame if one arrives within [timeoutMs], else null. Used to
     * assert that a message was *not* answered.
     */
    fun pollFrame(timeoutMs: Int = 750): JSONObject? {
        val previous = socket.soTimeout
        socket.soTimeout = timeoutMs
        return try {
            readFrame()
        } catch (e: IOException) {
            null
        } finally {
            runCatching { socket.soTimeout = previous }
        }
    }

    override fun close() {
        runCatching { socket.close() }
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}
