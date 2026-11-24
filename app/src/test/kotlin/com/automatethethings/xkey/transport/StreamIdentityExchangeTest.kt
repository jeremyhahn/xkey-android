/*
 * Copyright (c) 2025 Jeremy Hahn
 * Copyright (c) 2025 Automate The Things, LLC
 *
 * This file is part of xKey.
 *
 * xKey is dual-licensed:
 *
 * 1. GNU Affero General Public License v3.0 (AGPL-3.0)
 *    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
 *
 * 2. Commercial License
 *    Contact licensing@automatethethings.com for commercial licensing options.
 */

package com.automatethethings.xkey.transport

import android.content.Context
import android.util.Log
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.ble.NoiseException
import com.automatethethings.xkey.ble.NoiseInitiatorSession
import com.automatethethings.xkey.ble.NoiseSession
import com.automatethethings.xkey.ble.NoiseTestKeyStore
import com.automatethethings.xkey.protocol.ErrorCodes
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.settings.InMemorySharedPreferences
import com.automatethethings.xkey.settings.PairedDeviceRepository
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.runs
import io.mockk.unmockkAll
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.withTimeout
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The pre-handshake identity exchange of a [StreamPairingSession], over a
 * loopback socket against [DesktopPeer]: the ack the phone answers each
 * first frame with, the prologue a known device's handshake is bound to, and
 * that the key a desktop CLAIMS in the identity message never stands in for
 * the key its handshake AUTHENTICATES.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class StreamIdentityExchangeTest {

    private companion object {
        const val TIMEOUT_MS = 10_000L
        val FINGERPRINT = "c0ffee42".repeat(8)
        val FINGERPRINT_BYTES = ByteArray(32) { i -> FINGERPRINT.substring(i * 2, i * 2 + 2).toInt(16).toByte() }

        fun prologue(publicKey: ByteArray, fingerprint: ByteArray): ByteArray =
            MessageDigest.getInstance("SHA-256").run {
                update(publicKey)
                update(fingerprint)
                update("xkey-v1".toByteArray(Charsets.UTF_8))
                digest()
            }

        fun randomKey(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }

        fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }
    }

    private lateinit var context: Context
    private lateinit var repo: PairedDeviceRepository
    private lateinit var requestHandler: RequestHandler
    private lateinit var pairing: StreamPairingSession
    private lateinit var mainThread: ExecutorService
    private lateinit var listener: ServerSocket
    private val connections = ServedConnections()

    @Before
    fun setUp() {
        NoiseTestKeyStore.install()
        mockkStatic(Log::class)
        every { Log.v(any(), any<String>()) } returns 0
        every { Log.d(any(), any<String>()) } returns 0
        every { Log.i(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.e(any(), any<String>()) } returns 0
        every { Log.d(any(), any<String>(), any()) } returns 0
        every { Log.i(any(), any<String>(), any()) } returns 0
        every { Log.w(any(), any<String>(), any()) } returns 0
        every { Log.e(any(), any<String>(), any()) } returns 0
        mockkObject(AuditLogger)
        every { AuditLogger.logDeviceUnpaired(any(), any()) } just runs
        mainThread = Executors.newSingleThreadExecutor()
        Dispatchers.setMain(mainThread.asCoroutineDispatcher())

        context = mockk(relaxed = true)
        repo = PairedDeviceRepository(InMemorySharedPreferences())
        requestHandler = mockk(relaxed = true)
        coEvery { requestHandler.handleRawRequest(any<ByteArray>()) } answers {
            val id = JSONObject(String(firstArg<ByteArray>())).optLong("id")
            """{"jsonrpc":"2.0","id":$id,"result":{"ok":true}}""".toByteArray()
        }
        pairing = StreamPairingSession(
            requestHandler = requestHandler,
            messageRouter = null,
            pairingCallback = null,
            pairedDeviceRepository = repo,
            transportLabel = "TEST",
        )
        listener = ServerSocket(0, 4, InetAddress.getLoopbackAddress())
    }

    @After
    fun tearDown() {
        connections.end()
        listener.close()
        Dispatchers.resetMain()
        mainThread.shutdownNow()
        unmockkAll()
    }

    // ---------------------------------------------------------------------
    // Known device: fingerprint ack and prologue binding
    // ---------------------------------------------------------------------

    /**
     * A paired desktop with a stored 64-hex fingerprint is answered
     * `0x01 | fingerprint`, and both ends hold the prologue
     * SHA256(key || fingerprint || "xkey-v1"): the handshake completes, the
     * session is confirmed for that key, and a request reaches the handler.
     */
    @Test
    fun aKnownDesktopGetsItsFingerprintAndTheHandshakeIsBoundToIt() = runBlocking {
        val desktop = newDesktop()
        repo.addDevice(desktop.publicKeyHex, "desktop")
        repo.updateDeviceFingerprint(desktop.publicKeyHex, FINGERPRINT)
        val phone = serve()

        desktop.send(desktop.noise.createIdentityMessage())
        val ack = desktop.read()
        assertArrayEquals("known-device ack", byteArrayOf(0x01) + FINGERPRINT_BYTES, ack)
        desktop.noise.processIdentityAck(ack)
        desktop.sendMsg1AndReadMsg2()
        desktop.sendMsg3()
        withTimeout(TIMEOUT_MS) { phone.connected.await() }

        val expected = prologue(desktop.noise.getLocalStaticPublicKey(), FINGERPRINT_BYTES)
        assertArrayEquals("phone prologue", expected, phone.noise.getPrologue())
        assertArrayEquals("desktop prologue", expected, desktop.noise.getPrologue())
        assertEquals(desktop.publicKeyHex, pairing.confirmedPeerKeyHex())
        val reply = desktop.request("local.getCapabilities", id = 4)
        assertEquals(4L, reply.getLong("id"))
        assertTrue(reply.getJSONObject("result").getBoolean("ok"))
    }

    /**
     * A desktop that receives the known-device ack but handshakes with an
     * empty prologue cannot read msg2: the transcripts differ. The phone
     * never installs the session, so it is never confirmed.
     */
    @Test
    fun aDesktopThatIgnoresTheKnownAckFailsTheHandshake() = runBlocking {
        val desktop = newDesktop()
        repo.addDevice(desktop.publicKeyHex, "desktop")
        repo.updateDeviceFingerprint(desktop.publicKeyHex, FINGERPRINT)
        val phone = serve()

        desktop.send(desktop.noise.createIdentityMessage())
        assertEquals(0x01.toByte(), desktop.read()[0])
        desktop.send(desktop.noise.createHandshakeMessage1())
        val msg2 = desktop.read()
        val failure = runCatching { desktop.noise.processHandshakeMessage2(msg2) }.exceptionOrNull()
        assertNotNull("msg2 under another prologue must not verify", failure)
        desktop.close()

        assertNotNull("serve must end with the handshake failure", phone.awaitServeEnded())
        assertFalse("never connected", phone.connected.isCompleted)
        assertNull(pairing.confirmedPeerKeyHex())
        assertNull(pairing.confirmedConnection())
        coVerify(exactly = 0) { requestHandler.handleRawRequest(any<ByteArray>()) }
    }

    // ---------------------------------------------------------------------
    // Unknown-device ack
    // ---------------------------------------------------------------------

    /** A key the store does not know gets the single byte `0x00`; the session stays gated. */
    @Test
    fun anUnknownKeyGetsTheUnknownAck() = runBlocking {
        val desktop = newDesktop()
        val phone = serve()

        desktop.send(desktop.noise.createIdentityMessage())
        assertArrayEquals(byteArrayOf(0x00), desktop.read())
        desktop.sendMsg1AndReadMsg2()
        desktop.sendMsg3()
        withTimeout(TIMEOUT_MS) { phone.connected.await() }

        assertArrayEquals("empty prologue", ByteArray(0), phone.noise.getPrologue())
        assertEquals(desktop.publicKeyHex, pairing.connectedPeerKeyHex)
        assertNull(pairing.confirmedPeerKeyHex())
    }

    /** A paired desktop with no stored fingerprint gets `0x00` and is still confirmed by its key. */
    @Test
    fun aPairedDesktopWithoutAFingerprintGetsTheUnknownAckAndIsConfirmed() = runBlocking {
        val desktop = newDesktop()
        repo.addDevice(desktop.publicKeyHex, "desktop")
        val phone = serve()

        desktop.handshake() // asserts the ack is [0x00]
        withTimeout(TIMEOUT_MS) { phone.connected.await() }

        assertEquals(desktop.publicKeyHex, pairing.confirmedPeerKeyHex())
    }

    /** A stored fingerprint one byte short is not a fingerprint: `0x00`, empty prologue. */
    @Test
    fun aShortFingerprintGetsTheUnknownAck() = runBlocking {
        assertUnknownAckFor("cd".repeat(31))
    }

    /** A stored fingerprint one byte long is not a fingerprint either. */
    @Test
    fun aLongFingerprintGetsTheUnknownAck() = runBlocking {
        assertUnknownAckFor("cd".repeat(33))
    }

    // ---------------------------------------------------------------------
    // First frames that are not identity messages
    // ---------------------------------------------------------------------

    /**
     * 33 bytes with version `0x02` is not an identity message: it is taken
     * as msg1, which is 32 bytes, so the handshake fails and the connection
     * closes with no ack written.
     */
    @Test
    fun aVersion2IdentityMessageIsTakenAsMsg1AndGetsNoAck() = runBlocking {
        val desktop = newDesktop()
        repo.addDevice(desktop.publicKeyHex, "desktop")
        val phone = serve()

        desktop.send(byteArrayOf(0x02) + desktop.noise.getLocalStaticPublicKey())

        desktop.assertClosedByPhone()
        assertTrue(phone.awaitServeEnded() is NoiseException)
        assertFalse(phone.connected.isCompleted)
    }

    /** 34 bytes is not an identity message: no ack, the handshake fails. */
    @Test
    fun a34ByteFirstFrameIsTakenAsMsg1AndGetsNoAck() = runBlocking {
        val desktop = newDesktop()
        repo.addDevice(desktop.publicKeyHex, "desktop")
        val phone = serve()

        desktop.send(desktop.noise.createIdentityMessage() + byteArrayOf(0x00))

        desktop.assertClosedByPhone()
        assertTrue(phone.awaitServeEnded() is NoiseException)
        assertFalse(phone.connected.isCompleted)
    }

    /**
     * A 32-byte first frame is msg1 itself: the phone answers msg2 (not a
     * one-byte ack) and a desktop that skips the identity exchange still
     * completes the handshake, with an empty prologue.
     */
    @Test
    fun a32ByteFirstFrameIsMsg1() = runBlocking {
        val desktop = newDesktop()
        repo.addDevice(desktop.publicKeyHex, "desktop")
        val phone = serve()

        desktop.send(desktop.noise.createHandshakeMessage1())
        val msg2 = desktop.read()
        assertEquals("msg2, not an ack", 96, msg2.size)
        desktop.noise.processHandshakeMessage2(msg2)
        desktop.sendMsg3()
        withTimeout(TIMEOUT_MS) { phone.connected.await() }

        assertArrayEquals(ByteArray(0), phone.noise.getPrologue())
        assertEquals(desktop.publicKeyHex, pairing.confirmedPeerKeyHex())
    }

    // ---------------------------------------------------------------------
    // Claimed key versus authenticated key
    // ---------------------------------------------------------------------

    /**
     * The identity message claims paired desktop A; the handshake is run
     * under unpaired static key B. The session trusts B, the key the
     * handshake proved: it is not confirmed, and B's next request is
     * answered PAIRING_REQUIRED without reaching the handler.
     */
    @Test
    fun anIdentityClaimingAPairedKeyDoesNotConfirmAnotherHandshakeKey() = runBlocking {
        val claimed = NoiseInitiatorSession(randomKey()).getLocalStaticPublicKey()
        repo.addDevice(claimed.hex(), "desktop-a")
        val desktop = newDesktop() // B, unpaired
        val phone = serve()

        desktop.send(byteArrayOf(0x01) + claimed)
        assertArrayEquals("A has no fingerprint", byteArrayOf(0x00), desktop.read())
        desktop.sendMsg1AndReadMsg2()
        desktop.sendMsg3()
        withTimeout(TIMEOUT_MS) { phone.connected.await() }

        assertEquals("the authenticated key", desktop.publicKeyHex, pairing.connectedPeerKeyHex)
        assertNotEquals(claimed.hex(), desktop.publicKeyHex)
        assertNull(pairing.confirmedConnection())
        assertNull(pairing.confirmedPeerKeyHex())

        val reply = desktop.request("local.listKeys", id = 5)
        assertEquals(5L, reply.getLong("id"))
        assertEquals(ErrorCodes.PAIRING_REQUIRED, reply.getJSONObject("error").getInt("code"))
        coVerify(exactly = 0) { requestHandler.handleRawRequest(any<ByteArray>()) }
    }

    /**
     * The identity message claims paired desktop A, which has a fingerprint,
     * so the phone binds the prologue to A's key. A desktop holding key B
     * binds its own key and cannot complete the handshake.
     */
    @Test
    fun anIdentityClaimingAFingerprintedKeyFailsAnotherHandshakeKey() = runBlocking {
        val claimed = NoiseInitiatorSession(randomKey()).getLocalStaticPublicKey()
        repo.addDevice(claimed.hex(), "desktop-a")
        repo.updateDeviceFingerprint(claimed.hex(), FINGERPRINT)
        val desktop = newDesktop()
        val phone = serve()

        desktop.send(byteArrayOf(0x01) + claimed)
        val ack = desktop.read()
        assertArrayEquals(byteArrayOf(0x01) + FINGERPRINT_BYTES, ack)
        desktop.noise.processIdentityAck(ack)
        desktop.send(desktop.noise.createHandshakeMessage1())
        val msg2 = desktop.read()
        assertNotNull(runCatching { desktop.noise.processHandshakeMessage2(msg2) }.exceptionOrNull())
        desktop.close()

        assertNotNull(phone.awaitServeEnded())
        assertFalse(phone.connected.isCompleted)
        assertNull(pairing.confirmedConnection())
    }

    // ---------------------------------------------------------------------
    // Malformed handshake messages
    // ---------------------------------------------------------------------

    /** A garbage msg1 ends that connection; the next desktop still pairs and is served. */
    @Test
    fun aGarbageMsg1EndsThatConnectionAndTheNextDesktopPairs() = runBlocking {
        val desktop = newDesktop()
        val phone = serve()

        desktop.exchangeIdentity()
        desktop.send(byteArrayOf(1, 2, 3, 4, 5))

        desktop.assertClosedByPhone()
        assertTrue(phone.awaitServeEnded() is NoiseException)
        assertFalse(phone.connected.isCompleted)
        assertNextDesktopIsServed()
    }

    /** A garbage msg3 fails authentication and ends that connection; the next desktop still pairs. */
    @Test
    fun aGarbageMsg3EndsThatConnectionAndTheNextDesktopPairs() = runBlocking {
        val desktop = newDesktop()
        repo.addDevice(desktop.publicKeyHex, "desktop")
        val phone = serve()

        desktop.exchangeIdentity()
        desktop.sendMsg1AndReadMsg2()
        desktop.send(ByteArray(64).also { SecureRandom().nextBytes(it) })

        desktop.assertClosedByPhone()
        assertNotNull(phone.awaitServeEnded())
        assertFalse(phone.connected.isCompleted)
        assertNull(pairing.confirmedConnection())
        assertNextDesktopIsServed()
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    private suspend fun assertUnknownAckFor(fingerprint: String) {
        val desktop = newDesktop()
        repo.addDevice(desktop.publicKeyHex, "desktop")
        repo.updateDeviceFingerprint(desktop.publicKeyHex, fingerprint)
        val phone = serve()

        desktop.send(desktop.noise.createIdentityMessage())
        assertArrayEquals(byteArrayOf(0x00), desktop.read())
        desktop.sendMsg1AndReadMsg2()
        desktop.sendMsg3()
        withTimeout(TIMEOUT_MS) { phone.connected.await() }

        assertArrayEquals(ByteArray(0), phone.noise.getPrologue())
        assertEquals(desktop.publicKeyHex, pairing.confirmedPeerKeyHex())
    }

    private suspend fun assertNextDesktopIsServed() {
        val next = newDesktop()
        repo.addDevice(next.publicKeyHex, "desktop-next")
        val phone = serve()
        next.handshake()
        withTimeout(TIMEOUT_MS) { phone.connected.await() }
        assertEquals(next.publicKeyHex, pairing.confirmedPeerKeyHex())
        val reply = next.request("local.getCapabilities", id = 11)
        assertTrue(reply.getJSONObject("result").getBoolean("ok"))
    }

    private fun newDesktop(): DesktopPeer = DesktopPeer(Socket(listener.inetAddress, listener.localPort))

    private class Phone(
        val noise: NoiseSession,
        val connected: CompletableDeferred<Unit>,
        private val served: CompletableDeferred<Throwable?>,
    ) {
        /** Waits for [StreamPairingSession.serve] to return; its failure, or null. */
        suspend fun awaitServeEnded(): Throwable? = withTimeout(TIMEOUT_MS) { served.await() }
    }

    /** Accepts the next connection and runs the phone's side of it. */
    private suspend fun serve(): Phone {
        val accepted = connections.track(listener.accept())
        val noise = NoiseSession().also { it.loadStaticKey(context) }
        val connected = CompletableDeferred<Unit>()
        val served = CompletableDeferred<Throwable?>()
        connections.scope.launch {
            val failure = runCatching {
                pairing.serve(
                    input = accepted.getInputStream(),
                    output = accepted.getOutputStream(),
                    noiseSession = noise,
                    connectionId = "test:${java.util.UUID.randomUUID()}",
                    isActive = { !accepted.isClosed },
                    onConnected = { connected.complete(Unit) },
                )
            }.exceptionOrNull()
            accepted.close()
            served.complete(failure)
        }
        return Phone(noise, connected, served)
    }
}
