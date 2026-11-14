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
import android.util.Log
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.ble.NoiseSession
import com.automatethethings.xkey.ble.PairingConfirmationCallback
import com.automatethethings.xkey.protocol.ErrorCodes
import com.automatethethings.xkey.protocol.MethodNames
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.remote.BidirectionalMessageRouter
import com.automatethethings.xkey.remote.ConnectionChangedException
import com.automatethethings.xkey.remote.RemoteShareClient
import com.automatethethings.xkey.remote.ShareSession
import com.automatethethings.xkey.settings.InMemorySharedPreferences
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.settings.PeerNotPairedException
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.runs
import io.mockk.unmockkAll
import io.mockk.verify
import java.io.IOException
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.withTimeout
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

/**
 * Unpairing a desktop revokes its live stream session, and every
 * phone-initiated send revalidates the peer first (#59). The shared
 * [StreamPairingSession] serves TCP and USB alike; here it runs over a
 * loopback socket against [DesktopPeer].
 */
@OptIn(ExperimentalCoroutinesApi::class)
class StreamPairingSessionRevocationTest {

    private companion object {
        const val TIMEOUT_MS = 10_000L
        val TRANSPORT_SECRETS = setOf("sendKey", "recvKey")
        val REQUEST = """{"jsonrpc":"2.0","id":9,"method":"remote.sync","params":{}}""".toByteArray()

        fun ByteArray.isAllZero(): Boolean = all { it == 0.toByte() }
    }

    private lateinit var context: Context
    private lateinit var prefs: InMemorySharedPreferences
    private lateinit var repo: PairedDeviceRepository
    private lateinit var requestHandler: RequestHandler
    private lateinit var pairing: StreamPairingSession
    private lateinit var mainThread: ExecutorService
    private lateinit var listener: ServerSocket
    private val connections = ServedConnections()
    private val scope = connections.scope

    @Before
    fun setUp() {
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
        prefs = InMemorySharedPreferences()
        repo = PairedDeviceRepository(prefs)
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
        listener = ServerSocket(0, 1, InetAddress.getLoopbackAddress())
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
    // Unpair of an active connection
    // ---------------------------------------------------------------------

    /**
     * Unpairing the peer of a live session closes the transport, zeroes the
     * session keys, and leaves nothing a later send could use.
     */
    @Test
    fun unpairingTheActivePeerTearsDownTheSession() = runBlocking {
        val phone = connectPaired()
        val keys = phone.noise.secretArraysForTest().filterKeys { it in TRANSPORT_SECRETS }
        assertEquals(TRANSPORT_SECRETS, keys.keys)

        repo.removeDevice(phone.desktop.publicKeyHex)

        phone.desktop.assertClosedByPhone()
        phone.awaitServeEnded()
        keys.forEach { (name, key) -> assertTrue("$name must be zero", key.isAllZero()) }
        try {
            pairing.sendEncryptedMessage(REQUEST)
            fail("a send after the teardown must be refused")
        } catch (e: IOException) {
            // No session left to send on.
        }
    }

    /**
     * The removal lands while a phone-initiated frame is blocked mid-write:
     * that write fails, nothing reaches the desktop, and the keys are zeroed
     * only after the write has released the send lock.
     */
    @Test
    fun unpairingWhileAFrameIsMidSendFailsItAndZeroesAfterIt() = runBlocking {
        val gate = GatedOutputStream()
        val phone = connectPaired(gate)
        val keys = phone.noise.secretArraysForTest().filterKeys { it in TRANSPORT_SECRETS }

        gate.armed = true
        val send = scope.async { runCatching { pairing.sendEncryptedMessage(REQUEST) } }
        assertTrue("the send never reached the stream", gate.entered.await(5, TimeUnit.SECONDS))
        assertFalse("the keys are live while the frame is mid-send", keys.values.any { it.isAllZero() })

        repo.removeDevice(phone.desktop.publicKeyHex)

        val result = withTimeout(TIMEOUT_MS) { send.await() }
        assertTrue("the in-flight send must fail: $result", result.exceptionOrNull() is IOException)
        phone.desktop.assertClosedByPhone()
        phone.awaitServeEnded()
        keys.forEach { (name, key) -> assertTrue("$name must be zero", key.isAllZero()) }
    }

    /**
     * A phone-initiated send is paused after its dispatch to the IO
     * dispatcher and before admission; the peer is removed; then the send
     * resumes. Admission and revocation share one lock, so the send is
     * refused: nothing reaches the stream, no nonce is consumed, and the send
     * fails with the typed not-paired error.
     */
    @Test
    fun aSendPausedBeforeAdmissionWhenThePeerIsRemovedWritesNothing() = runBlocking<Unit> {
        val gate = GatedOutputStream()
        val phone = connectPaired(gate)
        val paused = CompletableDeferred<Unit>()
        val resume = CompletableDeferred<Unit>()
        pairing.beforeAdmissionForTest = {
            paused.complete(Unit)
            resume.await()
        }
        val send = scope.async { runCatching { pairing.sendEncryptedMessage(REQUEST) } }
        withTimeout(TIMEOUT_MS) { paused.await() }
        val writes = gate.writes.get()
        val nonce = phone.noise.sendNonceForTest()

        repo.removeDevice(phone.desktop.publicKeyHex)
        resume.complete(Unit)

        val failure = withTimeout(TIMEOUT_MS) { send.await() }.exceptionOrNull()
        assertTrue("the send must fail as not paired: $failure", failure is PeerNotPairedException)
        assertEquals("nothing may reach the stream", writes, gate.writes.get())
        assertEquals("a refused send must not consume a nonce", nonce, phone.noise.sendNonceForTest())
        phone.desktop.assertClosedByPhone()
        phone.awaitServeEnded()
    }

    /**
     * The sender is cancelled after its frame was encrypted and before it is
     * written, with the peer still paired. The admitted send is not
     * cancellable: the frame still goes out, so the next send decrypts on
     * the desktop and the two sides stay in nonce step.
     */
    @Test
    fun aSenderCancelledAfterAdmissionStillWritesItsFrame() = runBlocking<Unit> {
        val phone = connectPaired()
        val admitted = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        pairing.afterAdmissionForTest = {
            admitted.complete(Unit)
            release.await()
        }
        val sender = scope.launch { pairing.sendEncryptedMessage(REQUEST) }
        withTimeout(TIMEOUT_MS) { admitted.await() }

        sender.cancel()
        release.complete(Unit)
        withTimeout(TIMEOUT_MS) { sender.join() }
        pairing.afterAdmissionForTest = null

        pairing.sendEncryptedMessage(REQUEST)
        assertEquals("remote.sync", phone.desktop.readEncrypted().getString("method"))
        assertEquals("remote.sync", phone.desktop.readEncrypted().getString("method"))
    }

    /**
     * The peer ends its stream while a phone-initiated write is blocked on it.
     * The teardown closes the streams before it waits on the
     * send lock, so the blocked write fails, serve returns, and the keys are
     * zeroed.
     */
    @Test
    fun anEofWhileAWriteIsBlockedEndsTheConnectionAndZeroesTheKeys() = runBlocking {
        val gate = GatedOutputStream()
        val phone = connectPaired(gate)
        val keys = phone.noise.secretArraysForTest().filterKeys { it in TRANSPORT_SECRETS }
        assertEquals(TRANSPORT_SECRETS, keys.keys)

        gate.armed = true
        val send = scope.async { runCatching { pairing.sendEncryptedMessage(REQUEST) } }
        assertTrue("the send never reached the stream", gate.entered.await(5, TimeUnit.SECONDS))

        phone.desktop.endOutput()

        phone.awaitServeEnded()
        val result = withTimeout(TIMEOUT_MS) { send.await() }
        assertTrue("the blocked send must fail: $result", result.exceptionOrNull() is IOException)
        keys.forEach { (name, key) -> assertTrue("$name must be zero", key.isAllZero()) }
        try {
            pairing.sendEncryptedMessage(REQUEST)
            fail("a send after the teardown must be refused")
        } catch (e: IOException) {
            // No session left to send on.
        }
    }

    // ---------------------------------------------------------------------
    // Send-time revalidation
    // ---------------------------------------------------------------------

    /**
     * The record is gone but no notice reached the session (it was wiped
     * behind the repository's back): the send is refused before encryption,
     * the nonce does not move, and nothing is written.
     */
    @Test
    fun aSendToAPeerThatIsNoLongerPairedIsRefusedBeforeEncryption() = runBlocking {
        val phone = connectPaired()
        prefs.edit().clear().apply()
        val nonce = phone.noise.sendNonceForTest()

        try {
            pairing.sendEncryptedMessage(REQUEST)
            fail("the send must be refused")
        } catch (e: PeerNotPairedException) {
            assertEquals(phone.desktop.publicKeyHex, e.publicKeyHex)
        }

        assertEquals("a refused send must not consume a nonce", nonce, phone.noise.sendNonceForTest())
        phone.desktop.assertNoFrame()
    }

    // ---------------------------------------------------------------------
    // Removal during the handshake
    // ---------------------------------------------------------------------

    /** The peer's claimed key is unpaired between msg2 and msg3: the handshake is torn down. */
    @Test
    fun unpairingDuringTheHandshakeTearsItDown() = runBlocking {
        val socket = Socket(listener.inetAddress, listener.localPort)
        val desktop = DesktopPeer(socket)
        repo.addDevice(desktop.publicKeyHex, "desktop")
        val phone = serve(desktop)
        desktop.exchangeIdentity()
        desktop.sendMsg1AndReadMsg2()
        val handshakeSecrets = phone.noise.secretArraysForTest() - "staticPrivateKey"

        repo.removeDevice(desktop.publicKeyHex)

        desktop.assertClosedByPhone()
        assertTrue("serve must fail", phone.awaitServeEnded() != null)
        assertFalse("the session must not be connected", phone.connected.isCompleted)
        handshakeSecrets.forEach { (name, key) -> assertTrue("$name must be zero", key.isAllZero()) }
    }

    /**
     * Unpaired before the phone knows who is connecting: the handshake still
     * completes, but the session is not adopted as paired, so it serves only
     * pairing.confirm and the phone sends it nothing.
     */
    @Test
    fun unpairingBeforeThePeerKeyIsKnownLeavesTheSessionGated() = runBlocking {
        val socket = Socket(listener.inetAddress, listener.localPort)
        val desktop = DesktopPeer(socket)
        repo.addDevice(desktop.publicKeyHex, "desktop")
        val phone = serve(desktop)

        repo.removeDevice(desktop.publicKeyHex)
        desktop.handshake()
        withTimeout(TIMEOUT_MS) { phone.connected.await() }

        val reply = desktop.request("system.ping")
        assertEquals(ErrorCodes.PAIRING_REQUIRED, reply.getJSONObject("error").getInt("code"))
        try {
            pairing.sendEncryptedMessage(REQUEST)
            fail("the send must be refused")
        } catch (e: PeerNotPairedException) {
            // Nothing was written.
        }
        desktop.assertNoFrame()
    }

    /**
     * `local.verifyUser` answers only a confirmed, paired session (#13): an
     * unconfirmed one is refused by the gate, so the handler — and with it
     * the biometric prompt — is never reached.
     */
    @Test
    fun verifyUserOnAnUnconfirmedSessionIsRefusedBeforeTheHandler() = runBlocking {
        val phone = connectUnpaired()
        val nonce = java.util.Base64.getEncoder().encodeToString(ByteArray(32))

        val reply = phone.desktop.request(
            MethodNames.LOCAL_VERIFY_USER,
            params = JSONObject().put("protocolVersion", 2).put("nonce", nonce)
        )

        assertEquals(ErrorCodes.PAIRING_REQUIRED, reply.getJSONObject("error").getInt("code"))
        coVerify(exactly = 0) { requestHandler.handleRawRequest(any<ByteArray>()) }
        coVerify(exactly = 0) { requestHandler.handleRawRequest(any<ByteArray>(), any(), any()) }
    }

    /**
     * The removal lands inside msg3 processing, after the transport keys are
     * split and before the session is installed. The keys are
     * zero when msg3 returns, and the session never connects.
     */
    @Test
    fun aRemovalBetweenTheSplitAndInstallingTheKeysLeavesNoKeysAndNoConnection() = runBlocking {
        val socket = Socket(listener.inetAddress, listener.localPort)
        val desktop = DesktopPeer(socket)
        repo.addDevice(desktop.publicKeyHex, "desktop")
        val phone = serve(desktop)
        desktop.exchangeIdentity()
        desktop.sendMsg1AndReadMsg2()
        val split = CompletableDeferred<Map<String, ByteArray>>()
        phone.noise.afterSplitForTest = {
            split.complete(phone.noise.secretArraysForTest().filterKeys { it in TRANSPORT_SECRETS })
            repo.removeDevice(desktop.publicKeyHex)
        }

        desktop.send(desktop.noise.createHandshakeMessage3())

        val keys = withTimeout(TIMEOUT_MS) { split.await() }
        assertEquals(TRANSPORT_SECRETS, keys.keys)
        assertTrue("serve must fail", phone.awaitServeEnded() is PeerNotPairedException)
        keys.forEach { (name, key) -> assertTrue("$name must be zero", key.isAllZero()) }
        assertFalse("the session must not be connected", phone.connected.isCompleted)
        desktop.assertClosedByPhone()
    }

    // ---------------------------------------------------------------------
    // Approval outlived by its connection
    // ---------------------------------------------------------------------

    /**
     * The user is asked to approve one desktop; it is removed and a new
     * desktop connects before the user answers yes (the stream
     * counterpart of the BLE guard). The removed peer is not re-added, and the
     * new connection stays gated.
     */
    @Test
    fun anApprovalAnsweredAfterThePeerWasRemovedAndReplacedChangesNothing() = runBlocking<Unit> {
        val asked = CompletableDeferred<Unit>()
        val answer = CompletableDeferred<Boolean>()
        val callback = mockk<PairingConfirmationCallback>()
        coEvery { callback.onPairingConfirmationRequired(any(), any(), any()) } coAnswers {
            asked.complete(Unit)
            answer.await()
        }
        pairing = StreamPairingSession(
            requestHandler = requestHandler,
            messageRouter = null,
            pairingCallback = callback,
            pairedDeviceRepository = repo,
            transportLabel = "TEST",
        )
        val old = connectUnpaired()
        val pending = scope.async { pairing.interceptOrRoute(pairingConfirm(old.desktop.publicKeyHex)) }
        withTimeout(TIMEOUT_MS) { asked.await() }

        repo.removeDevice(old.desktop.publicKeyHex)
        old.desktop.assertClosedByPhone()
        old.awaitServeEnded()
        val replacement = connectUnpaired()

        answer.complete(true)

        assertEquals("the old approval answers nothing", null, withTimeout(TIMEOUT_MS) { pending.await() })
        assertFalse("the removed peer must not be re-added", repo.isDeviceKnown(old.desktop.publicKeyHex))
        verify(exactly = 0) { requestHandler.setConnectedDevicePublicKeyHex(old.desktop.publicKeyHex, any()) }
        val reply = replacement.desktop.request("system.ping")
        assertEquals(ErrorCodes.PAIRING_REQUIRED, reply.getJSONObject("error").getInt("code"))
    }

    // ---------------------------------------------------------------------
    // The confirmed peer a key share is checked against
    // ---------------------------------------------------------------------

    /**
     * A key share is authorized against the peer confirmed on the connection
     * it goes out on. That is this connection's own authenticated peer, never
     * the handler-wide key, and the answer ends with the connection's
     * revocation, before its teardown has run.
     */
    @Test
    fun theConfirmedConnectionIsThisConnectionsOwnPeerUntilItIsRevoked() = runBlocking<Unit> {
        val unconfirmed = connectUnpaired()
        assertNull("an unconfirmed connection confirms no one", pairing.confirmedConnection())
        unconfirmed.desktop.close()
        unconfirmed.awaitServeEnded()

        val phone = connectPaired()
        val confirmed = pairing.confirmedConnection()
        assertEquals(phone.desktop.publicKeyHex, confirmed?.peerPublicKeyHex)

        repo.removeDevice(phone.desktop.publicKeyHex)
        assertNull("a revoked connection confirms no one", pairing.confirmedConnection())
        phone.awaitServeEnded()
    }

    /**
     * A share goes out on the connection it was authorized on, or not at
     * all: a second paired desktop that connects after the check passed for
     * the first, and before the bytes reach the transport, receives nothing.
     */
    @Test
    fun aShareAuthorizedForOnePeerNeverReachesAPeerThatConnectedBeforeTheSend() = runBlocking<Unit> {
        val first = connectPaired()
        var second: Phone? = null
        val router = BidirectionalMessageRouter(requestHandler)
        // The check (same connection, same peer) has passed for the first
        // desktop when this runs; the second one, paired alongside it (so the
        // first is not revoked), connects in that window.
        val session = ShareSession.of(listOf(ShareSession.Transport(pairing, router))) {
            if (second == null) second = runBlocking { connectPaired(deviceName = "second desktop") }
            true
        }!!
        assertEquals(first.desktop.publicKeyHex, session.peerPublicKeyHex)

        val share = RemoteShareClient.PublicKeyShare("k1", "-----BEGIN PUBLIC KEY-----", null, "ECDSA-P256", null, null)
        val outcome = runCatching { session.client(300).sharePublicKey(share) }

        assertTrue(
            "the share must be refused as a changed connection, got $outcome",
            outcome.exceptionOrNull() is ConnectionChangedException
        )
        val late = second ?: error("the second desktop never connected")
        assertTrue(
            "the second desktop is another peer",
            late.desktop.publicKeyHex != first.desktop.publicKeyHex
        )
        late.desktop.assertNoFrame()
    }

    /**
     * The connection-scoped send works: on the current confirmed connection
     * the frame goes out on that connection's own session and its peer
     * decrypts it.
     */
    @Test
    fun aScopedSendOnTheCurrentConfirmedConnectionReachesItsPeer() = runBlocking<Unit> {
        val phone = connectPaired()
        val confirmed = pairing.confirmedConnection() ?: error("the connection confirms no one")

        pairing.sendEncryptedMessageOn(confirmed, REQUEST)

        assertEquals("remote.sync", phone.desktop.readEncrypted().getString("method"))
    }

    /**
     * The production share path, end to end: a [ShareSession] taken on the
     * shared stream session sends `remote.sharePublicKey` to the confirmed
     * desktop, which decrypts the request.
     */
    @Test
    fun aShareOnTheCurrentConnectionReachesTheConfirmedDesktop() = runBlocking<Unit> {
        val phone = connectPaired()
        val router = BidirectionalMessageRouter(requestHandler)
        val session = ShareSession.of(listOf(ShareSession.Transport(pairing, router))) { true }!!
        assertEquals(phone.desktop.publicKeyHex, session.peerPublicKeyHex)

        val share = RemoteShareClient.PublicKeyShare("k1", "-----BEGIN PUBLIC KEY-----", null, "ECDSA-P256", null, null)
        // No reply comes back to this router; only the request is checked.
        val sending = scope.async { runCatching { session.client(TIMEOUT_MS).sharePublicKey(share) } }

        val request = phone.desktop.readEncrypted()
        assertEquals("remote.sharePublicKey", request.getString("method"))
        assertEquals("k1", request.getJSONObject("params").getString("key_id"))
        sending.cancel()
    }

    /**
     * Admission itself refuses a scoped send whose connection was replaced
     * after the early check: a second paired desktop that connects at that
     * point receives nothing, and neither does the first.
     */
    @Test
    fun aScopedSendReplacedAfterTheEarlyCheckIsRefusedAtAdmission() = runBlocking<Unit> {
        val first = connectPaired()
        val confirmed = pairing.confirmedConnection() ?: error("the connection confirms no one")
        var second: Phone? = null
        pairing.beforeAdmissionForTest = {
            if (second == null) second = connectPaired(deviceName = "second desktop")
        }

        val outcome = runCatching { pairing.sendEncryptedMessageOn(confirmed, REQUEST) }
        pairing.beforeAdmissionForTest = null

        val late = second ?: error("the second desktop never connected")
        assertTrue(
            "admission must refuse the replaced connection, got $outcome",
            outcome.exceptionOrNull() is ConnectionChangedException
        )
        late.desktop.assertNoFrame()
        first.desktop.assertNoFrame()
    }

    // ---------------------------------------------------------------------
    // Re-pairing
    // ---------------------------------------------------------------------

    /**
     * After a removal tore the session down, the same desktop key pairs
     * again: the next connection on the same transport is served, receives
     * the phone's requests, and is itself revoked by a second removal.
     */
    @Test
    fun rePairingTheSameKeyAfterARemovalWorks() = runBlocking<Unit> {
        val key = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        val first = connectPaired(staticPrivateKey = key)
        repo.removeDevice(first.desktop.publicKeyHex)
        first.desktop.assertClosedByPhone()
        first.awaitServeEnded()

        val second = connectPaired(staticPrivateKey = key)
        assertEquals(first.desktop.publicKeyHex, second.desktop.publicKeyHex)
        assertTrue(second.desktop.request("system.ping").getJSONObject("result").getBoolean("ok"))
        pairing.sendEncryptedMessage(REQUEST)
        assertEquals("remote.sync", second.desktop.readEncrypted().getString("method"))

        repo.removeDevice(second.desktop.publicKeyHex)
        second.desktop.assertClosedByPhone()
        second.awaitServeEnded()
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    private inner class Phone(
        val desktop: DesktopPeer,
        val noise: NoiseSession,
        val connected: CompletableDeferred<Unit>,
        private val served: CompletableDeferred<Throwable?>,
    ) {
        /** Waits for [StreamPairingSession.serve] to return; its failure, or null. */
        suspend fun awaitServeEnded(): Throwable? = withTimeout(TIMEOUT_MS) { served.await() }
    }

    /** Pairs a desktop, connects it, completes the handshake and waits for the session. */
    private suspend fun connectPaired(
        gate: GatedOutputStream? = null,
        staticPrivateKey: ByteArray? = null,
        deviceName: String = "desktop",
    ): Phone {
        val socket = Socket(listener.inetAddress, listener.localPort)
        val desktop = if (staticPrivateKey != null) DesktopPeer(socket, staticPrivateKey) else DesktopPeer(socket)
        repo.addDevice(desktop.publicKeyHex, deviceName)
        val phone = serve(desktop, gate)
        desktop.handshake()
        withTimeout(TIMEOUT_MS) { phone.connected.await() }
        return phone
    }

    /** Connects a desktop that is not paired and completes the handshake; the session is gated. */
    private suspend fun connectUnpaired(): Phone {
        val desktop = DesktopPeer(Socket(listener.inetAddress, listener.localPort))
        val phone = serve(desktop)
        desktop.handshake()
        withTimeout(TIMEOUT_MS) { phone.connected.await() }
        return phone
    }

    private fun pairingConfirm(keyHex: String): ByteArray = JSONObject()
        .put("jsonrpc", "2.0")
        .put("id", 3)
        .put("method", "pairing.confirm")
        .put("params", JSONObject().put("deviceName", "desktop").put("publicKeyHex", keyHex))
        .toString()
        .toByteArray()

    /** Accepts [desktop]'s connection and runs the phone's side of it. */
    private suspend fun serve(desktop: DesktopPeer, gate: GatedOutputStream? = null): Phone {
        val accepted = connections.track(listener.accept())
        val noise = NoiseSession().also { it.loadStaticKey(context) }
        val connected = CompletableDeferred<Unit>()
        val served = CompletableDeferred<Throwable?>()
        val output: OutputStream = gate?.also { it.target = accepted.getOutputStream() } ?: accepted.getOutputStream()
        scope.launch {
            val failure = runCatching {
                pairing.serve(
                    input = accepted.getInputStream(),
                    output = output,
                    noiseSession = noise,
                    connectionId = "test:${java.util.UUID.randomUUID()}",
                    isActive = { !accepted.isClosed },
                    onConnected = { connected.complete(Unit) },
                )
            }.exceptionOrNull()
            accepted.close()
            served.complete(failure)
        }
        return Phone(desktop, noise, connected, served)
    }

    /**
     * Passes writes through until [armed]; then a write blocks until the
     * stream is closed and fails, as a socket write does when the peer is
     * not reading and the connection is torn down.
     */
    private class GatedOutputStream : OutputStream() {
        lateinit var target: OutputStream
        @Volatile var armed = false
        val entered = CountDownLatch(1)

        /** Every write that reached this stream, passed through or blocked. */
        val writes = AtomicInteger()
        private val closed = CountDownLatch(1)

        override fun write(b: Int) = write(byteArrayOf(b.toByte()), 0, 1)

        override fun write(b: ByteArray, off: Int, len: Int) {
            writes.incrementAndGet()
            if (armed) {
                entered.countDown()
                closed.await()
                throw IOException("stream closed")
            }
            target.write(b, off, len)
        }

        override fun flush() = target.flush()

        override fun close() {
            closed.countDown()
            target.close()
        }
    }
}
