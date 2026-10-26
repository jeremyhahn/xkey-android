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

import android.app.KeyguardManager
import android.app.NotificationManager
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattServer
import android.content.Context
import android.os.Looper
import android.util.Log
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.ble.ConnectionState
import com.automatethethings.xkey.ble.GattServer
import com.automatethethings.xkey.ble.NoiseInitiatorSession
import com.automatethethings.xkey.ble.NoiseSession
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.UserVerificationKey
import com.automatethethings.xkey.crypto.UserVerificationPrompt
import com.automatethethings.xkey.protocol.AttestTranscript
import com.automatethethings.xkey.protocol.AttestedKeyFingerprint
import com.automatethethings.xkey.protocol.MethodNames
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.protocol.Response
import com.automatethethings.xkey.remote.BidirectionalMessageRouter
import com.automatethethings.xkey.settings.InMemorySharedPreferences
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.storage.XKeyDatabase
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.runs
import io.mockk.unmockkAll
import io.mockk.verify
import java.lang.reflect.InvocationTargetException
import java.math.BigInteger
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.Date
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import kotlin.coroutines.intrinsics.suspendCoroutineUninterceptedOrReturn
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
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
 * Each `local.verifyUser` request signs over the binding of the connection it
 * arrived on (Codex 7346, finding 2).
 *
 * BLE, TCP and USB share one [RequestHandler]. Here desktop A is served over
 * a real [GattServer] and desktop B over a real [StreamPairingSession] on a
 * loopback socket, both into one real handler, with their requests in flight
 * at once. Each desktop checks the answer as go-xkms does, against the
 * channel binding derived from *its own* side of its Noise session, so a
 * signature over the other connection's binding fails. B then disconnects,
 * and A's next answer must still bind A's session.
 *
 * The UVK is a software key behind the [UserVerificationKey] seam and the
 * prompt signs with it; the GATT server's Android edges are mocked and its
 * connected state installed by reflection, as in `GattServerSessionRaceTest`.
 */
@OptIn(ExperimentalCoroutinesApi::class)
@Suppress("DEPRECATION")
class VerifyUserPerConnectionTest {

    private lateinit var context: Context
    private lateinit var repo: PairedDeviceRepository
    private lateinit var uvk: SoftwareUserVerificationKey
    private lateinit var prompt: GatedPrompt
    private lateinit var handler: RequestHandler
    private lateinit var gattServer: GattServer
    private lateinit var router: BidirectionalMessageRouter
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
        mockkStatic(Looper::class)
        every { Looper.getMainLooper() } returns mockk(relaxed = true)
        mockkObject(XKeyDatabase.Companion)
        every { XKeyDatabase.getInstance(any()) } returns mockk(relaxed = true)
        mockkObject(AuditLogger)
        every { AuditLogger.logDeviceUnpaired(any(), any()) } just runs
        mainThread = Executors.newSingleThreadExecutor()
        Dispatchers.setMain(mainThread.asCoroutineDispatcher())

        context = mockk(relaxed = true)
        every { context.getSystemService(Context.KEYGUARD_SERVICE) } returns
            mockk<KeyguardManager>(relaxed = true)
        every { context.getSystemService(NotificationManager::class.java) } returns
            mockk<NotificationManager>(relaxed = true)
        repo = PairedDeviceRepository(InMemorySharedPreferences())
        uvk = SoftwareUserVerificationKey()
        prompt = GatedPrompt(uvk)
        handler = RequestHandler(
            context = context,
            keystoreManager = mockk<KeystoreManager>(relaxed = true),
            biometricLauncher = mockk(relaxed = true),
            sessionAuthManager = null,
            userVerificationKey = uvk,
            userVerificationPrompt = prompt
        )

        gattServer = GattServer(context, handler, pairingCallback = mockk(), pairedDeviceRepository = repo)
        val gatt = mockk<BluetoothGattServer>(relaxed = true)
        every { gatt.notifyCharacteristicChanged(any(), any(), any()) } returns true
        every { gatt.notifyCharacteristicChanged(any(), any(), any(), any<ByteArray>()) } returns 0
        setGattField("gattServer", gatt)
        setGattField("responseCharacteristic", mockk<BluetoothGattCharacteristic>(relaxed = true))

        router = BidirectionalMessageRouter(handler)
        pairing = StreamPairingSession(
            requestHandler = handler,
            messageRouter = router,
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
        gattServer.destroy()
        // destroy() cancels the server's scope but does not wait for it; a
        // coroutine still unwinding logs through Log, so wait for the scope
        // before Log is unmocked. The wait comes before resetMain and the main
        // thread's shutdown, so work dispatched to Main can still finish.
        awaitGattScopeFinished()
        Dispatchers.resetMain()
        mainThread.shutdownNow()
        unmockkAll()
    }

    private fun awaitGattScopeFinished() {
        val job = getGattField<CoroutineScope>("scope").coroutineContext.job
        assertTrue("destroy() must cancel the GATT server's scope", job.isCancelled)
        val finished = runBlocking { withTimeoutOrNull(SCOPE_DRAIN_TIMEOUT_MS) { job.join() } }
        if (finished == null) {
            fail("the GATT server's scope did not finish within $SCOPE_DRAIN_TIMEOUT_MS ms of destroy()")
        }
    }

    @Test
    fun eachConnectionSignsItsOwnBindingAndADisconnectLeavesTheOtherBound() = runBlocking<Unit> {
        val desktopA = connectOverBle()
        val desktopB = connectOverStream()
        assertFalse(
            "the two sessions must have different bindings, or the test proves nothing",
            channelBinding(desktopA).contentEquals(channelBinding(desktopB.desktop.noise))
        )

        // Both requests reach the prompt before either is answered.
        prompt.holdUntil(prompts = 2)
        val answerA = scope.async { verifyUserOverBle(NONCE_A) }
        val answerB = scope.async { desktopB.desktop.request(MethodNames.LOCAL_VERIFY_USER, params = params(NONCE_B)) }
        withTimeout(TIMEOUT_MS) { prompt.allArrived.await() }
        prompt.release()

        assertSignedFor(desktopA, NONCE_A, withTimeout(TIMEOUT_MS) { answerA.await() })
        assertSignedFor(desktopB.desktop.noise, NONCE_B, withTimeout(TIMEOUT_MS) { answerB.await() })

        // B goes away; A's binding is A's own, not a handler-wide one B cleared.
        desktopB.desktop.close()
        desktopB.awaitServeEnded()

        assertSignedFor(desktopA, NONCE_C, verifyUserOverBle(NONCE_C))
        assertEquals(3, prompt.prompts.get())
    }

    // -----------------------------------------------------------------
    // The peer goes away while the prompt shows (Codex 7369)
    // -----------------------------------------------------------------

    /**
     * The desktop's stream ends while its `local.verifyUser` waits on a prompt
     * nobody answers. The end is seen at once: the request and its prompt are
     * cancelled, nothing is written, and `serve` returns with no user input.
     */
    @Test
    fun aStreamThatClosesWhileThePromptShowsCancelsItAndServeReturns() = runBlocking<Unit> {
        val peer = connectOverStream()
        prompt.unanswered = true
        peer.desktop.send(peer.desktop.noise.encrypt(verifyUserRequest(NONCE_B)))
        val promptJob = withTimeout(TIMEOUT_MS) { prompt.shown.await() }

        peer.desktop.endOutput()

        withTimeout(TIMEOUT_MS) { prompt.dismissed.await() }
        withTimeout(TIMEOUT_MS) { promptJob.join() }
        assertTrue("the request must be cancelled", promptJob.isCancelled)
        val served = peer.awaitServeEnded()
        assertTrue("serve must return: $served", served.isSuccess)
        // Read to the end of the stream: a frame here is an answer written after the close.
        peer.desktop.assertClosedByPhone()
        assertEquals(1, prompt.prompts.get())
    }

    /**
     * The desktop answers the phone's `remote.*` request while its own
     * `local.verifyUser` waits on a prompt, then ends its stream. The prompt
     * is cancelled with no user input, and the answer, read before the end,
     * still reaches its caller rather than "Connection lost" (Codex 7380).
     */
    @Test
    fun aResultThatArrivesWhileThePromptShowsStillReachesItsCallerWhenTheStreamEnds() = runBlocking<Unit> {
        val peer = connectOverStream()
        val answer = CompletableDeferred<Response>()
        router.registerPendingResponse(REMOTE_ID, answer)
        pairing.sendEncryptedMessage(
            JSONObject().put("jsonrpc", "2.0").put("id", REMOTE_ID).put("method", "remote.backup.restore")
                .put("params", JSONObject()).toString().toByteArray()
        )
        assertEquals(REMOTE_ID, peer.desktop.readEncrypted().getLong("id"))
        prompt.unanswered = true
        peer.desktop.send(peer.desktop.noise.encrypt(verifyUserRequest(NONCE_B)))
        val promptJob = withTimeout(TIMEOUT_MS) { prompt.shown.await() }

        val result = JSONObject().put("jsonrpc", "2.0").put("id", REMOTE_ID)
            .put("result", JSONObject().put("restored", 2)).toString().toByteArray()
        peer.desktop.send(peer.desktop.noise.encrypt(result))
        peer.desktop.endOutput()

        withTimeout(TIMEOUT_MS) { prompt.dismissed.await() }
        withTimeout(TIMEOUT_MS) { promptJob.join() }
        assertTrue("the request must be cancelled", promptJob.isCancelled)
        val response = withTimeout(TIMEOUT_MS) { answer.await() }
        assertNull("the desktop's result, not a lost connection: ${response.error?.message}", response.error)
        assertEquals(2, response.result!!.getInt("restored"))
        val served = peer.awaitServeEnded()
        assertTrue("serve must return: $served", served.isSuccess)
        peer.desktop.assertClosedByPhone()
        assertEquals(1, prompt.prompts.get())
    }

    /**
     * The desktop fills the frame buffer while its `local.verifyUser` waits on
     * a prompt nobody answers, then closes. The reader still sees the end of
     * the stream behind the full buffer.
     */
    @Test
    fun aStreamThatFillsTheFrameBufferAndClosesWhileThePromptShowsCancelsIt() = runBlocking<Unit> {
        assertPromptCancelledAfterFrames(frames = FRAME_BUFFER, thenClose = true)
    }

    /**
     * The desktop sends past the frame buffer while its prompt waits, then
     * closes (Codex 7374). The reader never parks on the full buffer, so the
     * prompt is cancelled and the next request is shown.
     */
    @Test
    fun aStreamThatOverflowsTheFrameBufferAndClosesWhileThePromptShowsCancelsIt() = runBlocking<Unit> {
        assertPromptCancelledAfterFrames(frames = FRAME_BUFFER + 4, thenClose = true)
    }

    /** The overflow alone ends the connection: a request-response peer never sends that far ahead. */
    @Test
    fun aFrameBufferOverflowWhileThePromptShowsEndsTheConnection() = runBlocking<Unit> {
        assertPromptCancelledAfterFrames(frames = FRAME_BUFFER + 1, thenClose = false)
    }

    /**
     * Desktop B's `local.verifyUser` waits on an unanswered prompt while B
     * sends [frames] more frames and, if [thenClose], ends its stream. The
     * request and its prompt are cancelled, nothing is written, `serve`
     * returns, and the next desktop's request is shown and signed.
     */
    private suspend fun assertPromptCancelledAfterFrames(frames: Int, thenClose: Boolean) {
        val peer = connectOverStream()
        prompt.unanswered = true
        peer.desktop.send(peer.desktop.noise.encrypt(verifyUserRequest(NONCE_B)))
        val promptJob = withTimeout(TIMEOUT_MS) { prompt.shown.await() }

        sendUntilOverflowEnds(peer.desktop, frames, thenClose)

        withTimeout(TIMEOUT_MS) { prompt.dismissed.await() }
        withTimeout(TIMEOUT_MS) { promptJob.join() }
        assertTrue("the request must be cancelled", promptJob.isCancelled)
        val served = peer.awaitServeEnded()
        assertTrue("serve must return: $served", served.isSuccess)
        // Read to the end of the stream: a frame here is an answer written after the end.
        peer.desktop.assertClosedByPhone()
        assertEquals(1, prompt.prompts.get())

        prompt.unanswered = false
        val next = connectOverStream()
        val reply = withTimeout(TIMEOUT_MS) {
            next.desktop.request(MethodNames.LOCAL_VERIFY_USER, params = params(NONCE_C))
        }
        assertSignedFor(next.desktop.noise, NONCE_C, reply)
        assertEquals(2, prompt.prompts.get())
    }

    /**
     * Sends [frames] pings on [desktop] and, if [thenClose], ends its stream.
     *
     * The frame past [FRAME_BUFFER] ends the connection (#69): the phone
     * closes its socket with the later frames unread, which resets the
     * connection, so a send or the close after that frame may fail. That is
     * the overflow at work, and the desktop stops there. A failure before
     * the overflowing frame is sent is not, and fails the test.
     */
    private fun sendUntilOverflowEnds(desktop: DesktopPeer, frames: Int, thenClose: Boolean) {
        var sent = 0
        try {
            while (sent < frames) {
                desktop.send(desktop.noise.encrypt(pingRequest(id = 2 + sent)))
                sent++
            }
            if (thenClose) desktop.endOutput()
        } catch (e: SocketException) {
            if (sent <= FRAME_BUFFER) throw e
        }
    }

    /**
     * The BLE desktop disconnects while its `local.verifyUser` waits on a
     * prompt nobody answers: the request and its prompt are cancelled, and
     * nothing is notified.
     */
    @Test
    fun aBleDisconnectWhileThePromptShowsCancelsIt() = runBlocking<Unit> {
        val desktop = connectOverBle()
        val device = getGattField<BluetoothDevice>("connectedDevice")
        prompt.unanswered = true
        val request = scope.async {
            callGatt("handleApplicationMessage", device, desktop.encrypt(verifyUserRequest(NONCE_A)))
        }
        val promptJob = withTimeout(TIMEOUT_MS) { prompt.shown.await() }

        callGatt("handleDeviceDisconnected", device)

        withTimeout(TIMEOUT_MS) { prompt.dismissed.await() }
        withTimeout(TIMEOUT_MS) { promptJob.join() }
        assertTrue("the request must be cancelled", promptJob.isCancelled)
        withTimeout(TIMEOUT_MS) { request.await() }
        val gatt = getGattField<BluetoothGattServer>("gattServer")
        verify(exactly = 0) { gatt.notifyCharacteristicChanged(any(), any(), any()) }
        verify(exactly = 0) { gatt.notifyCharacteristicChanged(any(), any(), any(), any<ByteArray>()) }
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    /** What the desktop checks: the UVK's signature over a transcript built from its own session. */
    private fun assertSignedFor(desktop: NoiseInitiatorSession, nonce: ByteArray, reply: JSONObject) {
        assertNull("no error expected: ${reply.optJSONObject("error")}", reply.optJSONObject("error"))
        val result = reply.getJSONObject("result")
        val transcript = AttestTranscript.build(
            purpose = AttestTranscript.PURPOSE_VERIFY_USER,
            nonce = nonce,
            channelBinding = channelBinding(desktop),
            deviceFingerprint = AttestedKeyFingerprint.of(uvk.chain().first().encoded)
        )
        val verified = Signature.getInstance("SHA256withECDSA").run {
            initVerify(uvk.keyPair.public)
            update(transcript)
            verify(Base64.getDecoder().decode(result.getString("signature")))
        }
        assertTrue("the signature must bind this desktop's own session", verified)
    }

    private fun channelBinding(desktop: NoiseInitiatorSession): ByteArray = AttestTranscript.channelBinding(
        initiatorStaticPublicKey = desktop.getLocalStaticPublicKey(),
        responderStaticPublicKey = checkNotNull(desktop.getRemoteStaticKey()),
        prologue = desktop.getPrologue()
    )

    private fun params(nonce: ByteArray): JSONObject = JSONObject()
        .put("protocolVersion", AttestTranscript.PROTOCOL_VERSION)
        .put("nonce", Base64.getEncoder().encodeToString(nonce))

    // --- BLE: desktop A ---

    /** Completes a handshake with the GATT server and installs it as a confirmed, paired session. */
    private suspend fun connectOverBle(): NoiseInitiatorSession {
        val desktop = NoiseInitiatorSession(randomKey())
        val keyHex = desktop.getLocalStaticPublicKey().joinToString("") { "%02x".format(it) }
        repo.addDevice(keyHex, "desktop A")
        val session = NoiseSession().also { it.loadStaticKey(context) }
        val msg2 = session.processHandshakeMessage(desktop.createHandshakeMessage1())
            ?: throw AssertionError("the responder produced no msg2")
        desktop.processHandshakeMessage2(msg2)
        session.processHandshakeMessage(desktop.createHandshakeMessage3())
        desktop.finalizeHandshake()

        val device = mockk<BluetoothDevice>(relaxed = true)
        every { device.address } returns BLE_ADDRESS
        setGattField("connectedDevice", device)
        setGattField("noiseSession", session)
        setGattField("remotePublicKeyHex", keyHex)
        setGattField("authenticatedPeerKeyHex", keyHex)
        setGattField("identityExchangeComplete", true)
        setGattField("pairingConfirmed", true)
        getGattField<ConcurrentHashMap<String, Int>>("deviceMtu")[BLE_ADDRESS] = 247
        getGattField<ConcurrentHashMap<String, Boolean>>("notificationEnabled")[BLE_ADDRESS] = true
        getGattField<ConcurrentHashMap<String, CompletableDeferred<Unit>>>("notificationReady")[BLE_ADDRESS] =
            CompletableDeferred(Unit)
        getGattField<MutableStateFlow<ConnectionState>>("_connectionState").value =
            ConnectionState.Connected("desktop A", BLE_ADDRESS)
        return desktop
    }

    private fun verifyUserRequest(nonce: ByteArray): ByteArray = JSONObject()
        .put("jsonrpc", "2.0")
        .put("id", 1)
        .put("method", MethodNames.LOCAL_VERIFY_USER)
        .put("params", params(nonce))
        .toString()
        .toByteArray()

    private fun pingRequest(id: Int): ByteArray = JSONObject()
        .put("jsonrpc", "2.0")
        .put("id", id)
        .put("method", "system.ping")
        .toString()
        .toByteArray()

    /** Routes a decrypted `local.verifyUser` request as the GATT write callback does. */
    private suspend fun verifyUserOverBle(nonce: ByteArray): JSONObject {
        val response = callGatt("interceptOrRoute", verifyUserRequest(nonce)) as ByteArray?
        return JSONObject(String(checkNotNull(response) { "the BLE request answered nothing" }, Charsets.UTF_8))
    }

    /** Calls the private suspend member [name] of the GATT server, as its callbacks do. */
    private suspend fun callGatt(name: String, vararg args: Any?): Any? =
        suspendCoroutineUninterceptedOrReturn { continuation ->
            val method = GattServer::class.java.declaredMethods
                .single { it.name == name && it.parameterCount == args.size + 1 }
                .apply { isAccessible = true }
            try {
                method.invoke(gattServer, *args, continuation)
            } catch (e: InvocationTargetException) {
                throw e.targetException
            }
        }

    private fun setGattField(name: String, value: Any?) {
        GattServer::class.java.getDeclaredField(name).apply { isAccessible = true }.set(gattServer, value)
    }

    @Suppress("UNCHECKED_CAST")
    private fun <T> getGattField(name: String): T =
        GattServer::class.java.getDeclaredField(name).apply { isAccessible = true }.get(gattServer) as T

    // --- Stream: desktop B ---

    private inner class StreamPeer(val desktop: DesktopPeer, private val served: CompletableDeferred<Result<Unit>>) {
        /** How `serve` ended: it returned, or what it threw. */
        suspend fun awaitServeEnded(): Result<Unit> = withTimeout(TIMEOUT_MS) { served.await() }
    }

    /** Pairs desktop B, connects it over loopback and completes the handshake. */
    private suspend fun connectOverStream(): StreamPeer {
        val desktop = DesktopPeer(Socket(listener.inetAddress, listener.localPort))
        repo.addDevice(desktop.publicKeyHex, "desktop B")
        val accepted = connections.track(listener.accept())
        val connected = CompletableDeferred<Unit>()
        val served = CompletableDeferred<Result<Unit>>()
        scope.launch {
            val outcome = runCatching {
                pairing.serve(
                    input = accepted.getInputStream(),
                    output = accepted.getOutputStream(),
                    noiseSession = NoiseSession().also { it.loadStaticKey(context) },
                    isActive = { !accepted.isClosed },
                    onConnected = { connected.complete(Unit) },
                )
            }
            accepted.close()
            served.complete(outcome)
        }
        desktop.handshake()
        withTimeout(TIMEOUT_MS) { connected.await() }
        return StreamPeer(desktop, served)
    }

    // --- The UVK and its prompt ---

    /** A software UVK with a self-signed leaf certifying [keyPair]. */
    private class SoftwareUserVerificationKey : UserVerificationKey {
        val keyPair: KeyPair = KeyPairGenerator.getInstance("EC")
            .apply { initialize(ECGenParameterSpec("secp256r1")) }
            .generateKeyPair()
        private val certificates = listOf(selfSigned(keyPair))

        override fun exists(): Boolean = true
        override fun chain(): List<X509Certificate> = certificates
        override fun regenerate(): List<X509Certificate> = certificates
        override fun initSignature(): Signature =
            Signature.getInstance("SHA256withECDSA").apply { initSign(keyPair.private) }

        private fun selfSigned(key: KeyPair): X509Certificate {
            val now = System.currentTimeMillis()
            val holder = JcaX509v3CertificateBuilder(
                X500Name("CN=UVK"),
                BigInteger.valueOf(now),
                Date(now - 60_000),
                Date(now + 3_600_000),
                X500Name("CN=UVK"),
                key.public
            ).build(JcaContentSignerBuilder("SHA256withECDSA").build(key.private))
            return JcaX509CertificateConverter().getCertificate(holder)
        }
    }

    /**
     * Signs with the UVK as the Class 3 prompt does once the user approves.
     * While held, each prompt waits until [holdUntil]'s count has arrived and
     * the test releases them, so the requests are in flight together.
     */
    private class GatedPrompt(private val key: SoftwareUserVerificationKey) : UserVerificationPrompt {
        val prompts = AtomicInteger(0)
        val allArrived = CompletableDeferred<Unit>()
        private var expected = 0
        private var gate = CompletableDeferred(Unit)

        /** When set, a prompt nobody answers: it shows until its request is cancelled. */
        @Volatile var unanswered = false

        /** The job the unanswered prompt ran in, part of its request's. */
        val shown = CompletableDeferred<Job>()
        val dismissed = CompletableDeferred<Unit>()

        fun holdUntil(prompts: Int) {
            expected = prompts
            gate = CompletableDeferred()
        }

        fun release() {
            gate.complete(Unit)
        }

        override suspend fun sign(
            message: ByteArray,
            title: String,
            subtitle: String,
            showOnLockScreen: Boolean
        ): ByteArray {
            if (prompts.incrementAndGet() >= expected) allArrived.complete(Unit)
            if (unanswered) {
                shown.complete(currentCoroutineContext().job)
                try {
                    awaitCancellation()
                } finally {
                    dismissed.complete(Unit)
                }
            }
            gate.await()
            return key.initSignature().run {
                update(message)
                sign()
            }
        }
    }

    private companion object {
        const val TIMEOUT_MS = 10_000L
        const val SCOPE_DRAIN_TIMEOUT_MS = 5_000L
        const val BLE_ADDRESS = "AA:BB:CC:DD:EE:FF"

        /** StreamPairingSession's frame buffer. */
        const val FRAME_BUFFER = 16
        const val REMOTE_ID = 77L
        val NONCE_A = ByteArray(AttestTranscript.BINDING_SIZE) { (0x40 + it).toByte() }
        val NONCE_B = ByteArray(AttestTranscript.BINDING_SIZE) { (0x60 + it).toByte() }
        val NONCE_C = ByteArray(AttestTranscript.BINDING_SIZE) { (0x80 + it).toByte() }

        fun randomKey(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }
    }
}
