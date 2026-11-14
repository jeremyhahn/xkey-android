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
import android.content.Context
import android.os.Looper
import android.util.Log
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.ble.NoiseSession
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.protocol.Response
import com.automatethethings.xkey.remote.BidirectionalMessageRouter
import com.automatethethings.xkey.remote.sendOnBoundSession
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
import java.io.FilterInputStream
import java.io.InputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CountDownLatch
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
import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The desktop answers a phone-initiated `remote.*` request and then ends its
 * stream before the phone has dispatched the answer. The frames
 * read before the end of the stream are still delivered: each caller gets the
 * desktop's own result or error, not "Connection lost". The main thread is
 * held while the reader reads the answer and the end of the stream, so the
 * dispatch can only run after the reader has seen both.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class StreamResponseDrainTest {

    private lateinit var context: Context
    private lateinit var repo: PairedDeviceRepository
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
        val handler = RequestHandler(
            context = context,
            keystoreManager = mockk<KeystoreManager>(relaxed = true),
            biometricLauncher = mockk(relaxed = true),
            sessionAuthManager = null,
        )
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
        Dispatchers.resetMain()
        mainThread.shutdownNow()
        unmockkAll()
    }

    @Test
    fun aResultAndAnErrorSentJustBeforeTheStreamEndsBothReachTheirCallers() = runBlocking<Unit> {
        val peer = connect()
        val first = phoneRequest(peer, id = 201)
        val second = phoneRequest(peer, id = 202)

        val main = holdMainThread()
        peer.desktop.send(peer.desktop.noise.encrypt(result(id = 201, restored = 1)))
        peer.desktop.send(peer.desktop.noise.encrypt(error(id = 202, code = DESKTOP_ERROR, message = "wrong password")))
        peer.desktop.endOutput()
        awaitEndOfStreamRead(peer)
        main.countDown()

        val ok = withTimeout(TIMEOUT_MS) { first.await() }
        assertNull(ok.error)
        assertEquals(1, ok.result!!.getInt("restored"))
        val failed = withTimeout(TIMEOUT_MS) { second.await() }
        assertEquals("the desktop's own error", DESKTOP_ERROR, failed.error?.code)
        assertEquals("wrong password", failed.error?.message)
        assertServeEndedQuietly(peer)
    }

    @Test
    fun twoResultsSentJustBeforeTheStreamEndsBothReachTheirCallers() = runBlocking<Unit> {
        val peer = connect()
        val first = phoneRequest(peer, id = 301)
        val second = phoneRequest(peer, id = 302)

        val main = holdMainThread()
        peer.desktop.send(peer.desktop.noise.encrypt(result(id = 301, restored = 1)))
        peer.desktop.send(peer.desktop.noise.encrypt(result(id = 302, restored = 2)))
        peer.desktop.endOutput()
        awaitEndOfStreamRead(peer)
        main.countDown()

        assertEquals(1, withTimeout(TIMEOUT_MS) { first.await() }.result!!.getInt("restored"))
        assertEquals(2, withTimeout(TIMEOUT_MS) { second.await() }.result!!.getInt("restored"))
        assertServeEndedQuietly(peer)
    }

    /** A request the desktop left behind is not run: nobody would read its answer. */
    @Test
    fun aRequestSentJustBeforeTheStreamEndsIsNotRunButTheResultBeforeItIsDelivered() = runBlocking<Unit> {
        val peer = connect()
        val restore = phoneRequest(peer, id = 401)

        val main = holdMainThread()
        peer.desktop.send(peer.desktop.noise.encrypt(result(id = 401, restored = 4)))
        peer.desktop.send(peer.desktop.noise.encrypt(request(id = 402, method = "system.ping")))
        peer.desktop.endOutput()
        awaitEndOfStreamRead(peer)
        main.countDown()

        assertEquals(4, withTimeout(TIMEOUT_MS) { restore.await() }.result!!.getInt("restored"))
        assertServeEndedQuietly(peer)
    }

    /** Unpairing the desktop (#59) delivers nothing more: what is pending settles as lost. */
    @Test
    fun anUnpairingWhileResultsAreBufferedDeliversNone() = runBlocking<Unit> {
        val peer = connect()
        val restore = phoneRequest(peer, id = 501)

        val main = holdMainThread()
        peer.desktop.send(peer.desktop.noise.encrypt(result(id = 501, restored = 5)))
        peer.desktop.endOutput()
        awaitEndOfStreamRead(peer)
        repo.removeDevice(peer.desktop.publicKeyHex)
        main.countDown()

        val response = withTimeout(TIMEOUT_MS) { restore.await() }
        assertNull("nothing is delivered after a revocation", response.result)
        assertNotNull(response.error)
        peer.awaitServeEnded()
        peer.desktop.assertClosedByPhone()
    }

    /** Serve returned and wrote nothing after the end of the stream. */
    private suspend fun assertServeEndedQuietly(peer: Peer) {
        val served = peer.awaitServeEnded()
        assertTrue("serve must return: $served", served.isSuccess)
        peer.desktop.assertClosedByPhone()
    }

    /**
     * The phone sends a `remote.*` request with [id] on the pending-request
     * path RemoteBackupClient uses; the deferred settles with what answers it.
     */
    private suspend fun phoneRequest(peer: Peer, id: Long): CompletableDeferred<Response> {
        val answer = CompletableDeferred<Response>()
        router.registerPendingResponse(id, answer)
        pairing.sendOnBoundSession(request(id = id, method = "remote.backup.restore"))
        assertEquals(id, peer.desktop.readEncrypted().getLong("id"))
        return answer
    }

    /** Parks the main thread, where requests are dispatched, until the latch is released. */
    private fun holdMainThread(): CountDownLatch {
        val gate = CountDownLatch(1)
        mainThread.execute { gate.await() }
        return gate
    }

    /**
     * The reader has read the end of the stream and acted on it. Without the
     * fix it ends the connection and closes the input at once; with it the
     * input stays open until the frames are delivered, so a short wait stands
     * in for that.
     */
    private suspend fun awaitEndOfStreamRead(peer: Peer) {
        withTimeout(TIMEOUT_MS) { peer.input.ended.await() }
        withTimeoutOrNull(END_SETTLE_MS) { peer.input.closed.await() }
    }

    /** Pairs a desktop, connects it over loopback and completes the handshake. */
    private suspend fun connect(): Peer {
        val desktop = DesktopPeer(Socket(listener.inetAddress, listener.localPort))
        repo.addDevice(desktop.publicKeyHex, "desktop")
        val accepted = connections.track(listener.accept())
        val input = ObservedInput(accepted.getInputStream())
        val connected = CompletableDeferred<Unit>()
        val served = CompletableDeferred<Result<Unit>>()
        scope.launch {
            val outcome = runCatching {
                pairing.serve(
                    input = input,
                    output = accepted.getOutputStream(),
                    noiseSession = NoiseSession().also { it.loadStaticKey(context) },
                    connectionId = "test:${java.util.UUID.randomUUID()}",
                    isActive = { !accepted.isClosed },
                    onConnected = { connected.complete(Unit) },
                )
            }
            accepted.close()
            served.complete(outcome)
        }
        desktop.handshake()
        withTimeout(TIMEOUT_MS) { connected.await() }
        return Peer(desktop, input, served)
    }

    private class Peer(
        val desktop: DesktopPeer,
        val input: ObservedInput,
        private val served: CompletableDeferred<Result<Unit>>,
    ) {
        /** How `serve` ended: it returned, or what it threw. */
        suspend fun awaitServeEnded(): Result<Unit> = withTimeout(TIMEOUT_MS) { served.await() }
    }

    /** The phone's end of the stream, reporting when a read meets its end and when it is closed. */
    private class ObservedInput(input: InputStream) : FilterInputStream(input) {
        val ended = CompletableDeferred<Unit>()
        val closed = CompletableDeferred<Unit>()

        override fun read(): Int = super.read().also { if (it < 0) ended.complete(Unit) }

        override fun read(b: ByteArray, off: Int, len: Int): Int =
            super.read(b, off, len).also { if (it < 0) ended.complete(Unit) }

        override fun close() {
            closed.complete(Unit)
            super.close()
        }
    }

    private companion object {
        const val TIMEOUT_MS = 10_000L
        const val END_SETTLE_MS = 500L
        const val DESKTOP_ERROR = -32001

        fun request(id: Long, method: String): ByteArray = JSONObject()
            .put("jsonrpc", "2.0")
            .put("id", id)
            .put("method", method)
            .put("params", JSONObject())
            .toString()
            .toByteArray()

        fun result(id: Long, restored: Int): ByteArray = JSONObject()
            .put("jsonrpc", "2.0")
            .put("id", id)
            .put("result", JSONObject().put("restored", restored))
            .toString()
            .toByteArray()

        fun error(id: Long, code: Int, message: String): ByteArray = JSONObject()
            .put("jsonrpc", "2.0")
            .put("id", id)
            .put("error", JSONObject().put("code", code).put("message", message))
            .toString()
            .toByteArray()
    }
}
