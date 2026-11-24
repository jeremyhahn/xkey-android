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
import com.automatethethings.xkey.ble.NoiseTestKeyStore
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
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The limits of a [StreamPairingSession]'s frame loop, over a loopback
 * socket against [DesktopPeer]: the 16-frame read-ahead behind a request
 * that is still running, frames that do not decrypt, and a response too
 * large for one frame. Each ends that connection without a reply, and the
 * next desktop is still served.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class StreamFrameLimitsTest {

    private companion object {
        const val TIMEOUT_MS = 10_000L
        const val FRAME_BUFFER = 16

        fun ok(id: Long) = """{"jsonrpc":"2.0","id":$id,"result":{"ok":true}}""".toByteArray()

        /** A reply whose ciphertext cannot fit one 65535-byte frame. */
        fun oversized(id: Long) =
            """{"jsonrpc":"2.0","id":$id,"result":{"blob":"${"a".repeat(70_000)}"}}""".toByteArray()
    }

    private lateinit var context: Context
    private lateinit var repo: PairedDeviceRepository
    private lateinit var requestHandler: RequestHandler
    private lateinit var pairing: StreamPairingSession
    private lateinit var mainThread: ExecutorService
    private lateinit var listener: ServerSocket
    private val connections = ServedConnections()
    private val entered = CompletableDeferred<Unit>()
    private val release = CompletableDeferred<Unit>()

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
        coEvery { requestHandler.handleRawRequest(any<ByteArray>()) } coAnswers {
            val json = JSONObject(String(firstArg<ByteArray>()))
            val id = json.optLong("id")
            when (json.optString("method")) {
                "test.block" -> {
                    entered.complete(Unit)
                    release.await()
                    ok(id)
                }
                "test.big" -> oversized(id)
                else -> ok(id)
            }
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
        release.complete(Unit)
        connections.end()
        listener.close()
        Dispatchers.resetMain()
        mainThread.shutdownNow()
        unmockkAll()
    }

    /**
     * More than [FRAME_BUFFER] frames sent while a request is still in the
     * handler overflow the read-ahead: the phone ends the connection without
     * answering the request, and the session's transport keys are zeroed.
     */
    @Test
    fun moreThanSixteenFramesBehindABlockedRequestEndTheConnection() = runBlocking {
        val (desktop, phone) = pairedDesktop()
        desktop.send(desktop.noise.encrypt(request("test.block", id = 1)))
        withTimeout(TIMEOUT_MS) { entered.await() }

        runCatching {
            repeat(FRAME_BUFFER + 4) { desktop.send(ByteArray(48).also { SecureRandom().nextBytes(it) }) }
        }

        desktop.assertClosedByPhone()
        phone.awaitServeEnded()
        assertKeysZeroed(phone)
        assertNull(pairing.confirmedConnection())
        assertNextDesktopIsServed()
    }

    /** A frame sent a second time does not decrypt: the session ends with no reply to it. */
    @Test
    fun aReplayedFrameEndsTheSession() = runBlocking {
        val (desktop, phone) = pairedDesktop()
        val frame = desktop.noise.encrypt(request("local.getCapabilities", id = 2))
        desktop.send(frame)
        assertEquals(2L, desktop.readEncrypted().getLong("id"))

        desktop.send(frame)

        desktop.assertClosedByPhone()
        phone.awaitServeEnded()
        coVerify(exactly = 1) { requestHandler.handleRawRequest(any<ByteArray>()) }
        assertKeysZeroed(phone)
        assertNextDesktopIsServed()
    }

    /** A frame with one byte flipped fails authentication: the session ends and nothing runs. */
    @Test
    fun aCorruptedFrameEndsTheSession() = runBlocking {
        val (desktop, phone) = pairedDesktop()
        val frame = desktop.noise.encrypt(request("local.getCapabilities", id = 3))
        frame[frame.size / 2] = (frame[frame.size / 2].toInt() xor 0x01).toByte()

        desktop.send(frame)

        desktop.assertClosedByPhone()
        phone.awaitServeEnded()
        coVerify(exactly = 0) { requestHandler.handleRawRequest(any<ByteArray>()) }
        assertNextDesktopIsServed()
    }

    /** A zero-length frame carries no authentication tag: the session ends and nothing runs. */
    @Test
    fun aZeroLengthFrameEndsTheSession() = runBlocking {
        val (desktop, phone) = pairedDesktop()

        desktop.send(ByteArray(0))

        desktop.assertClosedByPhone()
        phone.awaitServeEnded()
        coVerify(exactly = 0) { requestHandler.handleRawRequest(any<ByteArray>()) }
        assertNextDesktopIsServed()
    }

    /**
     * A reply over 65535 bytes cannot be framed: it is replaced by an
     * INTERNAL_ERROR under the request's id, and the same connection answers
     * the next request.
     */
    @Test
    fun aResponseOverTheFrameLimitIsAnsweredWithAnErrorAndTheConnectionGoesOn() = runBlocking {
        val (desktop, _) = pairedDesktop()

        desktop.send(desktop.noise.encrypt(request("test.big", id = 4)))

        val refused = desktop.readEncrypted()
        assertEquals(4L, refused.getLong("id"))
        assertEquals(
            com.automatethethings.xkey.protocol.ErrorCodes.INTERNAL_ERROR,
            refused.getJSONObject("error").getInt("code")
        )

        desktop.send(desktop.noise.encrypt(request("local.getCapabilities", id = 5)))
        assertEquals(5L, desktop.readEncrypted().getLong("id"))
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    private fun request(method: String, id: Long): ByteArray =
        JSONObject().put("jsonrpc", "2.0").put("id", id).put("method", method).toString().toByteArray()

    /** The transport key arrays [phone] held once connected are all zero now. */
    private fun assertKeysZeroed(phone: Phone) {
        assertEquals("both transport keys were held", 2, phone.keys.size)
        phone.keys.forEach { (name, key) -> assertTrue("$name is zeroed", key.all { it == 0.toByte() }) }
    }

    /** A paired desktop, handshaken and confirmed. */
    private suspend fun pairedDesktop(): Pair<DesktopPeer, Phone> {
        val desktop = newDesktop()
        repo.addDevice(desktop.publicKeyHex, "desktop")
        val phone = serve()
        desktop.handshake()
        withTimeout(TIMEOUT_MS) { phone.connected.await() }
        assertEquals(desktop.publicKeyHex, pairing.confirmedPeerKeyHex())
        // The arrays themselves: teardown may drop the references after zeroing them.
        phone.keys = phone.noise.secretArraysForTest().filterKeys { it in setOf("sendKey", "recvKey") }
        return desktop to phone
    }

    private suspend fun assertNextDesktopIsServed() {
        val (next, _) = pairedDesktop()
        val reply = next.request("local.getCapabilities", id = 11)
        assertTrue(reply.getJSONObject("result").getBoolean("ok"))
    }

    private fun newDesktop(): DesktopPeer = DesktopPeer(Socket(listener.inetAddress, listener.localPort))

    private class Phone(
        val noise: NoiseSession,
        val connected: CompletableDeferred<Unit>,
        private val served: CompletableDeferred<Throwable?>,
    ) {
        /** The session's transport key arrays, captured once connected. */
        var keys: Map<String, ByteArray> = emptyMap()

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
