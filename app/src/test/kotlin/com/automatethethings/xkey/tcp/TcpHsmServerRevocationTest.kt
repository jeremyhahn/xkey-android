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

package com.automatethethings.xkey.tcp

import android.content.Context
import android.util.Log
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.settings.InMemorySharedPreferences
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.settings.PeerNotPairedException
import com.automatethethings.xkey.transport.DesktopPeer
import io.mockk.coEvery
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
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.withTimeout
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

/**
 * Unpairing a desktop revokes its live TCP session, and a phone-initiated
 * send to a peer that is no longer paired is refused before encryption (#59).
 * Runs [TcpHsmServer] end to end on a loopback port against [DesktopPeer].
 */
@OptIn(ExperimentalCoroutinesApi::class)
class TcpHsmServerRevocationTest {

    private companion object {
        const val TIMEOUT_MS = 10_000L

        /** StreamPairingSession's frame buffer. */
        const val FRAME_BUFFER = 16
        val REQUEST = """{"jsonrpc":"2.0","id":9,"method":"remote.sync","params":{}}""".toByteArray()
    }

    private lateinit var prefs: InMemorySharedPreferences
    private lateinit var repo: PairedDeviceRepository
    private lateinit var requestHandler: RequestHandler
    private lateinit var server: TcpHsmServer
    private lateinit var mainThread: ExecutorService
    private var port = 0

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

        prefs = InMemorySharedPreferences()
        repo = PairedDeviceRepository(prefs)
        requestHandler = mockk(relaxed = true)
        coEvery { requestHandler.handleRawRequest(any<ByteArray>()) } answers {
            val id = JSONObject(String(firstArg<ByteArray>())).optLong("id")
            """{"jsonrpc":"2.0","id":$id,"result":{"ok":true}}""".toByteArray()
        }
        server = TcpHsmServer(requestHandler = requestHandler, pairedDeviceRepository = repo)
        port = ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { it.localPort }
        server.start(mockk<Context>(relaxed = true), port)
        runBlocking { withTimeout(TIMEOUT_MS) { server.state.first { it is TcpHsmState.Listening } } }
    }

    @After
    fun tearDown() {
        server.stopAndAwaitStopped()
        Dispatchers.resetMain()
        mainThread.shutdownNow()
        unmockkAll()
    }

    /** Unpairing the connected desktop closes its connection; the phone has nothing left to send on. */
    @Test
    fun unpairingTheConnectedDesktopClosesItsConnection() = runBlocking {
        val desktop = connectPaired()
        assertTrue(desktop.request("system.ping").getJSONObject("result").getBoolean("ok"))

        repo.removeDevice(desktop.publicKeyHex)

        desktop.assertClosedByPhone()
        withTimeout(TIMEOUT_MS) { server.state.first { it is TcpHsmState.Listening } }
        try {
            server.sendEncryptedMessage(REQUEST)
            fail("a send after the teardown must be refused")
        } catch (e: IOException) {
            // No session left to send on.
        }
    }

    /**
     * A send to a desktop whose record is gone is refused and writes nothing.
     * Once the record is back, the next request decrypts on the desktop, which
     * proves the refused send consumed no nonce.
     */
    @Test
    fun aSendToADesktopThatIsNoLongerPairedIsRefusedAndConsumesNoNonce() = runBlocking {
        val desktop = connectPaired()
        prefs.edit().clear().apply()

        try {
            server.sendEncryptedMessage(REQUEST)
            fail("the send must be refused")
        } catch (e: PeerNotPairedException) {
            assertEquals(desktop.publicKeyHex, e.publicKeyHex)
        }
        desktop.assertNoFrame()

        repo.addDevice(desktop.publicKeyHex, "desktop")
        server.sendEncryptedMessage(REQUEST)
        assertEquals("remote.sync", desktop.readEncrypted().getString("method"))
        server.closeAndAwaitListening(desktop)
    }

    /**
     * The desktop is unpaired while its `local.generateKey` waits for the
     * user's approval (Codex 7155). The request is cancelled there: approving
     * afterwards runs nothing, the connection's teardown clears the handler's
     * identity, and the server accepts and serves the next connection.
     */
    @Test
    fun unpairingWhileARequestAwaitsApprovalCancelsItAndTheNextConnectionIsServed() = runBlocking<Unit> {
        val started = CompletableDeferred<Unit>()
        val approval = CompletableDeferred<Unit>()
        val ran = AtomicBoolean(false)
        val finished = CompletableDeferred<Unit>()
        coEvery {
            requestHandler.handleRawRequest(match<ByteArray> { String(it).contains("local.generateKey") })
        } coAnswers {
            started.complete(Unit)
            try {
                approval.await()
                ran.set(true)
            } finally {
                finished.complete(Unit)
            }
            """{"jsonrpc":"2.0","id":5,"result":{"ok":true}}""".toByteArray()
        }
        val desktop = connectPaired()
        val generateKey = JSONObject()
            .put("jsonrpc", "2.0")
            .put("id", 5)
            .put("method", "local.generateKey")
            .put("params", JSONObject())
        desktop.send(desktop.noise.encrypt(generateKey.toString().toByteArray()))
        withTimeout(TIMEOUT_MS) { started.await() }

        repo.removeDevice(desktop.publicKeyHex)

        desktop.assertClosedByPhone()
        withTimeout(TIMEOUT_MS) { server.state.first { it is TcpHsmState.Listening } }
        verify(timeout = TIMEOUT_MS) { requestHandler.setConnectedDevicePublicKeyHex(null) }
        approval.complete(Unit)
        // A request the revocation left waiting would run now; either way its body ends.
        withTimeout(TIMEOUT_MS) { finished.await() }
        assertFalse("an approval after the revocation must run nothing", ran.get())

        val next = connectPaired()
        assertTrue(next.request("system.ping").getJSONObject("result").getBoolean("ok"))
        server.closeAndAwaitListening(next)
    }

    /**
     * The desktop's stream ends while its `local.verifyUser` waits on a prompt
     * nobody answers (Codex 7369). The request is cancelled with no user
     * input, nothing is written, and the server goes back to listening and
     * serves the next connection.
     */
    @Test
    fun aStreamThatEndsWhileVerifyUserPromptsCancelsItAndTheNextConnectionIsServed() = runBlocking<Unit> {
        val shown = CompletableDeferred<Unit>()
        val dismissed = CompletableDeferred<Unit>()
        coEvery {
            requestHandler.handleRawRequest(match<ByteArray> { String(it).contains("local.verifyUser") })
        } coAnswers {
            shown.complete(Unit)
            try {
                awaitCancellation()
            } finally {
                dismissed.complete(Unit)
            }
        }
        val desktop = connectPaired()
        val verifyUser = JSONObject()
            .put("jsonrpc", "2.0")
            .put("id", 7)
            .put("method", "local.verifyUser")
            .put("params", JSONObject())
        desktop.send(desktop.noise.encrypt(verifyUser.toString().toByteArray()))
        withTimeout(TIMEOUT_MS) { shown.await() }

        desktop.endOutput()

        withTimeout(TIMEOUT_MS) { dismissed.await() }
        desktop.assertClosedByPhone()
        withTimeout(TIMEOUT_MS) { server.state.first { it is TcpHsmState.Listening } }
        verify(timeout = TIMEOUT_MS) { requestHandler.setConnectedDevicePublicKeyHex(null) }

        val next = connectPaired()
        assertTrue(next.request("system.ping").getJSONObject("result").getBoolean("ok"))
        server.closeAndAwaitListening(next)
    }

    /**
     * The desktop sends past the frame buffer while its `local.verifyUser`
     * waits on a prompt nobody answers. The overflow ends the
     * connection and cancels the request, and the server serves the next one.
     */
    @Test
    fun aFrameBufferOverflowWhileVerifyUserPromptsEndsTheConnectionAndTheNextIsServed() = runBlocking<Unit> {
        val shown = CompletableDeferred<Unit>()
        val dismissed = CompletableDeferred<Unit>()
        coEvery {
            requestHandler.handleRawRequest(match<ByteArray> { String(it).contains("local.verifyUser") })
        } coAnswers {
            shown.complete(Unit)
            try {
                awaitCancellation()
            } finally {
                dismissed.complete(Unit)
            }
        }
        val desktop = connectPaired()
        desktop.send(desktop.noise.encrypt(jsonRpc(id = 7, method = "local.verifyUser")))
        withTimeout(TIMEOUT_MS) { shown.await() }

        repeat(FRAME_BUFFER + 1) { desktop.send(desktop.noise.encrypt(jsonRpc(id = 8 + it, method = "system.ping"))) }

        withTimeout(TIMEOUT_MS) { dismissed.await() }
        desktop.assertClosedByPhone()
        withTimeout(TIMEOUT_MS) { server.state.first { it is TcpHsmState.Listening } }
        verify(timeout = TIMEOUT_MS) { requestHandler.setConnectedDevicePublicKeyHex(null) }

        val next = connectPaired()
        assertTrue(next.request("system.ping").getJSONObject("result").getBoolean("ok"))
        server.closeAndAwaitListening(next)
    }

    private fun jsonRpc(id: Int, method: String): ByteArray = JSONObject()
        .put("jsonrpc", "2.0")
        .put("id", id)
        .put("method", method)
        .put("params", JSONObject())
        .toString()
        .toByteArray()

    /**
     * The desktop stops reading, and an outbound write from the phone fills
     * the socket buffers until it blocks ([HoldingOutputStream]); then the
     * desktop ends its stream
     * (Codex 7162). The teardown closes the connection before it waits on
     * the send lock: the blocked write fails, the connection ends, and the
     * server accepts and serves the next one.
     */
    @Test
    fun anEofWhileAnOutboundWriteIsBlockedEndsTheConnectionAndTheNextIsServed() = runBlocking<Unit> {
        assertEofBehindABlockedWriteEndsTheConnection(answerWaiting = false)
    }

    /**
     * As above, but an answer to the desktop's last request waits on the send
     * lock behind the blocked write when the stream ends, so the frames read
     * before the end cannot finish draining. The drain is bounded: the
     * connection ends, and the next one is served (Codex 7380).
     */
    @Test
    fun anEofWhileAnAnswerWaitsBehindABlockedWriteEndsTheConnectionAndTheNextIsServed() = runBlocking<Unit> {
        assertEofBehindABlockedWriteEndsTheConnection(answerWaiting = true)
    }

    private suspend fun assertEofBehindABlockedWriteEndsTheConnection(answerWaiting: Boolean) = coroutineScope {
        val output = CompletableDeferred<HoldingOutputStream>()
        server.outputStreamForTest = { stream -> HoldingOutputStream(stream).also { output.complete(it) } }
        val desktop = connectPaired()
        val held = output.await()
        val large = JSONObject()
            .put("jsonrpc", "2.0")
            .put("id", 9)
            .put("method", "remote.sync")
            .put("params", JSONObject().put("pad", "x".repeat(60_000)))
            .toString()
            .toByteArray()
        val sent = AtomicInteger()
        val sender = launch(Dispatchers.IO) {
            try {
                while (true) {
                    server.sendEncryptedMessage(large)
                    // The first frame goes out; the next write blocks.
                    if (sent.incrementAndGet() == 1) held.holdWrites()
                }
            } catch (e: IOException) {
                // The teardown closed the connection under the blocked write.
            }
        }
        withTimeout(TIMEOUT_MS) { held.writeBlocked.await() }
        assertTrue("no send went out before the write blocked", sent.get() > 0)
        assertTrue("a write must be blocked", sender.isActive)

        if (answerWaiting) {
            val answerQueued = CompletableDeferred<Unit>()
            server.beforeSendLockForTest = { answerQueued.complete(Unit) }
            desktop.send(desktop.noise.encrypt(jsonRpc(id = 10, method = "system.ping")))
            // The ping is answered and its answer queues for the send lock.
            withTimeout(TIMEOUT_MS) { answerQueued.await() }
        }
        desktop.endOutput()

        withTimeout(TIMEOUT_MS) { sender.join() }
        withTimeout(TIMEOUT_MS) { server.state.first { it is TcpHsmState.Listening } }
        verify(timeout = TIMEOUT_MS) { requestHandler.setConnectedDevicePublicKeyHex(null) }
        desktop.close()

        val next = connectPaired()
        assertTrue(next.request("system.ping").getJSONObject("result").getBoolean("ok"))
        server.closeAndAwaitListening(next)
    }

    /** The same desktop key, paired again after a removal, is served on the next connection. */
    @Test
    fun rePairingTheSameDesktopAfterARemovalWorks() = runBlocking {
        val key = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        val first = connectPaired(key)
        repo.removeDevice(first.publicKeyHex)
        first.assertClosedByPhone()
        withTimeout(TIMEOUT_MS) { server.state.first { it is TcpHsmState.Listening } }

        val second = connectPaired(key)
        assertTrue(second.request("system.ping").getJSONObject("result").getBoolean("ok"))
        server.sendEncryptedMessage(REQUEST)
        assertEquals("remote.sync", second.readEncrypted().getString("method"))
        server.closeAndAwaitListening(second)
    }

    private suspend fun connectPaired(
        staticPrivateKey: ByteArray = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) },
    ): DesktopPeer {
        val desktop = DesktopPeer(Socket(InetAddress.getLoopbackAddress(), port), staticPrivateKey)
        repo.addDevice(desktop.publicKeyHex, "desktop")
        desktop.handshake()
        withTimeout(TIMEOUT_MS) { server.state.first { it is TcpHsmState.Connected } }
        return desktop
    }

    /**
     * A connection's output stream whose next write, once [holdWrites] is
     * called, never finishes: it keeps writing to the socket until the
     * buffers fill and the write blocks, and fails when the socket is closed.
     */
    private class HoldingOutputStream(private val socket: OutputStream) : OutputStream() {
        @Volatile private var holding = false

        /** Completes when a write that cannot finish has started. */
        val writeBlocked = CompletableDeferred<Unit>()

        fun holdWrites() {
            holding = true
        }

        override fun write(b: Int) = write(byteArrayOf(b.toByte()), 0, 1)

        override fun write(b: ByteArray, off: Int, len: Int) {
            if (!holding) return socket.write(b, off, len)
            writeBlocked.complete(Unit)
            // The desktop reads nothing: this blocks once the socket buffers
            // fill, and fails when the connection is closed.
            val filler = ByteArray(64 * 1024)
            while (true) socket.write(filler)
        }

        override fun flush() = socket.flush()

        override fun close() = socket.close()
    }
}
