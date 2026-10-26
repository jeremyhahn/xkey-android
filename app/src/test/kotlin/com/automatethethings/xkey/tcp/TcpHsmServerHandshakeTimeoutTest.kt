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
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.settings.InMemorySharedPreferences
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.transport.DesktopPeer
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mockk.verify
import java.io.IOException
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import kotlin.concurrent.thread
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.withTimeout
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

/**
 * The handshake deadline (#64): a peer that connects and does not finish the
 * identity exchange and the Noise XX handshake in time is cut, so the accept
 * loop serves the next desktop. The deadline is shortened through the
 * server's seam; the encrypted session that follows a handshake has none.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class TcpHsmServerHandshakeTimeoutTest {

    private companion object {
        const val TIMEOUT_MS = 10_000L

        /** The test's handshake deadline, in place of the 10 s default. */
        const val DEADLINE_MS = 500L

        /** Slack for a loaded runner between the deadline and the close being seen. */
        const val SLACK_MS = 1_500L
    }

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
        mainThread = Executors.newSingleThreadExecutor()
        Dispatchers.setMain(mainThread.asCoroutineDispatcher())

        repo = PairedDeviceRepository(InMemorySharedPreferences())
        requestHandler = mockk(relaxed = true)
        coEvery { requestHandler.handleRawRequest(any<ByteArray>()) } answers {
            val id = JSONObject(String(firstArg<ByteArray>())).optLong("id")
            """{"jsonrpc":"2.0","id":$id,"result":{"ok":true}}""".toByteArray()
        }
        server = TcpHsmServer(requestHandler = requestHandler, pairedDeviceRepository = repo)
        server.handshakeTimeoutMs = DEADLINE_MS
        port = ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { it.localPort }
        server.start(mockk<Context>(relaxed = true), port)
        runBlocking { withTimeout(TIMEOUT_MS) { server.state.first { it is TcpHsmState.Listening } } }
    }

    @After
    fun tearDown() {
        server.stop()
        Dispatchers.resetMain()
        mainThread.shutdownNow()
        unmockkAll()
    }

    /**
     * The #64 regression: a peer that sends the identity exchange and half of
     * msg1, then goes quiet, is closed at the deadline, and the desktop
     * queued behind it pairs.
     */
    @Test
    fun aPeerThatGoesQuietMidHandshakeIsCutAndTheNextDesktopPairs() = runBlocking {
        val silentSocket = Socket(InetAddress.getLoopbackAddress(), port)
        val started = System.nanoTime()
        val silent = DesktopPeer(silentSocket)
        silent.exchangeIdentity()
        // A frame header promising 48 bytes, and one of them.
        silentSocket.getOutputStream().apply { write(byteArrayOf(0x00, 0x30, 0x01)); flush() }

        // Connected now, so it waits in the backlog behind the silent peer.
        val next = DesktopPeer(Socket(InetAddress.getLoopbackAddress(), port))
        repo.addDevice(next.publicKeyHex, "desktop")

        assertClosedWithin(silentSocket, DEADLINE_MS + SLACK_MS)
        val elapsedMs = (System.nanoTime() - started) / 1_000_000
        assertTrue("cut after ${elapsedMs} ms, before the deadline", elapsedMs >= DEADLINE_MS)
        // The cut connection never reached the encrypted session.
        verify(exactly = 0) { requestHandler.setConnectedDevicePublicKeyHex(any()) }

        next.handshake()
        withTimeout(TIMEOUT_MS) { server.state.first { it is TcpHsmState.Connected } }
        assertTrue(next.request("system.ping").getJSONObject("result").getBoolean("ok"))
        silent.close()
        server.closeAndAwaitListening(next)
    }

    /**
     * A peer that drips the identity frame one byte at a time, each well
     * inside the deadline, is still cut when the deadline for the whole
     * handshake runs out, long before its last byte.
     */
    @Test
    fun aPeerThatDripsBytesIsCutAtTheWholeHandshakeDeadline() = runBlocking {
        val gapMs = 100L
        // The identity frame: a 2-byte length (33) and [0x01 | 32-byte key].
        val frame = byteArrayOf(0x00, 0x21, 0x01) + ByteArray(32) { 0x11 }
        val dripMs = frame.size * gapMs
        val socket = Socket(InetAddress.getLoopbackAddress(), port)
        val started = System.nanoTime()
        val dripper = thread(name = "drip") {
            try {
                for (b in frame) {
                    socket.getOutputStream().apply { write(b.toInt()); flush() }
                    Thread.sleep(gapMs)
                }
            } catch (e: IOException) {
                // The phone closed the connection under the drip.
            } catch (e: InterruptedException) {
                // The test is over.
            }
        }

        assertClosedWithin(socket, DEADLINE_MS + SLACK_MS)
        val elapsedMs = (System.nanoTime() - started) / 1_000_000
        assertTrue("cut after ${elapsedMs} ms, not at the deadline", elapsedMs < dripMs - gapMs * 5)
        dripper.interrupt()
        socket.close()

        val next = DesktopPeer(Socket(InetAddress.getLoopbackAddress(), port))
        repo.addDevice(next.publicKeyHex, "desktop")
        next.handshake()
        assertTrue(next.request("system.ping").getJSONObject("result").getBoolean("ok"))
        server.closeAndAwaitListening(next)
    }

    /** Once the handshake completes the deadline is gone: a quiet paired desktop stays connected. */
    @Test
    fun aCompletedHandshakeThatThenIdlesStaysOpen() = runBlocking {
        val desktop = DesktopPeer(Socket(InetAddress.getLoopbackAddress(), port))
        repo.addDevice(desktop.publicKeyHex, "desktop")
        desktop.handshake()
        withTimeout(TIMEOUT_MS) { server.state.first { it is TcpHsmState.Connected } }

        delay(DEADLINE_MS * 3)

        assertTrue(server.state.value is TcpHsmState.Connected)
        assertTrue(desktop.request("system.ping").getJSONObject("result").getBoolean("ok"))
        server.closeAndAwaitListening(desktop)
    }

    /** The phone closes [socket] within [millis]: a read ends without a byte. */
    private fun assertClosedWithin(socket: Socket, millis: Long) {
        socket.soTimeout = millis.toInt()
        try {
            val read = socket.getInputStream().read()
            if (read != -1) fail("expected the transport to close, got a byte")
        } catch (e: SocketTimeoutException) {
            fail("the phone did not close the transport within $millis ms")
        } catch (e: IOException) {
            // A reset: the phone closed it.
        } finally {
            socket.soTimeout = 0
        }
    }
}
