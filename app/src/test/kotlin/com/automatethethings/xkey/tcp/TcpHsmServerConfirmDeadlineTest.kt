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

package com.automatethethings.xkey.tcp

import com.automatethethings.xkey.ble.NoiseTestKeyStore
import com.automatethethings.xkey.ble.PairingConfirmationCallback
import android.content.Context
import android.util.Log
import com.automatethethings.xkey.protocol.ErrorCodes
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.settings.InMemorySharedPreferences
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.transport.DesktopPeer
import io.mockk.clearMocks
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
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
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * After the handshake, a connection the user has not approved has a
 * deadline to send pairing.confirm, and one pairing.confirm to send: a
 * local client that handshakes with its own key cannot hold the one-at-a-time
 * listener by idling, or raise prompt after prompt until one is approved by
 * mistake. A confirmed connection keeps no deadline.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class TcpHsmServerConfirmDeadlineTest {

    private companion object {
        const val TIMEOUT_MS = 10_000L

        /** The test's confirm deadline, in place of the default. */
        const val DEADLINE_MS = 500L

        /** Slack for a loaded runner between the deadline and the close being seen. */
        const val SLACK_MS = 1_500L
    }

    private lateinit var repo: PairedDeviceRepository
    private lateinit var requestHandler: RequestHandler
    private lateinit var server: TcpHsmServer
    private lateinit var mainThread: ExecutorService
    private val prompts = AtomicInteger()
    @Volatile private var approve = false
    private var port = 0

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
        mainThread = Executors.newSingleThreadExecutor()
        Dispatchers.setMain(mainThread.asCoroutineDispatcher())

        repo = PairedDeviceRepository(InMemorySharedPreferences())
        requestHandler = mockk(relaxed = true)
        coEvery { requestHandler.handleRawRequest(any<ByteArray>()) } answers {
            val id = JSONObject(String(firstArg<ByteArray>())).optLong("id")
            """{"jsonrpc":"2.0","id":$id,"result":{"ok":true}}""".toByteArray()
        }
        val callback = object : PairingConfirmationCallback {
            override suspend fun onPairingConfirmationRequired(deviceName: String, publicKeyFingerprint: String): Boolean {
                prompts.incrementAndGet()
                return approve
            }
        }
        server = TcpHsmServer(
            requestHandler = requestHandler,
            pairingCallback = callback,
            pairedDeviceRepository = repo,
        )
        port = ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { it.localPort }
        server.start(mockk<Context>(relaxed = true), port)
        runBlocking {
            withTimeout(TIMEOUT_MS) { server.state.first { it is TcpHsmState.Listening } }
            warmUp()
        }
        server.confirmTimeoutMs = DEADLINE_MS
    }

    /** One paired desktop end to end, so each test times warm connections. */
    private suspend fun warmUp() {
        val desktop = DesktopPeer(Socket(InetAddress.getLoopbackAddress(), port))
        repo.addDevice(desktop.publicKeyHex, "warm-up")
        desktop.handshake()
        assertTrue(desktop.request("system.ping").getJSONObject("result").getBoolean("ok"))
        server.closeAndAwaitListening(desktop)
        clearMocks(requestHandler, answers = false)
    }

    @After
    fun tearDown() {
        server.stopAndAwaitStopped()
        Dispatchers.resetMain()
        mainThread.shutdownNow()
        unmockkAll()
    }

    /**
     * A client that handshakes with a key the phone does not know and then
     * sends nothing is closed at the confirm deadline, and the desktop queued
     * behind it is served.
     */
    @Test
    fun anUnconfirmedClientThatIdlesIsCutAndTheNextDesktopIsServed() = runBlocking {
        val idle = DesktopPeer(Socket(InetAddress.getLoopbackAddress(), port))
        idle.handshake()
        val started = System.nanoTime()

        // Connected now, so it waits in the backlog behind the idle client.
        val next = DesktopPeer(Socket(InetAddress.getLoopbackAddress(), port))
        repo.addDevice(next.publicKeyHex, "desktop")

        idle.assertClosedByPhone((DEADLINE_MS + SLACK_MS).toInt())
        val elapsedMs = (System.nanoTime() - started) / 1_000_000
        assertTrue("cut after $elapsedMs ms, before the deadline", elapsedMs >= DEADLINE_MS)
        assertEquals("no prompt for a client that sent nothing", 0, prompts.get())

        next.handshake()
        assertTrue(next.request("system.ping").getJSONObject("result").getBoolean("ok"))
        idle.close()
        server.closeAndAwaitListening(next)
    }

    /**
     * A refused pairing.confirm ends the connection: a second confirm sent
     * behind it raises no second prompt and is not answered, so a client
     * cannot repeat the prompt until the user approves one by mistake.
     */
    @Test
    fun aSecondPairingConfirmAfterARefusalRaisesNoPromptAndTheConnectionCloses() = runBlocking {
        approve = false
        val desktop = DesktopPeer(Socket(InetAddress.getLoopbackAddress(), port))
        desktop.handshake()
        withTimeout(TIMEOUT_MS) { server.state.first { it is TcpHsmState.Connected } }

        // Both sent before the first is answered, as a client repeating the prompt would.
        desktop.send(desktop.noise.encrypt(confirmText(1, desktop.publicKeyHex).toByteArray()))
        desktop.send(desktop.noise.encrypt(confirmText(2, desktop.publicKeyHex).toByteArray()))

        val first = desktop.readEncrypted()
        assertEquals(1L, first.getLong("id"))
        assertEquals(ErrorCodes.PAIRING_REJECTED, first.getJSONObject("error").getInt("code"))
        desktop.assertClosedByPhone((TIMEOUT_MS).toInt())
        assertEquals("one prompt per connection", 1, prompts.get())
        assertTrue(!repo.isDeviceKnown(desktop.publicKeyHex))
        server.closeAndAwaitListening(desktop)
    }

    private fun confirmText(id: Long, key: String) =
        """{"jsonrpc":"2.0","id":$id,"method":"pairing.confirm",""" +
            """"params":{"publicKeyHex":"$key","deviceName":"desktop"}}"""
}
