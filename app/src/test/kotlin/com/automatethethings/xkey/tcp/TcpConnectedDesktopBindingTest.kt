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

import android.content.Context
import android.util.Log
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.oath.OathCredentialEntity
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.remote.BidirectionalMessageRouter
import com.automatethethings.xkey.remote.ConnectedDesktop
import com.automatethethings.xkey.settings.InMemorySharedPreferences
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.transport.DesktopPeer
import com.automatethethings.xkey.ui.DesktopOathLinks
import com.automatethethings.xkey.ui.OathDesktopActions
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.runs
import io.mockk.unmockkAll
import java.io.IOException
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

/**
 * A [ConnectedDesktop] from [TcpHsmServer.connectedDesktop] sends only on
 * the connection whose handshake authenticated its key: once desktop A has
 * gone and paired desktop B holds the server, a send captured for A fails
 * and B receives nothing (ruling 554, #141).
 */
@OptIn(ExperimentalCoroutinesApi::class)
class TcpConnectedDesktopBindingTest {

    private companion object {
        const val TIMEOUT_MS = 10_000L
        val REQUEST = """{"jsonrpc":"2.0","id":9,"method":"remote.oathGenerate","params":{}}""".toByteArray()
    }

    private lateinit var repo: PairedDeviceRepository
    private lateinit var router: BidirectionalMessageRouter
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

        repo = PairedDeviceRepository(InMemorySharedPreferences())
        val requestHandler = mockk<RequestHandler>(relaxed = true)
        router = BidirectionalMessageRouter(requestHandler)
        server = TcpHsmServer(requestHandler = requestHandler, messageRouter = router, pairedDeviceRepository = repo)
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

    @Test
    fun aSendCapturedForDesktopAFailsOnceBHoldsTheServerAndBReceivesNothing() = runBlocking {
        val a = connectPaired()
        val captured = server.connectedDesktop(router)
        assertNotNull(captured)
        captured!!
        assertEquals(a.publicKeyHex, captured.peerKeyHex)

        val b = replace(a)
        assertEquals(b.publicKeyHex, server.connectedDesktop(router)!!.peerKeyHex)

        try {
            captured.sender.sendEncryptedMessage(REQUEST)
            fail("a send captured for A must not go out once B holds the server")
        } catch (e: IOException) {
            // A's connection is over.
        }
        b.assertNoFrame()
        server.closeAndAwaitListening(b)
    }

    @Test
    fun copyToDesktopWithAPeerSwapBeforeTheSendSendsBNothingAndLinksNothing() = runBlocking {
        var current = connectPaired()
        val links = RecordingLinks()
        val actions = OathDesktopActions(
            desktop = { server.connectedDesktop(router) },
            links = links,
            // The secret is read after the desktop is captured and before the send.
            secretOf = { _ -> current = replace(current); ByteArray(10) { 0x41 } }
        )

        val outcome = actions.copyToDesktop(entity())

        assertTrue("copy across a peer swap must fail: $outcome", outcome is OathDesktopActions.Outcome.Failed)
        current.assertNoFrame()
        assertTrue("no link may be written: ${links.puts}", links.puts.isEmpty())
        server.closeAndAwaitListening(current)
    }

    @Test
    fun desktopCodeWithAPeerSwapBeforeTheSendSendsBNothing() = runBlocking {
        var current = connectPaired()
        val links = RecordingLinks(onGet = { current = replace(current) })
        val actions = OathDesktopActions(
            desktop = { server.connectedDesktop(router) },
            links = links,
            secretOf = { _ -> fail("desktop code reads no secret"); ByteArray(0) }
        )

        val outcome = actions.desktopCode(entity())

        assertTrue("desktop code across a peer swap must fail: $outcome", outcome is OathDesktopActions.Outcome.Failed)
        current.assertNoFrame()
        server.closeAndAwaitListening(current)
    }

    @Test
    fun noDesktopOnceTheConnectionEnds() = runBlocking {
        val a = connectPaired()
        server.closeAndAwaitListening(a)
        assertNull(server.connectedDesktop(router))
    }

    /** Desktop [old] goes away and a second paired desktop takes the server. */
    private suspend fun replace(old: DesktopPeer): DesktopPeer {
        server.closeAndAwaitListening(old)
        return connectPaired()
    }

    private suspend fun connectPaired(): DesktopPeer {
        val desktop = DesktopPeer(Socket(InetAddress.getLoopbackAddress(), port))
        repo.addDevice(desktop.publicKeyHex, "desktop")
        desktop.handshake()
        withTimeout(TIMEOUT_MS) { server.state.first { it is TcpHsmState.Connected } }
        return desktop
    }

    private fun entity() = OathCredentialEntity(
        oathId = "GitHub:alice",
        oathType = "TOTP",
        algorithm = "SHA1",
        digits = 6,
        periodSeconds = 30,
        counter = 0,
        issuer = "GitHub",
        accountName = "alice",
        secretEncrypted = ByteArray(4),
        createdAt = 0L
    )

    /** Links that answer every lookup with a desktop ID, recording writes; [onGet] runs on each lookup. */
    private class RecordingLinks(private val onGet: suspend () -> Unit = {}) : DesktopOathLinks {
        val puts = mutableListOf<Triple<String, String, String>>()

        override fun get(peerKeyHex: String, oathId: String): String {
            runBlocking { onGet() }
            return "desk-7"
        }

        override fun put(peerKeyHex: String, oathId: String, desktopId: String) {
            puts += Triple(peerKeyHex, oathId, desktopId)
        }
    }
}
