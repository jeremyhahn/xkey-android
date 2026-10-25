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
import kotlinx.coroutines.delay
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
        server.stop()
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
        coEvery {
            requestHandler.handleRawRequest(match<ByteArray> { String(it).contains("local.generateKey") })
        } coAnswers {
            started.complete(Unit)
            approval.await()
            ran.set(true)
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
        delay(200)
        assertFalse("an approval after the revocation must run nothing", ran.get())

        val next = connectPaired()
        assertTrue(next.request("system.ping").getJSONObject("result").getBoolean("ok"))
    }

    /**
     * The desktop stops reading, so the phone's outbound writes fill the
     * socket buffers until one blocks; then the desktop ends its stream
     * (Codex 7162). The teardown closes the connection before it waits on
     * the send lock: the blocked write fails, the connection ends, and the
     * server accepts and serves the next one.
     */
    @Test
    fun anEofWhileAnOutboundWriteIsBlockedEndsTheConnectionAndTheNextIsServed() = runBlocking<Unit> {
        val desktop = connectPaired()
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
                    sent.incrementAndGet()
                }
            } catch (e: IOException) {
                // The teardown closed the connection under the blocked write.
            }
        }
        var last = -1
        withTimeout(TIMEOUT_MS) {
            while (sent.get() != last) {
                last = sent.get()
                delay(500)
            }
        }
        assertTrue("the sends never filled the socket buffers", last > 0)
        assertTrue("a write must be blocked", sender.isActive)

        desktop.endOutput()

        withTimeout(TIMEOUT_MS) { sender.join() }
        withTimeout(TIMEOUT_MS) { server.state.first { it is TcpHsmState.Listening } }
        verify(timeout = TIMEOUT_MS) { requestHandler.setConnectedDevicePublicKeyHex(null) }
        desktop.close()

        val next = connectPaired()
        assertTrue(next.request("system.ping").getJSONObject("result").getBoolean("ok"))
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
}
