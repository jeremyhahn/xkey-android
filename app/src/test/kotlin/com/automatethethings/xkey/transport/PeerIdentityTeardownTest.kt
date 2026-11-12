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

import android.app.KeyguardManager
import android.app.NotificationManager
import android.content.Context
import android.os.Looper
import android.util.Log
import com.automatethethings.xkey.ble.NoiseSession
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.settings.InMemorySharedPreferences
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.storage.XKeyDatabase
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.SecureRandom
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test

/**
 * The connected peer identity on the [RequestHandler] every transport shares
 * belongs to the session that set it (#134).
 *
 * A USB detach and reattach gives the reattached desktop a new
 * [StreamPairingSession], on a new server, while the detached session may
 * still be tearing down. That late teardown must not clear the identity the
 * replacement has already set, even for the same desktop key.
 *
 * Both sessions are real and run over loopback sockets against
 * [DesktopPeer]; so is the handler that holds the identity.
 */
class PeerIdentityTeardownTest {

    private companion object {
        const val TIMEOUT_MS = 10_000L
    }

    private lateinit var context: Context
    private lateinit var repo: PairedDeviceRepository
    private lateinit var handler: RequestHandler
    private lateinit var listener: ServerSocket
    private val connections = ServedConnections()

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

        context = mockk(relaxed = true)
        every { context.getSystemService(Context.KEYGUARD_SERVICE) } returns
            mockk<KeyguardManager>(relaxed = true)
        every { context.getSystemService(NotificationManager::class.java) } returns
            mockk<NotificationManager>(relaxed = true)
        repo = PairedDeviceRepository(InMemorySharedPreferences())
        handler = RequestHandler(
            context = context,
            keystoreManager = mockk<KeystoreManager>(relaxed = true),
            biometricLauncher = null,
            sessionAuthManager = null,
            pairedDeviceRepository = repo,
        )
        listener = ServerSocket(0, 1, InetAddress.getLoopbackAddress())
    }

    @After
    fun tearDown() {
        connections.end()
        listener.close()
        unmockkAll()
    }

    @Test
    fun `a detached session's late teardown keeps the reattached desktop's identity`() = runBlocking {
        val desktopKey = ByteArray(32).also { SecureRandom().nextBytes(it) }

        val old = connect(newSession(), desktopKey)
        assertEquals(old.desktop.publicKeyHex, handler.getConnectedDevicePublicKeyHex())

        // The reattach is served, and sets its peer, before the old session ends.
        val replacement = connect(newSession(), desktopKey)
        assertEquals(replacement.desktop.publicKeyHex, handler.getConnectedDevicePublicKeyHex())

        old.desktop.endOutput()
        withTimeout(TIMEOUT_MS) { old.served.await() }

        assertEquals(
            "the old session's teardown cleared the reattached desktop's identity",
            replacement.desktop.publicKeyHex,
            handler.getConnectedDevicePublicKeyHex(),
        )

        replacement.desktop.endOutput()
        withTimeout(TIMEOUT_MS) { replacement.served.await() }
        assertEquals(null, handler.getConnectedDevicePublicKeyHex())
    }

    private fun newSession() = StreamPairingSession(
        requestHandler = handler,
        messageRouter = null,
        pairingCallback = null,
        pairedDeviceRepository = repo,
        transportLabel = "USB",
    )

    private class Served(val desktop: DesktopPeer, val served: CompletableDeferred<Unit>)

    /** Connects a paired desktop with [key] to [session] and waits for the handshake. */
    private suspend fun connect(session: StreamPairingSession, key: ByteArray): Served {
        val desktop = DesktopPeer(Socket(listener.inetAddress, listener.localPort), key)
        repo.addDevice(desktop.publicKeyHex, "desktop")
        val accepted = connections.track(listener.accept())
        val noise = NoiseSession().also { it.loadStaticKey(context) }
        val connected = CompletableDeferred<Unit>()
        val served = CompletableDeferred<Unit>()
        connections.scope.launch {
            runCatching {
                session.serve(
                    input = accepted.getInputStream(),
                    output = accepted.getOutputStream(),
                    noiseSession = noise,
                    isActive = { !accepted.isClosed },
                    onConnected = { connected.complete(Unit) },
                )
            }
            accepted.close()
            served.complete(Unit)
        }
        desktop.handshake()
        withTimeout(TIMEOUT_MS) { connected.await() }
        return Served(desktop, served)
    }
}
