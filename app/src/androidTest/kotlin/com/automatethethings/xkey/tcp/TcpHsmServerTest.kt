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
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.auth.SessionAuthManager
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.remote.BidirectionalMessageRouter
import com.automatethethings.xkey.settings.AttestationBiometricPolicy
import com.automatethethings.xkey.settings.BiometricSettingsData
import com.automatethethings.xkey.settings.UserVerificationPolicy
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Lifecycle and failure-path coverage for [TcpHsmServer] — the loopback
 * listener the desktop reaches through `adb forward tcp:8444`.
 *
 * The protocol itself is covered by `ProtocolIntegrationTest` and
 * [com.automatethethings.xkey.transport.StreamPairingSessionTest]; what is
 * tested here is everything around it: binding, refusing a second start,
 * stopping (including before ever starting), and recovering from a connection
 * that dies during the handshake.
 *
 * Every server binds loopback on a port unique to this suite and is stopped in
 * [tearDown], so nothing is left listening for another suite to trip over.
 */
@RunWith(AndroidJUnit4::class)
class TcpHsmServerTest {

    private companion object {
        const val PRIMARY_PORT = 18611
        const val CONFLICT_PORT = 18612
        const val LIFECYCLE_PORT = 18613
    }

    private lateinit var context: Context
    private val servers = mutableListOf<TcpHsmServer>()

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        servers.clear()
    }

    @After
    fun tearDown() {
        for (server in servers) {
            runCatching { server.stop() }
        }
        servers.clear()
    }

    // ------------------------------------------------------------------
    // Start and stop
    // ------------------------------------------------------------------

    @Test
    fun startingBindsLoopbackAndReportsTheListeningPort() {
        val server = newServer()
        server.start(context, PRIMARY_PORT)

        assertEquals(TcpHsmState.Listening(PRIMARY_PORT), awaitListening(server))

        // Loopback only: the listener must be reachable at 127.0.0.1.
        Socket().use {
            it.connect(InetSocketAddress(InetAddress.getLoopbackAddress(), PRIMARY_PORT), 2000)
            assertTrue(it.isConnected)
        }
    }

    /** A second start on an already-running server is ignored, not an error. */
    @Test
    fun startingTwiceIsANoOp() {
        val server = newServer()
        server.start(context, PRIMARY_PORT)
        awaitListening(server)

        // Would throw "address already in use" if it really started again.
        server.start(context, PRIMARY_PORT)

        assertEquals(TcpHsmState.Listening(PRIMARY_PORT), server.state.value)
    }

    /** Stopping a server that was never started must not throw. */
    @Test
    fun stoppingAServerThatNeverStartedIsSafe() {
        val server = newServer()

        server.stop()

        assertEquals(TcpHsmState.Stopped, server.state.value)
    }

    @Test
    fun stoppingReleasesThePortForAnotherServer() {
        val first = newServer()
        first.start(context, LIFECYCLE_PORT)
        awaitListening(first)
        first.stop()
        assertEquals(TcpHsmState.Stopped, first.state.value)

        val second = newServer()
        second.start(context, LIFECYCLE_PORT)
        assertEquals(TcpHsmState.Listening(LIFECYCLE_PORT), awaitListening(second))
    }

    @Test
    fun stoppingIsIdempotent() {
        val server = newServer()
        server.start(context, LIFECYCLE_PORT)
        awaitListening(server)

        server.stop()
        server.stop()

        assertEquals(TcpHsmState.Stopped, server.state.value)
    }

    /**
     * A port already taken must leave the server stopped rather than silently
     * reporting itself as listening on a socket it never got.
     */
    @Test
    fun bindingAPortAlreadyInUseDoesNotReportListening() {
        val holder = newServer()
        holder.start(context, CONFLICT_PORT)
        awaitListening(holder)

        val loser = newServer()
        loser.start(context, CONFLICT_PORT)

        // The bind failure is reported and then the loop unwinds to Stopped, so
        // sample the state rather than waiting for one transient value.
        val deadline = System.currentTimeMillis() + 2000
        while (System.currentTimeMillis() < deadline) {
            assertTrue(
                "a server that could not bind must never claim to be listening",
                loser.state.value !is TcpHsmState.Listening
            )
            Thread.sleep(50)
        }
        assertEquals(TcpHsmState.Stopped, loser.state.value)

        // The holder is untouched by the failed bind.
        assertEquals(TcpHsmState.Listening(CONFLICT_PORT), holder.state.value)
    }

    // ------------------------------------------------------------------
    // Connection handling
    // ------------------------------------------------------------------

    /**
     * A peer that connects and vanishes before the handshake completes is an
     * ordinary occurrence (a probe, a cancelled `xkey device pair`). The server
     * must clean the connection up and go back to accepting.
     */
    @Test
    fun aConnectionThatDiesDuringTheHandshakeReturnsTheServerToListening() {
        val server = newServer()
        server.start(context, PRIMARY_PORT)
        awaitListening(server)

        Socket().use {
            it.connect(InetSocketAddress(InetAddress.getLoopbackAddress(), PRIMARY_PORT), 2000)
        }

        assertTrue(
            "the server must accept another connection afterwards",
            runBlocking {
                withTimeoutOrNull(5000) {
                    server.state.first { it is TcpHsmState.Listening }
                } != null
            }
        )

        Socket().use {
            it.connect(InetSocketAddress(InetAddress.getLoopbackAddress(), PRIMARY_PORT), 2000)
            assertTrue(it.isConnected)
        }
    }

    @Test
    fun aStoppedServerOffersNoDesktopToSendTo() {
        val server = newServer()
        server.start(context, PRIMARY_PORT)
        awaitListening(server)
        server.stop()

        // Sends go only through a ConnectedDesktop's bound sender.
        assertNull(server.connectedDesktop(BidirectionalMessageRouter(newHandler())))
    }

    // ------------------------------------------------------------------
    // Fixtures
    // ------------------------------------------------------------------

    /** A server registered for teardown, built with every optional argument defaulted. */
    private fun newServer(): TcpHsmServer = TcpHsmServer(newHandler()).also { servers.add(it) }

    private fun newHandler(): RequestHandler {
        val handler = RequestHandler(
            context = context,
            keystoreManager = KeystoreManager(context),
            biometricLauncher = null,
            sessionAuthManager = SessionAuthManager()
        ).apply {
            updateSettings(
                BiometricSettingsData(
                    uvPolicy = UserVerificationPolicy.DISABLED,
                    attestationBiometricPolicy = AttestationBiometricPolicy.NEVER
                )
            )
        }
        return handler
    }

    private fun awaitListening(server: TcpHsmServer): TcpHsmState = runBlocking {
        withTimeout(5000) { server.state.first { it is TcpHsmState.Listening } }
    }
}
