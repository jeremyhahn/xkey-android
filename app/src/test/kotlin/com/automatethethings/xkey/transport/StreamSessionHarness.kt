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

import android.content.Context
import com.automatethethings.xkey.ble.NoiseSession
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.settings.InMemorySharedPreferences
import com.automatethethings.xkey.settings.PairedDeviceRepository
import io.mockk.mockk
import java.io.Closeable
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout

/**
 * One [StreamPairingSession], as TCP and USB each hold, serving paired
 * desktops over loopback sockets: [connectPaired] may be called again while
 * an earlier desktop is still connected, so the newer one replaces it.
 * Android `Log` must be stubbed by the caller.
 */
internal class StreamSessionHarness : Closeable {

    private val context = mockk<Context>(relaxed = true)
    val repo = PairedDeviceRepository(InMemorySharedPreferences())
    val pairing = StreamPairingSession(
        requestHandler = mockk<RequestHandler>(relaxed = true),
        messageRouter = null,
        pairingCallback = null,
        pairedDeviceRepository = repo,
        transportLabel = "TEST",
    )
    private val listener = ServerSocket(0, 4, InetAddress.getLoopbackAddress())
    private val connections = ServedConnections()

    /** Pairs a new desktop, connects it and waits until its handshake is installed. */
    suspend fun connectPaired(): DesktopPeer {
        val desktop = DesktopPeer(Socket(listener.inetAddress, listener.localPort))
        repo.addDevice(desktop.publicKeyHex, "desktop")
        val accepted = connections.track(listener.accept())
        val connected = CompletableDeferred<Unit>()
        connections.scope.launch {
            runCatching {
                pairing.serve(
                    input = accepted.getInputStream(),
                    output = accepted.getOutputStream(),
                    noiseSession = NoiseSession().also { it.loadStaticKey(context) },
                    isActive = { !accepted.isClosed },
                    onConnected = { connected.complete(Unit) },
                )
            }
            accepted.close()
        }
        desktop.handshake()
        withTimeout(TIMEOUT_MS) { connected.await() }
        return desktop
    }

    override fun close() {
        connections.end()
        listener.close()
    }

    private companion object {
        const val TIMEOUT_MS = 10_000L
    }
}
