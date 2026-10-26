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
import com.automatethethings.xkey.ble.NoiseSession
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.remote.BidirectionalMessageRouter
import com.automatethethings.xkey.remote.MessageSender
import com.automatethethings.xkey.transport.StreamPairingSession
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket

/**
 * TCP pairing server for ADB-forwarded (and emulator) connections.
 *
 * The phone listens on loopback `:8444`; the desktop reaches it via
 * `adb forward tcp:8444 tcp:8444` and connects to its own `localhost:8444`
 * (matching go-xkms `pkg/pairing` `DefaultTCPAddress = "localhost:8444"`). The
 * pairing protocol — identity exchange, Noise XX handshake, encrypted JSON-RPC
 * loop — is handled by the shared [StreamPairingSession], identical to the USB
 * transport; only the byte streams differ (a [Socket] instead of a USB
 * accessory file descriptor).
 *
 * Binding to the loopback address keeps the listener reachable only via ADB
 * forwarding (or a local emulator), not the LAN. One connection is served at a
 * time, which matches a single paired desktop.
 *
 * @param requestHandler The shared request handler for processing JSON-RPC requests.
 * @param messageRouter Optional bidirectional message router for remote.* requests.
 * @param pairingCallback Optional callback for pairing confirmation UI.
 * @param pairedDeviceRepository Optional repository for paired device management.
 */
class TcpHsmServer(
    requestHandler: RequestHandler,
    messageRouter: BidirectionalMessageRouter? = null,
    pairingCallback: com.automatethethings.xkey.ble.PairingConfirmationCallback? = null,
    pairedDeviceRepository: com.automatethethings.xkey.settings.PairedDeviceRepository? = null
) : MessageSender {
    companion object {
        private const val TAG = "TcpHsmServer"

        /** Default listening port (matches go-xkms pairing.DefaultTCPAddress). */
        const val DEFAULT_PORT = 8444
    }

    private val pairingSession = StreamPairingSession(
        requestHandler = requestHandler,
        messageRouter = messageRouter,
        pairingCallback = pairingCallback,
        pairedDeviceRepository = pairedDeviceRepository,
        transportLabel = "TCP",
    )

    /** Test seam: the pairing session's handshake deadline. */
    internal var handshakeTimeoutMs: Long
        get() = pairingSession.handshakeTimeoutMs
        set(value) {
            pairingSession.handshakeTimeoutMs = value
        }

    private val _state = MutableStateFlow<TcpHsmState>(TcpHsmState.Stopped)

    /** Observable state of the TCP server. */
    val state: StateFlow<TcpHsmState> = _state.asStateFlow()

    private var serverScope: CoroutineScope? = null
    private var serverSocket: ServerSocket? = null
    @Volatile private var activeSocket: Socket? = null
    private var acceptJob: Job? = null

    /**
     * Starts listening on loopback [port]. No-op if already started.
     *
     * @param context Android context for per-connection Noise key loading.
     */
    fun start(context: Context, port: Int = DEFAULT_PORT) {
        if (serverScope != null) {
            Log.w(TAG, "TCP server already started")
            return
        }
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        serverScope = scope
        acceptJob = scope.launch { acceptLoop(context, port) }
    }

    /**
     * Stops the server, closing the listener and any active connection.
     */
    fun stop() {
        Log.i(TAG, "Stopping TCP server")
        closeQuietly(activeSocket)
        activeSocket = null
        closeQuietly(serverSocket)
        serverSocket = null
        serverScope?.cancel()
        serverScope = null
        acceptJob = null
        _state.value = TcpHsmState.Stopped
    }

    private suspend fun acceptLoop(context: Context, port: Int) {
        try {
            val server = ServerSocket()
            server.reuseAddress = true
            server.bind(InetSocketAddress(InetAddress.getLoopbackAddress(), port))
            serverSocket = server
            _state.value = TcpHsmState.Listening(port)
            Log.i(TAG, "TCP server listening on loopback:$port")

            while (serverScope?.isActive == true) {
                val socket = try {
                    server.accept()
                } catch (e: IOException) {
                    // accept() throws when the server socket is closed by stop().
                    break
                }
                activeSocket = socket
                handleConnection(context, socket)
                activeSocket = null
            }
        } catch (e: Exception) {
            Log.e(TAG, "TCP accept loop error", e)
            _state.value = TcpHsmState.Error(e.message ?: "accept failed")
        } finally {
            _state.value = TcpHsmState.Stopped
        }
    }

    /**
     * Serves a single accepted connection for its lifetime, then returns so the
     * accept loop can take the next one.
     */
    private suspend fun handleConnection(context: Context, socket: Socket) {
        val remote = socket.remoteSocketAddress?.toString() ?: "unknown"
        try {
            socket.tcpNoDelay = true
            _state.value = TcpHsmState.Handshaking

            val noiseSession = NoiseSession()
            noiseSession.loadStaticKey(context)

            pairingSession.serve(
                input = socket.getInputStream(),
                output = socket.getOutputStream(),
                noiseSession = noiseSession,
                isActive = { serverScope?.isActive == true && !socket.isClosed },
                onConnected = { _state.value = TcpHsmState.Connected(remote) },
            )
        } catch (e: Exception) {
            Log.e(TAG, "TCP connection error from $remote", e)
        } finally {
            closeQuietly(socket)
            Log.i(TAG, "TCP connection closed: $remote")
            if (serverScope?.isActive == true) {
                _state.value = TcpHsmState.Listening(socket.localPort)
            }
        }
    }

    /**
     * Sends an encrypted message to the connected desktop (outbound remote.*).
     */
    override suspend fun sendEncryptedMessage(data: ByteArray) {
        pairingSession.sendEncryptedMessage(data)
    }

    private fun closeQuietly(closeable: java.io.Closeable?) {
        try {
            closeable?.close()
        } catch (e: IOException) {
            Log.w(TAG, "Error closing ${closeable?.javaClass?.simpleName}", e)
        }
    }
}

/**
 * Represents the state of the TCP HSM server.
 */
sealed class TcpHsmState {
    /** Server is not running. */
    data object Stopped : TcpHsmState()

    /** Server is listening for connections on [port]. */
    data class Listening(val port: Int) : TcpHsmState()

    /** A client connected and is performing the Noise XX handshake. */
    data object Handshaking : TcpHsmState()

    /** A client is connected and the encrypted session is established. */
    data class Connected(val remote: String) : TcpHsmState()

    /** An error occurred. */
    data class Error(val message: String) : TcpHsmState()
}
