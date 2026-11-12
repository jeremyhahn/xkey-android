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
package com.automatethethings.xkey.usb

import android.content.Context
import android.hardware.usb.UsbAccessory
import android.hardware.usb.UsbManager
import android.os.ParcelFileDescriptor
import android.util.Log
import com.automatethethings.xkey.ble.NoiseSession
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.protocol.TransportMethods
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
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.util.UUID

/**
 * USB Accessory Mode server for direct USB communication without ADB.
 *
 * The phone acts as a USB accessory and the laptop as the USB host, eliminating
 * the need for ADB port forwarding. The pairing protocol — pre-handshake
 * identity exchange, Noise XX handshake, and the encrypted JSON-RPC message loop
 * — is handled by the shared [StreamPairingSession]; this class only manages the
 * USB accessory lifecycle and supplies the framed byte streams over a
 * [ParcelFileDescriptor].
 *
 * Message framing: see [com.automatethethings.xkey.transport.StreamMessageFraming]
 * (2-byte big-endian length prefix per Noise message), shared with the TCP transport.
 *
 * Lifecycle:
 * 1. Android delivers a USB_ACCESSORY_ATTACHED intent.
 * 2. [connect] starts watching for the accessory's USB_ACCESSORY_DETACHED
 *    broadcast, then opens the file descriptor and starts the session. The
 *    watch comes first so a cable pulled during the open is not missed.
 * 3. [StreamPairingSession] performs the handshake and processes messages.
 * 4. On USB_ACCESSORY_DETACHED (the cable pulled) the server [disconnect]s:
 *    it closes the streams and descriptor, ends the session and tells its
 *    owner through `onClosed`. A later attach serves again.
 *
 * A session that ends by itself (the host closed its end, or no broadcast
 * came) and a refused open close everything too and tell the owner through
 * `onClosed`, so a later [connect] opens the accessory again.
 *
 * @param requestHandler The shared request handler for processing JSON-RPC requests.
 * @param messageRouter Optional bidirectional message router for remote.* requests.
 * @param pairingCallback Optional callback for pairing confirmation UI.
 * @param pairedDeviceRepository Optional repository for paired device management.
 * @param storeMethods Method families served on USB only (the password and seal
 *   stores go-xkms proxies over this transport), ahead of [requestHandler].
 * @param detachWatcher Watches for the open accessory's detach.
 * @param onClosed Called when the accessory closes other than through
 *   [disconnect]: a detach, a session that ended by itself, or a refused
 *   open. The owner can drop this server and build a fresh one on the next
 *   attach.
 */
class UsbAccessoryServer(
    private val requestHandler: RequestHandler,
    messageRouter: BidirectionalMessageRouter? = null,
    pairingCallback: com.automatethethings.xkey.ble.PairingConfirmationCallback? = null,
    pairedDeviceRepository: com.automatethethings.xkey.settings.PairedDeviceRepository? = null,
    storeMethods: List<TransportMethods> = emptyList(),
    private val detachWatcher: AccessoryDetachWatcher = BroadcastAccessoryDetachWatcher(),
    private val onClosed: () -> Unit = {},
) : MessageSender {
    companion object {
        private const val TAG = "UsbAccessoryServer"
    }

    private val pairingSession = StreamPairingSession(
        requestHandler = requestHandler,
        messageRouter = messageRouter,
        pairingCallback = pairingCallback,
        pairedDeviceRepository = pairedDeviceRepository,
        transportLabel = "USB",
        transportMethods = storeMethods,
    )

    private val _state = MutableStateFlow<UsbAccessoryState>(UsbAccessoryState.Disconnected)

    /** Observable state of the USB accessory server. */
    val state: StateFlow<UsbAccessoryState> = _state.asStateFlow()

    /**
     * Guards the connection fields below and [_state] changes: the detach
     * broadcast, the session coroutine and [connect] race.
     */
    private val lock = Any()
    private var serverScope: CoroutineScope? = null
    private var fileDescriptor: ParcelFileDescriptor? = null
    private var inputStream: FileInputStream? = null
    private var outputStream: FileOutputStream? = null
    private var connectionJob: Job? = null

    /** The accessory opened last, until it detaches or [disconnect] runs. */
    private var accessory: UsbAccessory? = null

    /** True while an accessory's streams are open and its session runs. */
    internal val isOpen: Boolean
        get() = synchronized(lock) { serverScope != null }

    /** The coroutine of the session started last, kept after it ends. */
    private var lastSessionJob: Job? = null

    /** The last session's coroutine, for tests that wait for it to end. */
    internal val sessionJob: Job?
        get() = synchronized(lock) { lastSessionJob }

    /**
     * Opens the USB accessory and starts the communication session.
     *
     * @param context Android context for USB manager access and Noise key loading.
     * @param accessory The USB accessory to connect to.
     */
    fun connect(context: Context, accessory: UsbAccessory) {
        val opened = synchronized(lock) {
            if (serverScope != null) {
                Log.w(TAG, "Already connected to an accessory")
                return
            }

            // Watch before the open: the detach broadcast is not sticky, so a
            // cable pulled during the open would otherwise go unseen. A detach
            // on another thread waits on the lock and then closes what opened.
            this.accessory = accessory
            detachWatcher.stop()
            detachWatcher.start(context) { detached -> onAccessoryDetached(detached) }

            val usbManager = context.getSystemService(Context.USB_SERVICE) as UsbManager
            val fd = usbManager.openAccessory(accessory)
            when {
                this.accessory !== accessory -> {
                    // Detached on this thread during the open, which has
                    // already told the owner: the descriptor is for a gone
                    // accessory.
                    Log.w(TAG, "USB accessory detached while opening")
                    closeQuietly(fd)
                    return
                }
                fd == null -> {
                    Log.e(TAG, "Failed to open USB accessory")
                    detachWatcher.stop()
                    this.accessory = null
                    _state.value = UsbAccessoryState.Error("Failed to open USB accessory")
                    false
                }
                else -> {
                    fileDescriptor = fd
                    // Each connection is its own session, so a PER_SESSION
                    // approval given before a detach does not carry over to
                    // the next attach (#134).
                    requestHandler.setSessionId("usb:${UUID.randomUUID()}")
                    inputStream = FileInputStream(fd.fileDescriptor)
                    outputStream = FileOutputStream(fd.fileDescriptor)

                    val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
                    serverScope = scope
                    _state.value = UsbAccessoryState.Handshaking
                    connectionJob = scope.launch {
                        handleConnection(context, accessory.toString(), scope)
                    }
                    lastSessionJob = connectionJob
                    true
                }
            }
        }

        if (opened) {
            Log.i(TAG, "USB accessory opened: ${accessory.manufacturer} ${accessory.model}")
        } else {
            onClosed()
        }
    }

    /**
     * Disconnects from the USB accessory and releases resources: the streams,
     * the descriptor, the session scope and the detach watcher.
     */
    fun disconnect() {
        Log.i(TAG, "Disconnecting USB accessory")
        synchronized(lock) {
            detachWatcher.stop()
            accessory = null
            closeStreams()
            serverScope?.cancel()
            serverScope = null
            connectionJob = null
            _state.value = UsbAccessoryState.Disconnected
        }
    }

    /**
     * Handles USB_ACCESSORY_DETACHED for [detached] (null when the broadcast
     * names none): when it is the accessory this server opened, closes it and
     * its session and calls `onClosed`. A detach of another accessory is
     * ignored.
     */
    internal fun onAccessoryDetached(detached: UsbAccessory?) {
        synchronized(lock) {
            val current = accessory ?: return
            if (detached != null && detached != current) {
                Log.d(TAG, "Ignoring the detach of another accessory")
                return
            }
        }
        Log.i(TAG, "USB accessory detached")
        disconnect()
        onClosed()
    }

    /**
     * Drives the pairing session over the USB streams for the connection lifetime.
     */
    private suspend fun handleConnection(context: Context, accessoryInfo: String, scope: CoroutineScope) {
        try {
            val noiseSession = NoiseSession()
            noiseSession.loadStaticKey(context)

            val (input, output) = synchronized(lock) { inputStream to outputStream }
            if (input == null || output == null) throw IOException("USB streams not available")

            pairingSession.serve(
                input = input,
                output = output,
                noiseSession = noiseSession,
                isActive = { scope.isActive },
                onConnected = {
                    synchronized(lock) {
                        if (serverScope === scope) _state.value = UsbAccessoryState.Connected(accessoryInfo)
                    }
                },
            )
        } catch (e: IOException) {
            Log.e(TAG, "USB connection error", e)
        } catch (e: Exception) {
            Log.e(TAG, "Unexpected error in USB connection handler", e)
        } finally {
            Log.i(TAG, "USB connection closed: $accessoryInfo")
            releaseSession(scope)
        }
    }

    /**
     * Frees the connection slot when the session of [scope] ends by itself,
     * with or without a detach broadcast, and tells the owner through
     * `onClosed`. A session a [disconnect] already ended, or one a later
     * [connect] has replaced, leaves the current connection alone.
     */
    private fun releaseSession(scope: CoroutineScope) {
        synchronized(lock) {
            if (serverScope !== scope) return
            detachWatcher.stop()
            accessory = null
            closeStreams()
            serverScope = null
            connectionJob = null
            _state.value = UsbAccessoryState.Disconnected
        }
        scope.cancel()
        onClosed()
    }

    /**
     * Answers one decrypted request [plaintext] exactly as the USB message loop
     * does, or returns null for a message that needs no answer. The wire-contract
     * tests use it to reach the USB dispatch without a Noise session.
     */
    internal suspend fun handlePlaintext(plaintext: ByteArray): ByteArray? =
        pairingSession.interceptOrRoute(plaintext)

    /**
     * Sends an encrypted message to the connected USB host (outbound remote.*).
     */
    override suspend fun sendEncryptedMessage(data: ByteArray) {
        pairingSession.sendEncryptedMessage(data)
    }

    /** Closes [fd], which no stream wraps yet. */
    private fun closeQuietly(fd: ParcelFileDescriptor?) {
        try {
            fd?.close()
        } catch (e: IOException) {
            Log.w(TAG, "Error closing USB file descriptor", e)
        }
    }

    /** Closes the streams and the descriptor; the caller holds [lock]. */
    private fun closeStreams() {
        try {
            inputStream?.close()
        } catch (e: IOException) {
            Log.w(TAG, "Error closing USB input stream", e)
        }
        inputStream = null

        try {
            outputStream?.close()
        } catch (e: IOException) {
            Log.w(TAG, "Error closing USB output stream", e)
        }
        outputStream = null

        try {
            fileDescriptor?.close()
        } catch (e: IOException) {
            Log.w(TAG, "Error closing USB file descriptor", e)
        }
        fileDescriptor = null
    }
}

/**
 * Represents the state of the USB accessory server.
 */
sealed class UsbAccessoryState {
    /** No USB accessory connected. */
    data object Disconnected : UsbAccessoryState()

    /** A USB accessory is connected and performing the Noise XX handshake. */
    data object Handshaking : UsbAccessoryState()

    /** A USB accessory is connected and the encrypted session is established. */
    data class Connected(val accessoryInfo: String) : UsbAccessoryState()

    /** An error occurred. */
    data class Error(val message: String) : UsbAccessoryState()
}
