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
import com.automatethethings.xkey.remote.ConnectedDesktop
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
 * 2. [connect] opens the file descriptor and starts the session.
 * 3. [StreamPairingSession] performs the handshake and processes messages.
 * 4. [disconnect] is called when the accessory is detached.
 *
 * @param requestHandler The shared request handler for processing JSON-RPC requests.
 * @param messageRouter Optional bidirectional message router for remote.* requests.
 * @param pairingCallback Optional callback for pairing confirmation UI.
 * @param pairedDeviceRepository Optional repository for paired device management.
 * @param storeMethods Method families served on USB only (the password and seal
 *   stores go-xkms proxies over this transport), ahead of [requestHandler].
 */
class UsbAccessoryServer(
    requestHandler: RequestHandler,
    messageRouter: BidirectionalMessageRouter? = null,
    pairingCallback: com.automatethethings.xkey.ble.PairingConfirmationCallback? = null,
    pairedDeviceRepository: com.automatethethings.xkey.settings.PairedDeviceRepository? = null,
    storeMethods: List<TransportMethods> = emptyList()
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

    private var serverScope: CoroutineScope? = null
    private var fileDescriptor: ParcelFileDescriptor? = null
    private var inputStream: FileInputStream? = null
    private var outputStream: FileOutputStream? = null
    private var connectionJob: Job? = null

    /**
     * Opens the USB accessory and starts the communication session.
     *
     * @param context Android context for USB manager access and Noise key loading.
     * @param accessory The USB accessory to connect to.
     */
    fun connect(context: Context, accessory: UsbAccessory) {
        if (serverScope != null) {
            Log.w(TAG, "Already connected to an accessory")
            return
        }

        val usbManager = context.getSystemService(Context.USB_SERVICE) as UsbManager
        val fd = usbManager.openAccessory(accessory)
        if (fd == null) {
            Log.e(TAG, "Failed to open USB accessory")
            _state.value = UsbAccessoryState.Error("Failed to open USB accessory")
            return
        }

        fileDescriptor = fd
        inputStream = FileInputStream(fd.fileDescriptor)
        outputStream = FileOutputStream(fd.fileDescriptor)

        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        serverScope = scope

        connectionJob = scope.launch {
            handleConnection(context, accessory.toString())
        }

        Log.i(TAG, "USB accessory opened: ${accessory.manufacturer} ${accessory.model}")
    }

    /**
     * Disconnects from the USB accessory and releases resources.
     */
    fun disconnect() {
        Log.i(TAG, "Disconnecting USB accessory")
        closeStreams()
        serverScope?.cancel()
        serverScope = null
        connectionJob = null
        _state.value = UsbAccessoryState.Disconnected
    }

    /**
     * Drives the pairing session over the USB streams for the connection lifetime.
     */
    private suspend fun handleConnection(context: Context, accessoryInfo: String) {
        try {
            _state.value = UsbAccessoryState.Handshaking

            val noiseSession = NoiseSession()
            noiseSession.loadStaticKey(context)

            val input = inputStream ?: throw IOException("Input stream not available")
            val output = outputStream ?: throw IOException("Output stream not available")

            pairingSession.serve(
                input = input,
                output = output,
                noiseSession = noiseSession,
                isActive = { serverScope?.isActive == true },
                onConnected = { _state.value = UsbAccessoryState.Connected(accessoryInfo) },
            )
        } catch (e: IOException) {
            Log.e(TAG, "USB connection error", e)
        } catch (e: Exception) {
            Log.e(TAG, "Unexpected error in USB connection handler", e)
        } finally {
            Log.i(TAG, "USB connection closed: $accessoryInfo")
            _state.value = UsbAccessoryState.Disconnected
        }
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

    /**
     * The desktop on this accessory for outbound `remote.*` clients, or null
     * unless the session is [UsbAccessoryState.Connected]. The server object
     * outlives the handshake, a refused open and the end of a session, so its
     * existence alone says nothing.
     */
    fun connectedDesktop(router: BidirectionalMessageRouter?): ConnectedDesktop? =
        connectedDesktop(state.value, pairingSession.connectedPeerKeyHex, router)

    /** [connectedDesktop] for a given [state] and authenticated [peerKeyHex]. */
    internal fun connectedDesktop(
        state: UsbAccessoryState,
        peerKeyHex: String?,
        router: BidirectionalMessageRouter?
    ): ConnectedDesktop? =
        ConnectedDesktop.ifEstablished(state is UsbAccessoryState.Connected, peerKeyHex, this, router)

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
