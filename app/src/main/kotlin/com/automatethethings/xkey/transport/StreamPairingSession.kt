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

import android.util.Log
import com.automatethethings.xkey.ble.NoiseSession
import com.automatethethings.xkey.ble.PairingConfirmationCallback
import com.automatethethings.xkey.ble.copyOf
import com.automatethethings.xkey.ble.sessionBinding
import com.automatethethings.xkey.protocol.AttestTranscript
import com.automatethethings.xkey.protocol.ErrorCodes
import com.automatethethings.xkey.protocol.MethodNames
import com.automatethethings.xkey.protocol.PairingConfirmParams
import com.automatethethings.xkey.protocol.PairingConfirmResult
import com.automatethethings.xkey.protocol.ProtocolException
import com.automatethethings.xkey.protocol.Request as ProtocolRequest
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.protocol.TransportMethods
import com.automatethethings.xkey.protocol.Response as ProtocolResponse
import com.automatethethings.xkey.protocol.SessionBinding
import com.automatethethings.xkey.protocol.readGeneration
import com.automatethethings.xkey.remote.BidirectionalMessageRouter
import com.automatethethings.xkey.remote.MessageSender
import com.automatethethings.xkey.settings.PairedDeviceRemovalListener
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.settings.PeerNotPairedException
import com.automatethethings.xkey.util.getStringOrNull
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.Closeable
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.CoroutineContext
import kotlin.coroutines.EmptyCoroutineContext

/**
 * Responder-side pairing protocol shared by the stream transports (USB Accessory
 * and TCP). It performs the pre-handshake identity exchange, the Noise XX
 * handshake (as responder), and the encrypted bidirectional JSON-RPC message
 * loop over a single [InputStream]/[OutputStream] pair.
 *
 * This is the single source of truth so USB and TCP stay byte-identical with the
 * go-xkms desktop initiator, which **always** performs the identity exchange
 * (see go-xkms `pkg/pairing/handshake_common.go` `PerformHandshake`). The BLE
 * GATT server implements the same protocol over GATT characteristics rather than
 * a byte stream.
 *
 * Framing is delegated to [StreamMessageFraming] (2-byte big-endian length
 * prefix, one Noise message per frame).
 *
 * Unpairing the connected desktop revokes its connection (#59): the request
 * it is running is cancelled, its streams are closed, and its keys are
 * zeroed once no frame is mid-send. Every phone-initiated frame revalidates
 * the peer against the paired-device store first.
 */
class StreamPairingSession(
    private val requestHandler: RequestHandler,
    private val messageRouter: BidirectionalMessageRouter?,
    private val pairingCallback: PairingConfirmationCallback?,
    private val pairedDeviceRepository: PairedDeviceRepository?,
    private val transportLabel: String,
    private val transportMethods: List<TransportMethods> = emptyList(),
) : MessageSender {

    companion object {
        private const val TAG = "StreamPairingSession"

        // Pre-handshake identity exchange constants — must match go-xkms
        // pkg/pairing/handshake_common.go and the BLE GattServer.
        private const val IDENTITY_MSG_VERSION: Byte = 0x01
        private const val IDENTITY_MSG_SIZE = 33      // 1-byte version + 32-byte public key
        private const val IDENTITY_ACK_KNOWN: Byte = 0x01
        private const val IDENTITY_ACK_UNKNOWN: Byte = 0x00
        private const val FINGERPRINT_SIZE = 32
        private const val PROLOGUE_VERSION = "xkey-v1"
    }

    /** What [transportMethods] add to each request routed to the shared handler. */
    private val routingContext: CoroutineContext =
        transportMethods.fold<TransportMethods, CoroutineContext>(EmptyCoroutineContext) { context, family ->
            context + family.routingContext()
        }

    /**
     * Runs each request apart from the message loop, so a revoked connection's
     * loop stops at once instead of waiting on a request that is suspended in
     * user approval.
     */
    private val requestScope = CoroutineScope(SupervisorJob())

    /** Closes a revoked connection's streams off the thread that removed the device. */
    private val teardownScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    /** The connection whose handshake completed most recently, while it lasts. */
    @Volatile private var activeConnection: Connection? = null

    /** Test seam: runs on the IO dispatcher just before a send is admitted. */
    @Volatile internal var beforeAdmissionForTest: (suspend () -> Unit)? = null

    /** Test seam: runs after a send's frame is encrypted and before it is written. */
    @Volatile internal var afterAdmissionForTest: (suspend () -> Unit)? = null

    /**
     * One served connection: its streams, its Noise session, and whether it
     * is still allowed to carry frames.
     *
     * [state] is the one lock that admits a send and revokes the connection,
     * so no frame is encrypted after a revocation lands.
     */
    private inner class Connection(
        val input: InputStream,
        val output: OutputStream,
        val noise: NoiseSession,
    ) : PairedDeviceRemovalListener {
        val state = Any()

        /** Serializes encrypt+write so outbound requests and inline responses never interleave. */
        val sendLock = Mutex()

        /** The key the peer named in the identity exchange, before the handshake proves it. */
        @Volatile var claimedPeerKeyHex: String? = null

        /**
         * The peer's static public key as authenticated by the Noise XX transcript.
         * This — not anything the peer asserts in a request body — is the identity
         * the session trusts.
         */
        @Volatile var peerKeyHex: String? = null

        /** The handshake's binding, captured once when the connection is installed. */
        @Volatile var binding: SessionBinding? = null

        @Volatile var established = false
        @Volatile var confirmed = false
        @Volatile var revoked = false
        @Volatile var ended = false

        /** The request the message loop is waiting on, if any. */
        @Volatile var request: Job? = null

        /** Completes when the connection is revoked or ends. */
        val over = CompletableDeferred<Unit>()

        private val keysZeroed = AtomicBoolean(false)

        val isLive: Boolean get() = !revoked && !ended

        val isCurrent: Boolean get() = isLive && activeConnection === this

        /** Fails a handshake step that a revocation or the end of the connection overtook. */
        fun ensureLive() {
            if (revoked) throw PeerNotPairedException(peerKeyHex ?: claimedPeerKeyHex)
            if (ended) throw IOException("Connection has ended")
        }

        /** Publishes the completed handshake, unless a revocation got there first. */
        fun install() {
            synchronized(state) {
                ensureLive()
                peerKeyHex = noise.getRemoteStaticKey()?.toHex()
                binding = noise.sessionBinding()
                established = true
                activeConnection = this
            }
        }

        /**
         * Admits one frame: the connection is live, and a phone-initiated
         * frame's peer is still paired. Only then is a nonce consumed.
         */
        fun admit(plaintext: ByteArray, phoneInitiated: Boolean): ByteArray = synchronized(state) {
            ensureLive()
            if (!established) throw IOException("No active Noise session")
            if (phoneInitiated) pairedDeviceRepository?.requirePaired(peerKeyHex)
            noise.encrypt(plaintext)
        }

        override fun onDeviceRemoved(publicKeyHex: String) {
            synchronized(state) {
                val matches = publicKeyHex.equals(peerKeyHex, ignoreCase = true) ||
                    publicKeyHex.equals(claimedPeerKeyHex, ignoreCase = true)
                if (!matches || revoked) return
                revoked = true
                ended = true
                confirmed = false
            }
            Log.i(TAG, "[$transportLabel] peer ${publicKeyHex.take(16)} was unpaired; revoking its connection")
            stop()
            teardownScope.launch { closeStreams() }
        }

        /** Marks the connection ended, stops its request and closes its streams. */
        fun end() {
            synchronized(state) { ended = true }
            stop()
            closeStreams()
        }

        private fun stop() {
            request?.cancel()
            over.complete(Unit)
        }

        private fun closeStreams() {
            closeQuietly(input)
            closeQuietly(output)
        }

        /** Zeroes the session keys once, after any frame mid-send has released the send lock. */
        suspend fun zeroKeys() {
            sendLock.withLock {
                if (keysZeroed.compareAndSet(false, true)) noise.reset()
            }
        }
    }

    /**
     * Runs the full responder protocol over [input]/[output] until the peer
     * disconnects, [isActive] returns false, or the peer is unpaired.
     *
     * @param noiseSession a session with its static key already loaded.
     * @param isActive returns false to stop the message loop (e.g., on shutdown).
     * @param onConnected invoked once the encrypted session is established.
     */
    suspend fun serve(
        input: InputStream,
        output: OutputStream,
        noiseSession: NoiseSession,
        isActive: () -> Boolean,
        onConnected: suspend () -> Unit,
    ) {
        val connection = Connection(input, output, noiseSession)
        PairedDeviceRepository.addRemovalListener(connection)
        try {
            performHandshake(connection)
            if (!noiseSession.isHandshakeComplete()) {
                throw IOException("Noise handshake did not complete")
            }

            connection.install()
            requestHandler.setSessionBindingProvider {
                connection.binding?.takeIf { connection.isCurrent }?.copyOf()
            }

            // A device the user already approved does not have to re-confirm on
            // every reconnect: the Noise handshake cryptographically proves it
            // holds that same static key. Requiring pairing.confirm each time
            // would also break the desktop, which only sends it during
            // `xkey device pair`.
            adoptExistingPairing(connection)
            Log.i(TAG, "[$transportLabel] Noise handshake complete")
            onConnected()

            messageLoop(connection, isActive)
        } finally {
            withContext(NonCancellable) {
                PairedDeviceRepository.removeRemovalListener(connection)
                connection.end()
                connection.zeroKeys()
                if (activeConnection === connection) {
                    activeConnection = null
                    messageRouter?.cancelAllPending()
                    requestHandler.setConnectedDevicePublicKeyHex(null)
                    requestHandler.setSessionBindingProvider(null)
                }
            }
        }
    }

    private suspend fun performHandshake(connection: Connection) {
        val session = connection.noise
        val first = StreamMessageFraming.readMessage(connection.input)
        val msg1 = exchangeIdentity(connection, first)

        val response1 = session.processHandshakeMessage(msg1)
        connection.ensureLive()
        if (response1 != null) writeFrame(connection.output, response1)

        val msg3 = StreamMessageFraming.readMessage(connection.input)
        val response3 = session.processHandshakeMessage(msg3)
        connection.ensureLive()
        if (response3 != null) writeFrame(connection.output, response3)
    }

    /**
     * Handles the pre-handshake identity exchange and returns the first Noise
     * handshake message (msg1). The desktop initiator sends
     * `[0x01 | publicKey(32)]`; we reply `[0x01 | fingerprint(32)]` for a known
     * device (binding the Noise prologue) or `[0x00]` for a new device. If
     * [first] is not a valid identity message it is treated as msg1 directly,
     * tolerating an initiator that skips the identity exchange.
     */
    private suspend fun exchangeIdentity(connection: Connection, first: ByteArray): ByteArray {
        val output = connection.output
        val session = connection.noise
        if (first.size != IDENTITY_MSG_SIZE || first[0] != IDENTITY_MSG_VERSION) {
            Log.d(TAG, "[$transportLabel] no identity message; treating ${first.size} bytes as msg1")
            return first
        }

        val publicKey = first.copyOfRange(1, first.size)
        val publicKeyHex = publicKey.toHex()
        // Named before the lookup, so a removal from here on revokes the handshake.
        connection.claimedPeerKeyHex = publicKeyHex
        val paired = pairedDeviceRepository?.getDevice(publicKeyHex)
        // The phone's OWN attested-key SPKI fingerprint, captured at pairing
        // (#93). The desktop byte-compares it and mixes it into the prologue.
        val fingerprint = paired?.deviceFingerprint

        if (paired != null && fingerprint != null && fingerprint.length == FINGERPRINT_SIZE * 2) {
            val fingerprintBytes = fingerprint.hexToBytes()
            val ack = ByteArray(1 + FINGERPRINT_SIZE)
            ack[0] = IDENTITY_ACK_KNOWN
            fingerprintBytes.copyInto(ack, 1)
            writeFrame(output, ack)
            connection.ensureLive()

            // Prologue = SHA256(initiator_public_key || responder_fingerprint || "xkey-v1").
            session.setPrologue(computePrologue(publicKey, fingerprintBytes))
            session.reset() // re-initialize handshake state with the new prologue
            Log.i(TAG, "[$transportLabel] identity exchange: known device '${paired.deviceName}'")
        } else {
            writeFrame(output, byteArrayOf(IDENTITY_ACK_UNKNOWN))
            Log.i(TAG, "[$transportLabel] identity exchange: new device")
        }

        // The actual Noise msg1 follows the identity exchange.
        return StreamMessageFraming.readMessage(connection.input)
    }

    private suspend fun messageLoop(connection: Connection, isActive: () -> Boolean) {
        while (isActive() && connection.isLive) {
            val ciphertext = try {
                StreamMessageFraming.readMessage(connection.input)
            } catch (e: IOException) {
                Log.i(TAG, "[$transportLabel] peer disconnected: ${e.message}")
                break
            }

            val plaintext = try {
                connection.noise.decrypt(ciphertext)
            } catch (e: Exception) {
                Log.e(TAG, "[$transportLabel] decryption failed", e)
                break
            }

            val responseBytes = try {
                runRequest(connection, plaintext)
            } catch (e: IOException) {
                Log.i(TAG, "[$transportLabel] connection ended while a request ran: ${e.message}")
                break
            }
            if (responseBytes == null) {
                // Incoming message was a response to one of our outbound requests.
                continue
            }

            try {
                send(connection, responseBytes, phoneInitiated = false)
            } catch (e: IOException) {
                Log.e(TAG, "[$transportLabel] failed to send response", e)
                break
            }
        }
    }

    /**
     * Runs one request on the main thread and waits for it, or for the
     * connection to be revoked or end, whichever comes first. A request
     * outlived by its connection is cancelled and answers nothing.
     */
    private suspend fun runRequest(connection: Connection, plaintext: ByteArray): ByteArray? {
        val context = currentCoroutineContext().minusKey(Job) + Dispatchers.Main
        val job = requestScope.async(context) { interceptOrRoute(plaintext, connection) }
        connection.request = job
        if (!connection.isLive) job.cancel()
        try {
            val response = try {
                select<ByteArray?> {
                    job.onAwait { it }
                    connection.over.onAwait { null }
                }
            } catch (e: CancellationException) {
                // Our own caller was cancelled, or the connection cancelled the request.
                currentCoroutineContext().ensureActive()
                null
            }
            connection.ensureLive()
            return response
        } finally {
            if (!job.isCompleted) job.cancel()
            connection.request = null
        }
    }

    /**
     * Intercepts pairing.confirm before normal routing, otherwise routes via the
     * message router (bidirectional) or directly to the request handler.
     *
     * Internal so that the USB wire-contract tests can drive a decrypted
     * request through the same dispatch the message loop uses; it runs
     * against the active connection.
     */
    internal suspend fun interceptOrRoute(plaintext: ByteArray): ByteArray? =
        interceptOrRoute(plaintext, activeConnection)

    private suspend fun interceptOrRoute(plaintext: ByteArray, connection: Connection?): ByteArray? {
        // A completed Noise XX handshake proves only that the peer holds *a*
        // key, not that the user approved it. Until pairing is confirmed, the
        // only request that may run is pairing.confirm itself; everything else
        // is refused. Without this, any peer that can reach the transport
        // could sign, list keys, or export shared material unapproved.
        if (pairingEnforced && connection?.confirmed != true) {
            handlePairingConfirm(plaintext, connection)?.let { return it }
            // A request that outlived its connection answers nothing.
            if (connection != null && !connection.isCurrent) return null
            return rejectUnpaired(plaintext)
        }

        // A peer that is already trusted still sends pairing.confirm when it
        // re-pairs, and adoptExistingPairing has already confirmed the session
        // by then. Letting it fall through answers METHOD_NOT_FOUND, which
        // reads as a protocol mismatch rather than "you are already paired" --
        // so re-running `xkey device pair` against a known phone failed with a
        // confusing error. Confirming again is a no-op, so it simply succeeds.
        if (pairingEnforced) {
            confirmAlreadyPaired(plaintext)?.let { return it }
        }

        routeTransportMethod(plaintext)?.let { return it }

        // The router calls the handler in this coroutine, so the elements
        // reach it per request and never outlive it.
        val router = messageRouter
        return withContext(routingContext) {
            if (router != null) router.processMessage(plaintext)
            else requestHandler.handleRawRequest(plaintext)
        }
    }

    /**
     * Serves a request whose method belongs to one of this transport's own
     * [transportMethods] families, or returns null so normal routing runs.
     *
     * A message that does not parse as a request (a response to an outbound
     * remote.* call, or garbage) is left to the normal path, which owns those
     * answers.
     */
    private suspend fun routeTransportMethod(plaintext: ByteArray): ByteArray? {
        if (transportMethods.isEmpty()) return null
        val request = try {
            ProtocolRequest.fromJson(plaintext)
        } catch (e: ProtocolException) {
            return null
        }
        val family = transportMethods.firstOrNull { it.handles(request.method) } ?: return null
        return withContext(Dispatchers.IO) { family.handle(request) }
            .copy(generation = request.generation)
            .toJson()
    }

    /**
     * Marks the session confirmed when the authenticated peer is already a
     * trusted device, so a reconnect does not need another `pairing.confirm`.
     * Approval still comes from the paired-device store — an unknown peer is
     * left gated.
     */
    private fun adoptExistingPairing(connection: Connection) {
        val repo = pairedDeviceRepository ?: return
        val peerKeyHex = connection.peerKeyHex ?: return
        if (!repo.isDeviceKnown(peerKeyHex)) return

        if (!confirm(connection, peerKeyHex)) return
        Log.i(TAG, "[$transportLabel] peer is already paired; session confirmed")
    }

    /**
     * Confirms [connection] for [peerKeyHex] if it is still the current,
     * unrevoked connection. Under its lock, so a revocation either sees the
     * confirmation or prevents it.
     */
    private fun confirm(connection: Connection, peerKeyHex: String): Boolean = synchronized(connection.state) {
        if (!connection.isCurrent) return false
        connection.confirmed = true
        requestHandler.setConnectedDevicePublicKeyHex(peerKeyHex)
        true
    }

    /**
     * Whether this session can enforce pairing. A transport constructed
     * without a paired-device repository has no notion of approval, so it
     * cannot gate on it.
     */
    private val pairingEnforced: Boolean
        get() = pairedDeviceRepository != null

    /**
     * Refuses a request that arrived before pairing was confirmed. Responses
     * to our own outbound requests are not refused — they carry no method and
     * belong to the router.
     */
    private fun rejectUnpaired(plaintext: ByteArray): ByteArray? {
        val text = String(plaintext, Charsets.UTF_8)
        val json = try {
            JSONObject(text)
        } catch (e: Exception) {
            Log.w(TAG, "[$transportLabel] dropping unparseable pre-pairing message")
            return null
        }
        val method = json.getStringOrNull("method") ?: return null // a response, not a request

        Log.w(TAG, "[$transportLabel] refusing '$method' from an unpaired peer")
        return ProtocolResponse.error(
            json.optLong("id", -1),
            ErrorCodes.PAIRING_REQUIRED,
            "Device is not paired; send pairing.confirm first",
            generation = readGeneration(text)
        ).toJson()
    }

    /**
     * Serves pairing.confirm for [connection], the connection it arrived on.
     * The approval may outlive that connection; an answer that arrives after
     * it was revoked or replaced changes nothing and answers nothing.
     */
    private suspend fun handlePairingConfirm(plaintext: ByteArray, connection: Connection?): ByteArray? {
        val text = String(plaintext, Charsets.UTF_8)
        val json = try {
            JSONObject(text)
        } catch (e: Exception) {
            return null
        }
        if (json.getStringOrNull("method") != MethodNames.PAIRING_CONFIRM) return null

        val id = json.optLong("id", -1)
        val generation = readGeneration(text)
        val params = json.optJSONObject("params") ?: return null
        val pairingParams = try {
            PairingConfirmParams.fromJson(params)
        } catch (e: Exception) {
            Log.e(TAG, "[$transportLabel] invalid pairing.confirm params", e)
            return null
        }

        val repo = pairedDeviceRepository!!
        val callback = pairingCallback
        Log.i(TAG, "[$transportLabel] pairing.confirm from \"${pairingParams.deviceName}\"")

        // Identity comes from the Noise transcript, never from the request
        // body. A peer that completes the handshake with its own key cannot
        // claim to be a device the user already trusts.
        val peerKeyHex = connection?.peerKeyHex
        if (connection == null || peerKeyHex == null) {
            Log.e(TAG, "[$transportLabel] no authenticated peer key; refusing pairing")
            return ProtocolResponse.error(
                id, ErrorCodes.PAIRING_REJECTED, "No authenticated peer identity", generation = generation
            ).toJson()
        }
        if (!pairingParams.publicKeyHex.equals(peerKeyHex, ignoreCase = true)) {
            Log.e(
                TAG,
                "[$transportLabel] pairing.confirm claimed a different key than the one " +
                    "authenticated by the handshake; refusing"
            )
            return ProtocolResponse.error(
                id,
                ErrorCodes.PAIRING_REJECTED,
                "Claimed public key does not match the authenticated peer",
                generation = generation
            ).toJson()
        }

        val confirmed = if (repo.isDeviceKnown(peerKeyHex)) {
            true
        } else {
            // The SAS the desktop prints during `xkey device pair`; the user
            // compares the two before trusting the peer. No session to derive
            // it from means nothing to compare, so nothing can grant trust.
            val sas = connection.binding?.let { AttestTranscript.shortAuthString(it) }
            if (sas == null) {
                Log.e(TAG, "[$transportLabel] no completed Noise session to derive the SAS; refusing pairing")
                false
            } else {
                // No approval UI available means nothing can grant trust.
                callback?.onPairingConfirmationRequired(
                    pairingParams.deviceName,
                    peerKeyHex.take(16),
                    sas,
                ) ?: false
            }
        }

        // The user may have answered after this connection was revoked or
        // replaced; that answer belongs to no live session.
        if (!connection.isCurrent) {
            Log.w(TAG, "[$transportLabel] pairing.confirm outlived its connection; ignoring the answer")
            return null
        }

        return if (confirmed) {
            // addDevice upserts, removing stale entries matching by key/address/name.
            repo.addDevice(peerKeyHex, pairingParams.deviceName)
            if (connection.revoked) {
                // A removal landed between the check and the add: it wins.
                repo.removeDevice(peerKeyHex)
                return null
            }
            if (!confirm(connection, peerKeyHex)) return null
            val result = PairingConfirmResult(confirmed = true, deviceName = android.os.Build.MODEL)
            ProtocolResponse.success(id, result.toJson(), generation = generation).toJson()
        } else {
            Log.w(TAG, "[$transportLabel] user rejected pairing from \"${pairingParams.deviceName}\"")
            ProtocolResponse.error(
                id, ErrorCodes.PAIRING_REJECTED, "Pairing rejected by user", generation = generation
            ).toJson()
        }
    }

    /**
     * [MessageSender] entry point used by outbound `remote.*` clients. Encrypts
     * and frames [data] on the active connection, after revalidating that its
     * peer is still paired.
     *
     * @throws PeerNotPairedException if the peer is no longer paired; nothing
     *   is written and no nonce is consumed.
     */
    override suspend fun sendEncryptedMessage(data: ByteArray) {
        val connection = activeConnection?.takeIf { it.established }
            ?: throw IOException("No active Noise session")
        send(connection, data, phoneInitiated = true)
    }

    /**
     * The one admitted operation every frame on an established connection
     * goes through: admission, encryption and the write run as a single
     * non-cancellable step under the send lock. Cancellation is honoured only
     * before admission; once a nonce is consumed the frame is written, or the
     * connection is ended.
     */
    private suspend fun send(connection: Connection, plaintext: ByteArray, phoneInitiated: Boolean) {
        connection.sendLock.withLock {
            currentCoroutineContext().ensureActive()
            withContext(NonCancellable + Dispatchers.IO) {
                beforeAdmissionForTest?.invoke()
                val frame = connection.admit(plaintext, phoneInitiated)
                try {
                    afterAdmissionForTest?.invoke()
                    StreamMessageFraming.writeMessage(connection.output, frame)
                } catch (e: Throwable) {
                    // The nonce is spent; a frame that did not go out leaves
                    // the peer one behind, so the connection cannot continue.
                    connection.end()
                    throw e
                }
            }
        }
    }

    private suspend fun writeFrame(output: OutputStream, data: ByteArray) {
        withContext(Dispatchers.IO) {
            StreamMessageFraming.writeMessage(output, data)
        }
    }

    private fun closeQuietly(stream: Closeable) {
        try {
            stream.close()
        } catch (e: IOException) {
            Log.d(TAG, "[$transportLabel] close failed: ${e.message}")
        }
    }

    private fun computePrologue(publicKey: ByteArray, fingerprint: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(publicKey)
        digest.update(fingerprint)
        digest.update(PROLOGUE_VERSION.toByteArray(Charsets.UTF_8))
        return digest.digest()
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    private fun String.hexToBytes(): ByteArray {
        val out = ByteArray(length / 2)
        var i = 0
        while (i < length) {
            out[i / 2] = ((Character.digit(this[i], 16) shl 4) + Character.digit(this[i + 1], 16)).toByte()
            i += 2
        }
        return out
    }
}

/**
 * Answers `pairing.confirm` on a session that is already confirmed.
 *
 * Returns null for every other method, so the caller falls through to
 * normal routing. Shared by the stream transports and the BLE GATT server;
 * the caller decides whether its session is still live and confirmed.
 */
internal fun confirmAlreadyPaired(plaintext: ByteArray): ByteArray? {
    val text = String(plaintext, Charsets.UTF_8)
    val json = try {
        JSONObject(text)
    } catch (e: Exception) {
        return null
    }
    if (json.getStringOrNull("method") != MethodNames.PAIRING_CONFIRM) return null

    val id = json.optLong("id", -1)
    val deviceName = android.os.Build.MODEL ?: "Android device"
    val result = PairingConfirmResult(confirmed = true, deviceName = deviceName)
    return ProtocolResponse.success(id, result.toJson(), generation = readGeneration(text)).toJson()
}
