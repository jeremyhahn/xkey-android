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
import com.automatethethings.xkey.protocol.ErrorCodes
import com.automatethethings.xkey.protocol.MethodNames
import com.automatethethings.xkey.protocol.PairingConfirmParams
import com.automatethethings.xkey.protocol.PairingConfirmResult
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.protocol.Response as ProtocolResponse
import com.automatethethings.xkey.protocol.SessionBinding
import com.automatethethings.xkey.remote.BidirectionalMessageRouter
import com.automatethethings.xkey.remote.MessageSender
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.util.getStringOrNull
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.security.MessageDigest

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
 */
class StreamPairingSession(
    private val requestHandler: RequestHandler,
    private val messageRouter: BidirectionalMessageRouter?,
    private val pairingCallback: PairingConfirmationCallback?,
    private val pairedDeviceRepository: PairedDeviceRepository?,
    private val transportLabel: String,
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

    /** Serializes encrypt+write so outbound requests and inline responses never interleave. */
    private val sendMutex = Mutex()

    @Volatile private var activeOutput: OutputStream? = null
    @Volatile private var activeSession: NoiseSession? = null
    @Volatile private var pairingConfirmed = false

    /**
     * The peer's static public key as authenticated by the Noise XX transcript.
     * This — not anything the peer asserts in a request body — is the identity
     * the session trusts.
     */
    @Volatile private var authenticatedPeerKeyHex: String? = null

    /**
     * Runs the full responder protocol over [input]/[output] until the peer
     * disconnects or [isActive] returns false.
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
        pairingConfirmed = false
        try {
            performHandshake(input, output, noiseSession)
            if (!noiseSession.isHandshakeComplete()) {
                throw IOException("Noise handshake did not complete")
            }

            activeOutput = output
            activeSession = noiseSession
            authenticatedPeerKeyHex = noiseSession.getRemoteStaticKey()?.toHex()
            requestHandler.setSessionBindingProvider { sessionBinding(noiseSession) }

            // A device the user already approved does not have to re-confirm on
            // every reconnect: the Noise handshake cryptographically proves it
            // holds that same static key. Requiring pairing.confirm each time
            // would also break the desktop, which only sends it during
            // `xkey device pair`.
            adoptExistingPairing()
            Log.i(TAG, "[$transportLabel] Noise handshake complete")
            onConnected()

            messageLoop(input, noiseSession, isActive)
        } finally {
            activeOutput = null
            activeSession = null
            authenticatedPeerKeyHex = null
            pairingConfirmed = false
            messageRouter?.cancelAllPending()
            requestHandler.setConnectedDevicePublicKeyHex(null)
            requestHandler.setSessionBindingProvider(null)
        }
    }

    /**
     * The static keys and prologue `local.attestDevice` binds its attestation to
     * (go-xkms#129 §5).
     *
     * This end is always the Noise **responder** on this transport — the desktop
     * opens the handshake — so the peer's static key is the initiator's. Null
     * before the handshake authenticates a peer, which the handler treats as
     * "cannot bind" and refuses rather than attesting to no channel.
     */
    private fun sessionBinding(session: NoiseSession): SessionBinding? {
        val initiator = session.getRemoteStaticKey() ?: return null
        val responder = session.getStaticPublicKey() ?: return null
        return SessionBinding(initiator, responder, session.getPrologue())
    }

    private suspend fun performHandshake(input: InputStream, output: OutputStream, session: NoiseSession) {
        val first = StreamMessageFraming.readMessage(input)
        val msg1 = exchangeIdentity(input, output, session, first)

        val response1 = session.processHandshakeMessage(msg1)
        if (response1 != null) writeFrame(output, response1)

        val msg3 = StreamMessageFraming.readMessage(input)
        val response3 = session.processHandshakeMessage(msg3)
        if (response3 != null) writeFrame(output, response3)
    }

    /**
     * Handles the pre-handshake identity exchange and returns the first Noise
     * handshake message (msg1). The desktop initiator sends
     * `[0x01 | publicKey(32)]`; we reply `[0x01 | fingerprint(32)]` for a known
     * device (binding the Noise prologue) or `[0x00]` for a new device. If
     * [first] is not a valid identity message it is treated as msg1 directly,
     * tolerating an initiator that skips the identity exchange.
     */
    private suspend fun exchangeIdentity(
        input: InputStream,
        output: OutputStream,
        session: NoiseSession,
        first: ByteArray,
    ): ByteArray {
        if (first.size != IDENTITY_MSG_SIZE || first[0] != IDENTITY_MSG_VERSION) {
            Log.d(TAG, "[$transportLabel] no identity message; treating ${first.size} bytes as msg1")
            return first
        }

        val publicKey = first.copyOfRange(1, first.size)
        val publicKeyHex = publicKey.toHex()
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

            // Prologue = SHA256(initiator_public_key || responder_fingerprint || "xkey-v1").
            session.setPrologue(computePrologue(publicKey, fingerprintBytes))
            session.reset() // re-initialize handshake state with the new prologue
            Log.i(TAG, "[$transportLabel] identity exchange: known device '${paired.deviceName}'")
        } else {
            writeFrame(output, byteArrayOf(IDENTITY_ACK_UNKNOWN))
            Log.i(TAG, "[$transportLabel] identity exchange: new device")
        }

        // The actual Noise msg1 follows the identity exchange.
        return StreamMessageFraming.readMessage(input)
    }

    private suspend fun messageLoop(input: InputStream, session: NoiseSession, isActive: () -> Boolean) {
        while (isActive()) {
            val ciphertext = try {
                StreamMessageFraming.readMessage(input)
            } catch (e: IOException) {
                Log.i(TAG, "[$transportLabel] peer disconnected: ${e.message}")
                break
            }

            val plaintext = try {
                session.decrypt(ciphertext)
            } catch (e: Exception) {
                Log.e(TAG, "[$transportLabel] decryption failed", e)
                break
            }

            val responseBytes = withContext(Dispatchers.Main) {
                interceptOrRoute(plaintext)
            }
            if (responseBytes == null) {
                // Incoming message was a response to one of our outbound requests.
                continue
            }

            try {
                sendEncrypted(session, responseBytes)
            } catch (e: IOException) {
                Log.e(TAG, "[$transportLabel] failed to send response", e)
                break
            }
        }
    }

    /**
     * Intercepts pairing.confirm before normal routing, otherwise routes via the
     * message router (bidirectional) or directly to the request handler.
     */
    private suspend fun interceptOrRoute(plaintext: ByteArray): ByteArray? {
        // A completed Noise XX handshake proves only that the peer holds *a*
        // key, not that the user approved it. Until pairing is confirmed, the
        // only request that may run is pairing.confirm itself; everything else
        // is refused. Without this, any peer that can reach the transport
        // could sign, list keys, or export shared material unapproved.
        if (pairingEnforced && !pairingConfirmed) {
            handlePairingConfirm(plaintext)?.let { return it }
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

        val router = messageRouter
        return if (router != null) router.processMessage(plaintext)
        else requestHandler.handleRawRequest(plaintext)
    }

    /**
     * Answers `pairing.confirm` on a session that is already confirmed.
     *
     * Returns null for every other method, so the caller falls through to
     * normal routing.
     */
    private fun confirmAlreadyPaired(plaintext: ByteArray): ByteArray? {
        val json = try {
            JSONObject(String(plaintext, Charsets.UTF_8))
        } catch (e: Exception) {
            return null
        }
        if (json.getStringOrNull("method") != MethodNames.PAIRING_CONFIRM) return null

        val id = json.optLong("id", -1)
        val result = PairingConfirmResult(confirmed = true, deviceName = android.os.Build.MODEL)
        return ProtocolResponse.success(id, result.toJson()).toJson()
    }

    /**
     * Marks the session confirmed when the authenticated peer is already a
     * trusted device, so a reconnect does not need another `pairing.confirm`.
     * Approval still comes from the paired-device store — an unknown peer is
     * left gated.
     */
    private fun adoptExistingPairing() {
        val repo = pairedDeviceRepository ?: return
        val peerKeyHex = authenticatedPeerKeyHex ?: return
        if (!repo.isDeviceKnown(peerKeyHex)) return

        pairingConfirmed = true
        requestHandler.setConnectedDevicePublicKeyHex(peerKeyHex)
        Log.i(TAG, "[$transportLabel] peer is already paired; session confirmed")
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
        val json = try {
            JSONObject(String(plaintext, Charsets.UTF_8))
        } catch (e: Exception) {
            Log.w(TAG, "[$transportLabel] dropping unparseable pre-pairing message")
            return null
        }
        val method = json.getStringOrNull("method") ?: return null // a response, not a request

        Log.w(TAG, "[$transportLabel] refusing '$method' from an unpaired peer")
        return ProtocolResponse.error(
            json.optLong("id", -1),
            ErrorCodes.PAIRING_REQUIRED,
            "Device is not paired; send pairing.confirm first"
        ).toJson()
    }

    private suspend fun handlePairingConfirm(plaintext: ByteArray): ByteArray? {
        val json = try {
            JSONObject(String(plaintext, Charsets.UTF_8))
        } catch (e: Exception) {
            return null
        }
        if (json.getStringOrNull("method") != MethodNames.PAIRING_CONFIRM) return null

        val id = json.optLong("id", -1)
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
        val peerKeyHex = authenticatedPeerKeyHex
        if (peerKeyHex == null) {
            Log.e(TAG, "[$transportLabel] no authenticated peer key; refusing pairing")
            return ProtocolResponse.error(
                id, ErrorCodes.PAIRING_REJECTED, "No authenticated peer identity"
            ).toJson()
        }
        if (!pairingParams.publicKeyHex.equals(peerKeyHex, ignoreCase = true)) {
            Log.e(
                TAG,
                "[$transportLabel] pairing.confirm claimed a different key than the one " +
                    "authenticated by the handshake; refusing"
            )
            return ProtocolResponse.error(
                id, ErrorCodes.PAIRING_REJECTED, "Claimed public key does not match the authenticated peer"
            ).toJson()
        }

        val confirmed = if (repo.isDeviceKnown(peerKeyHex)) {
            true
        } else {
            // No approval UI available means nothing can grant trust.
            callback?.onPairingConfirmationRequired(
                pairingParams.deviceName,
                peerKeyHex.take(16),
            ) ?: false
        }

        return if (confirmed) {
            // addDevice upserts, removing stale entries matching by key/address/name.
            repo.addDevice(peerKeyHex, pairingParams.deviceName)
            pairingConfirmed = true
            requestHandler.setConnectedDevicePublicKeyHex(peerKeyHex)
            val result = PairingConfirmResult(confirmed = true, deviceName = android.os.Build.MODEL)
            ProtocolResponse.success(id, result.toJson()).toJson()
        } else {
            Log.w(TAG, "[$transportLabel] user rejected pairing from \"${pairingParams.deviceName}\"")
            ProtocolResponse.error(id, ErrorCodes.PAIRING_REJECTED, "Pairing rejected by user").toJson()
        }
    }

    /**
     * [MessageSender] entry point used by outbound `remote.*` clients. Encrypts
     * and frames [data] on the active session.
     */
    override suspend fun sendEncryptedMessage(data: ByteArray) {
        val session = activeSession ?: throw IOException("No active Noise session")
        sendEncrypted(session, data)
    }

    private suspend fun sendEncrypted(session: NoiseSession, plaintext: ByteArray) {
        val output = activeOutput ?: throw IOException("No active connection")
        sendMutex.withLock {
            withContext(Dispatchers.IO) {
                StreamMessageFraming.writeMessage(output, session.encrypt(plaintext))
            }
        }
    }

    private suspend fun writeFrame(output: OutputStream, data: ByteArray) {
        withContext(Dispatchers.IO) {
            StreamMessageFraming.writeMessage(output, data)
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
