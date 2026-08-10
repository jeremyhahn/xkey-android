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

package com.automatethethings.xkey.e2e

import com.automatethethings.xkey.ble.NoiseInitiatorSession
import com.automatethethings.xkey.transport.StreamMessageFraming
import org.json.JSONObject
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicLong

/**
 * Test-side implementation of the go-xkms desktop initiator: identity exchange,
 * Noise XX handshake, and the encrypted JSON-RPC request loop over TCP. This is
 * wire-identical to `go-xkms/xkey/pkg/pairing` `PerformHandshake` so the
 * instrumented integration suite proves the phone's responder stack end-to-end
 * over a real socket.
 */
class ProtocolTestClient(
    private val port: Int,
    /**
     * Reuse a static key to simulate a RECONNECT by an already-paired peer.
     * Null generates a fresh key, i.e. a peer the phone has never seen.
     */
    reuseStaticKey: ByteArray? = null
) {

    /** This client's Noise static private key; pass it back in to reconnect. */
    val staticKey: ByteArray

    init {
        val key = ByteArray(32)
        if (reuseStaticKey != null) {
            reuseStaticKey.copyInto(key)
        } else {
            SecureRandom().nextBytes(key)
        }
        staticKey = key
    }

    private lateinit var socket: Socket
    private lateinit var input: InputStream
    private lateinit var output: OutputStream
    private lateinit var noise: NoiseInitiatorSession
    private val nextId = AtomicLong(1)

    /** Hex of the initiator's static public key, available after [connect]. */
    lateinit var publicKeyHex: String
        private set

    /**
     * Connects and completes the identity exchange plus the Noise XX handshake.
     * Retries the TCP connect briefly so the caller can start the server
     * asynchronously.
     */
    fun connect(timeoutMs: Long = 5000) {
        noise = NoiseInitiatorSession(staticKey)

        val deadline = System.currentTimeMillis() + timeoutMs
        var lastError: IOException? = null
        while (System.currentTimeMillis() < deadline) {
            try {
                socket = Socket()
                socket.tcpNoDelay = true
                socket.connect(InetSocketAddress(InetAddress.getLoopbackAddress(), port), 1000)
                lastError = null
                break
            } catch (e: IOException) {
                lastError = e
                Thread.sleep(100)
            }
        }
        lastError?.let { throw it }

        input = socket.getInputStream()
        output = socket.getOutputStream()

        // Identity exchange: -> [0x01|pub(32)], <- [0x01|fingerprint(32)] or [0x00].
        val identity = noise.createIdentityMessage()
        publicKeyHex = identity.copyOfRange(1, identity.size).joinToString("") { "%02x".format(it) }
        StreamMessageFraming.writeMessage(output, identity)
        noise.processIdentityAck(StreamMessageFraming.readMessage(input))

        // Noise XX: -> e, <- e ee s es, -> s se.
        StreamMessageFraming.writeMessage(output, noise.createHandshakeMessage1())
        noise.processHandshakeMessage2(StreamMessageFraming.readMessage(input))
        StreamMessageFraming.writeMessage(output, noise.createHandshakeMessage3())
        noise.finalizeHandshake()
        check(noise.isHandshakeComplete()) { "Noise handshake did not complete" }
    }

    /**
     * Sends `pairing.confirm` as the desktop does immediately after the
     * handshake, registering this client as a paired device.
     */
    fun confirmPairing(deviceName: String = "ProtocolIntegrationTest"): JSONObject {
        return call(
            "pairing.confirm",
            JSONObject().apply {
                put("deviceName", deviceName)
                put("publicKeyHex", publicKeyHex)
            }
        )
    }

    /**
     * Sends a request and blocks until its response arrives, returning the
     * `result` object. Throws [ProtocolErrorException] on an error response so
     * tests can assert on error codes.
     */
    fun call(method: String, params: JSONObject? = null): JSONObject {
        val id = nextId.getAndIncrement()
        val request = JSONObject().apply {
            put("id", id)
            put("method", method)
            if (params != null) put("params", params)
        }
        StreamMessageFraming.writeMessage(output, noise.encrypt(request.toString().toByteArray(Charsets.UTF_8)))

        // Read frames until our response id shows up. Inbound phone-initiated
        // requests (none are expected in this suite) are skipped, but must
        // still be decrypted to keep transport nonces in sync.
        while (true) {
            val plaintext = noise.decrypt(StreamMessageFraming.readMessage(input))
            val json = JSONObject(String(plaintext, Charsets.UTF_8))
            if (json.has("method")) continue
            if (json.optLong("id", -1) != id) continue

            json.optJSONObject("error")?.let {
                throw ProtocolErrorException(method, it.optInt("code"), it.optString("message"))
            }
            return json.getJSONObject("result")
        }
    }

    /** Like [call] but returns the error object instead of throwing (null on success). */
    fun callExpectingError(method: String, params: JSONObject? = null): ProtocolErrorException? {
        return try {
            call(method, params)
            null
        } catch (e: ProtocolErrorException) {
            e
        }
    }

    fun close() {
        try {
            socket.close()
        } catch (_: Exception) {
        }
    }
}

/** Error response surfaced from the phone, with the protocol error code. */
class ProtocolErrorException(method: String, val code: Int, val protocolMessage: String) :
    IOException("$method failed: [$code] $protocolMessage")
