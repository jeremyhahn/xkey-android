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

package com.automatethethings.xkey.transport

import com.automatethethings.xkey.ble.NoiseInitiatorSession
import java.io.Closeable
import java.io.IOException
import java.net.Socket
import java.net.SocketTimeoutException
import java.security.SecureRandom
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.fail

/**
 * The desktop end of a stream transport, as go-xkms drives it: the identity
 * exchange, the Noise XX handshake as initiator, then framed encrypted
 * JSON-RPC over [socket].
 */
internal class DesktopPeer(
    private val socket: Socket,
    staticPrivateKey: ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) },
) : Closeable {

    val noise = NoiseInitiatorSession(staticPrivateKey)
    val publicKeyHex: String = noise.getLocalStaticPublicKey().joinToString("") { "%02x".format(it) }

    private val input = socket.getInputStream()
    private val output = socket.getOutputStream()

    /** `[0x01 | publicKey]`; a device with no stored fingerprint is answered `[0x00]`. */
    fun exchangeIdentity() {
        send(byteArrayOf(0x01) + noise.getLocalStaticPublicKey())
        assertArrayEquals("identity ack", byteArrayOf(0x00), read())
    }

    fun sendMsg1AndReadMsg2() {
        send(noise.createHandshakeMessage1())
        noise.processHandshakeMessage2(read())
    }

    fun sendMsg3() {
        send(noise.createHandshakeMessage3())
        noise.finalizeHandshake()
    }

    fun handshake() {
        exchangeIdentity()
        sendMsg1AndReadMsg2()
        sendMsg3()
    }

    /** Sends one encrypted request and returns the decrypted reply. */
    fun request(method: String, id: Long = 1, params: JSONObject = JSONObject()): JSONObject {
        val request = JSONObject()
            .put("jsonrpc", "2.0")
            .put("id", id)
            .put("method", method)
            .put("params", params)
        send(noise.encrypt(request.toString().toByteArray()))
        return readEncrypted()
    }

    fun readEncrypted(): JSONObject = JSONObject(String(noise.decrypt(read()), Charsets.UTF_8))

    fun send(frame: ByteArray) = StreamMessageFraming.writeMessage(output, frame)

    fun read(): ByteArray = StreamMessageFraming.readMessage(input)

    /** Nothing arrives within [millis]: the read times out or the stream ends. */
    fun assertNoFrame(millis: Int = 300) {
        socket.soTimeout = millis
        try {
            val frame = read()
            fail("expected no frame, got ${frame.size} bytes")
        } catch (e: IOException) {
            // A timeout or the end of the stream: nothing was written.
        } finally {
            socket.soTimeout = 0
        }
    }

    /** The phone closed the transport: a read ends, without a frame, before [millis]. */
    fun assertClosedByPhone(millis: Int = 5_000) {
        socket.soTimeout = millis
        try {
            val frame = read()
            fail("expected the transport to close, got ${frame.size} bytes")
        } catch (e: SocketTimeoutException) {
            fail("the phone did not close the transport within $millis ms")
        } catch (e: IOException) {
            // The end of the stream.
        }
    }

    /** Ends the desktop's half of the stream: the phone reads EOF, and nothing here is read any more. */
    fun endOutput() = socket.shutdownOutput()

    override fun close() = socket.close()
}
