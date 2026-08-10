/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
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
package com.automatethethings.xkey.bootstrap

import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * The responder half of the Noise_NK exchange `BootstrapClient` speaks.
 *
 * The client's session is a private inner class, so the only way to reach its
 * handshake, HKDF, X25519 ladder and ChaCha20-Poly1305 code is to talk to it.
 * This mirrors the symmetric state the client keeps, byte for byte, over a
 * loopback socket:
 *
 * ```
 * h  = "Noise_NK_25519_ChaChaPoly_SHA256"   (exactly 32 octets, so no hashing)
 * ck = h
 * h  = SHA256(h)          MixHash(empty prologue)
 * h  = SHA256(h || rs)    MixHash(responder static, the NK pre-message)
 * ```
 *
 * then `-> e, es` and `<- e, ee` with `MixKey` = HKDF-SHA256 of the chaining
 * key, and finally a split whose first output is the initiator's send key.
 */
internal class NoiseBootstrapResponder(
    private val reply: (String) -> String = { """{"bundle_pem":"","certificates":[]}""" },
    private val encryptHandshakePayload: Boolean = false,
    private val truncatedHandshakeLength: Int? = null
) : AutoCloseable {

    private val staticKeyPair = NoiseTestCrypto.generateKeyPair()

    /** The pre-shared responder static public key, as the settings carry it. */
    val staticPublicKeyHex: String =
        staticKeyPair.second.joinToString("") { "%02x".format(it) }

    private val server = ServerSocket(0, 1, InetAddress.getLoopbackAddress())

    /** `host:port` for `noiseServerAddr`. */
    val address: String = "127.0.0.1:${server.localPort}"

    /** The request payload the client sent, once the exchange has completed. */
    @Volatile
    var receivedRequest: String? = null
        private set

    /** Anything that went wrong responder-side, so a test can report it. */
    @Volatile
    var failure: Throwable? = null
        private set

    private val worker = Thread({ serve() }, "noise-bootstrap-responder").apply {
        isDaemon = true
        start()
    }

    private fun serve() {
        try {
            server.accept().use { socket ->
                socket.soTimeout = SOCKET_TIMEOUT_MS
                val input = DataInputStream(socket.getInputStream())
                val output = DataOutputStream(socket.getOutputStream())

                var handshakeHash = PROTOCOL_NAME.toByteArray(Charsets.US_ASCII)
                var chainingKey = handshakeHash.copyOf()
                handshakeHash = NoiseTestCrypto.sha256(handshakeHash)
                handshakeHash = NoiseTestCrypto.sha256(handshakeHash + staticKeyPair.second)

                val initiatorEphemeral = readFrame(input)
                handshakeHash = NoiseTestCrypto.sha256(handshakeHash + initiatorEphemeral)
                var keys = NoiseTestCrypto.hkdf2(
                    chainingKey,
                    NoiseTestCrypto.diffieHellman(staticKeyPair.first, initiatorEphemeral)
                )
                chainingKey = keys.first
                var handshakeKey = keys.second

                truncatedHandshakeLength?.let { length ->
                    writeFrame(output, ByteArray(length))
                    return
                }

                val ephemeral = NoiseTestCrypto.generateKeyPair()
                handshakeHash = NoiseTestCrypto.sha256(handshakeHash + ephemeral.second)
                keys = NoiseTestCrypto.hkdf2(
                    chainingKey,
                    NoiseTestCrypto.diffieHellman(ephemeral.first, initiatorEphemeral)
                )
                chainingKey = keys.first
                handshakeKey = keys.second

                val message2 = if (encryptHandshakePayload) {
                    val ciphertext = NoiseTestCrypto.encrypt(
                        handshakeKey,
                        NoiseTestCrypto.nonce(0),
                        ByteArray(0),
                        handshakeHash
                    )
                    handshakeHash = NoiseTestCrypto.sha256(handshakeHash + ciphertext)
                    ephemeral.second + ciphertext
                } else {
                    ephemeral.second
                }
                writeFrame(output, message2)

                // Split: the initiator sends under the first key and receives
                // under the second, so the responder uses them the other way up.
                val (initiatorSendKey, initiatorReceiveKey) =
                    NoiseTestCrypto.hkdf2(chainingKey, ByteArray(0))

                val request = NoiseTestCrypto.decrypt(
                    initiatorSendKey,
                    NoiseTestCrypto.nonce(0),
                    readFrame(input),
                    ByteArray(0)
                )
                receivedRequest = String(request, Charsets.UTF_8)

                writeFrame(
                    output,
                    NoiseTestCrypto.encrypt(
                        initiatorReceiveKey,
                        NoiseTestCrypto.nonce(0),
                        reply(receivedRequest!!).toByteArray(Charsets.UTF_8),
                        ByteArray(0)
                    )
                )
            }
        } catch (e: Throwable) {
            failure = e
        }
    }

    private fun readFrame(input: DataInputStream): ByteArray {
        val data = ByteArray(input.readUnsignedShort())
        input.readFully(data)
        return data
    }

    private fun writeFrame(output: DataOutputStream, data: ByteArray) {
        output.writeShort(data.size)
        output.write(data)
        output.flush()
    }

    override fun close() {
        runCatching { server.close() }
        worker.interrupt()
    }

    companion object {
        private const val PROTOCOL_NAME = "Noise_NK_25519_ChaChaPoly_SHA256"
        private const val SOCKET_TIMEOUT_MS = 10_000

        /** A loopback port with nothing listening on it. */
        fun unusedLoopbackAddress(): String {
            val socket = ServerSocket(0, 1, InetAddress.getLoopbackAddress())
            val port = socket.localPort
            socket.close()
            return "127.0.0.1:$port"
        }
    }
}

/**
 * The primitives `BootstrapClient.NoiseNKSession` uses, expressed exactly as it
 * uses them: SHA-256 for MixHash, a two-output HKDF-SHA256 for MixKey and Split,
 * a little-endian 12-byte nonce, and ChaCha20-Poly1305 for the AEAD.
 */
internal object NoiseTestCrypto {

    private const val KEY_SIZE = 32

    private val privateKeyHeader = byteArrayOf(
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05,
        0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20
    )

    private val publicKeyHeader = byteArrayOf(
        0x30, 0x2a, 0x30, 0x05,
        0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00
    )

    /** A raw X25519 (private, public) pair, 32 bytes each. */
    fun generateKeyPair(): Pair<ByteArray, ByteArray> {
        val pair = KeyPairGenerator.getInstance("X25519").generateKeyPair()
        val private = pair.private.encoded.let { it.copyOfRange(it.size - KEY_SIZE, it.size) }
        val public = pair.public.encoded.let { it.copyOfRange(it.size - KEY_SIZE, it.size) }
        return private to public
    }

    fun diffieHellman(privateKey: ByteArray, publicKey: ByteArray): ByteArray {
        val factory = KeyFactory.getInstance("X25519")
        val agreement = KeyAgreement.getInstance("X25519")
        agreement.init(factory.generatePrivate(PKCS8EncodedKeySpec(privateKeyHeader + privateKey)))
        agreement.doPhase(factory.generatePublic(X509EncodedKeySpec(publicKeyHeader + publicKey)), true)
        return agreement.generateSecret()
    }

    fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

    fun hkdf2(salt: ByteArray, ikm: ByteArray): Pair<ByteArray, ByteArray> {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(salt, "HmacSHA256"))
        val prk = mac.doFinal(ikm)

        mac.init(SecretKeySpec(prk, "HmacSHA256"))
        mac.update(byteArrayOf(0x01))
        val first = mac.doFinal()

        mac.init(SecretKeySpec(prk, "HmacSHA256"))
        mac.update(first)
        mac.update(byteArrayOf(0x02))
        return first to mac.doFinal()
    }

    fun nonce(counter: Long): ByteArray = ByteBuffer.allocate(12)
        .order(ByteOrder.LITTLE_ENDIAN)
        .putInt(0)
        .putLong(counter)
        .array()

    fun encrypt(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray =
        cipher(Cipher.ENCRYPT_MODE, key, nonce, aad).doFinal(plaintext)

    fun decrypt(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray, aad: ByteArray): ByteArray =
        cipher(Cipher.DECRYPT_MODE, key, nonce, aad).doFinal(ciphertext)

    private fun cipher(mode: Int, key: ByteArray, nonce: ByteArray, aad: ByteArray): Cipher =
        Cipher.getInstance("ChaCha20-Poly1305").apply {
            init(mode, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
            updateAAD(aad)
        }
}
