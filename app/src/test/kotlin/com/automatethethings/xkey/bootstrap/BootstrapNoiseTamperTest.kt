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
package com.automatethethings.xkey.bootstrap

import android.util.Log
import com.automatethethings.xkey.settings.BootstrapMethod
import com.automatethethings.xkey.settings.BootstrapSettingsData
import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import kotlinx.coroutines.runBlocking
import org.json.JSONException
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.net.InetAddress
import java.net.ServerSocket
import javax.crypto.AEADBadTagException

/**
 * The Noise_NK bootstrap client against responders that misbehave.
 *
 * `BootstrapNoiseTest` only ever meets an honest responder. Each responder
 * here follows the same exchange (and, like a real Noise responder, always
 * sends the AEAD payload on `<- e, ee`) but tampers with one thing. Every
 * case must fail without a bundle, and fail as a [NoiseBootstrapException]:
 * `fetchWithMethod` promises a `BootstrapException`, as the DANE and SPKI
 * paths deliver by wrapping their transport failures.
 */
class BootstrapNoiseTamperTest {

    private enum class Tamper {
        /** Holds a static key other than the one the client is configured with. */
        WRONG_STATIC_KEY,

        /** Flips one bit of the responder ephemeral key in msg2. */
        FLIP_EPHEMERAL_BIT,

        /** Sends an all-zero (small-order) ephemeral key in msg2. */
        ZERO_EPHEMERAL,

        /** Flips one byte of the AEAD tag on the msg2 payload. */
        FLIP_HANDSHAKE_TAG,

        /** Flips one byte of the encrypted response. */
        FLIP_RESPONSE_CIPHERTEXT,

        /** Answers the request with msg2's payload ciphertext. */
        REPLAY_MSG2_CIPHERTEXT,

        /** Declares a 65535-byte response frame and closes after a few bytes. */
        TRUNCATED_RESPONSE_FRAME,

        /** Sends a well-encrypted response that is not JSON. */
        NON_JSON_RESPONSE
    }

    /** A Noise_NK responder that tampers with the exchange as [tamper] says. */
    private class HostileResponder(private val tamper: Tamper) : AutoCloseable {

        private val staticKeyPair = NoiseTestCrypto.generateKeyPair()

        /** The key the client is configured with: the responder's own, unless the case says otherwise. */
        val configuredKeyHex: String = (
            if (tamper == Tamper.WRONG_STATIC_KEY) NoiseTestCrypto.generateKeyPair().second
            else staticKeyPair.second
            ).joinToString("") { "%02x".format(it) }

        private val server = ServerSocket(0, 1, InetAddress.getLoopbackAddress())

        val address: String = "127.0.0.1:${server.localPort}"

        private val worker = Thread({ serve() }, "noise-hostile-responder").apply {
            isDaemon = true
            start()
        }

        private fun serve() {
            try {
                server.accept().use { socket ->
                    socket.soTimeout = 10_000
                    val input = DataInputStream(socket.getInputStream())
                    val output = DataOutputStream(socket.getOutputStream())

                    var hash = PROTOCOL_NAME.toByteArray(Charsets.US_ASCII)
                    var chainingKey = hash.copyOf()
                    hash = NoiseTestCrypto.sha256(hash)
                    hash = NoiseTestCrypto.sha256(hash + staticKeyPair.second)

                    val initiatorEphemeral = readFrame(input)
                    hash = NoiseTestCrypto.sha256(hash + initiatorEphemeral)
                    var keys = NoiseTestCrypto.hkdf2(
                        chainingKey,
                        NoiseTestCrypto.diffieHellman(staticKeyPair.first, initiatorEphemeral)
                    )
                    chainingKey = keys.first

                    val ephemeral = NoiseTestCrypto.generateKeyPair()
                    hash = NoiseTestCrypto.sha256(hash + ephemeral.second)
                    keys = NoiseTestCrypto.hkdf2(
                        chainingKey,
                        NoiseTestCrypto.diffieHellman(ephemeral.first, initiatorEphemeral)
                    )
                    chainingKey = keys.first
                    val payload = NoiseTestCrypto.encrypt(keys.second, NoiseTestCrypto.nonce(0), ByteArray(0), hash)

                    val message2 = ephemeral.second + payload
                    when (tamper) {
                        Tamper.FLIP_EPHEMERAL_BIT -> message2[0] = (message2[0].toInt() xor 0x01).toByte()
                        Tamper.ZERO_EPHEMERAL -> message2.fill(0, 0, ephemeral.second.size)
                        Tamper.FLIP_HANDSHAKE_TAG ->
                            message2[message2.size - 1] = (message2[message2.size - 1].toInt() xor 0x01).toByte()
                        else -> Unit
                    }
                    writeFrame(output, message2)

                    val (initiatorSendKey, initiatorReceiveKey) = NoiseTestCrypto.hkdf2(chainingKey, ByteArray(0))
                    NoiseTestCrypto.decrypt(initiatorSendKey, NoiseTestCrypto.nonce(0), readFrame(input), ByteArray(0))

                    fun seal(plaintext: String): ByteArray = NoiseTestCrypto.encrypt(
                        initiatorReceiveKey,
                        NoiseTestCrypto.nonce(0),
                        plaintext.toByteArray(Charsets.UTF_8),
                        ByteArray(0)
                    )

                    when (tamper) {
                        Tamper.FLIP_RESPONSE_CIPHERTEXT -> writeFrame(
                            output,
                            seal(HONEST_REPLY).also { it[0] = (it[0].toInt() xor 0x01).toByte() }
                        )
                        Tamper.REPLAY_MSG2_CIPHERTEXT -> writeFrame(output, payload)
                        Tamper.TRUNCATED_RESPONSE_FRAME -> {
                            output.writeShort(0xFFFF)
                            output.write(ByteArray(10))
                            output.flush()
                        }
                        Tamper.NON_JSON_RESPONSE -> writeFrame(output, seal("this is not json"))
                        else -> writeFrame(output, seal(HONEST_REPLY))
                    }
                }
            } catch (_: Throwable) {
                // The client refusing a tampered handshake ends the exchange early.
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
            private const val HONEST_REPLY = """{"bundle_pem":"","certificates":[]}"""
        }
    }

    private var responder: HostileResponder? = null

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.i(any(), any()) } returns 0
        every { Log.d(any(), any()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.e(any(), any<String>()) } returns 0
    }

    @After
    fun tearDown() {
        responder?.close()
        responder = null
        unmockkAll()
    }

    private fun start(tamper: Tamper): HostileResponder = HostileResponder(tamper).also { responder = it }

    private fun noiseSettings(server: HostileResponder) = BootstrapSettingsData(
        methodOrder = listOf(BootstrapMethod.NOISE),
        perMethodTimeoutSeconds = 15,
        daneEnabled = false,
        noiseEnabled = true,
        noiseServerAddr = server.address,
        noiseServerStaticKey = server.configuredKeyHex,
        spkiEnabled = false,
        directEnabled = false
    )

    /** Runs the Noise fetch against [tamper] and returns the failure it must raise. */
    private fun refusal(tamper: Tamper): NoiseBootstrapException {
        val server = start(tamper)
        val client = BootstrapClient(noiseSettings(server), StubBootstrapEndpoint.failing().client())
        return assertThrows(NoiseBootstrapException::class.java) {
            runBlocking { client.fetchWithMethod(BootstrapMethod.NOISE) }
        }
    }

    private fun assertCause(failure: Throwable, expected: Class<out Throwable>) {
        assertTrue("cause was ${failure.cause}", expected.isInstance(failure.cause))
    }

    // ------------------------------------------------------------- handshake

    @Test(timeout = 30_000)
    fun aResponderHoldingAnotherStaticKeyIsRefused() {
        assertCause(refusal(Tamper.WRONG_STATIC_KEY), AEADBadTagException::class.java)
    }

    @Test(timeout = 30_000)
    fun aFlippedBitInTheResponderEphemeralIsRefused() {
        assertCause(refusal(Tamper.FLIP_EPHEMERAL_BIT), AEADBadTagException::class.java)
    }

    @Test(timeout = 30_000)
    fun aSmallOrderResponderEphemeralIsRefused() {
        val failure = refusal(Tamper.ZERO_EPHEMERAL)

        assertTrue("cause was ${failure.cause}", failure.cause != null)
    }

    @Test(timeout = 30_000)
    fun aFlippedTagByteOnTheHandshakePayloadIsRefused() {
        assertCause(refusal(Tamper.FLIP_HANDSHAKE_TAG), AEADBadTagException::class.java)
    }

    // ------------------------------------------------------------- transport

    @Test(timeout = 30_000)
    fun aFlippedResponseCiphertextByteIsRefused() {
        assertCause(refusal(Tamper.FLIP_RESPONSE_CIPHERTEXT), AEADBadTagException::class.java)
    }

    @Test(timeout = 30_000)
    fun aResponseReplayingTheHandshakeCiphertextIsRefused() {
        assertCause(refusal(Tamper.REPLAY_MSG2_CIPHERTEXT), AEADBadTagException::class.java)
    }

    @Test(timeout = 30_000)
    fun aResponseFrameThatEndsBeforeItsDeclaredLengthIsRefused() {
        assertCause(refusal(Tamper.TRUNCATED_RESPONSE_FRAME), EOFException::class.java)
    }

    @Test(timeout = 30_000)
    fun aResponseThatDecryptsToSomethingOtherThanJsonIsRefused() {
        assertCause(refusal(Tamper.NON_JSON_RESPONSE), JSONException::class.java)
    }

    // ------------------------------------------------------------- fallback

    @Test(timeout = 30_000)
    fun aTamperedNoiseExchangeFallsThroughToDirect() {
        val server = start(Tamper.FLIP_RESPONSE_CIPHERTEXT)
        val endpoint = StubBootstrapEndpoint.serving(TestPki.bundle(1))
        val settings = noiseSettings(server).copy(
            methodOrder = listOf(BootstrapMethod.NOISE, BootstrapMethod.DIRECT),
            directEnabled = true,
            directServerUrl = "https://${TlsBootstrapServer.HOST}"
        )

        val result = runBlocking { BootstrapClient(settings, endpoint.client()).fetchCABundle() }

        assertEquals(BootstrapMethod.DIRECT, result.method)
        assertEquals(1, endpoint.requests.size)
    }

    @Test(timeout = 30_000)
    fun theNoiseFailureIsRecordedAsAttemptedBeforeDirect() {
        val server = start(Tamper.FLIP_RESPONSE_CIPHERTEXT)
        val settings = noiseSettings(server).copy(
            methodOrder = listOf(BootstrapMethod.NOISE, BootstrapMethod.DIRECT),
            directEnabled = true,
            directServerUrl = "https://${TlsBootstrapServer.HOST}"
        )

        val failure = assertThrows(BootstrapFailedException::class.java) {
            runBlocking {
                BootstrapClient(settings, StubBootstrapEndpoint.failing().client()).fetchCABundle()
            }
        }

        assertEquals(listOf(BootstrapMethod.NOISE, BootstrapMethod.DIRECT), failure.attempts.map { it.method })
        val noise = failure.attempts[0].error
        assertTrue("noise error was $noise", noise is NoiseBootstrapException)
        assertCause(noise, AEADBadTagException::class.java)
        assertTrue(failure.attempts[1].error is DirectException)
    }
}
