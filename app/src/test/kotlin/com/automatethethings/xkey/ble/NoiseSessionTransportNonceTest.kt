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

package com.automatethethings.xkey.ble

import android.content.Context
import android.util.Log
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import java.security.SecureRandom
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test

/**
 * [NoiseSession]'s transport counters follow the Noise framework (#236):
 * a frame that fails authentication leaves the receive counter where it was,
 * and the reserved counter value 2^64-1 (`-1L` as a signed Long) is never
 * used to encrypt or decrypt.
 *
 * The harness is the one [NoiseSessionZeroizationTest] uses: the responder
 * runs a real XX handshake against [NoiseInitiatorSession], and
 * `loadStaticKey` falls back to an in-memory static key off-device.
 */
class NoiseSessionTransportNonceTest {

    private companion object {
        const val KEY_SIZE = 32

        /** The reserved Noise counter value 2^64-1, as a signed Long. */
        const val RESERVED_NONCE = -1L

        fun randomBytes(size: Int): ByteArray =
            ByteArray(size).also { SecureRandom().nextBytes(it) }
    }

    private lateinit var context: Context

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.v(any(), any<String>()) } returns 0
        every { Log.d(any(), any<String>()) } returns 0
        every { Log.i(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.e(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>(), any()) } returns 0
        every { Log.e(any(), any<String>(), any()) } returns 0
        context = mockk(relaxed = true)
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    /**
     * A frame with one flipped ciphertext bit fails to decrypt, and the
     * genuine frame sent with the same nonce still decrypts after it.
     */
    @Test
    fun aFrameThatFailsAuthenticationLeavesTheReceiveNonceUnchanged() = runTest {
        val (responder, initiator) = establishedPair()
        val plaintext = "genuine".toByteArray()
        val genuine = initiator.encrypt(plaintext)

        assertThrows(Exception::class.java) { responder.decrypt(flipOneBit(genuine)) }

        assertArrayEquals(plaintext, responder.decrypt(genuine))
    }

    /** After a failed frame, three genuine frames decrypt in order. */
    @Test
    fun threeFramesAfterAFailureDecryptInOrder() = runTest {
        val (responder, initiator) = establishedPair()
        val plaintexts = listOf("one", "two", "three").map { it.toByteArray() }
        val frames = plaintexts.map { initiator.encrypt(it) }

        assertThrows(Exception::class.java) { responder.decrypt(flipOneBit(frames[0])) }

        frames.zip(plaintexts).forEach { (frame, plaintext) ->
            assertArrayEquals(plaintext, responder.decrypt(frame))
        }
    }

    /** A send counter at the reserved value refuses to encrypt. */
    @Test
    fun encryptRefusesTheReservedNonce() = runTest {
        val (responder, _) = establishedPair()
        responder.setTransportNoncesForTest(send = RESERVED_NONCE, recv = 0)

        assertThrows(NoiseException::class.java) { responder.encrypt("x".toByteArray()) }
    }

    /**
     * The last usable send counter encrypts once; the counter then sits at
     * the reserved value and the next encrypt is refused.
     */
    @Test
    fun encryptUsesTheLastCounterOnceThenRefuses() = runTest {
        val (responder, _) = establishedPair()
        responder.setTransportNoncesForTest(send = RESERVED_NONCE - 1, recv = 0)

        responder.encrypt("last".toByteArray())

        assertThrows(NoiseException::class.java) { responder.encrypt("x".toByteArray()) }
    }

    /** A receive counter at the reserved value refuses to decrypt. */
    @Test
    fun decryptRefusesTheReservedNonce() = runTest {
        val (responder, initiator) = establishedPair()
        val frame = initiator.encrypt("x".toByteArray())
        responder.setTransportNoncesForTest(send = 0, recv = RESERVED_NONCE)

        assertThrows(NoiseException::class.java) { responder.decrypt(frame) }
    }

    // ---------------------------------------------------------------------
    // Harness
    // ---------------------------------------------------------------------

    private suspend fun establishedPair(): Pair<NoiseSession, NoiseInitiatorSession> {
        val responder = NoiseSession().also { it.loadStaticKey(context) }
        val initiator = NoiseInitiatorSession(randomBytes(KEY_SIZE))
        val msg2 = responder.processHandshakeMessage(initiator.createHandshakeMessage1())
            ?: throw AssertionError("the responder produced no msg2")
        initiator.processHandshakeMessage2(msg2)
        responder.processHandshakeMessage(initiator.createHandshakeMessage3())
        initiator.finalizeHandshake()
        return responder to initiator
    }

    private fun flipOneBit(frame: ByteArray): ByteArray =
        frame.copyOf().also { it[0] = (it[0].toInt() xor 0x01).toByte() }
}
