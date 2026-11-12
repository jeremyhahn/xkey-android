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

package com.automatethethings.xkey.protocol

import android.content.Context
import android.util.Log
import com.automatethethings.xkey.ble.NoiseInitiatorSession
import com.automatethethings.xkey.ble.NoiseSession
import com.automatethethings.xkey.ble.sessionBinding
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import java.security.SecureRandom
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

/**
 * The pairing SAS — go-xkms `formatShortAuthString`, which the desktop prints
 * during `xkey device pair` and the phone shows on its pairing-confirm screen.
 *
 * The fixed vectors pin the format byte for byte; the handshake tests run the
 * phone's two Noise implementations against each other, since the SAS only
 * protects anything if both ends of one handshake derive the same code and two
 * different handshakes do not.
 */
class ShortAuthStringTest {

    private companion object {
        const val KEY_SIZE = 32

        /** `^\d{4}-\d{4}-\d{4}$`, the shape go-xkms prints. */
        val SAS_SHAPE = Regex("""^\d{4}-\d{4}-\d{4}$""")

        fun randomBytes(size: Int): ByteArray =
            ByteArray(size).also { SecureRandom().nextBytes(it) }
    }

    /** Only ever used to reach [NoiseSession.loadStaticKey]'s in-memory fallback. */
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

    // -----------------------------------------------------------------
    // The format
    // -----------------------------------------------------------------

    /**
     * The shared vector: a fixed session binding gives the code pinned in
     * [SasTestVectors], the one the phone-initiated SAS tests rely on.
     */
    @Test
    fun theSharedFixedBindingGivesThePinnedCode() {
        assertEquals(SasTestVectors.FIXED_BINDING_SAS, AttestTranscript.shortAuthString(SasTestVectors.fixedBinding()))
    }

    /** The go-xkms conformance vector: 0x0001, 0x0203 and 0x0405. */
    @Test
    fun bindingBytesZeroToThirtyOneGiveTheConformanceVector() {
        val binding = ByteArray(32) { it.toByte() }

        assertEquals("0001-0515-1029", AttestTranscript.formatShortAuthString(binding))
    }

    /** 0xFFFF is 65535, so the group is reduced mod 10000, not truncated. */
    @Test
    fun eachGroupIsReducedModTenThousand() {
        val binding = ByteArray(32).also {
            it[0] = 0xFF.toByte()
            it[1] = 0xFF.toByte()
        }

        assertEquals("5535-0000-0000", AttestTranscript.formatShortAuthString(binding))
    }

    @Test
    fun eachGroupIsZeroPaddedToFourDigits() {
        val binding = ByteArray(32).also {
            it[1] = 0x07
            it[3] = 0x63
            it[5] = 0x00
        }

        assertEquals("0007-0099-0000", AttestTranscript.formatShortAuthString(binding))
    }

    /** Only bytes 0..5 are read; the rest of the binding does not move the code. */
    @Test
    fun onlyTheFirstSixBytesAreRead() {
        val binding = ByteArray(32) { it.toByte() }
        binding.fill(0x5A, fromIndex = 6)

        assertEquals("0001-0515-1029", AttestTranscript.formatShortAuthString(binding))
    }

    @Test
    fun aBindingThatIsNotThirtyTwoBytesIsRefused() {
        for (size in listOf(0, 6, 31, 33)) {
            try {
                AttestTranscript.formatShortAuthString(ByteArray(size))
                fail("a $size-byte binding must be refused")
            } catch (expected: IllegalArgumentException) {
                // the channel binding is always a SHA-256
            }
        }
    }

    // -----------------------------------------------------------------
    // The handshake
    // -----------------------------------------------------------------

    /** No session means nothing to authenticate: an error, never a string. */
    @Test
    fun noBindingIsAnErrorNotACode() {
        try {
            AttestTranscript.shortAuthString(null)
            fail("a SAS without a completed handshake must be refused")
        } catch (expected: IllegalStateException) {
            // refused before the handshake completes
        }
    }

    /**
     * Mid-handshake the initiator already holds the responder's static key
     * (message 2 carries it), but the handshake is not complete, so there is
     * still no binding — and so no code.
     */
    @Test
    fun anIncompleteHandshakeYieldsNoBindingAndSoNoCode() = runTest {
        val initiator = NoiseInitiatorSession(randomBytes(KEY_SIZE))
        val responder = newResponder()
        val msg2 = responder.processHandshakeMessage(initiator.createHandshakeMessage1())
            ?: throw AssertionError("the responder produced no msg2")
        initiator.processHandshakeMessage2(msg2)

        assertNull("the initiator must not bind before completing", initiator.sessionBinding())
        assertNull("the responder must not bind before msg3", responder.sessionBinding())
        try {
            AttestTranscript.shortAuthString(initiator.sessionBinding())
            fail("a SAS before the handshake completes must be refused")
        } catch (expected: IllegalStateException) {
            // refused before the handshake completes
        }
    }

    /**
     * The phone-initiated direction ([NoiseInitiatorSession], the phone dialling
     * a desktop) and the phone-accepted one ([NoiseSession]) are both ends of
     * one handshake here, so the two codes are what the two screens would show.
     */
    @Test
    fun bothPeersOfOneHandshakeComputeTheSameCode() = runTest {
        val initiator = NoiseInitiatorSession(randomBytes(KEY_SIZE))
        val responder = newResponder()

        handshake(initiator, responder)

        val initiatorSas = AttestTranscript.shortAuthString(initiator.sessionBinding())
        val responderSas = AttestTranscript.shortAuthString(responder.sessionBinding())
        assertEquals(initiatorSas, responderSas)
        assertTrue("not NNNN-NNNN-NNNN: $initiatorSas", SAS_SHAPE.matches(initiatorSas))
    }

    /** A relay runs two handshakes; the two codes it produces must disagree. */
    @Test
    fun twoDifferentHandshakesGiveDifferentCodes() = runTest {
        val first = NoiseInitiatorSession(randomBytes(KEY_SIZE))
        val second = NoiseInitiatorSession(randomBytes(KEY_SIZE))
        handshake(first, newResponder())
        handshake(second, newResponder())

        assertNotEquals(
            AttestTranscript.shortAuthString(first.sessionBinding()),
            AttestTranscript.shortAuthString(second.sessionBinding())
        )
    }

    /** The SAS is the attestation's own channel binding, formatted. */
    @Test
    fun theCodeIsTheAttestationChannelBindingFormatted() = runTest {
        val initiator = NoiseInitiatorSession(randomBytes(KEY_SIZE))
        val responder = newResponder()
        handshake(initiator, responder)
        val binding = responder.sessionBinding()
            ?: throw AssertionError("a completed handshake must bind")

        val channelBinding = AttestTranscript.channelBinding(
            binding.initiatorStaticPublicKey,
            binding.responderStaticPublicKey,
            binding.prologue
        )
        assertEquals(
            AttestTranscript.formatShortAuthString(channelBinding),
            AttestTranscript.shortAuthString(binding)
        )
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private suspend fun newResponder(): NoiseSession =
        NoiseSession().also { it.loadStaticKey(context) }

    /** Runs the three XX messages between the two implementations. */
    private suspend fun handshake(initiator: NoiseInitiatorSession, responder: NoiseSession) {
        val msg2 = responder.processHandshakeMessage(initiator.createHandshakeMessage1())
            ?: throw AssertionError("the responder produced no msg2")
        initiator.processHandshakeMessage2(msg2)
        assertNull(
            "the responder must not reply to msg3",
            responder.processHandshakeMessage(initiator.createHandshakeMessage3())
        )
        initiator.finalizeHandshake()
    }
}
