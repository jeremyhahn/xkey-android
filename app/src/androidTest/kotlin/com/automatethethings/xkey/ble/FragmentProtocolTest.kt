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

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom

/**
 * Wire tests for the BLE fragmentation layer ([Fragmenter] /
 * [FragmentReassembler]).
 *
 * Every byte the phone exchanges with a desktop over BLE passes through this
 * 7-byte header, and the header layout is a cross-language contract with
 * `go-xkms/xkey/pkg/pairing` (big-endian flags/seq/total/len). None of it needs
 * a Bluetooth radio: it is pure byte manipulation, which makes it the cheapest
 * meaningful coverage in the `ble` package.
 *
 * These tests run instrumented rather than as JVM unit tests only because both
 * classes call `android.util.Log`.
 */
@RunWith(AndroidJUnit4::class)
class FragmentProtocolTest {

    private companion object {
        /** A realistic negotiated MTU payload: MTU 247 - 3 ATT - 7 header. */
        const val PAYLOAD = Fragmenter.DEFAULT_PAYLOAD_SIZE

        fun randomBytes(size: Int): ByteArray =
            ByteArray(size).also { SecureRandom().nextBytes(it) }

        /** Builds a raw fragment so malformed inputs can be constructed by hand. */
        fun rawFragment(
            flags: Int,
            sequence: Int,
            total: Int,
            length: Int,
            payload: ByteArray
        ): ByteArray = ByteBuffer.allocate(FragmentReassembler.HEADER_SIZE + payload.size)
            .order(ByteOrder.BIG_ENDIAN)
            .put(flags.toByte())
            .putShort(sequence.toShort())
            .putShort(total.toShort())
            .putShort(length.toShort())
            .put(payload)
            .array()
    }

    private val first = FragmentReassembler.FLAG_FIRST_FRAGMENT.toInt()
    private val last = FragmentReassembler.FLAG_LAST_FRAGMENT.toInt()

    // -----------------------------------------------------------------
    // Round trips
    // -----------------------------------------------------------------

    /** A message that fits in one fragment carries both the first and last flags. */
    @Test
    fun singleFragmentRoundTrip() {
        val message = "{\"id\":1,\"method\":\"ping\"}".toByteArray()
        val fragments = Fragmenter(PAYLOAD).fragment(message)

        assertEquals(1, fragments.size)
        val flags = fragments[0][0].toInt()
        assertTrue("lone fragment must be flagged first", flags and first != 0)
        assertTrue("lone fragment must be flagged last", flags and last != 0)

        assertArrayEquals(message, FragmentReassembler().addFragment(fragments[0]))
    }

    /** A message exactly the size of the payload budget must not split. */
    @Test
    fun exactPayloadBoundaryStaysSingleFragment() {
        val fragments = Fragmenter(PAYLOAD).fragment(randomBytes(PAYLOAD))
        assertEquals(1, fragments.size)
        assertEquals(FragmentReassembler.HEADER_SIZE + PAYLOAD, fragments[0].size)
    }

    /** One byte past the budget must split into exactly two fragments. */
    @Test
    fun onePastPayloadBoundarySplitsInTwo() {
        val message = randomBytes(PAYLOAD + 1)
        val fragments = Fragmenter(PAYLOAD).fragment(message)

        assertEquals(2, fragments.size)
        assertEquals(1, fragments[1].size - FragmentReassembler.HEADER_SIZE)
        assertArrayEquals(message, reassembleAll(fragments))
    }

    /** A response-sized payload survives fragmentation and reassembly intact. */
    @Test
    fun multiFragmentRoundTripPreservesBytes() {
        val message = randomBytes(10_000)
        val fragments = Fragmenter(PAYLOAD).fragment(message)

        val expectedCount = (message.size + PAYLOAD - 1) / PAYLOAD
        assertEquals(expectedCount, fragments.size)
        fragments.forEach {
            assertTrue(
                "no fragment may exceed the ATT payload budget",
                it.size <= FragmentReassembler.HEADER_SIZE + PAYLOAD
            )
        }
        assertArrayEquals(message, reassembleAll(fragments))
    }

    /** The minimum supported payload still round-trips (worst-case MTU). */
    @Test
    fun minimumPayloadSizeRoundTrips() {
        val message = randomBytes(431)
        val fragments = Fragmenter(20).fragment(message)
        assertEquals(22, fragments.size)
        assertArrayEquals(message, reassembleAll(fragments))
    }

    /** An empty message produces no fragments at all. */
    @Test
    fun emptyMessageProducesNoFragments() {
        assertTrue(Fragmenter(PAYLOAD).fragment(ByteArray(0)).isEmpty())
    }

    // -----------------------------------------------------------------
    // Header encoding: the cross-language contract
    // -----------------------------------------------------------------

    /**
     * Pins the header layout: 1 byte of flags then three big-endian uint16
     * fields. The Go initiator parses these positions verbatim, so a silent
     * endianness or ordering change here breaks every desktop.
     */
    @Test
    fun headerEncodingMatchesTheWireContract() {
        val message = randomBytes(3 * PAYLOAD)
        val fragments = Fragmenter(PAYLOAD).fragment(message)
        assertEquals(3, fragments.size)

        fragments.forEachIndexed { index, fragment ->
            val buffer = ByteBuffer.wrap(fragment).order(ByteOrder.BIG_ENDIAN)
            val flags = buffer.get().toInt()
            assertEquals(index, buffer.short.toInt() and 0xFFFF)
            assertEquals(3, buffer.short.toInt() and 0xFFFF)
            assertEquals(PAYLOAD, buffer.short.toInt() and 0xFFFF)

            assertEquals("first flag only on fragment 0", index == 0, flags and first != 0)
            assertEquals("last flag only on fragment 2", index == 2, flags and last != 0)
        }
    }

    // -----------------------------------------------------------------
    // Delivery anomalies
    // -----------------------------------------------------------------

    /** Fragments after the first may arrive in any order. */
    @Test
    fun outOfOrderFragmentsStillReassemble() {
        val message = randomBytes(3 * PAYLOAD)
        val fragments = Fragmenter(PAYLOAD).fragment(message)
        val reassembler = FragmentReassembler()

        assertNull(reassembler.addFragment(fragments[0]))
        assertNull(reassembler.addFragment(fragments[2]))
        assertArrayEquals(message, reassembler.addFragment(fragments[1]))
    }

    /** A repeated fragment is tolerated and does not corrupt the message. */
    @Test
    fun duplicateFragmentIsIgnored() {
        val message = randomBytes(3 * PAYLOAD)
        val fragments = Fragmenter(PAYLOAD).fragment(message)
        val reassembler = FragmentReassembler()

        assertNull(reassembler.addFragment(fragments[0]))
        assertNull(reassembler.addFragment(fragments[1]))
        assertNull(reassembler.addFragment(fragments[1]))
        assertEquals(2, reassembler.getFragmentCount())
        assertArrayEquals(message, reassembler.addFragment(fragments[2]))
    }

    /**
     * Documents the recovery rule: a fragment that arrives before any first
     * fragment is buffered, but the next first fragment discards it and starts a
     * fresh message. Re-sending the tail then completes normally.
     */
    @Test
    fun firstFragmentDiscardsAnEarlierPartialMessage() {
        val message = randomBytes(2 * PAYLOAD)
        val fragments = Fragmenter(PAYLOAD).fragment(message)
        val reassembler = FragmentReassembler()

        assertNull("a stray tail fragment cannot complete a message", reassembler.addFragment(fragments[1]))
        assertNull("a new first fragment restarts reassembly", reassembler.addFragment(fragments[0]))
        assertEquals(1, reassembler.getFragmentCount())
        assertArrayEquals(message, reassembler.addFragment(fragments[1]))
    }

    /** A message missing a fragment never completes and stays in progress. */
    @Test
    fun missingFragmentLeavesReassemblyIncomplete() {
        val fragments = Fragmenter(PAYLOAD).fragment(randomBytes(3 * PAYLOAD))
        val reassembler = FragmentReassembler()

        assertNull(reassembler.addFragment(fragments[0]))
        assertNull(reassembler.addFragment(fragments[2]))
        assertEquals(2, reassembler.getFragmentCount())
        assertEquals(3, reassembler.getExpectedTotal())
        assertTrue(reassembler.isInProgress())
    }

    /** Reset drops partial state so the next message starts clean. */
    @Test
    fun resetClearsPartialState() {
        val fragments = Fragmenter(PAYLOAD).fragment(randomBytes(3 * PAYLOAD))
        val reassembler = FragmentReassembler()

        reassembler.addFragment(fragments[0])
        reassembler.reset()

        assertFalse(reassembler.isInProgress())
        assertEquals(0, reassembler.getFragmentCount())
        assertEquals(0, reassembler.getExpectedTotal())
    }

    // -----------------------------------------------------------------
    // Malformed input
    // -----------------------------------------------------------------

    @Test
    fun fragmentShorterThanTheHeaderIsRejected() {
        assertFragmentRejected(ByteArray(FragmentReassembler.HEADER_SIZE - 1))
    }

    @Test
    fun zeroTotalIsRejected() {
        assertFragmentRejected(rawFragment(first or last, 0, 0, 4, randomBytes(4)))
    }

    @Test
    fun totalBeyondTheFragmentLimitIsRejected() {
        assertFragmentRejected(rawFragment(first, 0, 1001, 4, randomBytes(4)))
    }

    @Test
    fun sequenceOutsideTheTotalIsRejected() {
        assertFragmentRejected(rawFragment(0, 5, 3, 4, randomBytes(4)))
    }

    @Test
    fun declaredLengthLongerThanTheBufferIsRejected() {
        assertFragmentRejected(rawFragment(first, 0, 2, 100, randomBytes(10)))
    }

    @Test
    fun firstFlagOnANonZeroSequenceIsRejected() {
        assertFragmentRejected(rawFragment(first, 1, 3, 4, randomBytes(4)))
    }

    @Test
    fun lastFlagOnTheWrongSequenceIsRejected() {
        assertFragmentRejected(rawFragment(last, 1, 3, 4, randomBytes(4)))
    }

    /** A peer that changes its mind about the message length mid-stream is rejected. */
    @Test
    fun changingTheTotalMidMessageIsRejected() {
        val reassembler = FragmentReassembler()
        reassembler.addFragment(rawFragment(first, 0, 3, 4, randomBytes(4)))
        assertFragmentRejected(rawFragment(0, 1, 4, 4, randomBytes(4)), reassembler)
    }

    /**
     * A message large enough to exceed the 1000-fragment ceiling can be produced
     * by [Fragmenter] but is refused by [FragmentReassembler]. That ceiling —
     * not the documented 1 MB limit — is the real maximum message size: at the
     * default payload of 237 bytes it caps a message at ~237 KB.
     */
    @Test
    fun messagesBeyondTheFragmentCeilingCannotBeReassembled() {
        val fragments = Fragmenter(PAYLOAD).fragment(randomBytes(1001 * PAYLOAD))
        assertTrue(fragments.size > 1000)
        assertFragmentRejected(fragments[0])
    }

    /**
     * The fragmenter refuses payload budgets below 20 bytes.
     *
     * This is worth pinning because [GattServer] derives the budget as
     * `min(mtu - 3, 512) - 7`: at the BLE default MTU of 23 that is 13, so a
     * peer that never negotiates a larger MTU makes the responder throw before
     * it can send a single byte.
     */
    @Test
    fun fragmenterRefusesAPayloadBudgetBelowTheMinimum() {
        try {
            Fragmenter(19)
            fail("expected a payload budget below 20 bytes to be rejected")
        } catch (expected: IllegalArgumentException) {
            // expected
        }
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private fun reassembleAll(fragments: List<ByteArray>): ByteArray {
        val reassembler = FragmentReassembler()
        var complete: ByteArray? = null
        for (fragment in fragments) {
            reassembler.addFragment(fragment)?.let {
                assertNull("reassembly completed more than once", complete)
                complete = it
            }
        }
        return complete ?: throw AssertionError("fragments never reassembled")
    }

    private fun assertFragmentRejected(
        fragment: ByteArray,
        reassembler: FragmentReassembler = FragmentReassembler()
    ) {
        try {
            reassembler.addFragment(fragment)
            fail("expected FragmentException for malformed fragment")
        } catch (expected: FragmentException) {
            // expected
        }
    }
}
