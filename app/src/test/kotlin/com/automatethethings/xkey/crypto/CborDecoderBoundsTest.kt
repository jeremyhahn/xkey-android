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
package com.automatethethings.xkey.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.random.Random

/**
 * [CborDecoder] on hostile input: everything outside the CTAP2 subset, every
 * truncation and every declared length beyond the input is refused with a
 * [CborDecodingException], never another exception and never an allocation
 * sized by the attacker.
 */
class CborDecoderBoundsTest {

    private fun b(vararg values: Int) = ByteArray(values.size) { values[it].toByte() }

    /** A head with [major] and an 8-byte argument [value]. */
    private fun head64(major: Int, value: Long) =
        byteArrayOf(((major shl 5) or 27).toByte()) + ByteArray(8) { (value ushr (56 - 8 * it)).toByte() }

    /** A head with [major] and a 4-byte argument [value]. */
    private fun head32(major: Int, value: Long) =
        byteArrayOf(((major shl 5) or 26).toByte()) + ByteArray(4) { (value ushr (24 - 8 * it)).toByte() }

    private fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it) }

    /** [bytes] decodes to nothing: the decoder throws a [CborDecodingException] and nothing else. */
    private fun refused(bytes: ByteArray) {
        val outcome = runCatching { CborDecoder.decode(bytes) }
        val thrown = outcome.exceptionOrNull()
            ?: throw AssertionError("${hex(bytes)} decoded to ${outcome.getOrNull()}")
        if (thrown !is CborDecodingException) {
            throw AssertionError("${hex(bytes)} threw ${thrown.javaClass.name}, not CborDecodingException", thrown)
        }
    }

    private fun refused(vararg values: Int) = refused(b(*values))

    // --- truncation and trailing bytes ---

    @Test
    fun `empty input is refused`() = refused(ByteArray(0))

    @Test
    fun `trailing bytes after the item are refused`() {
        refused(0x01, 0x00)
        refused(0xA0, 0xA0)
        refused(0x41, 0x01, 0x02)
        refused(0xF6, 0xF6)
    }

    @Test
    fun `input ending inside a head is refused`() {
        refused(0x18)
        refused(0x19, 0x01)
        refused(0x1A, 0x00, 0x00, 0x00)
        refused(0x1B, 0, 0, 0, 0, 0, 0, 0)
        refused(0x38)
        refused(0x58)
        refused(0x79, 0x00)
        refused(0x98)
        refused(0xB9, 0x00)
    }

    @Test
    fun `input ending inside a byte string is refused`() {
        refused(0x43, 0x01, 0x02)
        refused(0x58, 0x20, *IntArray(31))
    }

    @Test
    fun `input ending inside a text string is refused`() {
        refused(0x63, 0x61, 0x62)
        refused(0x78, 0x05, 0x61)
    }

    @Test
    fun `input ending inside an array or a map is refused`() {
        refused(0x82, 0x01)
        refused(0xA1, 0x01)
        refused(0xA2, 0x01, 0x02, 0x03)
    }

    // --- declared lengths beyond the input ---

    @Test(timeout = 5_000)
    fun `a byte string length beyond the input is refused`() {
        refused(head32(2, 0x7FFFFFFF) + ByteArray(4))
        refused(head64(2, Long.MAX_VALUE) + ByteArray(4))
    }

    @Test(timeout = 5_000)
    fun `a text string length beyond the input is refused`() {
        refused(head32(3, 0xFFFFFFFFL) + "abc".toByteArray())
        refused(head64(3, Long.MAX_VALUE) + "abc".toByteArray())
    }

    @Test(timeout = 5_000)
    fun `an array header claiming 2^31 or 2^63 items fails fast`() {
        refused(head32(4, 1L shl 31) + b(0x01, 0x01))
        refused(head64(4, 1L shl 31) + b(0x01, 0x01))
        refused(head64(4, Long.MAX_VALUE) + b(0x01, 0x01))
        // 2^63 does not fit 63 bits.
        refused(head64(4, Long.MIN_VALUE) + b(0x01, 0x01))
    }

    @Test(timeout = 5_000)
    fun `a map header claiming 2^31 or 2^63 entries fails fast`() {
        refused(head32(5, 1L shl 31) + b(0x01, 0x01))
        refused(head64(5, Long.MAX_VALUE) + b(0x01, 0x01))
        refused(head64(5, Long.MIN_VALUE) + b(0x01, 0x01))
    }

    // --- nesting ---

    @Test
    fun `an item inside MAX_DEPTH containers is accepted`() {
        val depth = CborDecoder.MAX_DEPTH
        var value = CborDecoder.decode(ByteArray(depth) { 0x81.toByte() } + b(0x01))
        repeat(depth) { value = (value as List<*>).single() }
        assertEquals(1L, value)

        // The innermost container itself may sit at MAX_DEPTH, as long as it is empty.
        CborDecoder.decode(ByteArray(depth) { 0x81.toByte() } + b(0x80))

        // Maps count the same way, for their values.
        val maps = ByteArray(depth * 2) { if (it % 2 == 0) 0xA1.toByte() else 0x01 } + b(0x02)
        var map = CborDecoder.decode(maps)
        repeat(depth) { map = (map as Map<*, *>)[1L] }
        assertEquals(2L, map)
    }

    @Test
    fun `an item inside MAX_DEPTH plus one containers is refused`() {
        val depth = CborDecoder.MAX_DEPTH + 1
        refused(ByteArray(depth) { 0x81.toByte() } + b(0x01))
        refused(ByteArray(depth) { 0x81.toByte() } + b(0x80))
        refused(ByteArray(depth * 2) { if (it % 2 == 0) 0xA1.toByte() else 0x01 } + b(0x02))
        // A map key counts as nested too.
        refused(ByteArray(CborDecoder.MAX_DEPTH) { 0x81.toByte() } + b(0xA1, 0x01, 0x02))
    }

    @Test(timeout = 5_000)
    fun `deep nesting far past MAX_DEPTH is refused without exhausting the stack`() {
        refused(ByteArray(100_000) { 0x81.toByte() } + b(0x01))
        refused(ByteArray(100_000) { 0x9F.toByte() })
    }

    // --- integers ---

    @Test
    fun `an unsigned integer above 63 bits is refused and 2^63 - 1 is accepted`() {
        refused(head64(0, Long.MIN_VALUE))
        refused(head64(0, -1L))
        assertEquals(Long.MAX_VALUE, CborDecoder.decode(head64(0, Long.MAX_VALUE)))
    }

    @Test
    fun `a negative integer below -2^63 is refused`() {
        refused(head64(1, Long.MIN_VALUE))
        refused(head64(1, -1L))
    }

    @Test
    fun `negative integer edge values decode exactly`() {
        assertEquals(-1L, CborDecoder.decode(b(0x20)))
        assertEquals(-2L, CborDecoder.decode(b(0x21)))
        assertEquals(-24L, CborDecoder.decode(b(0x37)))
        assertEquals(-25L, CborDecoder.decode(b(0x38, 0x18)))
        assertEquals(-256L, CborDecoder.decode(b(0x38, 0xFF)))
        assertEquals(-4294967296L, CborDecoder.decode(head32(1, 0xFFFFFFFFL)))
        assertEquals(Long.MIN_VALUE, CborDecoder.decode(head64(1, Long.MAX_VALUE)))
    }

    // --- indefinite lengths, reserved values, tags, floats, simple values ---

    @Test
    fun `indefinite lengths are refused for every major type`() {
        refused(0x5F, 0x41, 0x01, 0xFF)
        refused(0x7F, 0x61, 0x61, 0xFF)
        refused(0x9F, 0x01, 0xFF)
        refused(0xBF, 0x01, 0x01, 0xFF)
        refused(0x1F)
        refused(0x3F)
    }

    @Test
    fun `reserved additional information 28 to 30 is refused`() {
        for (major in 0..5) for (info in 28..30) refused(b((major shl 5) or info, 0, 0, 0, 0, 0, 0, 0, 0))
    }

    @Test
    fun `tags are refused`() {
        refused(0xC0, 0x60)
        refused(0xC1, 0x01)
        refused(0xC2, 0x41, 0x01)
        refused(0xD8, 0x20, 0x60)
        refused(0xD9, 0xD9, 0xF7, 0x01)
    }

    @Test
    fun `floats are refused`() {
        refused(0xF9, 0x3C, 0x00)
        refused(0xFA, 0x3F, 0x80, 0x00, 0x00)
        refused(0xFB, 0x3F, 0xF0, 0, 0, 0, 0, 0, 0)
    }

    @Test
    fun `simple values other than false, true and null are refused`() {
        refused(0xE0)
        refused(0xF3)
        refused(0xF7)
        refused(0xF8, 0x20)
        refused(0xFF)
        assertEquals(false, CborDecoder.decode(b(0xF4)))
        assertEquals(true, CborDecoder.decode(b(0xF5)))
        assertNull(CborDecoder.decode(b(0xF6)))
    }

    // --- text ---

    @Test
    fun `invalid UTF-8 text is refused`() {
        refused(0x61, 0xFF)
        refused(0x61, 0x80)
        refused(0x61, 0xC3)
        refused(0x62, 0xC3, 0x28)
        refused(0x62, 0xC0, 0x80)
        refused(0x63, 0xED, 0xA0, 0x80)
        refused(0x64, 0xF4, 0x90, 0x80, 0x80)
    }

    @Test
    fun `valid UTF-8 text decodes`() {
        val text = "café € 😀"
        val utf8 = text.toByteArray(Charsets.UTF_8)
        assertEquals(text, CborDecoder.decode(b(0x60 + utf8.size) + utf8))
    }

    // --- map keys ---

    @Test
    fun `a map key that is a byte string, an array or a map is refused`() {
        refused(0xA1, 0x41, 0x01, 0x01)
        refused(0xA1, 0x40, 0x01)
        refused(0xA1, 0x80, 0x01)
        refused(0xA1, 0x81, 0x01, 0x01)
        refused(0xA1, 0xA0, 0x01)
    }

    @Test
    fun `a duplicate map key is refused`() {
        refused(0xA2, 0x01, 0x01, 0x01, 0x02)
        refused(0xA2, 0x20, 0x01, 0x20, 0x01)
        refused(0xA2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02)
        // A duplicate in a nested map too.
        refused(0xA1, 0x01, 0xA2, 0x02, 0x00, 0x02, 0x00)
    }

    @Test
    fun `integer and text keys decode in order`() {
        val map = CborDecoder.decode(b(0xA3, 0x01, 0x41, 0x07, 0x20, 0xF5, 0x61, 0x31, 0x80)) as Map<*, *>
        assertEquals(listOf(1L, -1L, "1"), map.keys.toList())
        assertArrayEquals(byteArrayOf(7), map[1L] as ByteArray)
        assertEquals(true, map[-1L])
        assertEquals(emptyList<Any>(), map["1"])
    }

    // --- every refusal is a CborDecodingException ---

    @Test(timeout = 60_000)
    fun `every short input decodes or throws CborDecodingException`() {
        refusedOrDecoded(ByteArray(0))
        for (first in 0..255) {
            refusedOrDecoded(b(first))
            for (second in 0..255) refusedOrDecoded(b(first, second))
        }
        val random = Random(342)
        repeat(200_000) {
            refusedOrDecoded(random.nextBytes(3 + random.nextInt(14)))
        }
    }

    private fun refusedOrDecoded(bytes: ByteArray) {
        try {
            CborDecoder.decode(bytes)
        } catch (e: CborDecodingException) {
            // Refused as it should be.
        } catch (t: Throwable) {
            throw AssertionError("${hex(bytes)} threw ${t.javaClass.name}, not CborDecodingException", t)
        }
    }
}
