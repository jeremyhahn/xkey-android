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
package com.automatethethings.xkey.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * Unit tests for [Base32] using the RFC 4648 §10 test vectors.
 */
class Base32Test {

    private fun bytes(s: String) = s.toByteArray(Charsets.US_ASCII)

    @Test
    fun `RFC 4648 encode vectors (unpadded)`() {
        assertEquals("", Base32.encode(bytes("")))
        assertEquals("MY", Base32.encode(bytes("f")))
        assertEquals("MZXQ", Base32.encode(bytes("fo")))
        assertEquals("MZXW6", Base32.encode(bytes("foo")))
        assertEquals("MZXW6YQ", Base32.encode(bytes("foob")))
        assertEquals("MZXW6YTB", Base32.encode(bytes("fooba")))
        assertEquals("MZXW6YTBOI", Base32.encode(bytes("foobar")))
    }

    @Test
    fun `RFC 4648 decode vectors accept padding`() {
        assertArrayEquals(bytes(""), Base32.decode(""))
        assertArrayEquals(bytes("f"), Base32.decode("MY======"))
        assertArrayEquals(bytes("fo"), Base32.decode("MZXQ===="))
        assertArrayEquals(bytes("foo"), Base32.decode("MZXW6==="))
        assertArrayEquals(bytes("foob"), Base32.decode("MZXW6YQ="))
        assertArrayEquals(bytes("fooba"), Base32.decode("MZXW6YTB"))
        assertArrayEquals(bytes("foobar"), Base32.decode("MZXW6YTBOI"))
    }

    @Test
    fun `decode is case-insensitive and ignores spaces`() {
        assertArrayEquals(bytes("foobar"), Base32.decode("mzxw6ytboi"))
        assertArrayEquals(bytes("foobar"), Base32.decode("MZXW 6YTB OI"))
    }

    @Test
    fun `encode then decode round-trips arbitrary bytes`() {
        val data = ByteArray(64) { (it * 7 - 3).toByte() }
        assertArrayEquals(data, Base32.decode(Base32.encode(data)))
    }

    @Test
    fun `decode rejects invalid characters`() {
        assertThrows(IllegalArgumentException::class.java) { Base32.decode("MZXW6YT!") }
    }

    @Test
    fun `encode zero-pads the trailing quantum`() {
        // Cross-checked against RFC 4648 Base32 (python base64.b32encode).
        assertEquals("AA", Base32.encode(byteArrayOf(0x00)))
        assertEquals("74", Base32.encode(byteArrayOf(0xFF.toByte())))
        assertEquals("AAAA", Base32.encode(byteArrayOf(0x00, 0x00)))
        assertEquals("AAAQEAYEAUDAOCAJ", Base32.encode(ByteArray(10) { it.toByte() }))
    }

    @Test
    fun `encodes the RFC 6238 shared secret used by TOTP fixtures`() {
        assertEquals(
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            Base32.encode(bytes("12345678901234567890"))
        )
        assertArrayEquals(
            bytes("12345678901234567890"),
            Base32.decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        )
    }

    @Test
    fun `decode rejects the 0 1 and 8 characters excluded from the alphabet`() {
        listOf("MZXW6YT0", "MZXW6YT1", "MZXW6YT8").forEach { input ->
            assertThrows(IllegalArgumentException::class.java) { Base32.decode(input) }
        }
    }

    @Test
    fun `decode error names the offending character`() {
        val error = assertThrows(IllegalArgumentException::class.java) { Base32.decode("MZ#W") }
        assertEquals("Invalid Base32 character: '#'", error.message)
    }

    @Test
    fun `decode discards a trailing partial group`() {
        // A lone character carries only 5 bits, which cannot form a byte.
        assertEquals(0, Base32.decode("A").size)
        // 11 characters = 55 bits: the 7 surplus bits are dropped.
        assertArrayEquals(bytes("foobar"), Base32.decode("MZXW6YTBOIA"))
    }

    @Test
    fun `decode trims surrounding whitespace and stray padding`() {
        assertArrayEquals(bytes("foobar"), Base32.decode("  MZXW6YTBOI  "))
        assertEquals(0, Base32.decode("=").size)
        assertEquals(0, Base32.decode("   ").size)
    }

    @Test
    fun `decode rejects embedded newlines`() {
        // Only spaces are stripped from the interior, so wrapped input fails.
        assertThrows(IllegalArgumentException::class.java) { Base32.decode("MZXW6\nYTBOI") }
    }

    @Test
    fun `encode then decode round-trips every length in one quantum`() {
        for (size in 0..16) {
            val data = ByteArray(size) { (it * 31 + size).toByte() }
            assertArrayEquals(
                "round trip failed for $size bytes",
                data,
                Base32.decode(Base32.encode(data))
            )
        }
    }

    @Test
    fun `encoded length is the ceiling of five-bit groups`() {
        for (size in 1..16) {
            val expected = (size * 8 + 4) / 5
            assertEquals(
                "unexpected encoded length for $size bytes",
                expected,
                Base32.encode(ByteArray(size)).length
            )
        }
    }
}
