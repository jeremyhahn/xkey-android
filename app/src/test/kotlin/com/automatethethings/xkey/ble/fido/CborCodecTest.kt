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

package com.automatethethings.xkey.ble.fido

import com.automatethethings.xkey.crypto.CborDecoder
import com.automatethethings.xkey.crypto.CborDecodingException
import com.automatethethings.xkey.crypto.CborEncoder
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

/** The general CBOR encoder and decoder CTAP2 requests and responses use. */
class CborCodecTest {

    private fun hex(s: String): ByteArray =
        s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    @Test
    fun `integers encode in their shortest form`() {
        assertArrayEquals(hex("00"), CborEncoder.encode(0))
        assertArrayEquals(hex("17"), CborEncoder.encode(23))
        assertArrayEquals(hex("1818"), CborEncoder.encode(24))
        assertArrayEquals(hex("190100"), CborEncoder.encode(256))
        assertArrayEquals(hex("1a00010000"), CborEncoder.encode(65536))
        assertArrayEquals(hex("26"), CborEncoder.encode(-7))
        assertArrayEquals(hex("3901ff"), CborEncoder.encode(-512))
    }

    @Test
    fun `strings, bytes, booleans and arrays encode per RFC 8949`() {
        assertArrayEquals(hex("6449455446"), CborEncoder.encode("IETF"))
        assertArrayEquals(hex("4401020304"), CborEncoder.encode(byteArrayOf(1, 2, 3, 4)))
        assertArrayEquals(hex("f5"), CborEncoder.encode(true))
        assertArrayEquals(hex("f4"), CborEncoder.encode(false))
        assertArrayEquals(hex("83010203"), CborEncoder.encode(listOf(1, 2, 3)))
    }

    @Test
    fun `map keys are sorted in CTAP2 canonical order`() {
        // Integers before text, shorter text before longer, then bytewise.
        val encoded = CborEncoder.encode(
            mapOf("type" to 1, 3 to 2, "id" to 3, 1 to 4, -1 to 5, "rk" to 6)
        )

        val expected = hex("a6") +
            hex("01") + hex("04") +
            hex("03") + hex("02") +
            hex("20") + hex("05") +
            hex("626964") + hex("03") +
            hex("62726b") + hex("06") +
            hex("6474797065") + hex("01")
        assertArrayEquals(expected, encoded)
    }

    @Test
    fun `decode round-trips a nested CTAP2-shaped request`() {
        val request = mapOf(
            1 to "example.com",
            2 to ByteArray(32) { it.toByte() },
            3 to listOf(mapOf("id" to byteArrayOf(9, 9), "type" to "public-key")),
            5 to mapOf("uv" to true, "up" to false)
        )

        val decoded = CborDecoder.decode(CborEncoder.encode(request)) as Map<*, *>

        assertEquals("example.com", decoded[1L])
        assertArrayEquals(ByteArray(32) { it.toByte() }, decoded[2L] as ByteArray)
        val allow = (decoded[3L] as List<*>)[0] as Map<*, *>
        assertArrayEquals(byteArrayOf(9, 9), allow["id"] as ByteArray)
        assertEquals("public-key", allow["type"])
        assertEquals(mapOf("uv" to true, "up" to false), decoded[5L])
    }

    @Test
    fun `decode reads negative and multi-byte integers`() {
        assertEquals(-7L, CborDecoder.decode(hex("26")))
        assertEquals(-512L, CborDecoder.decode(hex("3901ff")))
        assertEquals(65536L, CborDecoder.decode(hex("1a00010000")))
        assertEquals(1L shl 40, CborDecoder.decode(hex("1b0000010000000000")))
    }

    @Test
    fun `decode refuses truncated input, trailing bytes and indefinite lengths`() {
        assertThrows(CborDecodingException::class.java) { CborDecoder.decode(hex("44010203")) }
        assertThrows(CborDecodingException::class.java) { CborDecoder.decode(hex("0000")) }
        assertThrows(CborDecodingException::class.java) { CborDecoder.decode(hex("5f")) }
        assertThrows(CborDecodingException::class.java) { CborDecoder.decode(ByteArray(0)) }
    }

    @Test
    fun `decode refuses a length larger than the input before allocating it`() {
        assertThrows(CborDecodingException::class.java) {
            CborDecoder.decode(hex("5a7fffffff00"))
        }
    }

    @Test
    fun `decode refuses nesting deeper than the limit`() {
        val deep = ByteArray(40) { 0x81.toByte() } + hex("00")
        assertThrows(CborDecodingException::class.java) { CborDecoder.decode(deep) }
    }

    @Test
    fun `decode refuses invalid UTF-8 in a text string`() {
        assertThrows(CborDecodingException::class.java) { CborDecoder.decode(hex("61ff")) }
    }

    @Test
    fun `the COSE key encoder is unchanged`() {
        val x = ByteArray(32) { 1 }
        val y = ByteArray(32) { 2 }

        val cose = CborDecoder.decode(CborEncoder.encodeCOSEEC2Key(x, y)) as Map<*, *>

        assertEquals(2L, cose[1L])
        assertEquals(-7L, cose[3L])
        assertEquals(1L, cose[-1L])
        assertArrayEquals(x, cose[-2L] as ByteArray)
        assertArrayEquals(y, cose[-3L] as ByteArray)
    }
}
