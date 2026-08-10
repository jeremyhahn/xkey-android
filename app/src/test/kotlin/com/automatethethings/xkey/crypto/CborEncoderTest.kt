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
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for CborEncoder.
 *
 * These tests verify the CBOR encoding of COSE EC2 P-256 public keys,
 * ensuring compatibility with the WebAuthn/FIDO2 specification.
 */
class CborEncoderTest {

    @Test
    fun `encodeCOSEEC2Key encodes valid P-256 coordinates`() {
        // Test with zero coordinates (32 bytes each)
        val x = ByteArray(32)
        val y = ByteArray(32)

        val result = CborEncoder.encodeCOSEEC2Key(x, y)

        assertNotNull(result)
        assertTrue("Encoded key should not be empty", result.isNotEmpty())

        // Verify CBOR map header (0xA5 = map with 5 items)
        assertEquals("First byte should be map with 5 items", 0xA5.toByte(), result[0])
    }

    @Test
    fun `encodeCOSEEC2Key produces correct COSE structure`() {
        // Use known test values
        val x = ByteArray(32) { 0x01.toByte() }
        val y = ByteArray(32) { 0x02.toByte() }

        val result = CborEncoder.encodeCOSEEC2Key(x, y)

        // Expected structure:
        // A5           - map(5)
        // 01           - unsigned(1) = kty
        // 02           - unsigned(2) = EC2
        // 03           - unsigned(3) = alg
        // 26           - negative(-7) = ES256
        // 20           - negative(-1) = crv
        // 01           - unsigned(1) = P-256
        // 21           - negative(-2) = x
        // 58 20        - bytes(32)
        // [32 bytes x]
        // 22           - negative(-3) = y
        // 58 20        - bytes(32)
        // [32 bytes y]

        // Verify map header
        assertEquals(0xA5.toByte(), result[0])

        // Verify kty: 1 -> 2 (EC2)
        assertEquals(0x01.toByte(), result[1])
        assertEquals(0x02.toByte(), result[2])

        // Verify alg: 3 -> -7 (ES256)
        assertEquals(0x03.toByte(), result[3])
        assertEquals(0x26.toByte(), result[4]) // -7 encoded as 0x20 | 6

        // Verify crv: -1 -> 1 (P-256)
        assertEquals(0x20.toByte(), result[5]) // -1 encoded as 0x20 | 0
        assertEquals(0x01.toByte(), result[6])

        // Verify x coordinate key: -2
        assertEquals(0x21.toByte(), result[7]) // -2 encoded as 0x20 | 1

        // Verify x byte string header: 0x58 0x20 (byte string of length 32)
        assertEquals(0x58.toByte(), result[8])
        assertEquals(0x20.toByte(), result[9])

        // Verify x coordinate bytes start at position 10
        for (i in 0 until 32) {
            assertEquals("X coordinate byte $i should be 0x01", 0x01.toByte(), result[10 + i])
        }

        // Verify y coordinate key: -3
        assertEquals(0x22.toByte(), result[42]) // -3 encoded as 0x20 | 2

        // Verify y byte string header
        assertEquals(0x58.toByte(), result[43])
        assertEquals(0x20.toByte(), result[44])

        // Verify y coordinate bytes start at position 45
        for (i in 0 until 32) {
            assertEquals("Y coordinate byte $i should be 0x02", 0x02.toByte(), result[45 + i])
        }

        // Total length should be: 1 + 2 + 2 + 2 + 3 + 32 + 3 + 32 = 77 bytes
        assertEquals(77, result.size)
    }

    @Test
    fun `encodeCOSEEC2Key handles maximum coordinate values`() {
        // Test with maximum byte values
        val x = ByteArray(32) { 0xFF.toByte() }
        val y = ByteArray(32) { 0xFF.toByte() }

        val result = CborEncoder.encodeCOSEEC2Key(x, y)

        assertNotNull(result)
        assertEquals(77, result.size)

        // Verify x coordinate (starting at position 10)
        for (i in 0 until 32) {
            assertEquals(0xFF.toByte(), result[10 + i])
        }

        // Verify y coordinate (starting at position 45)
        for (i in 0 until 32) {
            assertEquals(0xFF.toByte(), result[45 + i])
        }
    }

    @Test(expected = CborEncodingException::class)
    fun `encodeCOSEEC2Key throws on invalid X coordinate size`() {
        val x = ByteArray(31) // Should be 32
        val y = ByteArray(32)

        CborEncoder.encodeCOSEEC2Key(x, y)
    }

    @Test(expected = CborEncodingException::class)
    fun `encodeCOSEEC2Key throws on invalid Y coordinate size`() {
        val x = ByteArray(32)
        val y = ByteArray(33) // Should be 32

        CborEncoder.encodeCOSEEC2Key(x, y)
    }

    @Test(expected = CborEncodingException::class)
    fun `encodeCOSEEC2Key throws on empty X coordinate`() {
        val x = ByteArray(0)
        val y = ByteArray(32)

        CborEncoder.encodeCOSEEC2Key(x, y)
    }

    @Test(expected = CborEncodingException::class)
    fun `encodeCOSEEC2Key throws on empty Y coordinate`() {
        val x = ByteArray(32)
        val y = ByteArray(0)

        CborEncoder.encodeCOSEEC2Key(x, y)
    }

    @Test
    fun `encodeCOSEEC2Key is deterministic`() {
        // Same inputs should always produce the same output
        val x = ByteArray(32) { it.toByte() }
        val y = ByteArray(32) { (31 - it).toByte() }

        val result1 = CborEncoder.encodeCOSEEC2Key(x, y)
        val result2 = CborEncoder.encodeCOSEEC2Key(x, y)

        assertArrayEquals("CBOR encoding should be deterministic", result1, result2)
    }

    @Test
    fun `encodeCOSEEC2Key uses canonical CBOR ordering`() {
        // CTAP2 requires canonical CBOR with keys in ascending order
        // For integer keys: positive < negative, smaller absolute value first
        // Expected order: 1, 3, -1, -2, -3

        val x = ByteArray(32)
        val y = ByteArray(32)

        val result = CborEncoder.encodeCOSEEC2Key(x, y)

        // Extract key bytes from the encoded result
        // After map header (0xA5), keys appear before their values

        // Key 1 (kty)
        assertEquals("First key should be 1", 0x01.toByte(), result[1])

        // Key 3 (alg) - after value 2
        assertEquals("Second key should be 3", 0x03.toByte(), result[3])

        // Key -1 (crv) - after negative value
        assertEquals("Third key should be -1 (0x20)", 0x20.toByte(), result[5])

        // Key -2 (x) - after value 1
        assertEquals("Fourth key should be -2 (0x21)", 0x21.toByte(), result[7])

        // Key -3 (y) - after byte string
        assertEquals("Fifth key should be -3 (0x22)", 0x22.toByte(), result[42])
    }

    @Test
    fun `encodeCOSEEC2Key output is valid for WebAuthn`() {
        // Use a realistic P-256 point (this is the generator point)
        val x = hexToBytes(
            "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
        )
        val y = hexToBytes(
            "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
        )

        val result = CborEncoder.encodeCOSEEC2Key(x, y)

        // The result should be a valid COSE_Key that can be parsed by
        // WebAuthn implementations. We verify the structure is correct.
        assertEquals("Result should be 77 bytes", 77, result.size)

        // Verify the x coordinate is embedded correctly
        val embeddedX = result.sliceArray(10 until 42)
        assertArrayEquals("X coordinate should be preserved", x, embeddedX)

        // Verify the y coordinate is embedded correctly
        val embeddedY = result.sliceArray(45 until 77)
        assertArrayEquals("Y coordinate should be preserved", y, embeddedY)
    }

    /**
     * Helper function to convert hex string to bytes.
     */
    private fun hexToBytes(hex: String): ByteArray {
        check(hex.length % 2 == 0) { "Hex string must have even length" }
        return ByteArray(hex.length / 2) { i ->
            hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }
}
