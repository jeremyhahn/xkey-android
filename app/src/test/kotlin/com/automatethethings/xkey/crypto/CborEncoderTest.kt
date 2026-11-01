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

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Unit tests for CborEncoder.
 *
 * These tests verify the CBOR encoding of COSE EC2 P-256 public keys,
 * ensuring compatibility with the WebAuthn/FIDO2 specification.
 */
class CborEncoderTest {

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

}
