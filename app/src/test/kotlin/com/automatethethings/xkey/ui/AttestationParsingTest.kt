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
package com.automatethethings.xkey.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for DER parsing helpers used by KeyDetailActivity attestation parsing.
 *
 * These tests verify the low-level DER (Distinguished Encoding Rules) parsing
 * logic that extracts attestation data from Android Key Attestation extensions.
 * All parsing is pure byte-array manipulation with no Android dependencies.
 */
class AttestationParsingTest {

    // -------------------------------------------------------------------------
    // derReadInteger
    // -------------------------------------------------------------------------

    @Test
    fun `derReadInteger reads single byte integer`() {
        // DER: 02 01 05 -> INTEGER length=1 value=5
        val data = byteArrayOf(0x02, 0x01, 0x05)
        assertEquals(5, derReadInteger(data, 0))
    }

    @Test
    fun `derReadInteger reads two byte integer`() {
        // DER: 02 02 01 00 -> INTEGER length=2 value=256
        val data = byteArrayOf(0x02, 0x02, 0x01, 0x00)
        assertEquals(256, derReadInteger(data, 0))
    }

    @Test
    fun `derReadInteger reads zero`() {
        // DER: 02 01 00 -> INTEGER value=0
        val data = byteArrayOf(0x02, 0x01, 0x00)
        assertEquals(0, derReadInteger(data, 0))
    }

    @Test
    fun `derReadInteger returns 0 for wrong tag`() {
        // Not an INTEGER tag
        val data = byteArrayOf(0x04, 0x01, 0x05)
        assertEquals(0, derReadInteger(data, 0))
    }

    @Test
    fun `derReadInteger returns 0 for empty data`() {
        assertEquals(0, derReadInteger(byteArrayOf(), 0))
    }

    @Test
    fun `derReadInteger returns 0 for out of bounds position`() {
        val data = byteArrayOf(0x02, 0x01, 0x05)
        assertEquals(0, derReadInteger(data, 10))
    }

    @Test
    fun `derReadInteger reads four byte integer`() {
        // 02 04 00 01 00 00 -> 65536
        val data = byteArrayOf(0x02, 0x04, 0x00, 0x01, 0x00, 0x00)
        assertEquals(65536, derReadInteger(data, 0))
    }

    // -------------------------------------------------------------------------
    // derReadLong
    // -------------------------------------------------------------------------

    @Test
    fun `derReadLong reads small value`() {
        val data = byteArrayOf(0x02, 0x01, 0x0A)
        assertEquals(10L, derReadLong(data, 0))
    }

    @Test
    fun `derReadLong reads large timestamp`() {
        // Encode 1704067200000 (2024-01-01 in millis) as DER INTEGER
        // 1704067200000 = 0x18CA14E7480
        val data = byteArrayOf(
            0x02, 0x06,
            0x01, 0x8C.toByte(), 0xA1.toByte(), 0x4E, 0x74.toByte(), 0x80.toByte()
        )
        assertEquals(0x018CA14E7480L, derReadLong(data, 0))
    }

    @Test
    fun `derReadLong returns 0 for wrong tag`() {
        val data = byteArrayOf(0x04, 0x01, 0x05)
        assertEquals(0L, derReadLong(data, 0))
    }

    // -------------------------------------------------------------------------
    // derReadEnumerated
    // -------------------------------------------------------------------------

    @Test
    fun `derReadEnumerated reads value`() {
        // DER: 0A 01 01 -> ENUMERATED value=1
        val data = byteArrayOf(0x0A, 0x01, 0x01)
        assertEquals(1, derReadEnumerated(data, 0))
    }

    @Test
    fun `derReadEnumerated reads zero`() {
        val data = byteArrayOf(0x0A, 0x01, 0x00)
        assertEquals(0, derReadEnumerated(data, 0))
    }

    @Test
    fun `derReadEnumerated returns -1 for wrong tag`() {
        val data = byteArrayOf(0x02, 0x01, 0x01)
        assertEquals(-1, derReadEnumerated(data, 0))
    }

    // -------------------------------------------------------------------------
    // derReadOctetString
    // -------------------------------------------------------------------------

    @Test
    fun `derReadOctetString reads bytes`() {
        // DER: 04 03 AA BB CC
        val data = byteArrayOf(0x04, 0x03, 0xAA.toByte(), 0xBB.toByte(), 0xCC.toByte())
        val result = derReadOctetString(data, 0)

        assertNotNull(result)
        assertEquals(3, result!!.size)
        assertEquals(0xAA.toByte(), result[0])
        assertEquals(0xBB.toByte(), result[1])
        assertEquals(0xCC.toByte(), result[2])
    }

    @Test
    fun `derReadOctetString reads empty bytes`() {
        val data = byteArrayOf(0x04, 0x00)
        val result = derReadOctetString(data, 0)

        assertNotNull(result)
        assertEquals(0, result!!.size)
    }

    @Test
    fun `derReadOctetString returns null for wrong tag`() {
        val data = byteArrayOf(0x02, 0x01, 0x05)
        assertNull(derReadOctetString(data, 0))
    }

    // -------------------------------------------------------------------------
    // derReadLength
    // -------------------------------------------------------------------------

    @Test
    fun `derReadLength reads short form`() {
        // Short form: length < 128 encoded as single byte
        val data = byteArrayOf(0x7F.toByte())
        assertEquals(127, derReadLength(data, 0))
    }

    @Test
    fun `derReadLength reads long form one byte`() {
        // Long form: 0x81 0x80 -> length 128
        val data = byteArrayOf(0x81.toByte(), 0x80.toByte())
        assertEquals(128, derReadLength(data, 0))
    }

    @Test
    fun `derReadLength reads long form two bytes`() {
        // Long form: 0x82 0x01 0x00 -> length 256
        val data = byteArrayOf(0x82.toByte(), 0x01, 0x00)
        assertEquals(256, derReadLength(data, 0))
    }

    @Test
    fun `derReadLength returns 0 for empty data`() {
        assertEquals(0, derReadLength(byteArrayOf(), 0))
    }

    // -------------------------------------------------------------------------
    // derSkipElement
    // -------------------------------------------------------------------------

    @Test
    fun `derSkipElement skips INTEGER`() {
        // 02 01 05 -> skip 3 bytes
        val data = byteArrayOf(0x02, 0x01, 0x05, 0x0A, 0x01, 0x01)
        assertEquals(3, derSkipElement(data, 0))
    }

    @Test
    fun `derSkipElement skips OCTET STRING`() {
        // 04 03 AA BB CC -> skip 5 bytes
        val data = byteArrayOf(0x04, 0x03, 0xAA.toByte(), 0xBB.toByte(), 0xCC.toByte())
        assertEquals(5, derSkipElement(data, 0))
    }

    @Test
    fun `derSkipElement at end of data returns data size`() {
        val data = byteArrayOf(0x02, 0x01, 0x05)
        assertEquals(data.size, derSkipElement(data, data.size))
    }

    @Test
    fun `derSkipElement handles empty SEQUENCE`() {
        // 30 00 -> empty SEQUENCE
        val data = byteArrayOf(0x30, 0x00)
        assertEquals(2, derSkipElement(data, 0))
    }

    // -------------------------------------------------------------------------
    // derLengthOffset
    // -------------------------------------------------------------------------

    @Test
    fun `derLengthOffset for short form is 2`() {
        // Short form: single length byte + tag byte = offset 2
        val data = byteArrayOf(0x02, 0x05)
        assertEquals(2, derLengthOffset(data, 1))
    }

    @Test
    fun `derLengthOffset for long form one byte is 3`() {
        // 0x81 xx -> 1 + 1 + 1 = 3
        val data = byteArrayOf(0x02, 0x81.toByte(), 0x80.toByte())
        assertEquals(3, derLengthOffset(data, 1))
    }

    @Test
    fun `derLengthOffset for long form two bytes is 4`() {
        // 0x82 xx xx -> 1 + 1 + 2 = 4
        val data = byteArrayOf(0x02, 0x82.toByte(), 0x01, 0x00)
        assertEquals(4, derLengthOffset(data, 1))
    }

    // -------------------------------------------------------------------------
    // Integration: Multiple elements in sequence
    // -------------------------------------------------------------------------

    @Test
    fun `can parse sequence of elements`() {
        // SEQUENCE { INTEGER 3, ENUMERATED 1, INTEGER 100 }
        // 30 09 02 01 03 0A 01 01 02 01 64
        val data = byteArrayOf(
            0x30, 0x09,                      // SEQUENCE length=9
            0x02, 0x01, 0x03,                // INTEGER 3
            0x0A, 0x01, 0x01,                // ENUMERATED 1
            0x02, 0x01, 0x64                 // INTEGER 100
        )

        val seqContentOffset = derLengthOffset(data, 1)
        val seqContent = data.copyOfRange(seqContentOffset, data.size)

        var pos = 0
        val firstInt = derReadInteger(seqContent, pos)
        pos = derSkipElement(seqContent, pos)

        val enumVal = derReadEnumerated(seqContent, pos)
        pos = derSkipElement(seqContent, pos)

        val secondInt = derReadInteger(seqContent, pos)

        assertEquals(3, firstInt)
        assertEquals(1, enumVal)
        assertEquals(100, secondInt)
    }

    @Test
    fun `can extract challenge from attestation-like structure`() {
        // Simplified attestation: { version=3, secLevel=1, kmVer=4, kmSecLevel=1, challenge=0xDEADBEEF, ... }
        val challenge = byteArrayOf(0xDE.toByte(), 0xAD.toByte(), 0xBE.toByte(), 0xEF.toByte())
        val data = byteArrayOf(
            0x30, 0x14,                      // SEQUENCE
            0x02, 0x01, 0x03,                // INTEGER 3 (version)
            0x0A, 0x01, 0x01,                // ENUMERATED 1 (security level)
            0x02, 0x01, 0x04,                // INTEGER 4 (keymaster version)
            0x0A, 0x01, 0x01,                // ENUMERATED 1 (km security level)
            0x04, 0x04, 0xDE.toByte(), 0xAD.toByte(), 0xBE.toByte(), 0xEF.toByte()  // OCTET STRING (challenge)
        )

        val seqContentOffset = derLengthOffset(data, 1)
        val seqContent = data.copyOfRange(seqContentOffset, data.size)

        var pos = 0
        val version = derReadInteger(seqContent, pos)
        pos = derSkipElement(seqContent, pos)

        val secLevel = derReadEnumerated(seqContent, pos)
        pos = derSkipElement(seqContent, pos)

        val kmVersion = derReadInteger(seqContent, pos)
        pos = derSkipElement(seqContent, pos)

        val kmSecLevel = derReadEnumerated(seqContent, pos)
        pos = derSkipElement(seqContent, pos)

        val extractedChallenge = derReadOctetString(seqContent, pos)

        assertEquals(3, version)
        assertEquals(1, secLevel)
        assertEquals(4, kmVersion)
        assertEquals(1, kmSecLevel)
        assertNotNull(extractedChallenge)
        assertTrue(challenge.contentEquals(extractedChallenge!!))
    }

    // -------------------------------------------------------------------------
    // Helpers - mirrors the DER parsing logic from KeyDetailActivity
    // -------------------------------------------------------------------------

    private fun derReadInteger(data: ByteArray, pos: Int): Int {
        if (pos >= data.size || data[pos] != 0x02.toByte()) return 0
        val contentOffset = pos + derLengthOffset(data, pos + 1)
        val length = derReadLength(data, pos + 1)
        var value = 0
        for (i in 0 until minOf(length, 4)) {
            value = (value shl 8) or (data[contentOffset + i].toInt() and 0xFF)
        }
        return value
    }

    private fun derReadLong(data: ByteArray, pos: Int): Long {
        if (pos >= data.size || data[pos] != 0x02.toByte()) return 0L
        val contentOffset = pos + derLengthOffset(data, pos + 1)
        val length = derReadLength(data, pos + 1)
        var value = 0L
        for (i in 0 until minOf(length, 8)) {
            value = (value shl 8) or (data[contentOffset + i].toLong() and 0xFF)
        }
        return value
    }

    private fun derReadEnumerated(data: ByteArray, pos: Int): Int {
        if (pos >= data.size || data[pos] != 0x0A.toByte()) return -1
        val contentOffset = pos + derLengthOffset(data, pos + 1)
        val length = derReadLength(data, pos + 1)
        var value = 0
        for (i in 0 until minOf(length, 4)) {
            value = (value shl 8) or (data[contentOffset + i].toInt() and 0xFF)
        }
        return value
    }

    private fun derReadOctetString(data: ByteArray, pos: Int): ByteArray? {
        if (pos >= data.size || data[pos] != 0x04.toByte()) return null
        val contentOffset = pos + derLengthOffset(data, pos + 1)
        val length = derReadLength(data, pos + 1)
        if (contentOffset + length > data.size) return null
        return data.copyOfRange(contentOffset, contentOffset + length)
    }

    private fun derReadLength(data: ByteArray, pos: Int): Int {
        if (pos >= data.size) return 0
        val firstByte = data[pos].toInt() and 0xFF
        if (firstByte and 0x80 == 0) return firstByte
        val numBytes = firstByte and 0x7F
        var length = 0
        for (i in 1..numBytes) {
            if (pos + i >= data.size) return 0
            length = (length shl 8) or (data[pos + i].toInt() and 0xFF)
        }
        return length
    }

    private fun derLengthOffset(data: ByteArray, pos: Int): Int {
        if (pos >= data.size) return 1
        val firstByte = data[pos].toInt() and 0xFF
        return if (firstByte and 0x80 == 0) {
            1 + 1
        } else {
            1 + 1 + (firstByte and 0x7F)
        }
    }

    private fun derSkipElement(data: ByteArray, pos: Int): Int {
        if (pos >= data.size) return data.size
        val tag = data[pos].toInt() and 0xFF

        var tagEnd = pos + 1
        if (tag and 0x1F == 0x1F) {
            while (tagEnd < data.size && data[tagEnd].toInt() and 0x80 != 0) {
                tagEnd++
            }
            tagEnd++
        }

        if (tagEnd >= data.size) return data.size
        val length = derReadLength(data, tagEnd)
        val lengthBytes = if (data[tagEnd].toInt() and 0x80 == 0) 1 else 1 + (data[tagEnd].toInt() and 0x7F)
        return tagEnd + lengthBytes + length
    }
}
