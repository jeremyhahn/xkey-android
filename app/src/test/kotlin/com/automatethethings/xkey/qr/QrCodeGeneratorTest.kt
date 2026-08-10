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
package com.automatethethings.xkey.qr

import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.WriterException
import com.google.zxing.qrcode.QRCodeWriter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for QR code encoding via ZXing.
 *
 * These tests verify the ZXing QRCodeWriter encoding directly,
 * since the full [QrCodeGenerator.generate] method requires
 * android.graphics.Bitmap which is only available in instrumented tests.
 */
class QrCodeGeneratorTest {

    private val writer = QRCodeWriter()

    @Test
    fun `encode produces non-null BitMatrix for valid input`() {
        val hints = mapOf(
            EncodeHintType.MARGIN to 1,
            EncodeHintType.CHARACTER_SET to "UTF-8"
        )
        val matrix = writer.encode("https://example.com", BarcodeFormat.QR_CODE, 512, 512, hints)
        assertNotNull(matrix)
    }

    @Test
    fun `encode produces BitMatrix with requested dimensions`() {
        val hints = mapOf(
            EncodeHintType.MARGIN to 1,
            EncodeHintType.CHARACTER_SET to "UTF-8"
        )
        val matrix = writer.encode("test data", BarcodeFormat.QR_CODE, 512, 512, hints)
        assertEquals(512, matrix.width)
        assertEquals(512, matrix.height)
    }

    @Test
    fun `encode with custom size`() {
        val hints = mapOf(
            EncodeHintType.MARGIN to 1,
            EncodeHintType.CHARACTER_SET to "UTF-8"
        )
        val matrix = writer.encode("test data", BarcodeFormat.QR_CODE, 256, 256, hints)
        assertEquals(256, matrix.width)
        assertEquals(256, matrix.height)
    }

    @Test
    fun `encode handles short string`() {
        val hints = mapOf(
            EncodeHintType.MARGIN to 1,
            EncodeHintType.CHARACTER_SET to "UTF-8"
        )
        val matrix = writer.encode("hi", BarcodeFormat.QR_CODE, 512, 512, hints)
        assertNotNull(matrix)
        assertTrue("BitMatrix should have set bits", matrix.width > 0)
    }

    @Test
    fun `encode handles medium string`() {
        val hints = mapOf(
            EncodeHintType.MARGIN to 1,
            EncodeHintType.CHARACTER_SET to "UTF-8"
        )
        val mediumString = "a".repeat(200)
        val matrix = writer.encode(mediumString, BarcodeFormat.QR_CODE, 512, 512, hints)
        assertNotNull(matrix)
    }

    @Test
    fun `encode handles near-limit string`() {
        val hints = mapOf(
            EncodeHintType.MARGIN to 1,
            EncodeHintType.CHARACTER_SET to "UTF-8"
        )
        val nearLimitString = "A".repeat(2000)
        val matrix = writer.encode(nearLimitString, BarcodeFormat.QR_CODE, 512, 512, hints)
        assertNotNull(matrix)
    }

    @Test
    fun `BitMatrix contains both set and unset pixels`() {
        val hints = mapOf(
            EncodeHintType.MARGIN to 1,
            EncodeHintType.CHARACTER_SET to "UTF-8"
        )
        val matrix = writer.encode("test", BarcodeFormat.QR_CODE, 512, 512, hints)

        var hasSet = false
        var hasUnset = false
        for (y in 0 until matrix.height) {
            for (x in 0 until matrix.width) {
                if (matrix[x, y]) hasSet = true else hasUnset = true
                if (hasSet && hasUnset) break
            }
            if (hasSet && hasUnset) break
        }
        assertTrue("Should have both set and unset pixels", hasSet && hasUnset)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `encode throws for empty string`() {
        val hints = mapOf(
            EncodeHintType.MARGIN to 1,
            EncodeHintType.CHARACTER_SET to "UTF-8"
        )
        writer.encode("", BarcodeFormat.QR_CODE, 512, 512, hints)
    }
}
