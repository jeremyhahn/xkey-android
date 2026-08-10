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
package com.automatethethings.xkey.qr

import android.graphics.Bitmap
import android.graphics.Color
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.NotFoundException
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented tests for [QrCodeGenerator].
 *
 * `QrCodeGeneratorTest` exercises ZXing's encoder directly, which proves the
 * library works but never runs xKey's own code: [QrCodeGenerator.generate]
 * turns the bit matrix into an `android.graphics.Bitmap`, and a `Bitmap` is a
 * stub on the JVM. The pixel conversion is exactly where a QR code can come out
 * unreadable — inverted, transposed, or clipped by the wrong stride — and none
 * of that would throw. So each code here is *decoded back* rather than merely
 * inspected.
 *
 * These tests allocate bitmaps only; there is no persistent state to clean up.
 */
@RunWith(AndroidJUnit4::class)
class QrCodeGeneratorInstrumentedTest {

    /** Reads a QR code back out of a bitmap, or throws [NotFoundException]. */
    private fun decode(bitmap: Bitmap): String {
        val pixels = IntArray(bitmap.width * bitmap.height)
        bitmap.getPixels(pixels, 0, bitmap.width, 0, 0, bitmap.width, bitmap.height)
        val source = RGBLuminanceSource(bitmap.width, bitmap.height, pixels)
        return QRCodeReader().decode(
            BinaryBitmap(HybridBinarizer(source)),
            mapOf(
                DecodeHintType.CHARACTER_SET to "UTF-8",
                DecodeHintType.TRY_HARDER to true
            )
        ).text
    }

    // -------------------------------------------------------------------------
    // Round trip
    // -------------------------------------------------------------------------

    @Test
    fun generate_producesACodeThatDecodesBackToTheSameText() {
        val payload = "xkey-pairing:04a1b2c3d4e5f6"

        assertEquals(payload, decode(QrCodeGenerator.generate(payload)))
    }

    @Test
    fun generate_roundTripsAnOtpauthUri() {
        val payload =
            "otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"

        assertEquals(payload, decode(QrCodeGenerator.generate(payload)))
    }

    @Test
    fun generate_roundTripsAShortPayload() {
        assertEquals("x", decode(QrCodeGenerator.generate("x")))
    }

    @Test
    fun generate_roundTripsAPayloadThatFillsSeveralVersions() {
        val payload = (1..400).joinToString("") { (it % 10).toString() }

        assertEquals(payload, decode(QrCodeGenerator.generate(payload, size = 768)))
    }

    @Test
    fun generate_roundTripsNonAsciiTextThroughTheUtf8Hint() {
        val payload = "ünïcödé — ✓"

        assertEquals(payload, decode(QrCodeGenerator.generate(payload)))
    }

    @Test
    fun generate_isDeterministicForTheSamePayload() {
        val first = QrCodeGenerator.generate("stable-payload")
        val second = QrCodeGenerator.generate("stable-payload")

        assertTrue(first.sameAs(second))
    }

    // -------------------------------------------------------------------------
    // Bitmap shape
    // -------------------------------------------------------------------------

    @Test
    fun generate_defaultsToA512PixelSquare() {
        val bitmap = QrCodeGenerator.generate("size-check")

        assertEquals(512, bitmap.width)
        assertEquals(512, bitmap.height)
    }

    @Test
    fun generate_honoursARequestedSize() {
        val bitmap = QrCodeGenerator.generate("size-check", size = 256)

        assertEquals(256, bitmap.width)
        assertEquals(256, bitmap.height)
        assertEquals("size-check", decode(bitmap))
    }

    @Test
    fun generate_producesAnOpaqueArgbBitmap() {
        val bitmap = QrCodeGenerator.generate("config-check")

        assertEquals(Bitmap.Config.ARGB_8888, bitmap.config)
        assertEquals(255, Color.alpha(bitmap.getPixel(0, 0)))
    }

    @Test
    fun generate_paintsOnlyBlackAndWhite() {
        val bitmap = QrCodeGenerator.generate("colour-check", size = 128)
        val pixels = IntArray(bitmap.width * bitmap.height)
        bitmap.getPixels(pixels, 0, bitmap.width, 0, 0, bitmap.width, bitmap.height)

        assertEquals(setOf(Color.BLACK, Color.WHITE), pixels.toSet())
    }

    @Test
    fun generate_leavesAWhiteQuietZoneInTheCorner() {
        // A code drawn edge-to-edge, or inverted, is unreadable by a scanner
        // even though every pixel is present.
        val bitmap = QrCodeGenerator.generate("quiet-zone", size = 256)

        assertEquals(Color.WHITE, bitmap.getPixel(0, 0))
        assertEquals(Color.WHITE, bitmap.getPixel(bitmap.width - 1, bitmap.height - 1))
    }

    @Test
    fun generate_marksTheFinderPatternInBlack() {
        val bitmap = QrCodeGenerator.generate("finder-pattern", size = 256)
        val pixels = IntArray(bitmap.width * bitmap.height)
        bitmap.getPixels(pixels, 0, bitmap.width, 0, 0, bitmap.width, bitmap.height)

        assertTrue(pixels.any { it == Color.BLACK })
    }

    // -------------------------------------------------------------------------
    // Rejections
    // -------------------------------------------------------------------------

    @Test
    fun generate_rejectsAnEmptyPayload() {
        assertThrows(IllegalArgumentException::class.java) {
            QrCodeGenerator.generate("")
        }
    }

    @Test
    fun aBlankBitmapDecodesToNothing() {
        // Guards the decoder helper itself: a passing round trip must mean the
        // generator drew something, not that the reader accepts anything.
        val blank = Bitmap.createBitmap(64, 64, Bitmap.Config.ARGB_8888).apply {
            eraseColor(Color.WHITE)
        }

        assertThrows(NotFoundException::class.java) { decode(blank) }
    }
}
