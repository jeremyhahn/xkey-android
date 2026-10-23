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
package com.automatethethings.xkey.media

import android.util.Log
import androidx.exifinterface.media.ExifInterface
import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.unmockkStatic
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * #47: JPEGs with `0xFF` fill bytes before APP1 (or before the first marker
 * when there is no APP1) and before a table the canonical hash keeps, run
 * through the real `ExifInterface` 1.4.2 reader and `saveAttributes` writer in
 * the JVM. After the write the signature must read back unchanged, its stored
 * hash must equal the canonical hash of the file as written, and the file must
 * still be a well-formed JPEG.
 *
 * What a plain JVM can run of the 1.4.2 class (line numbers in its sources jar):
 *
 *  - `ExifInterface`'s static initialiser calls `Log.isLoggable`
 *    (`ExifInterface.java:133`), which throws "not mocked" off-device. `Log` is
 *    stubbed with `mockkStatic` for this class only, as the other JVM suites
 *    do; with `DEBUG` false the JPEG path makes no other `Log` call. The module
 *    keeps `unitTests.isReturnDefaultValues` off.
 *  - The file-path constructor probes `Os.lseek` (`:4841`). The stub's throw is
 *    caught there, so the instance keeps its file name and `saveAttributes`
 *    copies through `FileInputStream`/`FileOutputStream` (`:4910`, `:4936`).
 *  - `setAttribute` cannot run: it unboxes the `android.util.Pair` that
 *    `guessDataFormat` returns (`:4488`-`:4490`), and the stub constructor leaves
 *    that Pair's fields null, so `XmpMetadataHelper.writeSignature` throws
 *    `NullPointerException` here. Each fixture therefore carries the signature
 *    in a COM segment: the reader loads it into `TAG_USER_COMMENT` through
 *    `ExifAttribute.createString` (`:5850`), the same call `setAttribute` makes
 *    for a UserComment (`:4518`). From there `saveAttributes` writes the same
 *    EXIF APP1 it writes after `writeSignature`.
 *
 * The full `writeSignature` call on the same fixtures runs on a device in
 * `XmpMetadataHelperInstrumentedTest` and `FileOperationFlowTest`. CI runs this
 * class and not those, because it has no androidTest stage.
 */
class XmpMetadataHelperExifFillByteTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    @Before
    fun stubLog() {
        mockkStatic(Log::class)
        every { Log.isLoggable(any(), any()) } returns false
        every { Log.d(any(), any<String>()) } returns 0
        every { Log.d(any(), any<String>(), any()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>(), any()) } returns 0
        every { Log.e(any(), any<String>(), any()) } returns 0
    }

    @After
    fun unstubLog() {
        unmockkStatic(Log::class)
    }

    // -----------------------------------------------------------------
    // Fixtures
    // -----------------------------------------------------------------

    private fun bytes(vararg values: Int) = ByteArray(values.size) { values[it].toByte() }
    private fun u(data: ByteArray, i: Int) = data[i].toInt() and 0xFF
    private fun segment(marker: Int, body: ByteArray): ByteArray {
        val length = body.size + 2
        return bytes(0xFF, marker, length shr 8, length and 0xFF) + body
    }

    private val jfif = segment(0xE0, bytes(0x4A, 0x46, 0x49, 0x46, 0x00, 1, 1, 0, 0, 1, 0, 1, 0, 0))

    /** `Exif\0\0`, a big-endian TIFF header and an empty IFD0, as a camera may leave it. */
    private val exif = segment(
        0xE1,
        bytes(0x45, 0x78, 0x69, 0x66, 0, 0, 0x4D, 0x4D, 0x00, 0x2A, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0)
    )

    /**
     * A complete 8x8 greyscale baseline JPEG: flat quantisation table, one
     * component, one-symbol DC and AC Huffman tables, and a single block coded
     * as DC difference 0 then EOB (bits `00`, padded with ones to `0x3F`).
     */
    private val dqt = segment(0xDB, bytes(0x00) + ByteArray(64) { 1 })
    private val sof0 = segment(0xC0, bytes(8, 0, 8, 0, 8, 1, 1, 0x11, 0))
    private val dhtDc = segment(0xC4, bytes(0x00, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00))
    private val dhtAc = segment(0xC4, bytes(0x10, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00))
    private val sos = segment(0xDA, bytes(1, 1, 0x00, 0, 63, 0))
    private val tables = dqt + sof0 + dhtDc + dhtAc
    private val scan = bytes(0x3F)

    private fun image(app: ByteArray) = bytes(0xFF, 0xD8) + app + tables + sos + scan + bytes(0xFF, 0xD9)

    /** A marker segment of a JPEG: its fill-byte run, its code and where it ends. */
    private data class Segment(val start: Int, val fill: Int, val marker: Int, val end: Int)

    /**
     * Walks [data]'s marker segments from SOI to SOS (or EOI), fill bytes
     * included, and asserts the chain is unbroken: every segment starts with a
     * marker and its length stays inside the file.
     */
    private fun segments(data: ByteArray): List<Segment> {
        assertTrue("SOI", data.size >= 4 && u(data, 0) == 0xFF && u(data, 1) == 0xD8)
        val out = mutableListOf<Segment>()
        var i = 2
        while (true) {
            assertTrue("a marker must start at $i", i + 1 < data.size && u(data, i) == 0xFF)
            val start = i
            while (i + 1 < data.size && u(data, i + 1) == 0xFF) i++
            assertTrue("fill bytes must end in a marker", i + 1 < data.size)
            val marker = u(data, i + 1)
            if (marker == 0xD9) return out + Segment(start, i - start, marker, i + 2)
            assertTrue("segment length at $i", i + 3 < data.size)
            val end = i + 2 + ((u(data, i + 2) shl 8) or u(data, i + 3))
            assertTrue("segment at $i must fit the file", end in i + 4..data.size)
            out += Segment(start, i - start, marker, end)
            if (marker == 0xDA) return out
            i = end
        }
    }

    /** The markers in [data] that are preceded by at least one fill byte. */
    private fun filled(data: ByteArray) = segments(data).filter { it.fill > 0 }.map { it.marker }

    /**
     * [base] with [count] fill bytes before the first [marker] segment, or
     * before the first segment after SOI when [marker] is null.
     */
    private fun withFill(base: ByteArray, marker: Int?, count: Int): ByteArray {
        val all = segments(base)
        val at = (if (marker == null) all.first() else all.first { it.marker == marker }).start
        return base.copyOfRange(0, at) + ByteArray(count) { 0xFF.toByte() } + base.copyOfRange(at, base.size)
    }

    private fun sampleData(contentHash: String) = ContentAuthenticityData(
        contentHash = contentHash,
        signatures = listOf(
            SignatureEntry(
                keyFingerprint = "b".repeat(64),
                signerName = "Test Signer",
                algorithm = "ES256",
                value = "MEUCIQD_test_signature",
                timestamp = "2026-10-22T00:00:00Z",
                role = SignerRole.CREATOR
            )
        )
    )

    // -----------------------------------------------------------------
    // The regression
    // -----------------------------------------------------------------

    /**
     * Builds the fixture, writes it through the real writer and checks the
     * result. [app] is the image's APPn segments, [first] the marker the
     * leading fill bytes go before (null: the first after SOI) and [retained]
     * the kept table they go before.
     */
    private fun assertSignsAndVerifies(app: ByteArray, first: Int?, retained: Int) {
        val unsigned = image(app)
        val data = sampleData(MediaHasher.hashCanonical(unsigned, "image/jpeg"))
        val comment = segment(0xFE, ("XKEY_SIG:" + data.toJsonString()).toByteArray(Charsets.US_ASCII))
        val signed = image(app + comment)
        val fixture = withFill(withFill(signed, retained, 3), first, 2)

        val expectedFirst = first ?: segments(signed).first().marker
        assertEquals("the fixture must hold fill bytes where intended", listOf(expectedFirst, retained), filled(fixture))
        assertEquals(data.contentHash, MediaHasher.hashCanonical(fixture, "image/jpeg"))

        val file = tempFolder.newFile("fill-${System.nanoTime()}.jpg")
        file.writeBytes(fixture)
        assertEquals("the reader must accept fill bytes", data, XmpMetadataHelper.readSignature(file.path))

        ExifInterface(file.path).saveAttributes()

        val after = file.readBytes()
        assertFalse("the write must change the file", fixture.contentEquals(after))
        assertEquals("the signature must read back unchanged", data, XmpMetadataHelper.readSignature(file.path))
        assertEquals(
            "the stored hash must equal the canonical hash of the file as written",
            data.contentHash,
            MediaHasher.hashCanonical(after, "image/jpeg")
        )

        val written = segments(after)
        val exifApp1 = written.first()
        assertEquals("the writer puts the EXIF APP1 first", 0xE1, exifApp1.marker)
        val app1Text = String(after.copyOfRange(exifApp1.start, exifApp1.end), Charsets.ISO_8859_1)
        assertTrue("the signature must be in the EXIF APP1", app1Text.contains("XKEY_SIG:"))
        assertEquals("the scan must follow the tables", 0xDA, written.last().marker)
        assertTrue("the tables must survive", written.map { it.marker }.containsAll(listOf(0xDB, 0xC0, 0xC4)))
        assertEquals("EOI", listOf(0xFF, 0xD9), listOf(u(after, after.size - 2), u(after, after.size - 1)))
        // 1.4.2 drops fill bytes when it rewrites (saveJpegAttributes skips them
        // before every marker), which is why the canonical hash skips them too.
        assertEquals("ExifInterface 1.4.2 writes no fill bytes", emptyList<Int>(), filled(after))
    }

    @Test
    fun `fill bytes before an EXIF APP1 and before DQT survive a real ExifInterface write`() {
        assertSignsAndVerifies(app = exif, first = 0xE1, retained = 0xDB)
    }

    @Test
    fun `fill bytes before an EXIF APP1 and before SOF0 survive a real ExifInterface write`() {
        assertSignsAndVerifies(app = exif + jfif, first = 0xE1, retained = 0xC0)
    }

    @Test
    fun `fill bytes before the first marker of a JFIF without APP1 and before DHT survive a real ExifInterface write`() {
        assertSignsAndVerifies(app = jfif, first = null, retained = 0xC4)
    }
}
