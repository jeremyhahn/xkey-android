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
package com.automatethethings.xkey.media

import android.content.ContentResolver
import android.net.Uri
import com.automatethethings.xkey.media.MediaHasher.SignatureSource
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream

/**
 * JVM vectors for [MediaHasher.canonicalContent], fill bytes included, and
 * the content-hash rule [MediaHasher.contentHashMatches] the two verify
 * screens share.
 *
 * These carry the proof for #47: CI runs no androidTest stage, so the
 * instrumented ExifInterface checks in `XmpMetadataHelperInstrumentedTest` and
 * `FileOperationFlowTest` only run on a device. Every JPEG here is built by
 * hand, segment by segment, so each vector states exactly which bytes it holds.
 */
class MediaHasherCanonicalTest {

    private fun bytes(vararg values: Int) = ByteArray(values.size) { values[it].toByte() }

    private val soi = bytes(0xFF, 0xD8)
    private val eoi = bytes(0xFF, 0xD9)
    private fun app1(payload: String = "Exif\u0000\u0000"): ByteArray {
        val body = payload.toByteArray(Charsets.ISO_8859_1)
        val length = body.size + 2
        return bytes(0xFF, 0xE1, length shr 8, length and 0xFF) + body
    }
    private val com = bytes(0xFF, 0xFE, 0x00, 0x05) + "hi!".toByteArray()
    private val dqt = bytes(0xFF, 0xDB, 0x00, 0x04, 0x01, 0x02)
    private val sos = bytes(0xFF, 0xDA, 0x00, 0x04, 0x03, 0x04)
    private fun scan(first: Int = 0x11) = bytes(first, 0x22, 0xFF, 0x00, 0x33)
    private fun fill(count: Int) = ByteArray(count) { 0xFF.toByte() }

    /** SOI, the tables, the scan header, the entropy-coded data and EOI. */
    private val expectedCanonical = soi + dqt + sos + scan() + eoi

    private fun jpeg(
        metadata: ByteArray = app1(),
        fillBeforeFirst: Int = 0,
        fillBeforeDqt: Int = 0,
        pixels: ByteArray = scan()
    ) = soi + fill(fillBeforeFirst) + metadata + fill(fillBeforeDqt) + dqt + sos + pixels + eoi

    private fun canonical(data: ByteArray) = MediaHasher.canonicalContent(data, "image/jpeg")

    // -----------------------------------------------------------------
    // canonicalContent
    // -----------------------------------------------------------------

    @Test
    fun `a jpeg without fill bytes keeps its tables and scan and drops APPn and COM`() {
        assertArrayEquals(expectedCanonical, canonical(jpeg(metadata = app1() + com)))
    }

    @Test
    fun `fill bytes before the first segment and between segments are both skipped`() {
        assertArrayEquals(
            expectedCanonical,
            canonical(jpeg(metadata = app1() + fill(1) + com, fillBeforeFirst = 1, fillBeforeDqt = 4))
        )
    }

    @Test
    fun `a metadata-only change to a jpeg with fill bytes keeps the canonical hash`() {
        val before = jpeg(metadata = app1("Exif\u0000\u0000"), fillBeforeDqt = 1)
        val after = jpeg(metadata = app1("Exif\u0000\u0000XKEY_SIG:{}"), fillBeforeFirst = 2)

        assertNotEquals(MediaHasher.hashBytes(before), MediaHasher.hashBytes(after))
        assertEquals(
            MediaHasher.hashCanonical(before, "image/jpeg"),
            MediaHasher.hashCanonical(after, "image/jpeg")
        )
    }

    @Test
    fun `a pixel change to a jpeg with fill bytes changes the canonical hash`() {
        val original = jpeg(fillBeforeDqt = 1)
        val edited = jpeg(fillBeforeDqt = 1, pixels = scan(first = 0x12))

        assertNotEquals(
            MediaHasher.hashCanonical(original, "image/jpeg"),
            MediaHasher.hashCanonical(edited, "image/jpeg")
        )
    }

    @Test
    fun `a jpeg that ends in fill bytes is returned unchanged`() {
        val truncated = soi + app1() + fill(3)

        assertArrayEquals(truncated, canonical(truncated))
    }

    @Test
    fun `a non-jpeg is hashed whole`() {
        val data = jpeg()

        assertArrayEquals(data, MediaHasher.canonicalContent(data, "image/png"))
    }

    // -----------------------------------------------------------------
    // contentHashMatches
    // -----------------------------------------------------------------

    private val file = jpeg()
    private val canonicalHash = MediaHasher.hashCanonical(file, "image/jpeg")
    private val wholeFileHash = MediaHasher.hashBytes(file)

    private fun matches(stored: String, data: ByteArray, source: SignatureSource) =
        MediaHasher.contentHashMatches(stored, data, "image/jpeg", source)

    @Test
    fun `a sidecar over the canonical hash verifies`() {
        assertTrue(matches(canonicalHash, file, SignatureSource.SIDECAR))
    }

    @Test
    fun `a sidecar matching neither hash fails`() {
        assertFalse(matches("0".repeat(64), file, SignatureSource.SIDECAR))
    }

    @Test
    fun `a one-byte change to the file fails a sidecar over either hash`() {
        val changed = jpeg(pixels = scan(first = 0x12))

        assertFalse(matches(wholeFileHash, changed, SignatureSource.SIDECAR))
        assertFalse(matches(canonicalHash, changed, SignatureSource.SIDECAR))
    }

    @Test
    fun `contentHashMatchesUri reads the bytes and the mime type from the resolver`() {
        val uri = mockk<Uri>()
        val resolver = mockk<ContentResolver>()
        every { resolver.openInputStream(uri) } answers { ByteArrayInputStream(file) }
        every { resolver.getType(uri) } returns "image/jpeg"

        assertTrue(
            MediaHasher.contentHashMatchesUri(resolver, uri, wholeFileHash, SignatureSource.SIDECAR)
        )
        assertTrue(
            MediaHasher.contentHashMatchesUri(resolver, uri, canonicalHash, SignatureSource.IN_BAND)
        )
        assertFalse(
            MediaHasher.contentHashMatchesUri(resolver, uri, wholeFileHash, SignatureSource.IN_BAND)
        )
    }
}
