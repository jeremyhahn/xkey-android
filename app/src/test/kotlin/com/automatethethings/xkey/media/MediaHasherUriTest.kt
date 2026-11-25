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
import io.mockk.every
import io.mockk.mockk
import io.mockk.unmockkAll
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream

/**
 * Unit tests for [MediaHasher.hashUri] and the stream-lifecycle guarantees of
 * [MediaHasher.hashStream], driven by a mocked `ContentResolver`.
 *
 * `MediaHasherInstrumentedTest` proves `hashUri` against a real resolver on a
 * device. The branches it cannot reach are the ones a device will not produce on
 * demand: a resolver that hands back `null` (the URI vanished between the
 * MediaStore notification and the read, which is routine when a camera app
 * rewrites a capture), and a stream that fails part-way through. Both must not
 * be mistaken for a successful hash — a signature is taken over this value.
 *
 * The suite also pins that the input stream is always closed. The auto-signing
 * service hashes on every MediaStore change, so a leaked descriptor per capture
 * would exhaust the process.
 */
class MediaHasherUriTest {

    @get:Rule
    val folder = TemporaryFolder()

    @After
    fun tearDown() {
        unmockkAll()
    }

    /** A stream that records whether the hasher closed it. */
    private class ClosingStream(data: ByteArray) : ByteArrayInputStream(data) {
        var closed = false
            private set

        override fun close() {
            closed = true
            super.close()
        }
    }

    /** A stream that fails once reading starts, modelling a truncated capture. */
    private class FailingStream : InputStream() {
        var closed = false
            private set

        override fun read(): Int = throw IOException("media went away mid-read")

        override fun read(b: ByteArray, off: Int, len: Int): Int =
            throw IOException("media went away mid-read")

        override fun close() {
            closed = true
        }
    }

    private fun resolverReturning(stream: InputStream?): ContentResolver {
        val resolver = mockk<ContentResolver>()
        every { resolver.openInputStream(any()) } returns stream
        return resolver
    }

    // -------------------------------------------------------------------------
    // The signer's hash of a JPEG the resolver does not type as JPEG
    // -------------------------------------------------------------------------

    private fun assertCanonicalJpegHash(type: String?) {
        val jpeg = jpeg("camera=test")
        val canonical = MediaHasher.hashCanonical(jpeg, "image/jpeg")
        assertNotEquals(MediaHasher.hashBytes(jpeg), canonical)

        assertEquals("a JPEG typed $type is hashed canonically", canonical, hashCanonicalUri(jpeg, type))
    }

    @Test
    fun `contentHashUri hashes a JPEG typed application octet-stream canonically`() {
        assertCanonicalJpegHash("application/octet-stream")
    }

    @Test
    fun `contentHashUri hashes a JPEG with no resolver type canonically`() {
        assertCanonicalJpegHash(null)
    }

    // -------------------------------------------------------------------------
    // hashUri
    // -------------------------------------------------------------------------

    @Test
    fun `hashUri closes the resolver's stream on success`() {
        val stream = ClosingStream("hello world".toByteArray())

        MediaHasher.hashUri(resolverReturning(stream), mockk<Uri>(relaxed = true))

        assertTrue("the resolver's stream must not be leaked", stream.closed)
    }

    @Test
    fun `hashUri rejects a URI the resolver cannot open`() {
        val e = assertThrows(IllegalArgumentException::class.java) {
            MediaHasher.hashUri(resolverReturning(null), mockk<Uri>(relaxed = true))
        }

        assertTrue(e.message!!, e.message!!.startsWith("Cannot open URI:"))
    }

    @Test
    fun `hashUri propagates a read failure instead of returning a partial hash`() {
        val stream = FailingStream()

        assertThrows(IOException::class.java) {
            MediaHasher.hashUri(resolverReturning(stream), mockk<Uri>(relaxed = true))
        }

        assertTrue("a failed read must still close the stream", stream.closed)
    }

    @Test
    fun `hashUri and hashBytes agree for the same content`() {
        val data = ByteArray(20_000) { (it % 97).toByte() }

        val fromUri = MediaHasher.hashUri(
            resolverReturning(ByteArrayInputStream(data)),
            mockk<Uri>(relaxed = true)
        )

        assertEquals(MediaHasher.hashBytes(data), fromUri)
    }

    // -------------------------------------------------------------------------
    // The signer's content hash over a URI (AutoSignHash.contentHashUri)
    // -------------------------------------------------------------------------

    private fun resolverOf(stream: InputStream, mimeType: String?): ContentResolver {
        val resolver = resolverReturning(stream)
        every { resolver.getType(any()) } returns mimeType
        return resolver
    }

    private fun segment(marker: Int, payload: ByteArray): ByteArray {
        val length = payload.size + 2
        return byteArrayOf(0xFF.toByte(), marker.toByte(), (length shr 8).toByte(), length.toByte()) + payload
    }

    /** A JPEG with an EXIF APP1 segment holding [exif], then a table, a scan and EOI. */
    private fun jpeg(exif: String): ByteArray =
        byteArrayOf(0xFF.toByte(), 0xD8.toByte()) +
            segment(0xE1, "Exif\u0000\u0000$exif".toByteArray()) +
            segment(0xDB, ByteArray(65) { it.toByte() }) +
            segment(0xDA, byteArrayOf(1, 1, 0, 0, 63, 0)) +
            byteArrayOf(0x12, 0x34, 0x56, 0xFF.toByte(), 0xD9.toByte())

    private fun hashCanonicalUri(data: ByteArray, mimeType: String?): String =
        contentHashUri(resolverOf(ByteArrayInputStream(data), mimeType))

    private fun contentHashUri(resolver: ContentResolver): String =
        AutoSignHash.contentHashUri(resolver, mockk<Uri>(relaxed = true), folder.root)

    @Test
    fun `contentHashUri of a JPEG is its canonical hash, not the whole-file hash`() {
        val data = jpeg("camera=test")

        val hash = hashCanonicalUri(data, "image/jpeg")

        assertEquals(MediaHasher.hashCanonical(data, "image/jpeg"), hash)
        assertNotEquals("the APP1 segment must be left out", MediaHasher.hashBytes(data), hash)
    }

    @Test
    fun `contentHashUri of a JPEG keeps its value across a metadata-only change`() {
        assertEquals(
            hashCanonicalUri(jpeg("camera=test"), "image/jpeg"),
            hashCanonicalUri(jpeg("camera=test;signed=yes;comment=longer"), "image/jpeg")
        )
    }

    @Test
    fun `contentHashUri canonicalises an uppercase JPEG type`() {
        val data = jpeg("camera=test")

        assertEquals(MediaHasher.hashCanonical(data, "image/jpeg"), hashCanonicalUri(data, "IMAGE/JPEG"))
    }

    @Test
    fun `contentHashUri of JPEG content is canonical whatever the type`() {
        val data = jpeg("camera=test")

        for (type in listOf("video/mp4", "application/octet-stream", null)) {
            assertEquals("type $type", MediaHasher.hashCanonical(data, "image/jpeg"), hashCanonicalUri(data, type))
        }
    }

    @Test
    fun `contentHashUri hashes anything but a JPEG whole`() {
        val data = jpeg("camera=test").copyOfRange(2, 60)

        for (type in listOf("video/mp4", "image/png", null)) {
            assertEquals("type $type", MediaHasher.hashBytes(data), hashCanonicalUri(data, type))
        }
    }

    @Test
    fun `contentHashUri rejects a URI the resolver cannot open`() {
        val e = assertThrows(IllegalArgumentException::class.java) {
            contentHashUri(resolverReturning(null).also { every { it.getType(any()) } returns "image/jpeg" })
        }

        assertTrue(e.message!!, e.message!!.startsWith("Cannot open URI:"))
    }

    @Test
    fun `contentHashUri closes the resolver's stream on success`() {
        val stream = ClosingStream(jpeg("camera=test"))

        contentHashUri(resolverOf(stream, "image/jpeg"))

        assertTrue("the resolver's stream must not be leaked", stream.closed)
    }

    @Test
    fun `contentHashUri propagates a read failure and closes the stream`() {
        val stream = FailingStream()

        assertThrows(IOException::class.java) {
            contentHashUri(resolverOf(stream, "image/jpeg"))
        }

        assertTrue("a failed read must still close the stream", stream.closed)
    }

    // -------------------------------------------------------------------------
    // isJpeg
    // -------------------------------------------------------------------------

    @Test
    fun `isJpeg accepts the JPEG types in any case and with parameters`() {
        for (type in listOf("image/jpeg", "image/jpg", "IMAGE/JPEG", "image/jpeg; q=1")) {
            assertTrue(type, MediaHasher.isJpeg(type))
        }
    }

    @Test
    fun `isJpeg rejects every other type with no name or content`() {
        for (type in listOf(null, "", "image/png", "video/mp4", "application/jpeg")) {
            assertFalse("type $type", MediaHasher.isJpeg(type))
        }
    }

    @Test
    fun `isJpeg accepts a jpg or jpeg name whatever the type`() {
        for (name in listOf("a.jpg", "B.JPEG", "/x/c.Jpg")) {
            assertTrue(name, MediaHasher.isJpeg("application/octet-stream", name))
        }
        assertFalse(MediaHasher.isJpeg(null, "a.png"))
    }

    @Test
    fun `isJpeg accepts content that starts with the JPEG SOI whatever the type`() {
        val head = jpeg("camera=test").copyOf(MediaHasher.JPEG_HEAD_SIZE)
        assertTrue(MediaHasher.isJpeg("application/octet-stream", "capture.bin", head))
        assertFalse(MediaHasher.isJpeg(null, null, byteArrayOf(0xFF.toByte(), 0xD8.toByte())))
        assertFalse(MediaHasher.isJpeg(null, null, byteArrayOf(0x89.toByte(), 0x50, 0x4E)))
    }
}
