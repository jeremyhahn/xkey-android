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

import android.content.ContentResolver
import android.net.Uri
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.io.InputStream

/**
 * The automatic signer hashes every capture, videos included, so the hash
 * must never need the whole file in the app heap.
 */
class AutoSignHashTest {

    /** [size] zero bytes, produced on demand so nothing holds them. */
    private class ZeroStream(private val size: Long) : InputStream() {
        private var position = 0L

        override fun read(): Int = if (position < size) { position++; 0 } else -1

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (position >= size) return -1
            val n = minOf(len.toLong(), size - position).toInt()
            java.util.Arrays.fill(b, off, off + n, 0)
            position += n
            return n
        }
    }

    private fun resolverFor(mimeType: String, size: Long): Pair<ContentResolver, Uri> {
        val resolver = mockk<ContentResolver>()
        val uri = mockk<Uri>()
        every { resolver.getType(uri) } returns mimeType
        every { resolver.openInputStream(uri) } answers { ZeroStream(size) }
        return resolver to uri
    }

    @Test
    fun `a video larger than any byte array is hashed by streaming the whole file`() {
        // One byte more than a ByteArray can hold: reading it whole cannot work.
        val size = Int.MAX_VALUE.toLong() + 1
        val (resolver, uri) = resolverFor("video/mp4", size)

        assertEquals(
            MediaHasher.hashStream(ZeroStream(size)),
            AutoSignHash.contentHashUri(resolver, uri)
        )
    }

    @Test
    fun `a JPEG above the bound is refused, never read whole`() {
        val (resolver, uri) = resolverFor("image/jpeg", 1025)

        val refused = assertThrows(AutoSignHash.TooLargeException::class.java) {
            AutoSignHash.contentHashUri(resolver, uri, limit = 1024)
        }
        assertEquals(1024, refused.limit)
    }

    @Test
    fun `a JPEG at the bound gets the canonical hash`() {
        val (resolver, uri) = resolverFor("image/jpeg", 1024)

        assertEquals(
            MediaHasher.hashCanonical(ByteArray(1024), "image/jpeg"),
            AutoSignHash.contentHashUri(resolver, uri, limit = 1024)
        )
    }

    @Test
    fun `the default bound is 32 MiB`() {
        assertEquals(32 * 1024 * 1024, AutoSignHash.MAX_CANONICAL_JPEG_BYTES)
    }

    @get:Rule
    val tempFolder = TemporaryFolder()

    private fun resolverFor(mimeType: String, file: File): Pair<ContentResolver, Uri> {
        val resolver = mockk<ContentResolver>()
        val uri = mockk<Uri>()
        every { resolver.getType(uri) } returns mimeType
        every { resolver.openInputStream(uri) } answers { file.inputStream() }
        return resolver to uri
    }

    private fun signatureOver(hash: String) = ContentAuthenticityData(
        contentHash = hash,
        signatures = listOf(
            SignatureEntry(
                keyFingerprint = "SHA256:autofp",
                signerName = "Auto",
                algorithm = "ES256",
                value = "MEUCIQD",
                timestamp = "2026-01-15T10:30:00Z",
                role = SignerRole.CREATOR
            )
        )
    )

    @Test
    fun `already signed png and mp4 signed again through the uri path verify after the packet is replaced`() {
        for ((name, mime) in listOf("photo.png" to "image/png", "clip.mp4" to "video/mp4")) {
            val format = XmpContainers.formatOf(mime)!!
            val original = XmpFixtures.all.getValue(mime)
            val earlier = XmpContainers.embed(original, format, XmpFixtures.json(MediaHasher.hashCanonical(original, mime)))!!
            val file = tempFolder.newFile(name).apply { writeBytes(earlier) }
            val (resolver, uri) = resolverFor(mime, file)

            val hash = AutoSignHash.contentHashUri(resolver, uri)
            XmpMetadataHelper.writeSignature(file.path, signatureOver(hash))

            val read = XmpMetadataHelper.readSignature(file.path)!!
            assertEquals(mime, hash, read.contentHash)
            assertTrue(
                mime,
                MediaHasher.contentHashMatches(read.contentHash, file.readBytes(), mime, MediaHasher.SignatureSource.IN_BAND)
            )
        }
    }

    @Test
    fun `unsigned media above the embed bound is hashed streaming and signed in XMP, not a sidecar`() {
        val mime = "video/mp4"
        val original = XmpFixtures.mp4()
        val bound = XmpMetadataHelper.maxEmbedBytes
        XmpMetadataHelper.maxEmbedBytes = original.size - 1
        try {
            val file = tempFolder.newFile("long.mp4").apply { writeBytes(original) }
            val (resolver, uri) = resolverFor(mime, file)

            val hash = AutoSignHash.contentHashUri(resolver, uri)
            assertEquals(MediaHasher.hashBytes(original), hash)
            XmpMetadataHelper.writeSignature(file.path, signatureOver(hash))

            assertFalse("no sidecar", File(XmpMetadataHelper.getSidecarPath(file.path)).exists())
            val signedBytes = file.readBytes()
            assertArrayEquals(original, XmpContainers.strip(signedBytes, XmpContainers.Format.ISO_BMFF))
            val read = XmpMetadataHelper.readSignature(file.path)!!
            assertTrue(
                MediaHasher.contentHashMatches(read.contentHash, signedBytes, mime, MediaHasher.SignatureSource.IN_BAND)
            )

            // Oversized media already carrying an embedded signature keeps it:
            // a sidecar would be shadowed by it, so both steps refuse.
            val signed = XmpContainers.embed(original, XmpContainers.Format.ISO_BMFF, XmpFixtures.json())!!
            val carried = tempFolder.newFile("carried.mp4").apply { writeBytes(signed) }
            val (signedResolver, signedUri) = resolverFor(mime, carried)
            assertThrows(AutoSignHash.TooLargeException::class.java) {
                AutoSignHash.contentHashUri(signedResolver, signedUri)
            }
            assertThrows(java.io.IOException::class.java) {
                XmpMetadataHelper.writeSignature(carried.path, signatureOver(hash))
            }
            assertArrayEquals(signed, carried.readBytes())
            assertFalse(File(XmpMetadataHelper.getSidecarPath(carried.path)).exists())
        } finally {
            XmpMetadataHelper.maxEmbedBytes = bound
        }
    }
}
