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
            AutoSignHash.contentHashUri(resolver, uri, kotlin.io.path.createTempDirectory("hash").toFile())
        )
    }

    @Test
    fun `a JPEG above the bound is refused, never read whole`() {
        val (resolver, uri) = resolverFor("image/jpeg", 1025)

        val refused = assertThrows(AutoSignHash.TooLargeException::class.java) {
            AutoSignHash.contentHashUri(resolver, uri, kotlin.io.path.createTempDirectory("hash").toFile(), limit = 1024)
        }
        assertEquals(1024, refused.limit)
    }

    @Test
    fun `a JPEG at the bound gets the canonical hash`() {
        val (resolver, uri) = resolverFor("image/jpeg", 1024)

        assertEquals(
            MediaHasher.hashCanonical(ByteArray(1024), "image/jpeg"),
            AutoSignHash.contentHashUri(resolver, uri, kotlin.io.path.createTempDirectory("hash").toFile(), limit = 1024)
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

            val hash = AutoSignHash.contentHashUri(resolver, uri, kotlin.io.path.createTempDirectory("hash").toFile())
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

            val hash = AutoSignHash.contentHashUri(resolver, uri, kotlin.io.path.createTempDirectory("hash").toFile())
            assertEquals(MediaHasher.hashBytes(original), hash)
            XmpMetadataHelper.writeSignature(file.path, signatureOver(hash))

            assertFalse("no sidecar", File(XmpMetadataHelper.getSidecarPath(file.path)).exists())
            val signedBytes = file.readBytes()
            assertArrayEquals(original, XmpContainers.strip(signedBytes, XmpContainers.Format.ISO_BMFF))
            val read = XmpMetadataHelper.readSignature(file.path)!!
            assertTrue(
                MediaHasher.contentHashMatches(read.contentHash, signedBytes, mime, MediaHasher.SignatureSource.IN_BAND)
            )

            // Oversized media already carrying an embedded signature: the
            // automatic signer hashes it canonically while streaming, and the
            // writer streams a replacement as it streamed the first embed.
            val signed = XmpContainers.embed(original, XmpContainers.Format.ISO_BMFF, XmpFixtures.json())!!
            val carried = tempFolder.newFile("carried.mp4").apply { writeBytes(signed) }
            val (signedResolver, signedUri) = resolverFor(mime, carried)
            val again = AutoSignHash.contentHashUri(signedResolver, signedUri, kotlin.io.path.createTempDirectory("hash").toFile())
            assertEquals(MediaHasher.hashStreamedFile(carried, mime).canonical, again)
            assertEquals("the carried signature is not part of the hash", hash, again)
            XmpMetadataHelper.writeSignature(carried.path, signatureOver(hash))
            assertEquals(signatureOver(hash), XmpMetadataHelper.readSignature(carried.path))
            assertArrayEquals(original, XmpContainers.strip(carried.readBytes(), XmpContainers.Format.ISO_BMFF))
            assertFalse(File(XmpMetadataHelper.getSidecarPath(carried.path)).exists())
        } finally {
            XmpMetadataHelper.maxEmbedBytes = bound
        }
    }

    @Test
    fun `media already carrying XMP above the bound is hashed and signed again, whatever its container`() {
        val bound = XmpMetadataHelper.maxEmbedBytes
        XmpMetadataHelper.maxEmbedBytes = 8
        try {
            XmpFixtures.all.forEach { (mime, original) ->
                val format = XmpContainers.formatOf(mime)!!
                val ext = mime.substringAfter('/')
                val unsigned = tempFolder.newFile("unsigned.$ext").apply { writeBytes(original) }
                val expected = MediaHasher.hashStreamedFile(unsigned, mime).canonical
                val file = tempFolder.newFile("signed.$ext").apply {
                    writeBytes(XmpContainers.embed(original, format, XmpFixtures.json())!!)
                }
                assertTrue("$mime: the fixture is above the bound", file.length() > XmpMetadataHelper.maxEmbedBytes)

                val hash = AutoSignHash.contentHashFile(file, mime)
                assertEquals("$mime: hashed without its carried signature", expected, hash)

                XmpMetadataHelper.writeSignature(file.path, signatureOver(hash))
                assertEquals("$mime: the packet is replaced", signatureOver(hash), XmpMetadataHelper.readSignature(file.path))
                assertFalse("$mime: no sidecar", File(XmpMetadataHelper.getSidecarPath(file.path)).exists())
            }
        } finally {
            XmpMetadataHelper.maxEmbedBytes = bound
        }
    }

    private fun mainSources(): Map<String, String> {
        val rel = "src/main/kotlin"
        val dir = listOf(File(rel), File("app/$rel")).firstOrNull { it.isDirectory }
            ?: error("$rel not found from ${File(".").absolutePath}")
        return dir.walkTopDown().filter { it.isFile && it.name.endsWith(".kt") }
            .associate { it.relativeTo(dir).path to it.readText() }
    }

    /**
     * The streaming writer replaces a carried packet at any size, so the only
     * media refused before it is hashed is a JPEG too large to embed in
     * memory: one size check, in the one place the hash is computed.
     */
    @Test
    fun `only an oversized JPEG is refused before hashing`() {
        val sources = mainSources()
        val media = sources.filterKeys { it.startsWith("com/automatethethings/xkey/media/") }
        val constructions = media.flatMap { (name, text) ->
            text.lines().withIndex()
                .filter { (_, line) -> "TooLargeException(" in line && "class TooLargeException(" !in line }
                .map { (i, line) -> "$name:${i + 1}: ${line.trim()}" }
        }
        assertEquals("places that refuse media as too large: $constructions", 1, constructions.size)
        val signing = media.entries.single { it.key.endsWith("media/MediaSigningService.kt") }.value
        val start = signing.indexOf("private fun contentHashOfFile(")
        assertTrue("contentHashOfFile is declared", start >= 0)
        val body = signing.substring(start).substringBefore("\n    }\n")
        val jpeg = body.substringAfter("isCanonicalisedJpeg(mimeType)").substringBefore("\n        }")
        assertTrue("the one refusal is contentHashOfFile's JPEG check: $body", "TooLargeException(" in jpeg)

        val limits = sources.filterValues { "embedLimit" in it }.keys.sorted()
        assertEquals("sources that still name embedLimit", emptyList<String>(), limits)
    }
}
