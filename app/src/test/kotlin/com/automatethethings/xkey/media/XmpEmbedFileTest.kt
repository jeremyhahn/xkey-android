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

import com.automatethethings.xkey.media.XmpContainers.FileEmbed
import com.automatethethings.xkey.media.XmpFixtures.riff
import com.automatethethings.xkey.media.XmpFixtures.vp8
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.ByteArrayOutputStream
import java.io.File

/**
 * The streaming embed ([XmpContainers.embedFile]) every unsigned MP4/MOV, PNG
 * and WebP goes through, at any size, and the typed working copy co-signing
 * appends in.
 */
class XmpEmbedFileTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    private val json = XmpFixtures.json()

    private fun fileOf(bytes: ByteArray): File =
        tempFolder.newFile().also { it.writeBytes(bytes) }

    private fun embedFile(bytes: ByteArray, mime: String): Pair<FileEmbed, ByteArray> {
        val out = ByteArrayOutputStream()
        val result = XmpContainers.embedFile(fileOf(bytes), out, XmpContainers.formatOf(mime)!!, json)
        return result to out.toByteArray()
    }

    /** Unsigned inputs, by mime type: one per container shape embed handles or refuses. */
    private fun unsignedCases(): List<Pair<String, ByteArray>> {
        val simple = XmpFixtures.simpleWebp()
        // A VP8X equal to the one embed adds to [simple]: embed refuses it.
        val embeddedSimple = XmpContainers.embed(simple, XmpContainers.Format.WEBP, json)!!
        val addedLike = riff(embeddedSimple.copyOfRange(12, 30), vp8())
        val mp4 = XmpFixtures.mp4()
        return XmpFixtures.all.toList() + listOf(
            "image/webp" to simple,
            "image/webp" to XmpFixtures.losslessWebp(alpha = false),
            "image/webp" to XmpFixtures.losslessWebp(alpha = true),
            "image/webp" to addedLike,
            "video/mp4" to mp4.copyOf(mp4.size - 1),
            "video/mp4" to XmpFixtures.be32(0) + mp4.copyOfRange(4, mp4.size),
            "image/png" to XmpFixtures.png().let { it.copyOf(it.size - 12) },
            "image/webp" to XmpFixtures.webp().let { it.copyOf(it.size - 1) }
        ) + XmpFixtures.crowded.flatMap { (mime, build) -> listOf(5, 9).map { mime to build(it) } }
    }

    @Test
    fun `the streaming embed writes exactly what the in-memory embed returns`() {
        for ((mime, bytes) in unsignedCases()) {
            val expected = XmpContainers.embed(bytes, XmpContainers.formatOf(mime)!!, json)
            val (result, written) = embedFile(bytes, mime)
            if (expected == null) {
                assertEquals(mime, FileEmbed.REFUSED, result)
                assertEquals("$mime: nothing is written when refused", 0, written.size)
            } else {
                assertEquals(mime, FileEmbed.WRITTEN, result)
                assertArrayEquals(mime, expected, written)
            }
        }
    }

    @Test
    fun `a streamed embed reads back and strips to the file it came from`() {
        for ((mime, bytes) in XmpFixtures.all) {
            val format = XmpContainers.formatOf(mime)!!
            val (result, written) = embedFile(bytes, mime)
            assertEquals(mime, FileEmbed.WRITTEN, result)
            assertEquals(mime, json, XmpContainers.read(written.inputStream(), format))
            assertArrayEquals(mime, bytes, XmpContainers.strip(written, format))
        }
    }

    @Test
    fun `media already carrying an XMP packet is left to the in-memory embed`() {
        for ((mime, bytes) in XmpFixtures.all) {
            val signed = XmpContainers.embed(bytes, XmpContainers.formatOf(mime)!!, json)!!
            val (result, written) = embedFile(signed, mime)
            assertEquals(mime, FileEmbed.CARRIES_XMP, result)
            assertEquals(mime, 0, written.size)
        }
    }

    @Test
    fun `unsigned media above the in-memory bound embeds in XMP with no sidecar`() {
        val saved = XmpMetadataHelper.maxEmbedBytes
        try {
            XmpMetadataHelper.maxEmbedBytes = 8
            for ((mime, bytes) in XmpFixtures.all) {
                val file = tempFolder.newFile("big" + XmpMetadataHelper.stagingSuffix(mime)).apply { writeBytes(bytes) }
                val data = ContentAuthenticityData.fromJsonString(json)!!

                XmpMetadataHelper.writeSignature(file.path, data)

                assertFalse(mime, File(XmpMetadataHelper.getSidecarPath(file.path)).exists())
                val format = XmpContainers.formatOf(mime)!!
                assertEquals(mime, json, file.inputStream().use { XmpContainers.read(it.buffered(), format) })
                assertArrayEquals(mime, bytes, XmpContainers.strip(file.readBytes(), format))
            }
        } finally {
            XmpMetadataHelper.maxEmbedBytes = saved
        }
    }

    @Test
    fun `a co-signing working copy typed by the media reads and appends its embedded signature`() {
        val data = ContentAuthenticityData.fromJsonString(json)!!
        val witness = data.signatures.first().copy(keyFingerprint = "SHA256:witness", role = SignerRole.WITNESS)
        for ((mime, bytes) in XmpFixtures.all) {
            val signed = XmpContainers.embed(bytes, XmpContainers.formatOf(mime)!!, json)!!
            val copy = File.createTempFile("cosign-", XmpMetadataHelper.stagingSuffix(mime), tempFolder.root)
            copy.writeBytes(signed)
            assertEquals(mime, data, XmpMetadataHelper.readSignature(copy.path))

            XmpMetadataHelper.appendSignature(copy.path, witness)

            val after = XmpMetadataHelper.readSignature(copy.path)!!
            assertEquals(mime, listOf(data.signatures.first(), witness), after.signatures)
            assertFalse(mime, File(XmpMetadataHelper.getSidecarPath(copy.path)).exists())
        }
    }

    @Test
    fun `staging suffixes map each type back to its own container`() {
        assertEquals(".jpg", XmpMetadataHelper.stagingSuffix("image/jpeg"))
        assertEquals(".png", XmpMetadataHelper.stagingSuffix("image/png"))
        assertEquals(".webp", XmpMetadataHelper.stagingSuffix("image/webp"))
        assertEquals(".mp4", XmpMetadataHelper.stagingSuffix("video/mp4"))
        assertEquals(".mov", XmpMetadataHelper.stagingSuffix("video/quicktime"))
        assertEquals(".bin", XmpMetadataHelper.stagingSuffix(null))
        assertTrue(XmpMetadataHelper.stagingSuffix("image/heic").isNotEmpty())
    }
}
