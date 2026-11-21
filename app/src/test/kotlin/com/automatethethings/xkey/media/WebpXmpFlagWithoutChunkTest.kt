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

import com.automatethethings.xkey.media.XmpContainers.FileEmbed
import com.automatethethings.xkey.media.XmpContainers.Format
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.ByteArrayOutputStream
import java.io.File

/**
 * A WebP whose VP8X declares XMP (flag 0x04) but carries no XMP chunk cannot
 * be embedded: strip clears the flag, so the canonical bytes would not be the
 * file that was signed. Both writers refuse it and the signature goes to a
 * sidecar; every input they do embed strips back to itself.
 */
class WebpXmpFlagWithoutChunkTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    private val json = XmpFixtures.json()

    /** ICC (0x20) and XMP (0x04) declared, a 16x8 canvas, no XMP chunk. */
    private val flagged = XmpFixtures.riff(
        XmpFixtures.riffChunk("VP8X", XmpFixtures.bytes(0x24, 0, 0, 0, 15, 0, 0, 7, 0, 0)),
        XmpFixtures.vp8()
    )

    private fun embedFile(bytes: ByteArray): Pair<FileEmbed, ByteArray> {
        val out = ByteArrayOutputStream()
        val file = tempFolder.newFile().also { it.writeBytes(bytes) }
        return XmpContainers.embedFile(file, out, Format.WEBP, json) to out.toByteArray()
    }

    @Test
    fun `the in-memory embed refuses a VP8X declaring XMP it does not carry`() {
        assertNull(XmpContainers.embed(flagged, Format.WEBP, json))
    }

    @Test
    fun `the streaming embed refuses it and writes nothing`() {
        val (result, written) = embedFile(flagged)
        assertEquals(FileEmbed.REFUSED, result)
        assertEquals(0, written.size)
    }

    @Test
    fun `its signature goes to a sidecar and the file is left as it was`() {
        val file = tempFolder.newFile("flagged.webp").also { it.writeBytes(flagged) }
        val data = ContentAuthenticityData(
            contentHash = "e".repeat(64),
            signatures = listOf(
                SignatureEntry("SHA256:fp", "Alice", "ES256", "sig", "2026-01-15T10:30:00Z", SignerRole.CREATOR)
            )
        )

        XmpMetadataHelper.writeSignature(file.absolutePath, data)

        assertTrue("a sidecar is written", File(XmpMetadataHelper.getSidecarPath(file.absolutePath)).exists())
        assertArrayEquals("the webp is untouched", flagged, file.readBytes())
        assertEquals(data, XmpMetadataHelper.readSignature(file.absolutePath))
    }

    @Test
    fun `every webp the writers embed strips back to itself`() {
        val inputs = listOf(
            XmpFixtures.webp(),
            XmpFixtures.simpleWebp(),
            XmpFixtures.losslessWebp(alpha = false),
            XmpFixtures.losslessWebp(alpha = true),
            flagged
        ) + (0 until 0x40).map { flags ->
            XmpFixtures.riff(
                XmpFixtures.riffChunk("VP8X", XmpFixtures.bytes(flags, 0, 0, 0, 15, 0, 0, 7, 0, 0)),
                XmpFixtures.vp8()
            )
        }
        var embedded = 0
        for (input in inputs) {
            val signed = XmpContainers.embed(input, Format.WEBP, json)
            val (result, written) = embedFile(input)
            if (signed == null) {
                assertEquals(FileEmbed.REFUSED, result)
                continue
            }
            embedded++
            assertEquals(FileEmbed.WRITTEN, result)
            assertArrayEquals(signed, written)
            assertArrayEquals("strip(embed(input)) is the input", input, XmpContainers.strip(signed, Format.WEBP))
            assertNotNull(XmpContainers.extract(signed, Format.WEBP))
        }
        assertTrue("valid inputs are embedded", embedded > 0)
    }
}
