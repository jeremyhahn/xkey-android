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

import com.automatethethings.xkey.media.XmpContainers.Format
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.util.zip.CRC32

/**
 * Minimal media files built byte by byte, so each test states exactly what it
 * holds. Shared by the media package's JVM tests.
 */
internal object XmpFixtures {

    fun bytes(vararg values: Int) = ByteArray(values.size) { values[it].toByte() }

    fun be32(value: Long) = bytes(
        (value shr 24).toInt() and 0xFF, (value shr 16).toInt() and 0xFF,
        (value shr 8).toInt() and 0xFF, value.toInt() and 0xFF
    )

    fun le32(value: Long) = bytes(
        value.toInt() and 0xFF, (value shr 8).toInt() and 0xFF,
        (value shr 16).toInt() and 0xFF, (value shr 24).toInt() and 0xFF
    )

    fun ascii(text: String) = text.toByteArray(Charsets.US_ASCII)

    fun box(type: String, payload: ByteArray) = be32(8L + payload.size) + ascii(type) + payload

    /** ftyp, moov and mdat: the order a camera writes once recording stops. */
    fun mp4(pixels: ByteArray = bytes(0x10, 0x20, 0x30, 0x40)) =
        box("ftyp", ascii("isom") + be32(0x200) + ascii("isommp42")) +
            box("moov", box("mvhd", ByteArray(12) { 1 })) +
            box("mdat", pixels)

    /** A QuickTime movie: `qt  ` brand, a `wide` placeholder, then mdat and moov. */
    fun mov(pixels: ByteArray = bytes(0x11, 0x22, 0x33)) =
        box("ftyp", ascii("qt  ") + be32(0x200) + ascii("qt  ")) +
            box("wide", ByteArray(0)) +
            box("mdat", pixels) +
            box("moov", box("mvhd", ByteArray(12) { 2 }))

    fun pngChunk(type: String, data: ByteArray): ByteArray {
        val crc = CRC32().apply { update(ascii(type)); update(data) }.value
        return be32(data.size.toLong()) + ascii(type) + data + be32(crc)
    }

    val pngSignature = bytes(0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A)

    fun png(pixels: ByteArray = bytes(0x78, 0x9C, 0x01, 0x02, 0x03)) =
        pngSignature +
            pngChunk("IHDR", be32(1) + be32(1) + bytes(8, 2, 0, 0, 0)) +
            pngChunk("IDAT", pixels) +
            pngChunk("IEND", ByteArray(0))

    fun riffChunk(fourcc: String, payload: ByteArray): ByteArray {
        val pad = if (payload.size % 2 == 1) ByteArray(1) else ByteArray(0)
        return ascii(fourcc) + le32(payload.size.toLong()) + payload + pad
    }

    fun riff(vararg chunks: ByteArray): ByteArray {
        val body = chunks.fold(ascii("WEBP")) { acc, c -> acc + c }
        return ascii("RIFF") + le32(body.size.toLong()) + body
    }

    /** A lossy key frame header for a 16x8 image, then a few data bytes. */
    fun vp8(pixels: ByteArray = bytes(0x55, 0x66, 0x77)) =
        riffChunk("VP8 ", bytes(0x10, 0x02, 0x00, 0x9D, 0x01, 0x2A, 16, 0, 8, 0) + pixels)

    /** Extended format: VP8X with the ICC flag (0x20) and a 16x8 canvas. */
    fun webp(pixels: ByteArray = bytes(0x55, 0x66, 0x77)) =
        riff(riffChunk("VP8X", bytes(0x20, 0, 0, 0, 15, 0, 0, 7, 0, 0)), vp8(pixels))

    /** Simple format: a lone `VP8 ` chunk, no VP8X. */
    fun simpleWebp(pixels: ByteArray = bytes(0x55, 0x66, 0x77)) = riff(vp8(pixels))

    /** Simple lossless format: a lone `VP8L` chunk for a 16x8 image, [alpha] its alpha_is_used bit. */
    fun losslessWebp(alpha: Boolean = false): ByteArray {
        val bits = 15L or (7L shl 14) or (if (alpha) 1L shl 28 else 0L)
        return riff(riffChunk("VP8L", bytes(0x2F) + le32(bits) + bytes(0xAA, 0xBB)))
    }

    /** One fixture per embedded format, keyed by the mime type that names it. */
    val all: Map<String, ByteArray> by lazy {
        mapOf(
            "video/mp4" to mp4(),
            "video/quicktime" to mov(),
            "image/png" to png(),
            "image/webp" to webp()
        )
    }

    fun json(hash: String = "a".repeat(64)) = ContentAuthenticityData(
        contentHash = hash,
        signatures = listOf(
            SignatureEntry(
                keyFingerprint = "SHA256:testfp",
                signerName = "Alice <a&b>",
                algorithm = "ES256",
                value = "MEUCIQD",
                timestamp = "2026-01-15T10:30:00Z",
                role = SignerRole.CREATOR
            )
        )
    ).toJsonString()
}

class XmpContainersTest {

    private val json = XmpFixtures.json()

    private fun formatOf(mime: String) = XmpContainers.formatOf(mime)!!

    private fun embed(data: ByteArray, mime: String, text: String = json) =
        XmpContainers.embed(data, formatOf(mime), text)

    @Test
    fun `the embedded types are mp4, mov, png and webp`() {
        assertEquals(Format.ISO_BMFF, XmpContainers.formatOf("video/mp4"))
        assertEquals(Format.ISO_BMFF, XmpContainers.formatOf("video/quicktime"))
        assertEquals(Format.PNG, XmpContainers.formatOf("image/png"))
        assertEquals(Format.WEBP, XmpContainers.formatOf("image/webp"))
        assertNull(XmpContainers.formatOf("image/jpeg"))
        assertNull(XmpContainers.formatOf("image/heic"))
        assertNull(XmpContainers.formatOf("video/x-matroska"))
        assertNull(XmpContainers.formatOf(null))
    }

    @Test
    fun `every fixture round-trips its signature`() {
        for ((mime, file) in XmpFixtures.all) {
            val signed = embed(file, mime)
            assertNotNull(mime, signed)
            assertEquals(mime, json, XmpContainers.extract(signed!!, formatOf(mime)))
        }
    }

    @Test
    fun `simple lossy and lossless webp get a VP8X carrying only the XMP flag`() {
        for (file in listOf(XmpFixtures.simpleWebp(), XmpFixtures.losslessWebp())) {
            val signed = embed(file, "image/webp")!!
            assertEquals(json, XmpContainers.extract(signed, Format.WEBP))
            assertEquals("VP8X", String(signed, 12, 4, Charsets.US_ASCII))
            assertEquals(0x04, signed[20].toInt() and 0xFF)
            // Canvas 16x8, stored minus one, 24-bit little endian.
            assertEquals(15, signed[24].toInt() and 0xFF)
            assertEquals(7, signed[27].toInt() and 0xFF)
            assertArrayEquals(file, XmpContainers.strip(signed, Format.WEBP))
        }
    }

    @Test
    fun `an extended webp keeps its flags and gains the XMP flag and a correct RIFF size`() {
        val signed = embed(XmpFixtures.webp(), "image/webp")!!
        assertEquals(0x24, signed[20].toInt() and 0xFF)
        val riffSize = (signed[4].toInt() and 0xFF) or ((signed[5].toInt() and 0xFF) shl 8) or
            ((signed[6].toInt() and 0xFF) shl 16) or ((signed[7].toInt() and 0xFF) shl 24)
        assertEquals(signed.size - 8, riffSize)
    }

    @Test
    fun `rewriting replaces the box or chunk rather than adding a second`() {
        val second = XmpFixtures.json(hash = "b".repeat(64))
        for ((mime, file) in XmpFixtures.all) {
            val once = embed(file, mime)!!
            val twice = embed(once, mime, second)!!
            assertEquals(mime, once.size, twice.size)
            assertEquals(mime, second, XmpContainers.extract(twice, formatOf(mime)))
            assertArrayEquals(mime, file, XmpContainers.strip(twice, formatOf(mime)))
        }
    }

    @Test
    fun `strip undoes embed exactly and leaves an unsigned file unchanged`() {
        for ((mime, file) in XmpFixtures.all) {
            assertArrayEquals(mime, file, XmpContainers.strip(file, formatOf(mime)))
            assertArrayEquals(mime, file, XmpContainers.strip(embed(file, mime)!!, formatOf(mime)))
        }
    }

    @Test
    fun `the mp4 box is appended so no chunk offset moves`() {
        val file = XmpFixtures.mp4()
        val signed = embed(file, "video/mp4")!!
        assertArrayEquals(file, signed.copyOfRange(0, file.size))
        assertEquals("uuid", String(signed, file.size + 4, 4, Charsets.US_ASCII))
        assertArrayEquals(XmpContainers.XMP_UUID, signed.copyOfRange(file.size + 8, file.size + 24))
    }

    @Test
    fun `every png chunk has a valid CRC after the write`() {
        val signed = embed(XmpFixtures.png(), "image/png")!!
        var i = 8
        var chunks = 0
        var sawXmp = false
        while (i < signed.size) {
            val length = ((signed[i].toLong() and 0xFF) shl 24) or ((signed[i + 1].toLong() and 0xFF) shl 16) or
                ((signed[i + 2].toLong() and 0xFF) shl 8) or (signed[i + 3].toLong() and 0xFF)
            val typeAndData = signed.copyOfRange(i + 4, i + 8 + length.toInt())
            val stored = signed.copyOfRange(i + 8 + length.toInt(), i + 12 + length.toInt())
            val crc = CRC32().apply { update(typeAndData) }.value
            assertArrayEquals("chunk $chunks", XmpFixtures.be32(crc), stored)
            if (String(typeAndData, 0, 4, Charsets.US_ASCII) == "iTXt") {
                sawXmp = String(typeAndData, 4, 17, Charsets.ISO_8859_1) == "XML:com.adobe.xmp"
            }
            i += 12 + length.toInt()
            chunks++
        }
        assertEquals(signed.size, i)
        assertTrue(sawXmp)
        assertEquals("IEND", String(signed, signed.size - 8, 4, Charsets.US_ASCII))
    }

    @Test
    fun `a foreign XMP packet is never overwritten`() {
        val foreign = XmpFixtures.ascii("<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"></x:xmpmeta>")
        val mp4 = XmpFixtures.mp4() + XmpFixtures.box("uuid", XmpContainers.XMP_UUID + foreign)
        assertNull(embed(mp4, "video/mp4"))
        assertNull(XmpContainers.extract(mp4, Format.ISO_BMFF))
        assertArrayEquals(mp4, XmpContainers.strip(mp4, Format.ISO_BMFF))
    }

    @Test
    fun `an mp4 whose last box runs to the end of the file is not embedded`() {
        val open = XmpFixtures.box("ftyp", XmpFixtures.ascii("isom") + XmpFixtures.be32(0)) +
            XmpFixtures.be32(0) + XmpFixtures.ascii("mdat") + XmpFixtures.bytes(1, 2, 3)
        assertNull(embed(open, "video/mp4"))
    }

    @Test
    fun `a webp whose VP8X carries no flags is not embedded`() {
        val bare = XmpFixtures.riff(
            XmpFixtures.riffChunk("VP8X", XmpFixtures.bytes(0, 0, 0, 0, 15, 0, 0, 7, 0, 0)),
            XmpFixtures.vp8()
        )
        assertNull(embed(bare, "image/webp"))
    }

    @Test
    fun `a tampered canvas in the VP8X added to a simple webp stays in the canonical bytes`() {
        for (file in listOf(XmpFixtures.simpleWebp(), XmpFixtures.losslessWebp())) {
            val signed = embed(file, "image/webp")!!
            // Canvas width minus one: 16 becomes 256.
            val tampered = signed.copyOf().apply { this[24] = 0xFF.toByte() }
            assertEquals(json, XmpContainers.extract(tampered, Format.WEBP))
            assertFalse(XmpContainers.strip(tampered, Format.WEBP).contentEquals(file))
        }
    }

    @Test
    fun `a transparent simple lossless webp gets a VP8X declaring alpha`() {
        val file = XmpFixtures.losslessWebp(alpha = true)
        val signed = embed(file, "image/webp")!!
        assertEquals("VP8X", String(signed, 12, 4, Charsets.US_ASCII))
        assertEquals(0x14, signed[20].toInt() and 0xFF)
        assertArrayEquals(file, XmpContainers.strip(signed, Format.WEBP))
    }

    @Test
    fun `an extended webp indistinguishable from an added VP8X is not embedded`() {
        val alphaOnly = XmpFixtures.riff(
            XmpFixtures.riffChunk("VP8X", XmpFixtures.bytes(0x10, 0, 0, 0, 15, 0, 0, 7, 0, 0)),
            XmpFixtures.losslessWebp(alpha = true).copyOfRange(12, XmpFixtures.losslessWebp(alpha = true).size)
        )
        val signed = embed(alphaOnly, "image/webp")
        if (signed != null) assertArrayEquals(alphaOnly, XmpContainers.strip(signed, Format.WEBP))
    }

    @Test
    fun `a packet the stream reader would skip is never embedded`() {
        val limit = 1 shl 20
        val overhead = XmpContainers.packet("").size
        for ((mime, file) in XmpFixtures.all) {
            for (delta in listOf(-40, -23, -22, -21, -1, 0, 1)) {
                val text = "x".repeat(limit - overhead + delta)
                val signed = embed(file, mime, text)
                if (delta == -40) assertNotNull("$mime $delta", signed)
                if (delta == 1) assertNull("$mime $delta", signed)
                if (signed != null) {
                    assertEquals("$mime $delta", text, XmpContainers.read(ByteArrayInputStream(signed), formatOf(mime)))
                }
            }
        }
    }

    @Test
    fun `an unparseable file is not embedded and reads as unsigned`() {
        val junk = ByteArray(32)
        for (mime in XmpFixtures.all.keys) {
            assertNull(mime, embed(junk, mime))
            assertNull(mime, XmpContainers.extract(junk, formatOf(mime)))
            assertArrayEquals(mime, junk, XmpContainers.strip(junk, formatOf(mime)))
            assertNull(mime, XmpContainers.read(ByteArrayInputStream(junk), formatOf(mime)))
        }
    }

    @Test
    fun `the stream reader finds the signature and skips everything else`() {
        for ((mime, file) in XmpFixtures.all) {
            val signed = embed(file, mime)!!
            assertEquals(mime, json, XmpContainers.read(ByteArrayInputStream(signed), formatOf(mime)))
            assertNull(mime, XmpContainers.read(ByteArrayInputStream(file), formatOf(mime)))
        }
    }

    @Test
    fun `the packet escapes the json and declares the xkey namespace`() {
        val packet = String(XmpContainers.packet(json), Charsets.UTF_8)
        assertTrue(packet.contains("xmlns:xkey=\"${XmpContainers.XKEY_NAMESPACE}\""))
        assertTrue(packet.contains("&lt;a&amp;b&gt;"))
        assertEquals(json, XmpContainers.jsonFromPacket(XmpContainers.packet(json)))
    }
}
