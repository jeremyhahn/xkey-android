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

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.util.zip.CRC32

/**
 * The XMP packet xKey embeds in MP4/MOV, PNG and WebP, and the byte-level
 * box/chunk edits that put it there. Pure bytes: no Android APIs, so every
 * rule here is tested on the JVM.
 *
 * - ISO BMFF (MP4, MOV): a top-level `uuid` box with the XMP usertype
 *   [XMP_UUID], appended after the last box so no `stco`/`co64` offset moves.
 * - PNG: an uncompressed `iTXt` chunk with keyword [PNG_XMP_KEYWORD], just
 *   before `IEND`.
 * - WebP: a RIFF `XMP ` chunk at the end, the VP8X XMP flag set; a simple
 *   (VP8/VP8L-only) file gets a VP8X carrying that flag, the alpha flag a
 *   `VP8L` bitstream declares, and the bitstream's canvas.
 *
 * A packet is "ours" when it declares [XKEY_NAMESPACE]. [strip] removes our
 * box/chunk and undoes exactly what [embed] changed, so
 * `strip(embed(x)) == x` and a file without our packet is returned as is.
 * [embed] refuses (returns null) whenever that cannot hold: a foreign XMP
 * packet, an MP4 whose last box runs to the end of the file, a VP8X [strip]
 * would take for the one [embed] adds, a packet larger than [read] loads,
 * or bytes that do not parse (more than [MAX_PARTS] boxes or chunks among them).
 */
object XmpContainers {

    enum class Format { ISO_BMFF, PNG, WEBP }

    /** The namespace of the `xkey:signature` property that holds the JSON. */
    const val XKEY_NAMESPACE = "http://ns.automatethethings.com/xkey/media/1.0/"

    /** The ISO BMFF `uuid` usertype for XMP, BE7ACFCB-97A9-42E8-9C71-999491E3AFAC. */
    val XMP_UUID: ByteArray = intArrayOf(
        0xBE, 0x7A, 0xCF, 0xCB, 0x97, 0xA9, 0x42, 0xE8,
        0x9C, 0x71, 0x99, 0x94, 0x91, 0xE3, 0xAF, 0xAC
    ).let { values -> ByteArray(values.size) { values[it].toByte() } }

    const val PNG_XMP_KEYWORD = "XML:com.adobe.xmp"

    /** The largest packet the stream reader loads; ours are a few KB. */
    private const val MAX_PACKET = 1 shl 20

    /**
     * The most top-level boxes or chunks [parse] keeps. Each costs an object
     * and a string, so a file of millions of empty chunks, small on disk,
     * would otherwise fill the heap; a file with more is refused as if it did
     * not parse. Real media has a few, a fragmented video or an animation
     * some thousands.
     */
    private const val MAX_PARTS = 1 shl 16

    private const val WEBP_XMP_FLAG = 0x04
    private const val WEBP_ALPHA_FLAG = 0x10

    private val PNG_SIGNATURE = byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A)

    private const val NAMESPACE_DECLARATION = "xmlns:xkey=\"$XKEY_NAMESPACE\""
    private const val OPEN = "<xkey:signature>"
    private const val CLOSE = "</xkey:signature>"

    /** The container [mimeType] embeds in, or null when it keeps a sidecar (JPEG has its own EXIF path). */
    fun formatOf(mimeType: String?): Format? =
        when (mimeType.orEmpty().substringBefore(';').trim().lowercase()) {
            "video/mp4", "video/quicktime" -> Format.ISO_BMFF
            "image/png" -> Format.PNG
            "image/webp" -> Format.WEBP
            else -> null
        }

    /** An XMP packet holding [json], XML-escaped, as one `xkey:signature` property. */
    fun packet(json: String): ByteArray {
        val escaped = json.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        return (
            "<?xpacket begin=\"" + Char(0xFEFF) + "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?>" +
                "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\">" +
                "<rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">" +
                "<rdf:Description rdf:about=\"\" $NAMESPACE_DECLARATION>" +
                OPEN + escaped + CLOSE +
                "</rdf:Description></rdf:RDF></x:xmpmeta>" +
                "<?xpacket end=\"w\"?>"
            ).toByteArray(Charsets.UTF_8)
    }

    /** The JSON in [packet], or null when the packet is not ours. */
    fun jsonFromPacket(packet: ByteArray): String? {
        val text = String(packet, Charsets.UTF_8)
        if (!text.contains(NAMESPACE_DECLARATION)) return null
        val start = text.indexOf(OPEN)
        val end = text.indexOf(CLOSE, startIndex = start + 1)
        if (start < 0 || end < 0) return null
        return text.substring(start + OPEN.length, end)
            .replace("&lt;", "<").replace("&gt;", ">")
            .replace("&quot;", "\"").replace("&apos;", "'")
            .replace("&amp;", "&")
    }

    /** The JSON our box/chunk in [data] holds, or null when there is none or [data] does not parse. */
    fun extract(data: ByteArray, format: Format): String? {
        val parts = parse(data, format) ?: return null
        return parts.firstNotNullOfOrNull { part -> packetOf(data, part, format)?.let(::jsonFromPacket) }
    }

    /**
     * [data] without our box/chunk, as it was before [embed]: the bytes the
     * canonical hash covers. Returned unchanged when [data] holds no packet
     * of ours or does not parse.
     *
     * In MP4/MOV only a trailing run of our boxes is left out, the only place
     * [embed] puts one: sample offsets (`stco`/`co64`) are absolute, so a box
     * of ours before any other box would shift the media they address. Such a
     * file is returned unchanged, so its hash covers the extra box and can
     * never match the hash signed over the file without it.
     */
    fun strip(data: ByteArray, format: Format): ByteArray {
        val parts = parse(data, format) ?: return data
        val ours = parts.map { isOurs(data, it, format) }
        if (format == Format.ISO_BMFF) {
            val first = ours.indexOf(true)
            if (first >= 0 && ours.drop(first).any { !it }) return data
        }
        val kept = parts.filterIndexed { i, _ -> !ours[i] }
        if (kept.size == parts.size) return data
        val out = ByteArrayOutputStream(data.size)
        when (format) {
            Format.ISO_BMFF -> kept.forEach { out.write(data, it.start, it.end - it.start) }
            Format.PNG -> {
                out.write(PNG_SIGNATURE)
                kept.forEach { out.write(data, it.start, it.end - it.start) }
            }
            Format.WEBP -> {
                for (part in kept) {
                    if (part.type == "VP8X" && part.payloadEnd > part.payloadStart) {
                        val header = data.copyOfRange(part.payloadStart, part.payloadEnd)
                        if (isAddedVp8x(header, data, kept)) continue // the VP8X embed added to a simple file
                        // Any other VP8X stays, so an edited header is hashed.
                        val flags = (data[part.payloadStart].toInt() and 0xFF) and WEBP_XMP_FLAG.inv()
                        val chunk = data.copyOfRange(part.start, part.end)
                        chunk[part.payloadStart - part.start] = flags.toByte()
                        out.write(chunk)
                    } else {
                        out.write(data, part.start, part.end - part.start)
                    }
                }
                return riff(out.toByteArray())
            }
        }
        return out.toByteArray()
    }

    /**
     * [data] carrying [json] in our box/chunk, replacing any earlier one, or
     * null when it cannot be embedded so that [strip] restores the file
     * exactly (see the class comment); the caller then keeps a sidecar.
     */
    fun embed(data: ByteArray, format: Format, json: String): ByteArray? {
        val parts = parse(data, format) ?: return null
        val packets = parts.map { packetOf(data, it, format) }
        if (packets.any { it != null && jsonFromPacket(it) == null }) return null // foreign XMP
        if (format == Format.ISO_BMFF) {
            // Ours is only ever appended; a box after it would move if ours were removed.
            val first = packets.indexOfFirst { it != null }
            if (first >= 0 && packets.drop(first).any { it == null }) return null
        }
        val base = strip(data, format)
        val baseParts = parse(base, format) ?: return null
        val packet = packet(json)
        // The payload [read] would load: a larger one would read back as unsigned.
        val readerPayload = when (format) {
            Format.ISO_BMFF, Format.WEBP -> packet.size
            Format.PNG -> PNG_XMP_KEYWORD.length + 5 + packet.size
        }
        if (readerPayload > MAX_PACKET) return null
        return when (format) {
            Format.ISO_BMFF -> {
                if (baseParts.any { it.openEnded }) return null
                base + box("uuid", XMP_UUID + packet)
            }
            Format.PNG -> {
                val iend = baseParts.last()
                val keyword = PNG_XMP_KEYWORD.toByteArray(Charsets.ISO_8859_1)
                // keyword NUL, compression flag 0, method 0, empty language NUL, empty translated keyword NUL.
                val chunk = pngChunk("iTXt", keyword + byteArrayOf(0, 0, 0, 0, 0) + packet)
                base.copyOfRange(0, iend.start) + chunk + base.copyOfRange(iend.start, base.size)
            }
            Format.WEBP -> embedWebp(base, baseParts, packet)
        }
    }

    /**
     * The JSON our box/chunk holds, read from [input] by walking the box or
     * chunk headers and skipping every payload but an XMP one. Null when there
     * is none or the stream does not parse. An [java.io.IOException] from
     * [input] propagates: a read that failed has not shown the file unsigned.
     */
    fun read(input: InputStream, format: Format): String? = when (format) {
        Format.ISO_BMFF -> readBmff(input)
        Format.PNG -> readPng(input)
        Format.WEBP -> readWebp(input)
    }

    // -------------------------------------------------------------------------
    // Parsing
    // -------------------------------------------------------------------------

    /** One top-level box or chunk: `[start, end)` in the file, `[payloadStart, payloadEnd)` its data. */
    private class Part(
        val start: Int,
        val end: Int,
        val type: String,
        val payloadStart: Int,
        val payloadEnd: Int,
        val openEnded: Boolean = false
    )

    private fun parse(data: ByteArray, format: Format): List<Part>? = when (format) {
        Format.ISO_BMFF -> parseBmff(data)
        Format.PNG -> parsePng(data)
        Format.WEBP -> parseWebp(data)
    }

    private fun parseBmff(data: ByteArray): List<Part>? {
        val parts = mutableListOf<Part>()
        var i = 0
        while (i < data.size) {
            if (data.size - i < 8) return null
            val size32 = u32be(data, i)
            var header = 8
            val size = when (size32) {
                0L -> (data.size - i).toLong()
                1L -> {
                    if (data.size - i < 16) return null
                    header = 16
                    u64be(data, i + 8)
                }
                else -> size32
            }
            if (size < header || size > data.size - i) return null
            val end = i + size.toInt()
            if (parts.size == MAX_PARTS) return null
            parts += Part(i, end, fourcc(data, i + 4), i + header, end, openEnded = size32 == 0L)
            i = end
        }
        return parts.takeIf { it.isNotEmpty() && it[0].type == "ftyp" }
    }

    private fun parsePng(data: ByteArray): List<Part>? {
        if (data.size < 8 || !data.copyOfRange(0, 8).contentEquals(PNG_SIGNATURE)) return null
        val parts = mutableListOf<Part>()
        var i = 8
        while (data.size - i >= 12) {
            val length = u32be(data, i)
            if (length > data.size - i - 12) return null
            val end = i + 12 + length.toInt()
            if (parts.size == MAX_PARTS) return null
            val type = fourcc(data, i + 4)
            parts += Part(i, end, type, i + 8, end - 4)
            i = end
            if (type == "IEND") return parts.takeIf { i == data.size }
        }
        return null
    }

    private fun parseWebp(data: ByteArray): List<Part>? {
        if (data.size < 12 || fourcc(data, 0) != "RIFF" || fourcc(data, 8) != "WEBP") return null
        if (u32le(data, 4) != (data.size - 8).toLong()) return null
        val parts = mutableListOf<Part>()
        var i = 12
        while (i < data.size) {
            if (data.size - i < 8) return null
            val size = u32le(data, i + 4)
            val padded = size + (size and 1)
            if (padded > data.size - i - 8) return null
            val end = i + 8 + padded.toInt()
            if (parts.size == MAX_PARTS) return null
            parts += Part(i, end, fourcc(data, i), i + 8, i + 8 + size.toInt())
            i = end
        }
        return parts.takeIf { it.isNotEmpty() }
    }

    /** The XMP packet [part] holds, ours or not, or null when it is no XMP box/chunk. */
    private fun packetOf(data: ByteArray, part: Part, format: Format): ByteArray? {
        val payload = data.copyOfRange(part.payloadStart, part.payloadEnd)
        return when (format) {
            Format.ISO_BMFF -> if (part.type == "uuid") bmffPacket(payload) else null
            Format.PNG -> if (part.type == "iTXt") pngPacket(payload) else null
            Format.WEBP -> if (part.type == "XMP ") payload else null
        }
    }

    private fun isOurs(data: ByteArray, part: Part, format: Format): Boolean =
        packetOf(data, part, format)?.let(::jsonFromPacket) != null

    private fun bmffPacket(payload: ByteArray): ByteArray? =
        if (payload.size >= 16 && payload.copyOfRange(0, 16).contentEquals(XMP_UUID)) {
            payload.copyOfRange(16, payload.size)
        } else {
            null
        }

    /** The text of an XMP `iTXt` chunk; a compressed one reads as an empty (foreign) packet. */
    private fun pngPacket(payload: ByteArray): ByteArray? {
        val keyword = PNG_XMP_KEYWORD.toByteArray(Charsets.ISO_8859_1)
        if (payload.size < keyword.size + 5) return null
        if (!payload.copyOfRange(0, keyword.size).contentEquals(keyword) || payload[keyword.size] != 0.toByte()) {
            return null
        }
        if (payload[keyword.size + 1] != 0.toByte()) return ByteArray(0)
        val language = payload.indexOfNul(keyword.size + 3)
        if (language < 0) return ByteArray(0)
        val translated = payload.indexOfNul(language + 1)
        if (translated < 0) return ByteArray(0)
        return payload.copyOfRange(translated + 1, payload.size)
    }

    private fun ByteArray.indexOfNul(from: Int): Int {
        for (i in from until size) if (this[i] == 0.toByte()) return i
        return -1
    }

    // -------------------------------------------------------------------------
    // Writing
    // -------------------------------------------------------------------------

    private fun embedWebp(base: ByteArray, parts: List<Part>, packet: ByteArray): ByteArray? {
        val out = ByteArrayOutputStream(base.size + packet.size + 32)
        val vp8x = parts.firstOrNull { it.type == "VP8X" }
        if (vp8x != null) {
            if (vp8x.payloadEnd - vp8x.payloadStart < 10) return null
            val flags = base[vp8x.payloadStart].toInt() and 0xFF
            val header = base.copyOfRange(vp8x.payloadStart, vp8x.payloadEnd)
            header[0] = (flags or WEBP_XMP_FLAG).toByte()
            // strip would take it for the VP8X embed adds and drop the one the file came with.
            if (isAddedVp8x(header, base, parts)) return null
            for (part in parts) {
                val chunk = base.copyOfRange(part.start, part.end)
                if (part === vp8x) chunk[8] = header[0]
                out.write(chunk)
            }
        } else {
            // strip leaves out an added VP8X only beside a lone image chunk.
            if (parts.size != 1) return null
            val header = addedVp8xPayload(base, parts.first()) ?: return null
            out.write(riffChunk("VP8X", header))
            parts.forEach { out.write(base, it.start, it.end - it.start) }
        }
        out.write(riffChunk("XMP ", packet))
        return riff(out.toByteArray())
    }

    /**
     * The VP8X payload [embedWebp] adds to a simple file whose one image
     * chunk is [image]: the XMP flag, the alpha flag when a `VP8L` bitstream
     * declares alpha, and the canvas from the bitstream header. Null when
     * the bitstream header does not parse.
     */
    private fun addedVp8xPayload(data: ByteArray, image: Part): ByteArray? {
        val payload = data.copyOfRange(image.payloadStart, image.payloadEnd)
        val (width, height) = canvasOf(payload, image.type) ?: return null
        val alpha = image.type == "VP8L" && ((u32le(payload, 1) shr 28) and 1L) == 1L
        val flags = WEBP_XMP_FLAG or (if (alpha) WEBP_ALPHA_FLAG else 0)
        return byteArrayOf(flags.toByte(), 0, 0, 0) + le24(width - 1) + le24(height - 1)
    }

    /**
     * Whether [header], the VP8X payload of the first of [parts], is exactly
     * the one [embedWebp] adds to the simple file the other part makes up.
     * Only such a VP8X is left out of the canonical bytes, so an edited
     * canvas or flag stays in the hash.
     */
    private fun isAddedVp8x(header: ByteArray, data: ByteArray, parts: List<Part>): Boolean =
        parts.size == 2 && parts[0].type == "VP8X" &&
            header.contentEquals(addedVp8xPayload(data, parts[1]) ?: return false)

    /** Width and height from a simple file's `VP8 ` or `VP8L` bitstream header. */
    private fun canvasOf(payload: ByteArray, type: String): Pair<Int, Int>? = when (type) {
        "VP8 " -> if (payload.size >= 10 && (payload[3].toInt() and 0xFF) == 0x9D &&
            (payload[4].toInt() and 0xFF) == 0x01 && (payload[5].toInt() and 0xFF) == 0x2A
        ) {
            Pair(u16le(payload, 6) and 0x3FFF, u16le(payload, 8) and 0x3FFF)
        } else {
            null
        }
        "VP8L" -> if (payload.size >= 5 && (payload[0].toInt() and 0xFF) == 0x2F) {
            val bits = u32le(payload, 1)
            Pair((bits and 0x3FFF).toInt() + 1, ((bits shr 14) and 0x3FFF).toInt() + 1)
        } else {
            null
        }
        else -> null
    }?.takeIf { it.first > 0 && it.second > 0 }

    private fun box(type: String, payload: ByteArray): ByteArray =
        be32(8L + payload.size) + type.toByteArray(Charsets.US_ASCII) + payload

    private fun pngChunk(type: String, data: ByteArray): ByteArray {
        val typeBytes = type.toByteArray(Charsets.US_ASCII)
        val crc = CRC32().apply { update(typeBytes); update(data) }.value
        return be32(data.size.toLong()) + typeBytes + data + be32(crc)
    }

    private fun riffChunk(fourcc: String, payload: ByteArray): ByteArray {
        val pad = if (payload.size % 2 == 1) ByteArray(1) else ByteArray(0)
        return fourcc.toByteArray(Charsets.US_ASCII) + le32(payload.size.toLong()) + payload + pad
    }

    /** `RIFF`, the size, `WEBP` and [chunks]. */
    private fun riff(chunks: ByteArray): ByteArray =
        "RIFF".toByteArray(Charsets.US_ASCII) + le32(4L + chunks.size) + "WEBP".toByteArray(Charsets.US_ASCII) + chunks

    // -------------------------------------------------------------------------
    // Stream reading
    // -------------------------------------------------------------------------

    private fun readBmff(input: InputStream): String? {
        while (true) {
            val header = input.readExactly(8) ?: return null
            val size32 = u32be(header, 0)
            var headerSize = 8L
            val size = when (size32) {
                0L -> return null // runs to the end; ours is never open-ended
                1L -> {
                    headerSize = 16
                    u64be(input.readExactly(8) ?: return null, 0)
                }
                else -> size32
            }
            if (size < headerSize) return null
            var remaining = size - headerSize
            if (fourcc(header, 4) == "uuid" && remaining >= 16 && remaining - 16 <= MAX_PACKET) {
                val usertype = input.readExactly(16) ?: return null
                remaining -= 16
                if (usertype.contentEquals(XMP_UUID)) {
                    val packet = input.readExactly(remaining.toInt()) ?: return null
                    jsonFromPacket(packet)?.let { return it }
                    continue
                }
            }
            if (!input.skipExactly(remaining)) return null
        }
    }

    private fun readPng(input: InputStream): String? {
        val signature = input.readExactly(8) ?: return null
        if (!signature.contentEquals(PNG_SIGNATURE)) return null
        while (true) {
            val header = input.readExactly(8) ?: return null
            val length = u32be(header, 0)
            val type = fourcc(header, 4)
            if (type == "iTXt" && length <= MAX_PACKET) {
                val payload = input.readExactly(length.toInt()) ?: return null
                if (!input.skipExactly(4)) return null
                pngPacket(payload)?.let(::jsonFromPacket)?.let { return it }
            } else if (!input.skipExactly(length + 4)) {
                return null
            }
            if (type == "IEND") return null
        }
    }

    private fun readWebp(input: InputStream): String? {
        val header = input.readExactly(12) ?: return null
        if (fourcc(header, 0) != "RIFF" || fourcc(header, 8) != "WEBP") return null
        while (true) {
            val chunk = input.readExactly(8) ?: return null
            val size = u32le(chunk, 4)
            val pad = size and 1
            if (fourcc(chunk, 0) == "XMP " && size <= MAX_PACKET) {
                val packet = input.readExactly(size.toInt()) ?: return null
                jsonFromPacket(packet)?.let { return it }
                if (!input.skipExactly(pad)) return null
            } else if (!input.skipExactly(size + pad)) {
                return null
            }
        }
    }

    /** Exactly [count] bytes, or null at the end of the stream. */
    private fun InputStream.readExactly(count: Int): ByteArray? {
        val buffer = ByteArray(count)
        var read = 0
        while (read < count) {
            val n = read(buffer, read, count - read)
            if (n < 0) return null
            read += n
        }
        return buffer
    }

    /** Skips exactly [count] bytes; false at the end of the stream. */
    private fun InputStream.skipExactly(count: Long): Boolean {
        var left = count
        while (left > 0) {
            val skipped = skip(left)
            if (skipped > 0) {
                left -= skipped
            } else {
                if (read() < 0) return false
                left--
            }
        }
        return true
    }

    // -------------------------------------------------------------------------
    // Integers
    // -------------------------------------------------------------------------

    private fun b(data: ByteArray, i: Int): Long = (data[i].toLong() and 0xFF)

    private fun u32be(data: ByteArray, i: Int): Long =
        (b(data, i) shl 24) or (b(data, i + 1) shl 16) or (b(data, i + 2) shl 8) or b(data, i + 3)

    private fun u64be(data: ByteArray, i: Int): Long = (u32be(data, i) shl 32) or u32be(data, i + 4)

    private fun u32le(data: ByteArray, i: Int): Long =
        b(data, i) or (b(data, i + 1) shl 8) or (b(data, i + 2) shl 16) or (b(data, i + 3) shl 24)

    private fun u16le(data: ByteArray, i: Int): Int = (b(data, i) or (b(data, i + 1) shl 8)).toInt()

    private fun fourcc(data: ByteArray, i: Int): String = String(data, i, 4, Charsets.ISO_8859_1)

    private fun be32(value: Long): ByteArray = byteArrayOf(
        (value shr 24).toByte(), (value shr 16).toByte(), (value shr 8).toByte(), value.toByte()
    )

    private fun le32(value: Long): ByteArray = byteArrayOf(
        value.toByte(), (value shr 8).toByte(), (value shr 16).toByte(), (value shr 24).toByte()
    )

    private fun le24(value: Int): ByteArray = byteArrayOf(value.toByte(), (value shr 8).toByte(), (value shr 16).toByte())
}
