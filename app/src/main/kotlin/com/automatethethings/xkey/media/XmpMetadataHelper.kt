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
import androidx.exifinterface.media.ExifInterface
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

/**
 * Where a media file's signature lives:
 *
 * - JPEG: EXIF `UserComment`.
 * - MP4/MOV, PNG and WebP: an XMP box or chunk ([XmpContainers]), so the
 *   signature travels with the file.
 * - Anything else (HEIC, MKV, unknown), and an MP4/MOV, PNG or WebP that
 *   [XmpContainers.embed] refuses or that is larger than [maxEmbedBytes]: a
 *   `<name>.xkeysig` sidecar.
 *
 * Readers try the embedded form first and fall back to a sidecar, so a file
 * signed before embedding existed still reads. Writes to one path are
 * serialized, so overlapping signing jobs never interleave their updates.
 */
object XmpMetadataHelper {

    private const val XKEY_SIGNATURE_PREFIX = "XKEY_SIG:"

    /**
     * Largest MP4/MOV, PNG or WebP the writer embeds into: 128 MiB, or a
     * sixth of the heap when that is less. Embedding holds the file in memory
     * about three times over (the read, the stripped copy and the output), so
     * a larger file keeps a sidecar, which needs no read of the file at all.
     * Settable so tests can exercise the bound without a large fixture.
     */
    @Volatile
    var maxEmbedBytes: Int = minOf(128L * 1024 * 1024, Runtime.getRuntime().maxMemory() / 6).toInt()

    private val pathLocks = Array(64) { Any() }

    /** The lock serializing every write to [filePath]; a fixed set, so it never grows. */
    private fun lockFor(filePath: String): Any {
        val file = File(filePath)
        val key = try {
            file.canonicalPath
        } catch (_: IOException) {
            file.absolutePath
        }
        return pathLocks[Math.floorMod(key.hashCode(), pathLocks.size)]
    }

    fun writeSignature(filePath: String, data: ContentAuthenticityData): Unit = synchronized(lockFor(filePath)) {
        val mimeType = getMimeType(filePath)
        val format = XmpContainers.formatOf(mimeType)
        when {
            mimeType.startsWith("image/jpeg") || mimeType.startsWith("image/jpg") -> {
                writeExifSignature(filePath, data)
            }
            format != null && writeEmbeddedSignature(filePath, format, data) -> Unit
            else -> {
                writeSidecarSignature(filePath, data)
            }
        }
    }

    fun readSignature(filePath: String): ContentAuthenticityData? {
        val mimeType = getMimeType(filePath)
        val format = XmpContainers.formatOf(mimeType)
        return when {
            mimeType.startsWith("image/jpeg") || mimeType.startsWith("image/jpg") -> {
                readExifSignature(filePath) ?: readSidecarSignature(filePath)
            }
            format != null -> {
                readEmbeddedSignature(filePath, format) ?: readSidecarSignature(filePath)
            }
            else -> {
                readSidecarSignature(filePath)
            }
        }
    }

    /**
     * The signature embedded in the content at [uri], typed by [mimeType]:
     * EXIF for JPEG, the XMP box or chunk for MP4/MOV, PNG and WebP (read by
     * walking the container's headers, so a video is never loaded whole). A
     * URI has no sidecar beside it, so anything else reads as unsigned.
     */
    fun readSignatureFromUri(contentResolver: ContentResolver, uri: Uri, mimeType: String?): ContentAuthenticityData? {
        val type = mimeType ?: ""
        if (type.startsWith("image/jpeg") || type.startsWith("image/jpg")) {
            try {
                contentResolver.openInputStream(uri)?.use { inputStream ->
                    return readExifSignatureFromStream(inputStream)
                }
            } catch (_: Exception) { }
            return null
        }
        val format = XmpContainers.formatOf(type) ?: return null
        try {
            contentResolver.openInputStream(uri)?.use { inputStream ->
                return readEmbeddedSignatureFromStream(inputStream, format)
            }
        } catch (_: Exception) { }
        return null
    }

    /**
     * Adds [entry] to the file's signature, written back where it was read
     * from: an embedded signature stays embedded, and a legacy sidecar beside
     * an MP4/MOV, PNG or WebP stays a sidecar, so the media file is untouched.
     */
    fun appendSignature(filePath: String, entry: SignatureEntry): Unit = synchronized(lockFor(filePath)) {
        val format = XmpContainers.formatOf(getMimeType(filePath))
        // Not the swallowing reader: a failed read must not route the append to a sidecar.
        val embedded = format?.let { probeEmbeddedSignature(filePath, it) }
        val existing = embedded ?: readSignature(filePath)
            ?: throw IllegalStateException("No existing signature data found to append to")
        val updated = existing.copy(signatures = existing.signatures + entry)
        if (format != null && embedded == null) {
            writeSidecarSignature(filePath, updated)
        } else {
            writeSignature(filePath, updated)
        }
    }

    /**
     * Signs MP4/MOV, PNG or WebP the caller can only stream, such as a
     * shared content URI, in place: [open] is copied into a working file
     * under [workDir] (at most [maxEmbedBytes]), [data] is embedded there,
     * replacing any earlier signature, and the result is written to
     * [openOutput]. False, with nothing written, when the media cannot carry
     * an embedded signature and carries none, so a detached sidecar is what
     * verifies. Throws when it carries one that cannot be replaced, or a read
     * fails: a sidecar would then be shadowed by the old embedded signer.
     */
    fun replaceEmbeddedSignature(
        open: () -> InputStream,
        openOutput: () -> OutputStream,
        format: XmpContainers.Format,
        data: ContentAuthenticityData,
        workDir: File
    ): Boolean {
        val work = File.createTempFile(".xkey-sign.", ".xkeytmp", workDir)
        try {
            val whole = open().use { input -> work.outputStream().use { copyAtMost(input, it, maxEmbedBytes.toLong()) } }
            if (!whole) {
                val carried = open().use { XmpContainers.read(it.buffered(), format) }
                if (carried != null) {
                    throw IOException("media is larger than $maxEmbedBytes bytes and carries an embedded signature")
                }
                return false
            }
            val embedded = synchronized(lockFor(work.path)) { writeEmbeddedSignature(work.path, format, data) }
            if (!embedded) return false
            openOutput().use { output -> work.inputStream().use { it.copyTo(output) } }
            return true
        } finally {
            work.delete()
        }
    }

    /** Copies [input] to [output]; false as soon as it passes [limit] bytes. */
    private fun copyAtMost(input: InputStream, output: OutputStream, limit: Long): Boolean {
        val buffer = ByteArray(8192)
        var total = 0L
        while (true) {
            val n = input.read(buffer)
            if (n < 0) return true
            total += n
            if (total > limit) return false
            output.write(buffer, 0, n)
        }
    }

    fun getSidecarPath(filePath: String): String = "$filePath.xkeysig"

    private fun writeExifSignature(filePath: String, data: ContentAuthenticityData) {
        val exif = ExifInterface(filePath)
        exif.setAttribute(ExifInterface.TAG_USER_COMMENT, XKEY_SIGNATURE_PREFIX + data.toJsonString())
        exif.saveAttributes()
    }

    private fun readExifSignature(filePath: String): ContentAuthenticityData? {
        return try {
            val exif = ExifInterface(filePath)
            val comment = exif.getAttribute(ExifInterface.TAG_USER_COMMENT) ?: return null
            if (!comment.startsWith(XKEY_SIGNATURE_PREFIX)) return null
            ContentAuthenticityData.fromJsonString(comment.removePrefix(XKEY_SIGNATURE_PREFIX))
        } catch (_: Exception) {
            null
        }
    }

    private fun readExifSignatureFromStream(inputStream: InputStream): ContentAuthenticityData? {
        return try {
            val exif = ExifInterface(inputStream)
            val comment = exif.getAttribute(ExifInterface.TAG_USER_COMMENT) ?: return null
            if (!comment.startsWith(XKEY_SIGNATURE_PREFIX)) return null
            ContentAuthenticityData.fromJsonString(comment.removePrefix(XKEY_SIGNATURE_PREFIX))
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Embeds [data] in the file as XMP. False when the file cannot carry it
     * (see [XmpContainers.embed]) or is larger than [maxEmbedBytes], so the
     * caller writes a sidecar instead. A file that already carries an
     * embedded signature it cannot rewrite throws: a sidecar would be
     * shadowed by the stale embedded one.
     *
     * The new bytes go to a staging file beside the media, created
     * exclusively under a unique name for this write, and replace it by
     * rename, so a failed write never leaves half a video and no other write
     * shares or deletes it. Callers hold [lockFor] the path.
     */
    private fun writeEmbeddedSignature(
        filePath: String,
        format: XmpContainers.Format,
        data: ContentAuthenticityData
    ): Boolean {
        val file = File(filePath)
        // A failed read propagates (no catch): it has not shown the file
        // unsigned, and a sidecar beside a signed file would be shadowed.
        if (file.length() > maxEmbedBytes) {
            val carried = file.inputStream().use { XmpContainers.read(it.buffered(), format) }
            if (carried != null) {
                throw IOException("$filePath is larger than $maxEmbedBytes bytes and carries an embedded signature")
            }
            return false
        }
        val bytes = file.readBytes()
        val embedded = XmpContainers.embed(bytes, format, data.toJsonString())
        if (embedded == null) {
            // The readers' view: a file embed refuses, such as one with too
            // many boxes to parse, may still read as signed.
            if (XmpContainers.read(bytes.inputStream(), format) != null) {
                throw IOException("$filePath carries an embedded signature that cannot be rewritten")
            }
            return false
        }
        val temp = File.createTempFile(".${file.name}.", ".xkeytmp", file.absoluteFile.parentFile)
        try {
            temp.writeBytes(embedded)
            if (!temp.renameTo(file)) throw IOException("cannot replace $filePath")
        } finally {
            temp.delete()
        }
        return true
    }

/** The embedded signature, or null when the file carries none; an [IOException] reading it propagates. */
    private fun probeEmbeddedSignature(filePath: String, format: XmpContainers.Format): ContentAuthenticityData? {
        val json = File(filePath).inputStream().use { XmpContainers.read(it.buffered(), format) } ?: return null
        return try {
            ContentAuthenticityData.fromJsonString(json)
        } catch (_: Exception) {
            null
        }
    }

    private fun readEmbeddedSignature(filePath: String, format: XmpContainers.Format): ContentAuthenticityData? {
        return try {
            File(filePath).inputStream().use { readEmbeddedSignatureFromStream(it, format) }
        } catch (_: Exception) {
            null
        }
    }

    private fun readEmbeddedSignatureFromStream(
        inputStream: InputStream,
        format: XmpContainers.Format
    ): ContentAuthenticityData? {
        return try {
            XmpContainers.read(inputStream.buffered(), format)?.let(ContentAuthenticityData::fromJsonString)
        } catch (_: Exception) {
            null
        }
    }

    private fun writeSidecarSignature(filePath: String, data: ContentAuthenticityData) {
        File(getSidecarPath(filePath)).writeText(data.toJsonString())
    }

    private fun readSidecarSignature(filePath: String): ContentAuthenticityData? {
        return try {
            val sidecarFile = File(getSidecarPath(filePath))
            if (!sidecarFile.exists()) return null
            ContentAuthenticityData.fromJsonString(sidecarFile.readText())
        } catch (_: Exception) {
            null
        }
    }

    private fun getMimeType(filePath: String): String {
        val lower = filePath.lowercase()
        return when {
            lower.endsWith(".jpg") || lower.endsWith(".jpeg") -> "image/jpeg"
            lower.endsWith(".png") -> "image/png"
            lower.endsWith(".webp") -> "image/webp"
            lower.endsWith(".mp4") -> "video/mp4"
            lower.endsWith(".mkv") -> "video/x-matroska"
            lower.endsWith(".mov") -> "video/quicktime"
            else -> "application/octet-stream"
        }
    }
}
