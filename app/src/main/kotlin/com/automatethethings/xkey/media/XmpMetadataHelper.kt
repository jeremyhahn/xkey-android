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
 *   An unsigned file of any size is embedded streaming.
 * - Anything else (HEIC, MKV, unknown), and an MP4/MOV, PNG or WebP that
 *   cannot carry the packet (malformed, or foreign XMP): a `<name>.xkeysig`
 *   sidecar.
 *
 * Readers try the embedded form first and fall back to a sidecar, so a file
 * signed before embedding existed still reads. Writes to one path are
 * serialized, so overlapping signing jobs never interleave their updates.
 */
object XmpMetadataHelper {

    private const val XKEY_SIGNATURE_PREFIX = "XKEY_SIG:"

    /**
     * Largest MP4/MOV, PNG or WebP whose existing XMP packet the writer
     * replaces: 128 MiB, or a sixth of the heap when that is less. Replacing
     * holds the file in memory about three times over (the read, the
     * stripped copy and the output). A file with no packet yet is embedded
     * streaming at any size ([XmpContainers.embedFile]).
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
        return lockForKey(key)
    }

    /** The lock for a destination named by [identity], a canonical path or a URI. */
    private fun lockForKey(identity: String): Any = pathLocks[Math.floorMod(identity.hashCode(), pathLocks.size)]

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
        // A failed open or read propagates: unreadable media is not unsigned media.
        val input = contentResolver.openInputStream(uri) ?: throw IOException("cannot open $uri")
        return input.use { readEmbeddedSignatureFromStream(it, format) }
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

    /** How the Share-sheet signer signs MP4/MOV, PNG or WebP it can only stream. */
    enum class SharedSigning {
        /** A detached `.xkeysig`: the media is only read, so a read-only grant signs. */
        SIDECAR,

        /** The media carries an embedded signature, which a sidecar would not override: write a signed copy. */
        SIGNED_COPY
    }

    /**
     * Decides how a shared stream is signed, reading [open] only: never
     * opening it for writing keeps media shared with read access signable.
     * A read failure propagates: it has not shown the media unsigned.
     */
    fun sharedSigning(open: () -> InputStream, format: XmpContainers.Format?): SharedSigning {
        if (format == null) return SharedSigning.SIDECAR
        val carried = open().use { XmpContainers.read(it.buffered(), format) }
        return if (carried == null) SharedSigning.SIDECAR else SharedSigning.SIGNED_COPY
    }

    /**
     * Writes a signed copy of MP4/MOV, PNG or WebP the caller can only
     * stream, such as a shared content URI: [open] is copied into a working
     * file under [workDir] (any size; see [writeEmbeddedSignature]), [data] is embedded
     * there, replacing any earlier signature, and only the complete result
     * is copied to [openOutput], a document created for it, never [open]'s
     * own ([MediaPublisher.writeCopy]). Replacements naming one
     * [destination] (a URI or a canonical path) are serialized from the read
     * through the copy. Unless the write and the close both succeed, the
     * working file is kept and the thrown [MediaPublishException] names it.
     *
     * False, with nothing written, when the media cannot carry an embedded
     * signature and carries none, so a detached sidecar is what verifies.
     * Throws when it carries one that cannot be replaced, or a read fails:
     * a sidecar would then be shadowed by the old embedded signer.
     *
     * It does not check that [open] still holds what [data] signed: a
     * signed copy is written only through [writeSignedCopy], which does.
     */
    internal fun replaceEmbeddedSignature(
        open: () -> InputStream,
        openOutput: () -> OutputStream,
        format: XmpContainers.Format,
        data: ContentAuthenticityData,
        workDir: File,
        destination: String
    ): Boolean = signedCopy(open, openOutput, workDir, destination) { writeEmbeddedSignature(it, format, data) }

    /**
     * [replaceEmbeddedSignature] for any media that carries an embedded
     * signature, typed by [mimeType]: a JPEG gets its EXIF signature, MP4/MOV,
     * PNG and WebP their XMP. False, with nothing written, for any other type.
     *
     * The one signed-copy write. The bytes read from [open] are hashed as
     * the signer hashes them ([MediaHasher.hashStreamed]) before anything is
     * embedded or written: media edited or replaced since [data] was made
     * throws [SourceChangedException], with nothing written to [openOutput],
     * so a copy is never published under a signature that fails on it.
     */
    fun writeSignedCopy(
        open: () -> InputStream,
        openOutput: () -> OutputStream,
        mimeType: String,
        data: ContentAuthenticityData,
        workDir: File,
        destination: String
    ): Boolean {
        val format = XmpContainers.formatOf(mimeType)
        if (!isJpeg(mimeType) && format == null) return false
        return signedCopy(open, openOutput, workDir, destination) { path ->
            // The source is read again only now, maybe long after it was
            // signed: publish only bytes that are still what was signed.
            val payload = MediaHasher.hashStreamed({ File(path).inputStream() }, mimeType).canonical
            if (!payload.equals(data.contentHash, ignoreCase = true)) throw SourceChangedException()
            if (format == null) {
                writeExifSignature(path, data)
                true
            } else {
                writeEmbeddedSignature(path, format, data)
            }
        }
    }

    /** The media changed after it was signed: its signed copy would not verify, so none is written. */
    class SourceChangedException :
        IOException("the media changed after it was signed; sign it again to save a signed copy")

    private fun isJpeg(mimeType: String): Boolean {
        val type = mimeType.lowercase()
        return type.startsWith("image/jpeg") || type.startsWith("image/jpg")
    }

    private fun signedCopy(
        open: () -> InputStream,
        openOutput: () -> OutputStream,
        workDir: File,
        destination: String,
        embed: (String) -> Boolean
    ): Boolean = synchronized(lockForKey(destination)) {
        workDir.mkdirs()
        val work = File.createTempFile(".xkey-sign.", ".xkeytmp", workDir)
        var handed = false
        try {
            open().use { input -> work.outputStream().use { input.copyTo(it) } }
            // The working file is this call's own: no other write shares its lock.
            if (!embed(work.path)) return false
            // From here the working file is the publisher's: deleted once the
            // copy is written and closed, kept for recovery otherwise.
            handed = true
            MediaPublisher.writeCopy(work, openOutput)
            true
        } finally {
            if (!handed) work.delete()
        }
    }

    fun getSidecarPath(filePath: String): String = "$filePath.xkeysig"

    /**
     * The EXIF signature written into a copy of [filePath] that replaces it
     * atomically ([MediaPublisher.replaceFile]): `saveAttributes` rewrites a
     * file in place, so it never runs on the user's media itself.
     */
    private fun writeExifSignature(filePath: String, data: ContentAuthenticityData) {
        val file = File(filePath)
        MediaPublisher.replaceFile(file) { temp ->
            file.copyTo(temp, overwrite = true)
            val exif = ExifInterface(temp.path)
            exif.setAttribute(ExifInterface.TAG_USER_COMMENT, XKEY_SIGNATURE_PREFIX + data.toJsonString())
            exif.saveAttributes()
            true
        }
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
     * Embeds [data] in the file as XMP: the one embed path for MP4/MOV, PNG
     * and WebP. A file with no XMP packet is embedded streaming, whatever
     * its size ([XmpContainers.embedFile]); one that already carries a
     * packet is rewritten in memory up to [maxEmbedBytes]. False when the
     * file cannot carry it, so the caller writes a sidecar instead. A file
     * that already carries an embedded signature it cannot rewrite throws:
     * a sidecar would be shadowed by the stale embedded one.
     *
     * The new bytes replace the media atomically ([MediaPublisher.replaceFile]):
     * a failed write never leaves half a video, and no other write shares or
     * deletes its staging file. Callers hold [lockFor] the path.
     */
    private fun writeEmbeddedSignature(
        filePath: String,
        format: XmpContainers.Format,
        data: ContentAuthenticityData
    ): Boolean {
        val file = File(filePath)
        val json = data.toJsonString()
        return MediaPublisher.replaceFile(file) { temp ->
            // Media with no XMP packet, the common case, is embedded streaming
            // at any size: a camera video never falls back to a sidecar.
            val streamed = temp.outputStream().buffered().use { XmpContainers.embedFile(file, it, format, json) }
            val embedded: ByteArray? = when (streamed) {
                XmpContainers.FileEmbed.WRITTEN -> null
                XmpContainers.FileEmbed.REFUSED -> {
                    // The readers' view: a file the walk refuses, such as one with
                    // too many boxes to parse, may still read as signed.
                    if (file.inputStream().use { XmpContainers.read(it.buffered(), format) } != null) {
                        throw IOException("$filePath carries an embedded signature that cannot be rewritten")
                    }
                    return@replaceFile false
                }
                XmpContainers.FileEmbed.CARRIES_XMP -> {
                    // A failed read propagates (no catch): it has not shown the file
                    // unsigned, and a sidecar beside a signed file would be shadowed.
                    if (file.length() > maxEmbedBytes) {
                        val carried = file.inputStream().use { XmpContainers.read(it.buffered(), format) }
                        if (carried != null) {
                            throw IOException("$filePath is larger than $maxEmbedBytes bytes and carries an embedded signature")
                        }
                        return@replaceFile false
                    }
                    val bytes = file.readBytes()
                    XmpContainers.embed(bytes, format, json) ?: run {
                        // The readers' view: a file embed refuses, such as one with too
                        // many boxes to parse, may still read as signed.
                        if (XmpContainers.read(bytes.inputStream(), format) != null) {
                            throw IOException("$filePath carries an embedded signature that cannot be rewritten")
                        }
                        return@replaceFile false
                    }
                }
            }
            if (embedded != null) temp.writeBytes(embedded)
            true
        }
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

    /**
     * The embedded signature, or null when none is embedded or there is no
     * media file at [filePath]; an [IOException] reading media that is there
     * propagates.
     */
    private fun readEmbeddedSignature(filePath: String, format: XmpContainers.Format): ContentAuthenticityData? =
        if (File(filePath).exists()) probeEmbeddedSignature(filePath, format) else null

    /**
     * The signature embedded in [inputStream], or null when none is (or its
     * packet is not signature data). An [IOException] reading the container
     * propagates: media that cannot be read is not unsigned media.
     */
    private fun readEmbeddedSignatureFromStream(
        inputStream: InputStream,
        format: XmpContainers.Format
    ): ContentAuthenticityData? {
        val json = XmpContainers.read(inputStream.buffered(), format) ?: return null
        return try {
            ContentAuthenticityData.fromJsonString(json)
        } catch (_: Exception) {
            null
        }
    }

    /** The sidecar beside [filePath], replaced atomically ([MediaPublisher.replaceFile]). */
    private fun writeSidecarSignature(filePath: String, data: ContentAuthenticityData) {
        MediaPublisher.replaceFile(File(getSidecarPath(filePath))) { temp -> temp.writeText(data.toJsonString()); true }
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

    /**
     * The media types whose signature lives inside the file: JPEG in EXIF,
     * MP4/MOV, PNG and WebP in XMP. Co-signing writes the co-signature back
     * into the file it picked, so its picker offers exactly these; every one
     * maps to its own container through [stagingSuffix].
     */
    val EMBEDDED_MIME_TYPES: List<String> = listOf(
        "image/jpeg", "image/png", "image/webp", "video/mp4", "video/quicktime"
    )

    /**
     * The file suffix a working copy of content typed [mimeType] needs, so
     * the path-based readers and writers ([readSignature], [appendSignature])
     * pick the same EXIF or XMP container [readSignatureFromUri] read: the
     * inverse of the suffix-to-type map they use.
     */
    fun stagingSuffix(mimeType: String?): String {
        val type = mimeType.orEmpty().substringBefore(';').trim().lowercase()
        if (type.startsWith("image/jpeg") || type.startsWith("image/jpg")) return ".jpg"
        return when (XmpContainers.formatOf(type)) {
            XmpContainers.Format.PNG -> ".png"
            XmpContainers.Format.WEBP -> ".webp"
            XmpContainers.Format.ISO_BMFF -> if (type == "video/quicktime") ".mov" else ".mp4"
            null -> if (type == "video/x-matroska") ".mkv" else ".bin"
        }
    }
}
