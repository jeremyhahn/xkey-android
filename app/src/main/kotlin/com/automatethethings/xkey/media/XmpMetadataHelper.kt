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
import android.content.Context
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
        writeSignatureLocked(filePath, data)
    }

    /** [writeSignature] for a caller that already holds the lock of the media it writes. */
    private fun writeSignatureLocked(filePath: String, data: ContentAuthenticityData) {
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

    /** What [signMedia] did with a MediaStore item. */
    enum class MediaSignResult {
        /** The signature is in the media (or its sidecar). */
        Signed,

        /** Another app owns the media and the user has not granted xKey write access: nothing was written. */
        NeedsWriteAuthorization
    }

    /**
     * Sign the MediaStore item at [uri], whose file is [filePath] when
     * MediaStore names one: the auto-signer's one write. Media xKey owns is
     * written by path ([writeSignature]). Media another app owns, a camera
     * capture, is only ever written through its content URI once the user
     * granted access ([MediaPublisher.writeGranted]): without that grant this
     * returns [MediaSignResult.NeedsWriteAuthorization] and writes nothing,
     * and the caller queues a write request ([MediaWriteAuthorizations]).
     * With it the media is copied out, checked against [data]'s content hash
     * ([SourceChangedException] when it changed since it was signed),
     * signed and written back. A format that carries no in-band signature
     * takes a sidecar, a file of xKey's own beside the media, which needs no
     * grant.
     */
    fun signMedia(context: Context, uri: Uri, filePath: String?, data: ContentAuthenticityData): MediaSignResult {
        val access = MediaPublisher.writeAccess(context, uri)
        if (access == MediaPublisher.MediaWriteAccess.OWNED && filePath != null) {
            writeSignature(filePath, data)
            return MediaSignResult.Signed
        }
        // A provider that cannot type the item falls back to its file's suffix.
        val providerType = try {
            context.contentResolver.getType(uri)
        } catch (_: IllegalArgumentException) {
            null
        }
        val mimeType = providerType ?: filePath?.let(::getMimeType) ?: "application/octet-stream"
        if (!isJpeg(mimeType) && XmpContainers.formatOf(mimeType) == null) {
            val path = filePath ?: throw IOException("no file holds $uri, so its sidecar has nowhere to go")
            synchronized(lockFor(path)) { writeSidecarSignature(path, data) }
            return MediaSignResult.Signed
        }
        if (access == MediaPublisher.MediaWriteAccess.NEEDS_GRANT) return MediaSignResult.NeedsWriteAuthorization
        val lock = if (filePath != null) lockFor(filePath) else lockForKey(uri.toString())
        // The granted-write section puts back a write of this capture an
        // earlier process died in before it is staged.
        synchronized(lock) { MediaPublisher.grantedSection(context, uri) {
            val staged = File.createTempFile("sign-", stagingSuffix(mimeType), MediaPublisher.recoveryDirectory(context))
            var kept = false
            try {
                // The capture whole, location included: the signed bytes
                // written over it are made from this copy.
                MediaPublisher.openOriginal(context, uri).use { source -> staged.outputStream().use { source.copyTo(it) } }
                // What was staged, before the signature goes in: the granted
                // write refuses a capture that no longer matches it.
                val source = MediaPublisher.StagedSource.of(staged, mimeType, data.contentHash)
                writeSignatureLocked(staged.path, data)
                val sidecar = File(getSidecarPath(staged.path))
                if (sidecar.exists()) {
                    // The container refused the packet: the media stays as it
                    // is and the signature goes beside it.
                    val path = filePath ?: throw IOException("no file holds $uri, so its sidecar has nowhere to go")
                    MediaPublisher.replaceFile(File(getSidecarPath(path))) { temp -> sidecar.copyTo(temp, overwrite = true); true }
                    return MediaSignResult.Signed
                }
                MediaPublisher.writeGranted(context, uri, staged, source)
                return MediaSignResult.Signed
            } catch (e: MediaPublishException) {
                kept = true
                throw e
            } finally {
                File(getSidecarPath(staged.path)).delete()
                if (!kept) staged.delete()
            }
        } }
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
     *
     * Read as [contentResolver] serves it: for a MediaStore capture that is
     * the redacted view. App code reads source media through the Context
     * overload, which reads the original.
     */
    fun readSignatureFromUri(contentResolver: ContentResolver, uri: Uri, mimeType: String?): ContentAuthenticityData? =
        readSignature(uri, mimeType) { contentResolver.openInputStream(uri) }

    /**
     * The signature embedded in the original bytes at [uri]
     * ([MediaPublisher.openOriginal]), the ones its content hash covers.
     * Without location access a MediaStore capture throws
     * [MediaPublisher.OriginalUnavailableException]: unreadable is not unsigned.
     */
    fun readSignatureFromUri(context: Context, uri: Uri, mimeType: String?): ContentAuthenticityData? =
        readSignature(uri, mimeType) { MediaPublisher.openOriginal(context, uri) }

    private inline fun readSignature(uri: Uri, mimeType: String?, open: () -> InputStream?): ContentAuthenticityData? {
        val type = mimeType ?: ""
        if (type.startsWith("image/jpeg") || type.startsWith("image/jpg")) {
            try {
                open()?.use { inputStream ->
                    return readExifSignatureFromStream(inputStream)
                }
            } catch (e: MediaPublisher.OriginalUnavailableException) {
                throw e
            } catch (_: Exception) { }
            return null
        }
        val format = XmpContainers.formatOf(type) ?: return null
        // A failed open or read propagates: unreadable media is not unsigned media.
        val input = open() ?: throw IOException("cannot open $uri")
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
     * and WebP, first embed, co-sign and re-sign alike. Every write streams
     * ([XmpContainers.embedFile]), whatever the file's size: a file that
     * already carries our packet is first streamed to its stripped form
     * ([XmpContainers.stripPlan]), which then takes the new packet, so a
     * file the first embed signed can always be signed again. False when
     * the file cannot carry it, so the caller writes a sidecar instead. A
     * file that already carries an embedded signature it cannot rewrite
     * throws: a sidecar would be shadowed by the stale embedded one.
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
        // A failed read propagates (no catch): it has not shown the file
        // unsigned, and a sidecar beside a signed file would be shadowed.
        val refused: () -> Boolean = {
            // The readers' view: a file the writer refuses, such as one with
            // too many boxes to parse, may still read as signed.
            if (file.inputStream().use { XmpContainers.read(it.buffered(), format) } != null) {
                throw IOException("$filePath carries an embedded signature that cannot be rewritten")
            }
            false
        }
        return MediaPublisher.replaceFile(file) { temp ->
            val streamed = temp.outputStream().buffered().use { XmpContainers.embedFile(file, it, format, json) }
            when (streamed) {
                XmpContainers.FileEmbed.WRITTEN -> true
                XmpContainers.FileEmbed.REFUSED -> refused()
                XmpContainers.FileEmbed.CARRIES_XMP -> {
                    // The file without our packet, streamed beside the staging
                    // file (both this write's own under the path lock), then
                    // embedded as unsigned media is: what [XmpContainers.embed]
                    // returns for its bytes, without loading them.
                    val base = File(temp.path + ".base")
                    try {
                        val plan = java.io.RandomAccessFile(file, "r").use {
                            XmpContainers.stripPlan(FileByteSource(it), format)
                        } ?: return@replaceFile refused()
                        file.inputStream().buffered().use { input ->
                            base.outputStream().buffered().use { Pieces.write(plan, input, it) }
                        }
                        val written = temp.outputStream().buffered().use { XmpContainers.embedFile(base, it, format, json) }
                        written == XmpContainers.FileEmbed.WRITTEN || refused()
                    } finally {
                        base.delete()
                    }
                }
            }
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
