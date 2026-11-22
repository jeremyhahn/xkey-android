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
import android.os.CancellationSignal
import android.provider.DocumentsContract
import android.provider.MediaStore
import androidx.exifinterface.media.ExifInterface
import kotlinx.coroutines.Dispatchers
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
     * Memory bound of the in-memory JPEG embed, which holds the image and
     * its rewrite: 128 MiB, or a sixth of the heap when that is less
     * ([MediaJobGate.forSigning] budgets each signing job by it). It bounds
     * nothing else: an MP4/MOV, PNG or WebP is embedded streaming at any
     * size, a packet it already carries stripped and replaced while
     * streaming ([XmpContainers.embedFile]).
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

    /**
     * [writeSignature] for a caller that already holds the lock of the media
     * it writes. Returns the sidecar it wrote ([authoritativeSidecar]'s
     * choice), or null when the signature went into the media itself.
     */
    private fun writeSignatureLocked(filePath: String, data: ContentAuthenticityData): File? {
        val mimeType = getMimeType(filePath)
        val format = XmpContainers.formatOf(mimeType)
        return when {
            mimeType.startsWith("image/jpeg") || mimeType.startsWith("image/jpg") -> {
                writeExifSignature(filePath, data)
                null
            }
            format != null && writeEmbeddedSignature(filePath, format, data) -> null
            else -> writeSidecarSignature(filePath, data)
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
     * signed and written back. A format that carries no in-band signature,
     * or a container that refuses the packet, takes a sidecar: for media
     * another app owns a file xKey owns ([writeOwnedSidecar]), never one
     * beside the capture, which the grant does not cover.
     *
     * Every branch checks that the media still has [data]'s content hash
     * before it publishes anything ([requireCurrent], or the staged snapshot
     * on the granted path): a signature kept on the retry queue across an
     * edit throws [SourceChangedException] and is never published.
     */
    fun signMedia(context: Context, uri: Uri, filePath: String?, data: ContentAuthenticityData): MediaSignResult {
        val access = MediaPublisher.writeAccess(context, uri)
        if (access == MediaPublisher.MediaWriteAccess.OWNED && filePath != null) {
            synchronized(lockFor(filePath)) {
                requireCurrent(context, uri, filePath, getMimeType(filePath), data)
                writeSignatureLocked(filePath, data)
            }
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
            // Not xKey's file: its sidecar is one xKey owns, never a file beside it.
            val lock = if (filePath != null) lockFor(filePath) else lockForKey(uri.toString())
            synchronized(lock) {
                requireCurrent(context, uri, null, mimeType, data)
                writeOwnedSidecar(context, uri, filePath, data)
            }
            return MediaSignResult.Signed
        }
        if (access == MediaPublisher.MediaWriteAccess.NEEDS_GRANT) return MediaSignResult.NeedsWriteAuthorization
        val lock = if (filePath != null) lockFor(filePath) else lockForKey(uri.toString())
        synchronized(lock) {
            // A write of this capture an earlier process died in is put back
            // before it is staged; one that cannot be yet stages nothing.
            MediaPublisher.recoverInterruptedWrite(context, uri)
            val staged = MediaSaveRuns.work(MediaPublisher.recoveryDirectory(context), stagingSuffix(mimeType))
            var kept = false
            // The staged copy's sidecar, as the writer chose it: never a
            // second guess at where it went.
            var stagedSidecar: File? = null
            try {
                // The capture whole, location included: the signed bytes
                // written over it are made from this copy. It is read before
                // the publication lock is taken: a provider that stalls holds
                // this capture's signing alone, never another's publication.
                MediaPublisher.openOriginal(context, uri).use { source -> staged.outputStream().use { source.copyTo(it) } }
                MediaPublisher.grantedSection(context, uri) {
                    // What was staged, before the signature goes in: the granted
                    // write refuses a capture that no longer matches it.
                    val source = MediaPublisher.StagedSource.of(staged, mimeType, data.contentHash)
                    stagedSidecar = writeSignatureLocked(staged.path, data)
                    if (stagedSidecar != null) {
                        // The container refused the packet: the media stays as it
                        // is and the signature goes to a sidecar xKey owns: the
                        // grant covers the capture alone, never a file beside it.
                        writeOwnedSidecar(context, uri, filePath, data)
                        return MediaSignResult.Signed
                    }
                    MediaPublisher.writeGranted(context, uri, staged, source)
                    return MediaSignResult.Signed
                }
            } catch (e: MediaPublishException) {
                kept = true
                throw e
            } finally {
                stagedSidecar?.delete()
                if (!kept) staged.delete()
            }
        }
    }

    /**
     * The one check before [signMedia] publishes: the media still has
     * [data]'s content hash. Media xKey writes by path ([ownedPath]) is
     * hashed as it is written; any other is hashed from its original, as
     * the signer hashed it ([AutoSignHash.contentHashOriginal]). The granted
     * embedded branch makes the same comparison over its staged snapshot
     * ([MediaPublisher.StagedSource.of], which [MediaPublisher.writeGranted]
     * checks again), so it does not hash twice. A signature made before an
     * edit, kept on the retry queue, throws [SourceChangedException] and is
     * refused, never published.
     */
    private fun requireCurrent(context: Context, uri: Uri, ownedPath: String?, mimeType: String, data: ContentAuthenticityData) {
        val current = if (ownedPath != null) {
            AutoSignHash.contentHashFile(File(ownedPath), mimeType)
        } else {
            AutoSignHash.contentHashOriginal(context, uri)
        }
        if (!current.equals(data.contentHash, ignoreCase = true)) throw SourceChangedException()
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
     * It blocks for the whole copy of the original, its provider open
     * passed [cancel]: a screen reads through [readOriginalSignature] instead.
     */
    fun readSignatureFromUri(
        context: Context,
        uri: Uri,
        mimeType: String?,
        cancel: CancellationSignal? = null
    ): ContentAuthenticityData? =
        readSignature(uri, mimeType) { MediaPublisher.openOriginal(context, uri, cancel) }

    /**
     * [readSignatureFromUri] as a screen reads it, inside
     * [MediaPublisher.readCancellable]: cancelling the caller cancels the
     * provider's open of the original through its signal and interrupts the
     * copy, which deletes its snapshot, so leaving or recreating the screen
     * never leaves a read running, on either side of the provider.
     */
    suspend fun readOriginalSignature(context: Context, uri: Uri, mimeType: String?): ContentAuthenticityData? =
        MediaPublisher.readCancellable(Dispatchers.IO) { signal -> readSignatureFromUri(context, uri, mimeType, signal) }

    /**
     * [readSignatureFromUri] over [snapshot], a private copy of the media
     * read once ([MediaHasher.withSnapshot]), typed [mimeType]: the signature
     * is read from the bytes that are hashed.
     */
    internal fun readSignatureFromSnapshot(snapshot: File, mimeType: String?): ContentAuthenticityData? =
        readSignature(snapshot, mimeType) { snapshot.inputStream() }

    private inline fun readSignature(uri: Any, mimeType: String?, open: () -> InputStream?): ContentAuthenticityData? {
        val type = mimeType ?: ""
        val jpeg = type.startsWith("image/jpeg") || type.startsWith("image/jpg")
        val format = if (jpeg) null else XmpContainers.formatOf(type) ?: return null
        // A failed open propagates for every type, a JPEG included:
        // unreadable media is not unsigned media. Only a JPEG whose bytes
        // carry no readable signature reads as unsigned.
        val input = open() ?: throw IOException("cannot open $uri")
        return input.use { if (format == null) readExifSignatureFromStream(it) else readEmbeddedSignatureFromStream(it, format) }
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
     * the signer hashes them ([MediaHasher.hashStreamedFile], over the working copy) before anything is
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
            val payload = MediaHasher.hashStreamedFile(File(path), mimeType).canonical
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
        // A save's working file: one a process death leaves, the next start reclaims.
        val work = MediaSaveRuns.work(workDir, ".xkeytmp")
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

    fun getSidecarPath(filePath: String): String = "$filePath$SIDECAR_SUFFIX"

    private const val SIDECAR_SUFFIX = ".xkeysig"

    /** Where xKey keeps the sidecars of media other apps own (MediaStore RELATIVE_PATH, no trailing slash). */
    private const val OWNED_SIDECAR_ROOT = "Documents/xKey"

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

    /**
     * The one authoritative sidecar of the media at [filePath] (or at [uri]
     * when no file is named). Every sidecar read and every sidecar write
     * derives its file from here, with one precedence:
     * 1. the file xKey owns for it ([ownedSidecarLocation]) when it exists:
     *    the writer for media another app owns ([writeOwnedSidecar]) only
     *    ever writes there, so when it exists it is the newer one. It is
     *    named for the file, or for [uri] when the writer had no file; when
     *    both exist, the one written last;
     * 2. else the legacy sidecar beside [filePath] when it exists, so a
     *    capture signed before the owned location still reads and an append
     *    to xKey's own media stays in it;
     * 3. else where a new write by path goes: beside [filePath] (xKey's own
     *    media, or media another app owns before Android 10), else the owned
     *    one named for [uri]. Media another app owns takes its first sidecar
     *    through [writeOwnedSidecar], at the owned location, and from then on
     *    reads and appends find it at step 1.
     * Null only when no file is named and there is no shared storage root.
     */
    private fun authoritativeSidecar(filePath: String?, uri: Uri?): File? {
        val owned = listOfNotNull(
            filePath?.let { ownedSidecarFile(it, uri) },
            uri?.let { ownedSidecarFile(null, it) }
        ).distinct().filter { it.isFile }
        owned.maxByOrNull { it.lastModified() }?.let { return it }
        val beside = filePath?.let { File(getSidecarPath(it)) }
        if (beside != null && beside.exists()) return beside
        return beside ?: uri?.let { ownedSidecarFile(null, it) }
    }

    /**
     * The sidecar signature of the media at [uri], read where the signer
     * wrote it: the viewer's one sidecar lookup. A file, or a MediaStore
     * item with the file MediaStore names for it, reads the one
     * [authoritativeSidecar] picks: the file xKey owns for it under
     * `Documents/xKey/` ([ownedSidecarLocation]) when it exists, else the
     * legacy one beside the file. A MediaStore item with no file reads the
     * owned one named for the URI. Every spelling of a MediaStore item, its
     * media document URI included, reads as the item itself
     * ([MediaPublisher.canonicalMediaUri]), as the writer names it; another
     * document reads the one beside it in its tree. Null when there is none
     * or it cannot be read.
     */
    fun readSidecar(context: Context, uri: Uri): ContentAuthenticityData? = try {
        val item = MediaPublisher.canonicalMediaUri(uri)
        when {
            uri.scheme == ContentResolver.SCHEME_FILE -> uri.path?.let(::readSidecarSignature)
            item.authority == MediaStore.AUTHORITY -> readSidecarFile(authoritativeSidecar(mediaFilePath(context, item), item))
            DocumentsContract.isDocumentUri(context, uri) -> {
                val sidecar = DocumentsContract.buildDocumentUriUsingTree(
                    uri, DocumentsContract.getDocumentId(uri) + SIDECAR_SUFFIX
                )
                context.contentResolver.openInputStream(sidecar)?.use { ContentAuthenticityData.fromJsonStream(it) }
            }
            else -> readSidecarFile(authoritativeSidecar(mediaFilePath(context, uri), uri))
        }
    } catch (_: Exception) {
        null
    }

    /** The file MediaStore names for [uri] (`_data`), or null when it names none. */
    private fun mediaFilePath(context: Context, uri: Uri): String? = try {
        @Suppress("DEPRECATION")
        val column = MediaStore.MediaColumns.DATA
        context.contentResolver.query(uri, arrayOf(column), null, null, null)?.use { cursor ->
            if (cursor.moveToFirst() && !cursor.isNull(0)) cursor.getString(0) else null
        }
    } catch (_: Exception) {
        null
    }

    /** Write [data] to the sidecar of [filePath] ([authoritativeSidecar]), replaced atomically ([MediaPublisher.replaceFile]). */
    private fun writeSidecarSignature(filePath: String, data: ContentAuthenticityData): File {
        val sidecar = checkNotNull(authoritativeSidecar(filePath, null)) { "a named file always has a sidecar" }
        MediaPublisher.replaceFile(sidecar) { temp -> temp.writeText(data.toJsonString()); true }
        return sidecar
    }

    /**
     * Where the sidecar of [filePath] (or of [uri] when no file is named)
     * goes when the media is not xKey's own: the one sidecar identity, which
     * the writer ([writeOwnedSidecar]) publishes to and [authoritativeSidecar],
     * which every read and every later write asks, prefers over the legacy
     * sidecar beside the media when it exists. A file xKey owns under
     * `Documents/xKey/`, at the media's own directory (under `volumes/` with
     * its full path when it is not on primary storage, so captures sharing a
     * name in different directories or volumes never share a sidecar), named
     * `<media name>.xkeysig`; with no file, named for the item's one media
     * identity ([MediaPublisher.canonicalMediaUri]), so every spelling of it
     * names the same sidecar. The relative path ends in a slash.
     */
    internal fun ownedSidecarLocation(filePath: String?, uri: Uri?): Pair<String, String> {
        val item = uri?.let { MediaPublisher.canonicalMediaUri(it).lastPathSegment }
        val name = (filePath?.let { File(it).name } ?: item ?: "media") + SIDECAR_SUFFIX
        return ownedSidecarDirectory(filePath) to name
    }

    /** The MediaStore relative path, ending in a slash, of the owned sidecar of [filePath]. */
    private fun ownedSidecarDirectory(filePath: String?): String {
        val parent = filePath?.let { File(it).absoluteFile.parentFile } ?: return "$OWNED_SIDECAR_ROOT/"
        val directory = canonical(parent)
        val primary = externalRoot()?.let { root ->
            directory.relativeToOrNull(canonical(root))?.invariantSeparatorsPath?.takeIf { !it.startsWith("..") }
        }
        if (primary != null) return if (primary.isEmpty()) "$OWNED_SIDECAR_ROOT/" else "$OWNED_SIDECAR_ROOT/$primary/"
        // Not on primary storage: the full path, so the volume and directory stay part of it.
        val path = directory.invariantSeparatorsPath.trim('/')
        return if (path.isEmpty()) "$OWNED_SIDECAR_ROOT/$OTHER_VOLUMES/" else "$OWNED_SIDECAR_ROOT/$OTHER_VOLUMES/$path/"
    }

    private fun canonical(file: File): File = try {
        file.canonicalFile
    } catch (_: IOException) {
        file.absoluteFile
    }

    /** The directory under `Documents/xKey/` holding owned sidecars of media off primary storage. */
    private const val OTHER_VOLUMES = "volumes"

    /** The shared storage root MediaStore relative paths start from, or null where there is none. */
    private fun externalRoot(): File? = try {
        @Suppress("DEPRECATION")
        android.os.Environment.getExternalStorageDirectory()
    } catch (_: RuntimeException) {
        null
    }

    /** The file [ownedSidecarLocation] names, read by path; null where there is no shared storage root. */
    private fun ownedSidecarFile(filePath: String?, uri: Uri?): File? {
        val root = externalRoot() ?: return null
        val (relativePath, name) = ownedSidecarLocation(filePath, uri)
        return File(File(root, relativePath), name)
    }

    /**
     * Write [data] as the sidecar of media another app owns at [uri]: the
     * one sidecar write on the granted path. A write grant covers the capture
     * alone, and scoped storage refuses a file created beside it, so the
     * sidecar is a file xKey owns ([MediaPublisher.MediaStoreAccess.ownedFile],
     * at [ownedSidecarLocation]). Before Android 10, which has no scoped
     * storage, it goes beside [filePath] as before.
     */
    private fun writeOwnedSidecar(context: Context, uri: Uri, filePath: String?, data: ContentAuthenticityData) {
        val (relativePath, name) = ownedSidecarLocation(filePath, uri)
        val target = MediaPublisher.mediaStore.ownedFile(context, relativePath, name)
        if (target == null) {
            val path = filePath ?: throw IOException("no file holds $uri, so its sidecar has nowhere to go")
            writeSidecarSignature(path, data)
            return
        }
        MediaPublisher.writeOwned(context, target.uri, data.toJsonString().toByteArray(Charsets.UTF_8), target.created)
    }

    // The sidecar xKey owns for the media when it exists, else the legacy one beside it ([authoritativeSidecar]).
    private fun readSidecarSignature(filePath: String): ContentAuthenticityData? =
        readSidecarFile(authoritativeSidecar(filePath, null))

    private fun readSidecarFile(sidecarFile: File?): ContentAuthenticityData? {
        return try {
            if (sidecarFile == null || !sidecarFile.exists()) return null
            sidecarFile.inputStream().use { ContentAuthenticityData.fromJsonStream(it) }
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
