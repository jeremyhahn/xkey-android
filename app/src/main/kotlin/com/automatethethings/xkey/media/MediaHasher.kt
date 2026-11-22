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
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream
import java.io.RandomAccessFile
import java.io.OutputStream
import java.security.DigestInputStream
import java.security.MessageDigest

object MediaHasher {

    private const val BUFFER_SIZE = 8192

    fun hashStream(inputStream: InputStream): String {
        val digest = MessageDigest.getInstance("SHA-256")
        DigestInputStream(inputStream, digest).use { dis ->
            val buffer = ByteArray(BUFFER_SIZE)
            while (dis.read(buffer) != -1) { /* consume */ }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    /**
     * [hashCanonical] over the content at [uri], hashed streaming
     * ([hashStreamed]) so media of any size is signed. The mime type comes
     * from the resolver, so a JPEG is recognised whether it arrived as a file
     * or a document URI. It reads the original bytes, as the capture signer
     * does ([MediaPublisher.openOriginal]): without location access a
     * MediaStore item throws [MediaPublisher.OriginalUnavailableException].
     * The provider's open is passed [cancel]: a screen hashes inside
     * [MediaPublisher.readCancellable] and passes its signal.
     */
    fun hashCanonicalUri(context: Context, uri: Uri, cancel: CancellationSignal? = null): String =
        hashStreamedUri(context, uri, cancel).canonical

    fun hashUri(contentResolver: ContentResolver, uri: Uri): String {
        val inputStream = contentResolver.openInputStream(uri)
            ?: throw IllegalArgumentException("Cannot open URI: $uri")
        return inputStream.use { hashStream(it) }
    }

    fun hashBytes(data: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(data).joinToString("") { "%02x".format(it) }
    }

    /**
     * Hash of [data]'s content, excluding any metadata that signing itself
     * writes. **Signing and verification must both use this.**
     *
     * Signing hashes the file and then embeds the signature into it, so a hash
     * over the whole file cannot survive its own signature: the verifier
     * re-hashes a file that no longer matches what was signed, and every
     * in-band-signed image fails. Rewriting the metadata back out is not a way
     * round it either — `ExifInterface.saveAttributes` reserialises the file and
     * is not byte-stable.
     *
     * The domain is therefore chosen to be metadata-independent by construction:
     * for JPEG, every `APPn` and `COM` segment is skipped and the remaining
     * structure plus the entropy-coded scan is hashed. For MP4/MOV, PNG and
     * WebP, exactly the XMP box or chunk [XmpContainers.embed] writes is left
     * out ([XmpContainers.strip]), so the hash is the file's own as it was
     * before signing; an unsigned file is hashed whole. Anything else is
     * hashed whole, which is already stable because its signature lives in a
     * sidecar.
     */
    fun hashCanonical(data: ByteArray, mimeType: String?): String =
        hashBytes(canonicalContent(data, mimeType))

    fun canonicalContent(data: ByteArray, mimeType: String?): ByteArray =
        canonicalPlan(ArrayByteSource(data), mimeType)?.let { Pieces.bytes(it, data) } ?: data

    /**
     * The one place the canonical domain is decided, for bytes in memory and
     * streamed media alike: the pieces of [source] the canonical hash covers,
     * or null when it covers the media whole. Every format plans through
     * [MediaPlan.Builder], so media that would need more than
     * [MediaPlan.MAX_PIECES] pieces throws [MediaTooFragmentedException].
     */
    private fun canonicalPlan(source: ByteSource, mimeType: String?): MediaPlan? {
        if (isCanonicalisedJpeg(mimeType)) return jpegPlan(source)
        val format = XmpContainers.formatOf(mimeType) ?: return null
        return XmpContainers.stripPlan(source, format)
    }

    /** The whole-file and canonical SHA-256 of streamed media. */
    class StreamedHashes(val whole: String, val canonical: String)

    /**
     * [hashCanonical] and [hashBytes] of the media [open] streams, without
     * holding it in memory: a video of any size is hashed. The media is read
     * once ([withSnapshot]): that one read hashes the whole file and copies it
     * into a private snapshot under [workDir], and every canonical pass
     * ([hashStreamedFile]) reads that snapshot, so media that changes while
     * it is hashed is hashed as the one read saw it, never as a mix of two
     * versions. [open] is called exactly once; an [java.io.IOException]
     * propagates.
     */
    fun hashStreamed(open: () -> InputStream, mimeType: String?, workDir: File): StreamedHashes =
        withSnapshot(open, workDir) { snapshot, whole -> canonicalOf(snapshot, mimeType, whole) }

    /**
     * [hashStreamed] over [file], a private copy the caller owns and nothing
     * else writes: every pass reads it, with no further copy.
     */
    internal fun hashStreamedFile(file: File, mimeType: String?): StreamedHashes =
        canonicalOf(file, mimeType, file.inputStream().use { hashStream(it) })

    /**
     * The one read of mutable media: [open] is called once, its bytes are
     * hashed whole and copied, with one constant-size buffer, into a private
     * snapshot under [workDir] ([MediaSaveRuns.work], so a process death
     * leaves a file the sweep reclaims), and [use] gets that snapshot and
     * the whole-file hash. Every check and hash of one decision reads the
     * snapshot, never the media again. The snapshot is deleted after [use].
     */
    internal fun <T> withSnapshot(open: () -> InputStream, workDir: File, use: (File, String) -> T): T {
        val snapshot = MediaSaveRuns.work(workDir, ".hash")
        try {
            val digest = MessageDigest.getInstance("SHA-256")
            open().use { input ->
                FileOutputStream(snapshot).use { output ->
                    val buffer = ByteArray(64 * 1024)
                    while (true) {
                        val n = input.read(buffer)
                        if (n < 0) break
                        digest.update(buffer, 0, n)
                        output.write(buffer, 0, n)
                    }
                }
            }
            return use(snapshot, hex(digest.digest()))
        } finally {
            snapshot.delete()
        }
    }

    /**
     * The canonical passes over [file], whose whole-file hash is [whole]: one
     * walks only the headers ([canonicalPlan]) and one hashes the pieces it
     * keeps, both over the same private file.
     */
    private fun canonicalOf(file: File, mimeType: String?, whole: String): StreamedHashes {
        val plan = RandomAccessFile(file, "r").use { canonicalPlan(FileByteSource(it), mimeType) }
            ?: return StreamedHashes(whole, whole)
        val canonical = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            Pieces.write(plan, input, object : OutputStream() {
                override fun write(b: Int) = canonical.update(b.toByte())
                override fun write(b: ByteArray, off: Int, len: Int) = canonical.update(b, off, len)
            })
        }
        return StreamedHashes(whole, hex(canonical.digest()))
    }

    private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

    /**
     * [hashStreamed] over the original bytes at [uri], typed by the resolver:
     * the one read every verification and co-signing hash shares with the
     * signer ([MediaPublisher.openOriginal]), never MediaStore's redacted view.
     */
    private fun hashStreamedUri(context: Context, uri: Uri, cancel: CancellationSignal? = null): StreamedHashes {
        if (MediaPublisher.originalUri(context, uri) == null) throw MediaPublisher.OriginalUnavailableException(uri)
        return hashStreamed(
            { MediaPublisher.openOriginal(context, uri, cancel) },
            context.contentResolver.getType(uri),
            MediaPublisher.recoveryDirectory(context)
        )
    }

    /** A signature embedded in media and the check of its content hash, both from one read. */
    class InBandCheck(val data: ContentAuthenticityData, val check: ContentHashCheck)

    /**
     * The signature embedded in the original bytes at [uri], typed
     * [mimeType], and the check of its content hash, both read from one
     * snapshot of the original ([withSnapshot]): the signature checked is the
     * one in the bytes hashed. Null when the media carries none, and without
     * a read for a type that carries no in-band signature. Without location
     * access it throws [MediaPublisher.OriginalUnavailableException]. The
     * provider's open is passed [cancel]: a screen checks inside
     * [MediaPublisher.readCancellable] and passes its signal.
     */
    fun checkInBandUri(context: Context, uri: Uri, mimeType: String?, cancel: CancellationSignal? = null): InBandCheck? {
        val type = mimeType ?: ""
        val jpeg = type.startsWith("image/jpeg") || type.startsWith("image/jpg")
        if (!jpeg && XmpContainers.formatOf(type) == null) return null
        if (MediaPublisher.originalUri(context, uri) == null) throw MediaPublisher.OriginalUnavailableException(uri)
        return withSnapshot({ MediaPublisher.openOriginal(context, uri, cancel) }, MediaPublisher.recoveryDirectory(context)) { snapshot, whole ->
            val data = XmpMetadataHelper.readSignatureFromSnapshot(snapshot, mimeType) ?: return@withSnapshot null
            InBandCheck(data, contentHashCheck(canonicalOf(snapshot, mimeType, whole), data.contentHash, SignatureSource.IN_BAND))
        }
    }

    /**
     * Whether [hashCanonical] strips JPEG metadata for [mimeType]. Otherwise it
     * hashes the file whole, less only an embedded xKey XMP box or chunk.
     */
    fun isCanonicalisedJpeg(mimeType: String?): Boolean {
        val type = mimeType.orEmpty().lowercase()
        return type.startsWith("image/jpeg") || type.startsWith("image/jpg")
    }

    /** Where a signature was read from, which decides the hashes it may cover. */
    enum class SignatureSource {
        /** Embedded in the file itself (EXIF/XMP). */
        IN_BAND,

        /** A `.xkeysig` file beside the media. */
        SIDECAR
    }

    /**
     * Whether a signature's stored `contentHash` vouches for [data]. **Both
     * verify screens must use this**, so the rule cannot drift between them.
     *
     * The canonical hash ([hashCanonical]) always matches. A sidecar may also
     * carry the SHA-256 of the whole file: that is the documented `.xkeysig`
     * format ("Hex-encoded SHA-256 of the original file content"), and a
     * sidecar never changes the file it signs, so the whole-file hash is as
     * stable as the canonical one. An in-band signature never accepts it:
     * embedding the signature changes the file, so an in-band signature can
     * never cover the file's own whole-file hash, and accepting one would only
     * widen what verifies.
     *
     * This checks the content hash only. The caller still verifies the
     * signature over the stored hash.
     */
    fun contentHashMatches(
        storedContentHash: String,
        data: ByteArray,
        mimeType: String?,
        source: SignatureSource
    ): Boolean {
        if (storedContentHash == hashCanonical(data, mimeType)) return true
        return source == SignatureSource.SIDECAR && storedContentHash == hashBytes(data)
    }

    /** What [checkContentHashUri] found. */
    enum class ContentHashCheck {
        /** The stored hash covers the media. */
        MATCHES,

        /** The media is not what the stored hash covers: changed, or another file's signature. */
        MISMATCH,

        /**
         * Only MediaStore's redacted view is readable (no location access):
         * the original the signature covers cannot be read, which says
         * nothing about tampering.
         */
        ACCESS_UNAVAILABLE
    }

    /** Shown where a verification or co-signing check met [ContentHashCheck.ACCESS_UNAVAILABLE]. */
    const val ACCESS_UNAVAILABLE_MESSAGE =
        "Media access unavailable: allow xKey to access photo and video locations to read the original"

    /**
     * [contentHashMatches] over the original bytes at [uri] ([hashStreamedUri]),
     * typed by the resolver and hashed streaming, so a video larger than the
     * heap verifies. **Both verify screens use this**, inside
     * [MediaPublisher.readCancellable], passing its signal as [cancel].
     */
    fun checkContentHashUri(
        context: Context,
        uri: Uri,
        storedContentHash: String,
        source: SignatureSource,
        cancel: CancellationSignal? = null
    ): ContentHashCheck {
        val hashes = try {
            hashStreamedUri(context, uri, cancel)
        } catch (_: MediaPublisher.OriginalUnavailableException) {
            return ContentHashCheck.ACCESS_UNAVAILABLE
        }
        return contentHashCheck(hashes, storedContentHash, source)
    }

    /** Whether [storedContentHash] is the hash [hashes] give for a signature read from [source]. */
    private fun contentHashCheck(hashes: StreamedHashes, storedContentHash: String, source: SignatureSource): ContentHashCheck {
        if (storedContentHash == hashes.canonical) return ContentHashCheck.MATCHES
        if (source == SignatureSource.SIDECAR && storedContentHash == hashes.whole) return ContentHashCheck.MATCHES
        return ContentHashCheck.MISMATCH
    }

    /**
     * The JPEG [source] holds without its `APPn` (0xE0-0xEF) and `COM` (0xFE)
     * segments, as a plan: SOI, the quantisation/frame/Huffman tables, the scan
     * header and all entropy-coded data. Null, the file hashed unchanged, if it
     * is not a JPEG or is malformed — a hash over slightly more than intended is safe, whereas
     * throwing here would break signing on an unexpected encoder.
     *
     * A marker may be preceded by any number of `0xFF` fill bytes (ITU T.81
     * B.1.1.2). They are skipped and left out of the output: they carry no
     * image data, and a writer may add or drop them when it rewrites the
     * metadata (`ExifInterface.saveAttributes` reserialises every segment), so
     * keeping them would let a metadata-only edit change the hash. Without the
     * skip, a fill byte also reads as a marker with a bogus length and the whole
     * file falls back to being hashed raw. A file without fill bytes gives the
     * same output as before.
     *
     * Adjacent kept segments coalesce into one piece, so a run of standalone
     * markers costs nothing; a file whose kept segments are split apart more
     * than [MediaPlan.MAX_PIECES] times throws [MediaTooFragmentedException].
     */
    private fun jpegPlan(source: ByteSource): MediaPlan? {
        val n = source.length
        fun byteAt(index: Long): Int = source.readAt(index, 1)[0].toInt() and 0xFF
        if (n < 4 || byteAt(0) != 0xFF || byteAt(1) != 0xD8) return null

        val plan = MediaPlan.Builder().range(0, 2) // SOI
        var i = 2L

        while (i + 1 < n) {
            if (byteAt(i) != 0xFF) return null // not marker-aligned; bail out safely
            // Fill bytes: advance to the last 0xFF before the marker code.
            while (i + 1 < n && byteAt(i + 1) == 0xFF) i++
            if (i + 1 >= n) return null // fill runs to the end; no marker
            val marker = byteAt(i + 1)

            // Standalone markers carry no length field.
            if (marker == 0xD8 || marker in 0xD0..0xD7 || marker == 0x01) {
                plan.range(i, i + 2)
                i += 2
                continue
            }
            if (marker == 0xD9) { // EOI
                return plan.range(i, i + 2).build()
            }
            if (i + 3 >= n) return null

            val segmentLength = (byteAt(i + 2) shl 8) or byteAt(i + 3)
            if (segmentLength < 2) return null
            val segmentEnd = i + 2 + segmentLength
            if (segmentEnd > n) return null

            val isMetadata = marker in 0xE0..0xEF || marker == 0xFE
            if (!isMetadata) plan.range(i, segmentEnd)

            i = segmentEnd

            if (marker == 0xDA) {
                // Entropy-coded data runs from here to the end, EOI included.
                return plan.range(i, n).build()
            }
        }
        return plan.build()
    }
}
