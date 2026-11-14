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
import java.io.InputStream
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
     * [hashCanonical] over the content at [uri]. The mime type comes from the
     * resolver, so a JPEG is recognised whether it arrived as a file or a
     * document URI.
     */
    fun hashCanonicalUri(contentResolver: ContentResolver, uri: Uri): String {
        val bytes = contentResolver.openInputStream(uri)?.use { it.readBytes() }
            ?: throw IllegalArgumentException("Cannot open URI: $uri")
        return hashCanonical(bytes, contentResolver.getType(uri))
    }

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

    fun canonicalContent(data: ByteArray, mimeType: String?): ByteArray {
        if (isCanonicalisedJpeg(mimeType)) return jpegWithoutMetadata(data)
        val format = XmpContainers.formatOf(mimeType) ?: return data
        return XmpContainers.strip(data, format)
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

    /** [contentHashMatches] over the content at [uri], typed by the resolver. */
    fun contentHashMatchesUri(
        contentResolver: ContentResolver,
        uri: Uri,
        storedContentHash: String,
        source: SignatureSource
    ): Boolean {
        val bytes = contentResolver.openInputStream(uri)?.use { it.readBytes() }
            ?: throw IllegalArgumentException("Cannot open URI: $uri")
        return contentHashMatches(storedContentHash, bytes, contentResolver.getType(uri), source)
    }

    /**
     * Strips `APPn` (0xE0-0xEF) and `COM` (0xFE) segments from a JPEG, keeping
     * SOI, the quantisation/frame/Huffman tables, the scan header and all
     * entropy-coded data. Returns [data] unchanged if it is not a JPEG or is
     * malformed — a hash over slightly more than intended is safe, whereas
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
     */
    private fun jpegWithoutMetadata(data: ByteArray): ByteArray {
        if (data.size < 4 || byteAt(data, 0) != 0xFF || byteAt(data, 1) != 0xD8) return data

        val out = java.io.ByteArrayOutputStream(data.size)
        out.write(data, 0, 2) // SOI
        var i = 2

        while (i + 1 < data.size) {
            if (byteAt(data, i) != 0xFF) return data // not marker-aligned; bail out safely
            // Fill bytes: advance to the last 0xFF before the marker code.
            while (i + 1 < data.size && byteAt(data, i + 1) == 0xFF) i++
            if (i + 1 >= data.size) return data // fill runs to the end; no marker
            val marker = byteAt(data, i + 1)

            // Standalone markers carry no length field.
            if (marker == 0xD8 || marker in 0xD0..0xD7 || marker == 0x01) {
                out.write(data, i, 2)
                i += 2
                continue
            }
            if (marker == 0xD9) { // EOI
                out.write(data, i, 2)
                return out.toByteArray()
            }
            if (i + 3 >= data.size) return data

            val segmentLength = (byteAt(data, i + 2) shl 8) or byteAt(data, i + 3)
            if (segmentLength < 2) return data
            val segmentEnd = i + 2 + segmentLength
            if (segmentEnd > data.size) return data

            val isMetadata = marker in 0xE0..0xEF || marker == 0xFE
            if (!isMetadata) out.write(data, i, segmentEnd - i)

            i = segmentEnd

            if (marker == 0xDA) {
                // Entropy-coded data runs from here to the end, EOI included.
                out.write(data, i, data.size - i)
                return out.toByteArray()
            }
        }
        return out.toByteArray()
    }

    private fun byteAt(data: ByteArray, index: Int): Int = data[index].toInt() and 0xFF
}
