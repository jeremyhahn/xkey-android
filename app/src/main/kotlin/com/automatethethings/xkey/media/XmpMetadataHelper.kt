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
import java.io.InputStream

object XmpMetadataHelper {

    private const val XKEY_SIGNATURE_PREFIX = "XKEY_SIG:"

    fun writeSignature(filePath: String, data: ContentAuthenticityData) {
        if (MediaHasher.isJpegFile(filePath)) {
            writeExifSignature(filePath, data)
        } else {
            writeSidecarSignature(filePath, data)
        }
    }

    fun readSignature(filePath: String): ContentAuthenticityData? {
        return if (MediaHasher.isJpegFile(filePath)) {
            readExifSignature(filePath) ?: readSidecarSignature(filePath)
        } else {
            readSidecarSignature(filePath)
        }
    }

    /**
     * The signature embedded in the content at [uri]. The content is a JPEG
     * when [mimeType] or its first bytes say so ([MediaHasher.isJpeg]).
     */
    fun readSignatureFromUri(contentResolver: ContentResolver, uri: Uri, mimeType: String?): ContentAuthenticityData? {
        try {
            contentResolver.openInputStream(uri)?.buffered()?.use { stream ->
                stream.mark(MediaHasher.JPEG_HEAD_SIZE)
                val head = MediaHasher.readFully(stream, MediaHasher.JPEG_HEAD_SIZE)
                stream.reset()
                if (MediaHasher.isJpeg(mimeType, head = head)) return readExifSignatureFromStream(stream)
            }
        } catch (_: Exception) { }
        return null
    }

    fun appendSignature(filePath: String, entry: SignatureEntry) {
        val existing = readSignature(filePath)
        if (existing != null) {
            val updated = existing.copy(signatures = existing.signatures + entry)
            writeSignature(filePath, updated)
        } else {
            throw IllegalStateException("No existing signature data found to append to")
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
}
