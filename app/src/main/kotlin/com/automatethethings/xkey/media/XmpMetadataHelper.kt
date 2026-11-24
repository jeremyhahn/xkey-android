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

object XmpMetadataHelper {

    private const val XKEY_SIGNATURE_PREFIX = "XKEY_SIG:"

    fun writeSignature(filePath: String, data: ContentAuthenticityData) {
        val mimeType = getMimeType(filePath)
        when {
            mimeType.startsWith("image/jpeg") || mimeType.startsWith("image/jpg") -> {
                writeExifSignature(filePath, data)
            }
            else -> {
                writeSidecarSignature(filePath, data)
            }
        }
    }

    fun readSignature(filePath: String): ContentAuthenticityData? {
        val mimeType = getMimeType(filePath)
        return when {
            mimeType.startsWith("image/jpeg") || mimeType.startsWith("image/jpg") -> {
                readExifSignature(filePath) ?: readSidecarSignature(filePath)
            }
            else -> {
                readSidecarSignature(filePath)
            }
        }
    }

    /** Where [persistSignature] put a signature. */
    enum class SignatureLocation { IN_FILE, PRIVATE_STORE }

    /**
     * Signatures the app could not write into the media itself. Set once
     * per process ([usePrivateStore]); null keeps the store off.
     */
    @Volatile
    internal var privateStore: PrivateSignatureStore? = null

    /** Keeps refused signatures under the app's no-backup files directory. */
    fun usePrivateStore(context: Context) {
        privateStore = PrivateSignatureStore(File(context.noBackupFilesDir, "media-signatures"))
    }

    /**
     * Writes [data] with [writeInFile]; when the write is refused (on API
     * 30+ the app may not write to another app's media) keeps it in
     * [privateStore] instead, keyed by its content hash. Throws when
     * neither holds it, so the caller can audit the failure.
     */
    fun persistSignature(data: ContentAuthenticityData, writeInFile: () -> Unit): SignatureLocation {
        try {
            writeInFile()
            return SignatureLocation.IN_FILE
        } catch (e: Exception) {
            if (e !is IOException && e !is SecurityException) throw e
            val store = privateStore ?: throw IOException("no write access to the media and no private store", e)
            store.put(data)
            return SignatureLocation.PRIVATE_STORE
        }
    }

    /**
     * Writes [data] into the JPEG at [uri] through [contentResolver], which
     * reaches files the app may write (its own) without a raw path.
     */
    fun writeSignature(contentResolver: ContentResolver, uri: Uri, data: ContentAuthenticityData) {
        val pfd = contentResolver.openFileDescriptor(uri, "rw")
            ?: throw java.io.FileNotFoundException("cannot open $uri for writing")
        pfd.use {
            val exif = ExifInterface(it.fileDescriptor)
            exif.setAttribute(ExifInterface.TAG_USER_COMMENT, XKEY_SIGNATURE_PREFIX + data.toJsonString())
            exif.saveAttributes()
        }
    }

    fun readSignatureFromUri(contentResolver: ContentResolver, uri: Uri, mimeType: String?): ContentAuthenticityData? {
        val type = mimeType ?: ""
        if (type.startsWith("image/jpeg") || type.startsWith("image/jpg")) {
            try {
                contentResolver.openInputStream(uri)?.use { inputStream ->
                    readExifSignatureFromStream(inputStream)?.let { return it }
                }
            } catch (_: Exception) { }
        }
        return readPrivateSignature(contentResolver, uri)
    }

    /** A signature [persistSignature] kept for the content at [uri], if any. */
    private fun readPrivateSignature(contentResolver: ContentResolver, uri: Uri): ContentAuthenticityData? {
        val store = privateStore ?: return null
        if (store.isEmpty()) return null
        return try {
            store.get(AutoSignHash.contentHashUri(contentResolver, uri))
        } catch (_: Exception) {
            null
        }
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

/**
 * Signatures kept in app-private storage, one file per content hash, for
 * media the app may not write to. Verification hashes the content it is
 * shown and looks the hash up here, so a signature survives the file
 * being read-only to the app.
 */
class PrivateSignatureStore(private val dir: File) {

    /** Stores [data] under its content hash, replacing any earlier one. */
    fun put(data: ContentAuthenticityData) {
        val target = file(data.contentHash)
            ?: throw IllegalArgumentException("content hash is not a SHA-256 hex digest")
        if (!dir.isDirectory && !dir.mkdirs()) throw IOException("cannot create $dir")
        val temp = File(dir, "${target.name}.tmp")
        temp.writeText(data.toJsonString())
        if (!temp.renameTo(target)) {
            temp.delete()
            throw IOException("cannot store signature in $dir")
        }
    }

    /** The signature stored for [contentHash], or null. */
    fun get(contentHash: String): ContentAuthenticityData? {
        val f = file(contentHash) ?: return null
        if (!f.isFile) return null
        return try {
            ContentAuthenticityData.fromJsonString(f.readText())
        } catch (_: Exception) {
            null
        }
    }

    /** True when nothing is stored, so a reader can skip hashing. */
    fun isEmpty(): Boolean = dir.list()?.none { it.endsWith(SUFFIX) } ?: true

    private fun file(contentHash: String): File? =
        if (HEX_SHA256.matches(contentHash)) File(dir, contentHash + SUFFIX) else null

    private companion object {
        const val SUFFIX = ".json"
        val HEX_SHA256 = Regex("[0-9a-f]{64}")
    }
}
