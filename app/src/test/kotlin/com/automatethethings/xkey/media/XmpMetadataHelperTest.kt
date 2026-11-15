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
import io.mockk.every
import io.mockk.mockk
import java.io.ByteArrayInputStream
import java.io.File
import java.io.FileNotFoundException
import java.io.IOException
import java.io.InputStream
import java.io.SequenceInputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * Unit tests for [XmpMetadataHelper] sidecar signature path.
 *
 * JPEG/EXIF paths require ExifInterface which depends on the Android
 * framework, so those are covered by instrumented tests. These unit
 * tests exercise the sidecar file (.xkeysig) code path which uses
 * plain file I/O.
 */
class XmpMetadataHelperTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    @Test(expected = IllegalStateException::class)
    fun `appendSignature throws when no existing signature data`() {
        val videoFile = tempFolder.newFile("test_no_sig.mp4")
        videoFile.writeBytes(ByteArray(50))

        val entry = SignatureEntry(
            keyFingerprint = "SHA256:test",
            signerName = "Alice",
            algorithm = "ES256",
            value = "sig",
            timestamp = "2025-01-01T00:00:00Z"
        )

        XmpMetadataHelper.appendSignature(videoFile.absolutePath, entry)
    }

    @Test
    fun `writeSignature overwrites existing sidecar signature`() {
        val videoFile = tempFolder.newFile("overwrite_test.mp4")
        videoFile.writeBytes(ByteArray(50))

        val data1 = ContentAuthenticityData(
            contentHash = "hash1",
            signatures = listOf(
                SignatureEntry(
                    keyFingerprint = "fp1",
                    signerName = "Alice",
                    algorithm = "ES256",
                    value = "sig1",
                    timestamp = "2025-01-01T00:00:00Z"
                )
            )
        )
        XmpMetadataHelper.writeSignature(videoFile.absolutePath, data1)

        val data2 = ContentAuthenticityData(
            contentHash = "hash2",
            signatures = listOf(
                SignatureEntry(
                    keyFingerprint = "fp2",
                    signerName = "Bob",
                    algorithm = "ES384",
                    value = "sig2",
                    timestamp = "2025-02-01T00:00:00Z"
                )
            )
        )
        XmpMetadataHelper.writeSignature(videoFile.absolutePath, data2)

        val result = XmpMetadataHelper.readSignature(videoFile.absolutePath)

        assertNotNull(result)
        assertEquals("hash2", result!!.contentHash)
        assertEquals(1, result.signatures.size)
        assertEquals("fp2", result.signatures[0].keyFingerprint)
    }

    // -------------------------------------------------------------------------
    // Read failures surface through the public readers
    // -------------------------------------------------------------------------

    private val containerMimes = listOf("image/png" to "png", "image/webp" to "webp", "video/mp4" to "mp4")

    private fun staleSidecarData() = ContentAuthenticityData(
        contentHash = "f".repeat(64),
        signatures = listOf(
            SignatureEntry(
                keyFingerprint = "SHA256:stale",
                signerName = "Stale",
                algorithm = "ES256",
                value = "sig",
                timestamp = "2025-01-01T00:00:00Z"
            )
        )
    )

    @Test
    fun `readSignature throws when the embedded container cannot be read, ignoring a stale sidecar`() {
        for ((_, ext) in containerMimes) {
            // A directory at the media path: it exists, but opening it for
            // reading fails, as an unreadable file does.
            val media = tempFolder.newFolder("unreadable.$ext")
            File(media.absolutePath + ".xkeysig").writeText(staleSidecarData().toJsonString())

            assertThrows(ext, IOException::class.java) { XmpMetadataHelper.readSignature(media.absolutePath) }
        }
    }

    @Test
    fun `readSignatureFromUri throws when the stream fails mid-read`() {
        for ((mime, _) in containerMimes) {
            val file = XmpFixtures.all.getValue(mime)
            val broken = object : InputStream() {
                override fun read(): Int = throw IOException("device gone")
            }
            val resolver = mockk<ContentResolver>()
            val uri = mockk<Uri>(relaxed = true)
            every { resolver.openInputStream(uri) } returns
                SequenceInputStream(ByteArrayInputStream(file.copyOfRange(0, 12)), broken)

            assertThrows(mime, IOException::class.java) {
                XmpMetadataHelper.readSignatureFromUri(resolver, uri, mime)
            }
        }
    }

    @Test
    fun `readSignatureFromUri throws when the content cannot be opened`() {
        for ((mime, _) in containerMimes) {
            val resolver = mockk<ContentResolver>()
            val uri = mockk<Uri>(relaxed = true)
            every { resolver.openInputStream(uri) } throws FileNotFoundException("gone")

            assertThrows(mime, IOException::class.java) {
                XmpMetadataHelper.readSignatureFromUri(resolver, uri, mime)
            }
        }
    }

    @Test
    fun `readSignatureFromUri reads unsigned media as null`() {
        for ((mime, _) in containerMimes) {
            val resolver = mockk<ContentResolver>()
            val uri = mockk<Uri>(relaxed = true)
            every { resolver.openInputStream(uri) } returns ByteArrayInputStream(XmpFixtures.all.getValue(mime))

            assertNull(mime, XmpMetadataHelper.readSignatureFromUri(resolver, uri, mime))
        }
    }
}
