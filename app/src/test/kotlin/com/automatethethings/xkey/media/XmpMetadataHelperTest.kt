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

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

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

    private fun createSampleData(): ContentAuthenticityData = ContentAuthenticityData(
        contentHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        signatures = listOf(
            SignatureEntry(
                keyFingerprint = "SHA256:testfp",
                signerName = "Alice",
                algorithm = "ES256",
                value = "MEUCIQD_test_signature",
                timestamp = "2025-01-15T10:30:00Z",
                role = SignerRole.CREATOR
            )
        )
    )

    @Test
    fun `readSignature returns null for file with no signature`() {
        val videoFile = tempFolder.newFile("test_video.mp4")
        videoFile.writeBytes(ByteArray(100))

        val result = XmpMetadataHelper.readSignature(videoFile.absolutePath)

        assertNull(result)
    }

    @Test
    fun `writeSignature then readSignature round-trips via sidecar for non-JPEG`() {
        val videoFile = tempFolder.newFile("test_video.mp4")
        videoFile.writeBytes(ByteArray(100))

        val data = createSampleData()
        XmpMetadataHelper.writeSignature(videoFile.absolutePath, data)
        val restored = XmpMetadataHelper.readSignature(videoFile.absolutePath)

        assertNotNull(restored)
        assertEquals(data.version, restored!!.version)
        assertEquals(data.contentHash, restored.contentHash)
        assertEquals(data.hashAlgorithm, restored.hashAlgorithm)
        assertEquals(data.signatures.size, restored.signatures.size)
        assertEquals(data.signatures[0].keyFingerprint, restored.signatures[0].keyFingerprint)
        assertEquals(data.signatures[0].value, restored.signatures[0].value)
    }

    @Test
    fun `sidecar file is created for non-JPEG files`() {
        val videoFile = tempFolder.newFile("test_video.mp4")
        videoFile.writeBytes(ByteArray(50))

        val sidecarPath = XmpMetadataHelper.getSidecarPath(videoFile.absolutePath)
        val sidecarFile = File(sidecarPath)

        // Sidecar should not exist before writing
        assertTrue(!sidecarFile.exists())

        XmpMetadataHelper.writeSignature(videoFile.absolutePath, createSampleData())

        // Sidecar should now exist
        assertTrue(sidecarFile.exists())
        assertEquals(videoFile.absolutePath + ".xkeysig", sidecarPath)
    }

    @Test
    fun `getSidecarPath appends xkeysig extension`() {
        assertEquals("/path/to/file.mp4.xkeysig", XmpMetadataHelper.getSidecarPath("/path/to/file.mp4"))
        assertEquals("/path/to/file.png.xkeysig", XmpMetadataHelper.getSidecarPath("/path/to/file.png"))
        assertEquals("/path/to/file.mkv.xkeysig", XmpMetadataHelper.getSidecarPath("/path/to/file.mkv"))
    }

    @Test
    fun `appendSignature adds to existing sidecar signatures`() {
        val videoFile = tempFolder.newFile("test_video.mp4")
        videoFile.writeBytes(ByteArray(50))

        // Write initial signature
        val initialData = createSampleData()
        XmpMetadataHelper.writeSignature(videoFile.absolutePath, initialData)

        // Append a second signature
        val witnessEntry = SignatureEntry(
            keyFingerprint = "SHA256:witnessfp",
            signerName = "Bob",
            algorithm = "ES256",
            value = "MEUCIQD_witness_signature",
            timestamp = "2025-01-15T11:00:00Z",
            role = SignerRole.WITNESS
        )
        XmpMetadataHelper.appendSignature(videoFile.absolutePath, witnessEntry)

        // Read back and verify both signatures are present
        val result = XmpMetadataHelper.readSignature(videoFile.absolutePath)

        assertNotNull(result)
        assertEquals(2, result!!.signatures.size)
        assertEquals("SHA256:testfp", result.signatures[0].keyFingerprint)
        assertEquals(SignerRole.CREATOR, result.signatures[0].role)
        assertEquals("SHA256:witnessfp", result.signatures[1].keyFingerprint)
        assertEquals(SignerRole.WITNESS, result.signatures[1].role)
    }

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

    @Test
    fun `sidecar created for png file`() {
        val pngFile = tempFolder.newFile("image.png")
        pngFile.writeBytes(ByteArray(50))

        XmpMetadataHelper.writeSignature(pngFile.absolutePath, createSampleData())

        val sidecarFile = File(XmpMetadataHelper.getSidecarPath(pngFile.absolutePath))
        assertTrue(sidecarFile.exists())

        val result = XmpMetadataHelper.readSignature(pngFile.absolutePath)
        assertNotNull(result)
    }
}
