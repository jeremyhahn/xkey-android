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
}
