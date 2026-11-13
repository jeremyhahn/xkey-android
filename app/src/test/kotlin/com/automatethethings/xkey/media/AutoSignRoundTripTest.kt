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

import android.util.Base64
import android.util.Log
import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * Signing to verification, end to end on the JVM: the hash the automatic
 * signer stores must be one the share screen's in-band check accepts once the
 * signature has been embedded in the file.
 *
 * The verifier side is the one `FileOperationActivity.performVerify` runs:
 * [MediaHasher.contentHashMatches] with [MediaHasher.SignatureSource.IN_BAND],
 * then [SignerVerification.verify]. Embedding is modelled as what it does to
 * the bytes: a new APP1 segment after SOI, the camera's own APP segments kept.
 */
class AutoSignRoundTripTest {

    @Before
    fun setUp() {
        mockkStatic(Base64::class)
        every { Base64.decode(any<String>(), any()) } answers {
            java.util.Base64.getDecoder().decode(firstArg<String>())
        }
        mockkStatic(Log::class)
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>(), any()) } returns 0
        every { Log.e(any(), any(), any()) } returns 0
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    private fun segment(marker: Int, payload: ByteArray): ByteArray {
        val length = payload.size + 2
        return byteArrayOf(0xFF.toByte(), marker.toByte(), (length shr 8).toByte(), length.toByte()) + payload
    }

    /** A camera JPEG: JFIF APP0 and EXIF APP1 metadata, then tables and a scan. */
    private fun cameraJpeg(): ByteArray = ByteArrayOutputStream().apply {
        write(byteArrayOf(0xFF.toByte(), 0xD8.toByte()))
        write(segment(0xE0, "JFIF\u0000\u0001\u0001".toByteArray()))
        write(segment(0xE1, "Exif\u0000\u0000camera=test;iso=100".toByteArray()))
        write(segment(0xDB, ByteArray(65) { it.toByte() }))
        write(segment(0xDA, byteArrayOf(1, 1, 0, 0, 63, 0)))
        write(byteArrayOf(0x12, 0x34, 0x56, 0x78, 0x9A.toByte(), 0xBC.toByte()))
        write(byteArrayOf(0xFF.toByte(), 0xD9.toByte()))
    }.toByteArray()

    /** [jpeg] with an XMP APP1 segment written after SOI, as embedding does. */
    private fun embed(jpeg: ByteArray, xmp: String): ByteArray =
        jpeg.copyOfRange(0, 2) +
            segment(0xE1, "http://ns.adobe.com/xap/1.0/\u0000$xmp".toByteArray()) +
            jpeg.copyOfRange(2, jpeg.size)

    @Test
    fun `a camera JPEG signed by the automatic signer verifies through the share screen check`() {
        val keyPair = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()
        val original = cameraJpeg()

        // Signer side: the stored hash, signed as hex-decoded bytes.
        val contentHash = AutoSignHash.contentHash(original, "image/jpeg")
        val signature = Signature.getInstance("SHA256withECDSA").apply {
            initSign(keyPair.private)
            update(SignatureVerifier.hexToBytes(contentHash))
        }.sign()
        val entry = SignatureEntry(
            keyFingerprint = MediaHasher.hashBytes(keyPair.public.encoded),
            signerName = "Camera key",
            algorithm = "ES256",
            value = java.util.Base64.getEncoder().encodeToString(signature),
            timestamp = "2026-11-12T00:00:00Z",
            role = SignerRole.CREATOR
        )
        val signed = embed(original, "<xkey contentHash=\"$contentHash\"/>")

        // Verifier side, as performVerify runs it on the shared file.
        val matches = MediaHasher.contentHashMatches(
            contentHash, signed, "image/jpeg", MediaHasher.SignatureSource.IN_BAND
        )
        assertTrue("the in-band check must accept the automatic signer's hash", matches)
        val result = SignerVerification.verify(
            entry,
            contentHash,
            matches,
            contact = null,
            localKeys = listOf(SignerVerification.LocalKey("k1", "Camera key", keyPair.public.encoded))
        )
        assertEquals(SignerVerification.Status.VERIFIED, result.status)
    }
}
