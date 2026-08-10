/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
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

import android.content.Context
import android.graphics.Bitmap
import android.graphics.Color
import android.net.Uri
import androidx.exifinterface.media.ExifInterface
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.io.FileOutputStream

/**
 * Instrumented tests for the JPEG half of [XmpMetadataHelper].
 *
 * `XmpMetadataHelperTest` covers the sidecar branch in the JVM; the JPEG branch
 * writes into an EXIF `UserComment` and needs a real encoder to produce a file
 * `ExifInterface` will accept, plus a `ContentResolver` for the URI reader. This
 * is the branch that matters in the field: a photo carrying its signature
 * in-band survives being copied or shared, whereas a sidecar does not.
 *
 * Every file is created under the app cache with a per-run unique name and
 * deleted in teardown, sidecars included.
 */
@RunWith(AndroidJUnit4::class)
class XmpMetadataHelperInstrumentedTest {

    private lateinit var context: Context
    private val created = mutableListOf<File>()

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
    }

    @After
    fun tearDown() {
        created.forEach { file ->
            File(XmpMetadataHelper.getSidecarPath(file.path)).delete()
            file.delete()
        }
        created.clear()
    }

    /** Writes a small real JPEG so `ExifInterface` has something it can edit. */
    private fun jpeg(): File {
        val file = File(context.cacheDir, "xkey-media-${System.nanoTime()}.jpg")
        val bitmap = Bitmap.createBitmap(16, 16, Bitmap.Config.ARGB_8888)
        bitmap.eraseColor(Color.rgb(0x22, 0x44, 0x88))
        FileOutputStream(file).use { bitmap.compress(Bitmap.CompressFormat.JPEG, 90, it) }
        bitmap.recycle()
        created.add(file)
        return file
    }

    private fun png(): File {
        val file = File(context.cacheDir, "xkey-media-${System.nanoTime()}.png")
        val bitmap = Bitmap.createBitmap(16, 16, Bitmap.Config.ARGB_8888)
        bitmap.eraseColor(Color.RED)
        FileOutputStream(file).use { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }
        bitmap.recycle()
        created.add(file)
        return file
    }

    private fun sampleData(hash: String = "a".repeat(64)) = ContentAuthenticityData(
        contentHash = hash,
        signatures = listOf(
            SignatureEntry(
                keyFingerprint = "b".repeat(64),
                signerName = "Test Signer",
                algorithm = "ES256",
                value = "c2lnbmF0dXJl",
                timestamp = "2026-01-01T00:00:00Z",
                role = SignerRole.CREATOR
            )
        )
    )

    @Test
    fun jpegSignature_roundTripsThroughExif() {
        val file = jpeg()
        val data = sampleData()

        XmpMetadataHelper.writeSignature(file.path, data)

        val read = XmpMetadataHelper.readSignature(file.path)
        assertNotNull(read)
        assertEquals(data.contentHash, read!!.contentHash)
        assertEquals(data.hashAlgorithm, read.hashAlgorithm)
        assertEquals(1, read.signatures.size)
        assertEquals("Test Signer", read.signatures[0].signerName)
        assertEquals("ES256", read.signatures[0].algorithm)
        assertEquals(SignerRole.CREATOR, read.signatures[0].role)
    }

    @Test
    fun jpegSignature_isWrittenInBandNotToASidecar() {
        val file = jpeg()

        XmpMetadataHelper.writeSignature(file.path, sampleData())

        assertFalse(
            "a JPEG must carry its signature in EXIF, not alongside it",
            File(XmpMetadataHelper.getSidecarPath(file.path)).exists()
        )
        val comment = ExifInterface(file.path).getAttribute(ExifInterface.TAG_USER_COMMENT)
        assertNotNull(comment)
        assertTrue(comment!!, comment.startsWith("XKEY_SIG:"))
    }

    @Test
    fun anUnsignedJpeg_readsBackAsNull() {
        assertNull(XmpMetadataHelper.readSignature(jpeg().path))
    }

    @Test
    fun aJpegWithAForeignUserComment_readsBackAsNull() {
        val file = jpeg()
        ExifInterface(file.path).apply {
            setAttribute(ExifInterface.TAG_USER_COMMENT, "taken with a camera")
            saveAttributes()
        }

        assertNull(XmpMetadataHelper.readSignature(file.path))
    }

    @Test
    fun aJpegFallsBackToItsSidecarWhenExifHasNothing() {
        val file = jpeg()
        val data = sampleData(hash = "d".repeat(64))
        // A PNG-style sidecar next to a JPEG: the reader tries EXIF, finds
        // nothing, and must still pick the signature up.
        File(XmpMetadataHelper.getSidecarPath(file.path)).writeText(data.toJsonString())

        val read = XmpMetadataHelper.readSignature(file.path)

        assertNotNull(read)
        assertEquals(data.contentHash, read!!.contentHash)
    }

    @Test
    fun writingAJpegSignatureTwice_replacesTheFirst() {
        val file = jpeg()
        XmpMetadataHelper.writeSignature(file.path, sampleData(hash = "1".repeat(64)))

        XmpMetadataHelper.writeSignature(file.path, sampleData(hash = "2".repeat(64)))

        assertEquals("2".repeat(64), XmpMetadataHelper.readSignature(file.path)!!.contentHash)
    }

    @Test
    fun appendSignature_addsACosignerToAJpeg() {
        val file = jpeg()
        XmpMetadataHelper.writeSignature(file.path, sampleData())

        XmpMetadataHelper.appendSignature(
            file.path,
            SignatureEntry(
                keyFingerprint = "e".repeat(64),
                signerName = "Witness",
                algorithm = "ES256",
                value = "d2l0bmVzcw==",
                timestamp = "2026-01-02T00:00:00Z",
                role = SignerRole.WITNESS
            )
        )

        val read = XmpMetadataHelper.readSignature(file.path)!!
        assertEquals(2, read.signatures.size)
        assertEquals(SignerRole.CREATOR, read.signatures[0].role)
        assertEquals(SignerRole.WITNESS, read.signatures[1].role)
        assertEquals("Witness", read.signatures[1].signerName)
    }

    @Test(expected = IllegalStateException::class)
    fun appendSignature_refusesAnUnsignedJpeg() {
        XmpMetadataHelper.appendSignature(
            jpeg().path,
            SignatureEntry(
                keyFingerprint = "f".repeat(64),
                signerName = null,
                algorithm = "ES256",
                value = "bm9wZQ==",
                timestamp = "2026-01-03T00:00:00Z"
            )
        )
    }

    @Test
    fun readSignatureFromUri_readsAJpegSignature() {
        val file = jpeg()
        val data = sampleData(hash = "9".repeat(64))
        XmpMetadataHelper.writeSignature(file.path, data)

        val read = XmpMetadataHelper.readSignatureFromUri(
            context.contentResolver,
            Uri.fromFile(file),
            "image/jpeg"
        )

        assertNotNull(read)
        assertEquals(data.contentHash, read!!.contentHash)
        assertEquals(1, read.signatures.size)
    }

    @Test
    fun readSignatureFromUri_returnsNullForAnUnsignedJpeg() {
        val read = XmpMetadataHelper.readSignatureFromUri(
            context.contentResolver,
            Uri.fromFile(jpeg()),
            "image/jpeg"
        )

        assertNull(read)
    }

    @Test
    fun readSignatureFromUri_ignoresANonJpegMimeType() {
        val file = jpeg()
        XmpMetadataHelper.writeSignature(file.path, sampleData())

        // The URI reader only knows how to read EXIF, so anything else is a miss
        // even when the underlying bytes do carry a signature.
        val read = XmpMetadataHelper.readSignatureFromUri(
            context.contentResolver,
            Uri.fromFile(file),
            "video/mp4"
        )

        assertNull(read)
    }

    @Test
    fun readSignatureFromUri_toleratesAnUnknownMimeType() {
        val read = XmpMetadataHelper.readSignatureFromUri(
            context.contentResolver,
            Uri.fromFile(jpeg()),
            null
        )

        assertNull(read)
    }

    @Test
    fun readSignatureFromUri_swallowsAnUnopenableUri() {
        val missing = Uri.fromFile(File(context.cacheDir, "absent-${System.nanoTime()}.jpg"))

        val read = XmpMetadataHelper.readSignatureFromUri(
            context.contentResolver,
            missing,
            "image/jpeg"
        )

        assertNull(read)
    }

    @Test
    fun aPngStillUsesASidecar() {
        val file = png()
        val data = sampleData(hash = "7".repeat(64))

        XmpMetadataHelper.writeSignature(file.path, data)

        assertTrue(File(XmpMetadataHelper.getSidecarPath(file.path)).exists())
        assertEquals(data.contentHash, XmpMetadataHelper.readSignature(file.path)!!.contentHash)
    }
}
