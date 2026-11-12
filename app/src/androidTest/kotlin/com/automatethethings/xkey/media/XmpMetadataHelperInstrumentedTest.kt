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
import android.graphics.BitmapFactory
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
 * Instrumented tests for the JPEG half of [XmpMetadataHelper], and for the
 * URI reader over an embedded MP4 and PNG signature.
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

    /**
     * #47 regression under ExifInterface 1.4.2: embedding a signature rewrites
     * the file through `saveAttributes`, and the canonical hash the signature
     * covers must survive that rewrite, or every in-band signature fails. A
     * writer that adds `0xFF` fill bytes before a marker must not move it.
     *
     * CI runs no androidTest stage, so this only runs on a device. The proof CI
     * carries is the JVM vectors in `MediaHasherCanonicalTest`.
     */
    @Test
    fun exifWrite_keepsTheCanonicalHash() {
        val file = jpeg()
        val before = file.readBytes()

        XmpMetadataHelper.writeSignature(file.path, sampleData())

        val after = file.readBytes()
        assertFalse("the write must change the file", before.contentEquals(after))
        assertEquals(
            MediaHasher.hashCanonical(before, "image/jpeg"),
            MediaHasher.hashCanonical(after, "image/jpeg")
        )
    }

    /**
     * #47, Codex review 6661: an encoder JPEG given `0xFF` fill bytes before
     * [first] (null: the first marker after SOI) and before the kept table
     * [retained], with an EXIF APP1 added first when [withApp1], signed through
     * the real `writeSignature` under ExifInterface 1.4.2. The signature must
     * read back unchanged, its hash must equal the canonical hash of the file as
     * written, and the file must keep its structure and still decode.
     *
     * CI runs no androidTest stage, so these only run on a device. CI runs the
     * same fixtures through the real 1.4.2 reader and writer in the JVM, in
     * `XmpMetadataHelperExifFillByteTest`.
     */
    private fun assertFillByteJpegSignsAndVerifies(withApp1: Boolean, first: Int?, retained: Int) {
        val file = jpeg()
        val encoded = file.readBytes()
        val fixture = JpegFillBytes.fixture(
            if (withApp1) JpegFillBytes.withExifApp1(encoded) else encoded, first, retained
        )
        file.writeBytes(fixture)
        val data = sampleData(MediaHasher.hashCanonical(fixture, "image/jpeg"))

        XmpMetadataHelper.writeSignature(file.path, data)

        val after = file.readBytes()
        assertFalse("the write must change the file", fixture.contentEquals(after))
        assertEquals("the signature must read back unchanged", data, XmpMetadataHelper.readSignature(file.path))
        assertEquals(
            "the stored hash must equal the canonical hash of the file as written",
            data.contentHash,
            MediaHasher.hashCanonical(after, "image/jpeg")
        )
        JpegFillBytes.assertWellFormed(after)
        val bitmap = BitmapFactory.decodeByteArray(after, 0, after.size)
        assertNotNull("the written file must still decode", bitmap)
        assertEquals(16, bitmap!!.width)
        bitmap.recycle()
    }

    @Test
    fun exifWrite_fillBytesBeforeApp1AndDqt_signsAndVerifies() {
        assertFillByteJpegSignsAndVerifies(withApp1 = true, first = JpegFillBytes.APP1, retained = JpegFillBytes.DQT)
    }

    @Test
    fun exifWrite_fillBytesBeforeApp1AndSof0_signsAndVerifies() {
        assertFillByteJpegSignsAndVerifies(withApp1 = true, first = JpegFillBytes.APP1, retained = JpegFillBytes.SOF0)
    }

    @Test
    fun exifWrite_fillBytesBeforeFirstMarkerWithoutApp1AndDht_signsAndVerifies() {
        assertFillByteJpegSignsAndVerifies(withApp1 = false, first = null, retained = JpegFillBytes.DHT)
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

        // The mime type picks the reader: JPEG bytes read as an MP4 carry no
        // `uuid` XMP box, so they are a miss even though the EXIF is signed.
        val read = XmpMetadataHelper.readSignatureFromUri(
            context.contentResolver,
            Uri.fromFile(file),
            "video/mp4"
        )

        assertNull(read)
    }

    private fun be32(value: Long) = byteArrayOf(
        (value shr 24).toByte(), (value shr 16).toByte(), (value shr 8).toByte(), value.toByte()
    )

    private fun box(type: String, payload: ByteArray) = be32(8L + payload.size) + type.toByteArray() + payload

    private fun pngChunk(type: String, data: ByteArray): ByteArray {
        val crc = java.util.zip.CRC32().apply { update(type.toByteArray()); update(data) }.value
        return be32(data.size.toLong()) + type.toByteArray() + data + be32(crc)
    }

    /** A minimal MP4 or PNG, written by hand: no encoder is needed to embed XMP. */
    private fun container(extension: String): File {
        val bytes = when (extension) {
            "mp4" -> box("ftyp", "isom".toByteArray() + be32(0x200) + "isom".toByteArray()) +
                box("moov", ByteArray(8)) + box("mdat", byteArrayOf(1, 2, 3, 4))
            else -> byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A) +
                pngChunk("IHDR", be32(1) + be32(1) + byteArrayOf(8, 2, 0, 0, 0)) +
                pngChunk("IDAT", byteArrayOf(0x78, 0x9C.toByte(), 1, 2)) +
                pngChunk("IEND", ByteArray(0))
        }
        val file = File(context.cacheDir, "xkey-media-${System.nanoTime()}.$extension")
        file.writeBytes(bytes)
        created.add(file)
        return file
    }

    @Test
    fun readSignatureFromUri_readsAnEmbeddedMp4Signature() {
        val file = container("mp4")
        val data = sampleData(hash = "7".repeat(64))
        XmpMetadataHelper.writeSignature(file.path, data)
        assertFalse(File(XmpMetadataHelper.getSidecarPath(file.path)).exists())

        val read = XmpMetadataHelper.readSignatureFromUri(context.contentResolver, Uri.fromFile(file), "video/mp4")

        assertEquals(data, read)
    }

    @Test
    fun readSignatureFromUri_readsAnEmbeddedPngSignature() {
        val file = container("png")
        val data = sampleData(hash = "6".repeat(64))
        XmpMetadataHelper.writeSignature(file.path, data)
        assertFalse(File(XmpMetadataHelper.getSidecarPath(file.path)).exists())

        val read = XmpMetadataHelper.readSignatureFromUri(context.contentResolver, Uri.fromFile(file), "image/png")

        assertEquals(data, read)
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
    fun replaceEmbeddedSignature_signedCopyThroughAUriShowsTheSecondSigner() {
        val file = container("png")
        val uri = Uri.fromFile(file)
        val copy = File(file.parentFile, "copy-${file.name}")
        val copyUri = Uri.fromFile(copy)
        val resolver = context.contentResolver
        XmpMetadataHelper.writeSignature(file.path, sampleData(hash = "5".repeat(64)))
        val second = ContentAuthenticityData(
            contentHash = "5".repeat(64),
            signatures = listOf(
                SignatureEntry(
                    keyFingerprint = "d".repeat(64),
                    signerName = "Second Signer",
                    algorithm = "ES256",
                    value = "c2Vjb25k",
                    timestamp = "2026-01-02T00:00:00Z",
                    role = SignerRole.CREATOR
                )
            )
        )

        val original = file.readBytes()

        // The streams the Share-sheet signer opens: the shared URI read only,
        // the signed copy written to the document the user picked.
        assertEquals(
            XmpMetadataHelper.SharedSigning.SIGNED_COPY,
            XmpMetadataHelper.sharedSigning({ resolver.openInputStream(uri)!! }, XmpContainers.Format.PNG)
        )
        val replaced = XmpMetadataHelper.replaceEmbeddedSignature(
            open = { resolver.openInputStream(uri)!! },
            openOutput = { resolver.openOutputStream(copyUri, "w")!! },
            format = XmpContainers.Format.PNG,
            data = second,
            workDir = context.cacheDir,
            destination = copyUri.toString()
        )

        assertTrue(replaced)
        assertTrue(original.contentEquals(file.readBytes()))
        assertFalse(File(XmpMetadataHelper.getSidecarPath(copy.path)).exists())
        assertEquals(second, XmpMetadataHelper.readSignatureFromUri(resolver, copyUri, "image/png"))
    }
}
