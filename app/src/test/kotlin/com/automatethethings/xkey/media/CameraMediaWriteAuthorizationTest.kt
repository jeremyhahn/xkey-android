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

import android.Manifest
import android.app.Application
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.exifinterface.media.ExifInterface
import androidx.test.core.app.ApplicationProvider
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import java.io.ByteArrayInputStream
import java.io.File

/**
 * A capture the camera app owns is not xKey's to rename over: READ_MEDIA_*
 * grants no write. Signing it asks the user for write access
 * (MediaStore.createWriteRequest) and, once granted, writes the signed
 * bytes through the content URI; media xKey owns keeps its path.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class CameraMediaWriteAuthorizationTest {

    @get:Rule
    val folder = TemporaryFolder()

    private lateinit var context: Context
    private val uri: Uri = Uri.parse("content://media/external/images/media/4242")
    private lateinit var capture: File
    private lateinit var original: ByteArray
    /** What MediaStore serves at [uri]: the capture's bytes as its provider sees them. */
    private lateinit var media: File
    private lateinit var provider: FakeMediaProvider

    /** What the fake MediaStore answers, and the write requests it was asked for. */
    private var owner: String? = "com.example.camera"
    private var granted = false
    private val requests = mutableListOf<List<Uri>>()

    private val previousStore = MediaPublisher.mediaStore

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        capture = File(folder.newFolder("DCIM", "Camera"), "IMG_0001.png")
        original = XmpFixtures.png()
        capture.writeBytes(original)
        media = folder.newFile("media-4242.png").apply { writeBytes(original) }
        provider = Robolectric.setupContentProvider(FakeMediaProvider::class.java, "media")
        provider.media = media
        MediaPublisher.mediaStore = object : MediaPublisher.MediaStoreAccess {
            override fun ownerPackage(context: Context, uri: Uri): String? = owner
            override fun hasWriteGrant(context: Context, uri: Uri): Boolean = granted
            override fun createWriteRequest(context: Context, uris: List<Uri>): PendingIntent {
                requests += uris
                return PendingIntent.getActivity(context, 0, Intent(), PendingIntent.FLAG_IMMUTABLE)
            }
        }
        MediaWriteAuthorizations.clear(context)
        // MediaStore serves a foreign capture's original bytes only with this.
        shadowOf(context as Application).grantPermissions(Manifest.permission.ACCESS_MEDIA_LOCATION)
    }

    @After
    fun tearDown() {
        MediaPublisher.mediaStore = previousStore
        MediaWriteAuthorizations.clear(context)
    }

    private fun data(hash: String = AutoSignHash.contentHashFile(capture, "image/png")) = ContentAuthenticityData(
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

    private fun embedded(bytes: ByteArray): String? =
        XmpContainers.read(ByteArrayInputStream(bytes).buffered(), XmpContainers.Format.PNG)

    @Test
    fun `camera-owned media asks for write access and is signed through its URI once granted`() {
        val data = data()

        val first = XmpMetadataHelper.signMedia(context, uri, capture.path, data)

        assertEquals(XmpMetadataHelper.MediaSignResult.NeedsWriteAuthorization, first)
        assertArrayEquals("the capture is never renamed over", original, capture.readBytes())
        assertArrayEquals("nothing is written before the grant", original, media.readBytes())

        MediaWriteAuthorizations.add(context, PendingMediaWrite(uri.toString(), capture.path, "key-1", "Key", data))
        assertNotNull(MediaWriteAuthorizations.request(context))
        assertEquals(listOf(listOf(uri)), requests)

        granted = true
        val signed = mutableListOf<PendingMediaWrite>()
        MediaWriteAuthorizations.publishGranted(context) { signed += it }

        assertEquals(listOf(uri.toString()), signed.map { it.uri })
        assertArrayEquals("the path is still not written", original, capture.readBytes())
        assertEquals(data.toJsonString(), embedded(media.readBytes()))
        assertTrue("the queue is empty", MediaWriteAuthorizations.pending(context).isEmpty())
        assertNull("no request once nothing waits", MediaWriteAuthorizations.request(context))
    }

    @Test
    fun `a denied request drops its media unsigned`() {
        MediaWriteAuthorizations.add(context, PendingMediaWrite(uri.toString(), capture.path, "key-1", "Key", data()))
        val signed = mutableListOf<PendingMediaWrite>()
        MediaWriteAuthorizations.publishGranted(context) { signed += it }
        assertTrue("nothing is signed without the grant", signed.isEmpty())
        assertEquals(1, MediaWriteAuthorizations.pending(context).size)

        MediaWriteAuthorizations.deny(context, listOf(uri.toString()))

        assertTrue(MediaWriteAuthorizations.pending(context).isEmpty())
        assertArrayEquals(original, capture.readBytes())
        assertArrayEquals(original, media.readBytes())
    }

    @Test
    fun `granted media that changed since it was hashed is refused`() {
        granted = true
        val stale = data(hash = "0".repeat(64))

        assertThrows(XmpMetadataHelper.SourceChangedException::class.java) {
            XmpMetadataHelper.signMedia(context, uri, capture.path, stale)
        }
        assertArrayEquals(original, media.readBytes())
        assertArrayEquals(original, capture.readBytes())
    }

    @Test
    fun `media xKey owns keeps its path`() {
        owner = context.packageName
        val data = data()

        val result = XmpMetadataHelper.signMedia(context, uri, capture.path, data)

        assertEquals(XmpMetadataHelper.MediaSignResult.Signed, result)
        assertTrue(requests.isEmpty())
        assertArrayEquals(original, media.readBytes())
        assertEquals(data.toJsonString(), embedded(capture.readBytes()))
    }

    @Test
    fun `a granted write that fails mid-copy leaves the capture whole and its request queued`() {
        val data = data()
        MediaWriteAuthorizations.add(context, PendingMediaWrite(uri.toString(), capture.path, "key-1", "Key", data))
        granted = true
        provider.failWrites = true

        val signed = mutableListOf<PendingMediaWrite>()
        MediaWriteAuthorizations.publishGranted(context) { signed += it }

        assertTrue("nothing is reported signed", signed.isEmpty())
        assertArrayEquals("the capture is never truncated before the signed copy is in", original, media.readBytes())
        assertEquals("the request stays queued to retry", listOf(uri.toString()), MediaWriteAuthorizations.pending(context).map { it.uri })

        provider.failWrites = false
        MediaWriteAuthorizations.publishGranted(context) { signed += it }

        assertEquals("the retry signs it", listOf(uri.toString()), signed.map { it.uri })
        assertEquals(data.toJsonString(), embedded(media.readBytes()))
        assertTrue(MediaWriteAuthorizations.pending(context).isEmpty())
    }

    @Test
    fun `a granted write interrupted at its final step leaves the capture byte-for-byte whole`() {
        val data = data()
        MediaWriteAuthorizations.add(context, PendingMediaWrite(uri.toString(), capture.path, "key-1", "Key", data))
        granted = true
        // Every signed byte is in; the thread is interrupted before the cut to length.
        var interrupts = 1
        MediaPublisher.overwriteStep = { if (it == "truncate" && interrupts-- > 0) Thread.currentThread().interrupt() }

        val signed = mutableListOf<PendingMediaWrite>()
        try {
            MediaWriteAuthorizations.publishGranted(context) { signed += it }
        } finally {
            MediaPublisher.overwriteStep = {}
            Thread.interrupted()
        }

        assertTrue("nothing is reported signed", signed.isEmpty())
        assertArrayEquals("the interrupted write is undone", original, media.readBytes())
        assertEquals("the request stays queued to retry", listOf(uri.toString()), MediaWriteAuthorizations.pending(context).map { it.uri })

        MediaWriteAuthorizations.publishGranted(context) { signed += it }

        assertEquals("the retry signs it", listOf(uri.toString()), signed.map { it.uri })
        assertEquals(data.toJsonString(), embedded(media.readBytes()))
    }

    /**
     * Queue [data]'s capture, grant it, and leave the disk as a process
     * killed part-way through its overwrite would.
     */
    private fun killMidOverwrite(data: ContentAuthenticityData) {
        MediaWriteAuthorizations.add(context, PendingMediaWrite(uri.toString(), capture.path, "key-1", "Key", data))
        granted = true
        val recovery = MediaPublisher.recoveryDirectory(context)
        val atKill = folder.newFolder("recovery-at-kill")
        var mediaAtKill = ByteArray(0)
        var kills = 1
        // What a kill part-way through the write leaves on disk: the capture
        // starts with signed bytes (past where they first differ from the
        // original) and ends with the original's, and the recovery directory
        // is as it stood. No catch block runs.
        MediaPublisher.overwriteStep = {
            if (it == "truncate" && kills-- > 0) {
                val written = original.size - 4
                mediaAtKill = media.readBytes().copyOf(written) + original.copyOfRange(written, original.size)
                check(!mediaAtKill.contentEquals(original)) { "the kill must leave mixed bytes" }
                recovery.listFiles()!!.forEach { f -> f.copyTo(File(atKill, f.name)) }
                throw IllegalStateException("process killed")
            }
        }
        try {
            MediaWriteAuthorizations.publishGranted(context) {}
        } finally {
            MediaPublisher.overwriteStep = {}
        }
        media.writeBytes(mediaAtKill)
        recovery.listFiles()!!.forEach { it.delete() }
        atKill.listFiles()!!.forEach { f -> f.copyTo(File(recovery, f.name)) }
    }

    @Test
    fun `a process killed part-way through the overwrite has its capture restored at the next start`() {
        killMidOverwrite(data())
        assertTrue("the kill left the capture mixed", !media.readBytes().contentEquals(original))

        MediaPublisher.recoverInterruptedWrites(context)

        assertArrayEquals("the capture is whole again", original, media.readBytes())
        assertTrue(
            "the record and backup are gone",
            MediaPublisher.recoveryDirectory(context).listFiles()!!.none { it.name.startsWith(MediaPublisher.GrantedWriteJournal.PREFIX) }
        )
    }

    @Test
    fun `a granted write called directly, past signMedia, still refuses an edited capture`() {
        granted = true
        val hash = AutoSignHash.contentHashFile(capture, "image/png")
        val staged = folder.newFile("staged.png").apply { writeBytes(original) }
        val edited = XmpFixtures.png(byteArrayOf(0x78, 0x9C.toByte(), 0x07, 0x07, 0x07))
        media.writeBytes(edited)

        assertThrows(XmpMetadataHelper.SourceChangedException::class.java) {
            MediaPublisher.writeGranted(context, uri, staged, hash, "image/png")
        }
        assertArrayEquals(edited, media.readBytes())
    }

    @Test
    fun `only signMedia calls the granted write`() {
        val rel = "src/main/kotlin"
        val dir = listOf(File(rel), File("app/$rel")).firstOrNull { it.isDirectory }
            ?: error("$rel not found from ${File(".").absolutePath}")
        val callers = dir.walkTopDown().filter { it.isFile && it.extension == "kt" }
            .filter { "MediaPublisher.writeGranted(" in it.readText() }.map { it.name }.toList()
        assertEquals(listOf("XmpMetadataHelper.kt"), callers)
    }

    @Test
    fun `a process killed part-way through the overwrite has its capture restored before the retry`() {
        val data = data()
        killMidOverwrite(data)
        assertEquals("the request is still queued", listOf(uri.toString()), MediaWriteAuthorizations.pending(context).map { it.uri })

        val signed = mutableListOf<PendingMediaWrite>()
        MediaWriteAuthorizations.publishGranted(context) { signed += it }

        assertEquals("the retry finds the capture whole again and signs it", listOf(uri.toString()), signed.map { it.uri })
        assertEquals(data.toJsonString(), embedded(media.readBytes()))
        assertTrue(MediaWriteAuthorizations.pending(context).isEmpty())
    }

    @Test
    fun `a capture edited after it was staged is refused and keeps the edit`() {
        granted = true
        val data = data()
        val edited = XmpFixtures.png(byteArrayOf(0x78, 0x9C.toByte(), 0x09, 0x09, 0x09))
        var reads = 0
        // The first read stages the capture; the editor saves before the next one.
        provider.onOpen = { mode -> if (mode == "r" && ++reads == 2) media.writeBytes(edited) }

        assertThrows(XmpMetadataHelper.SourceChangedException::class.java) {
            XmpMetadataHelper.signMedia(context, uri, capture.path, data)
        }
        assertArrayEquals("the edit is never overwritten by the older snapshot", edited, media.readBytes())
    }

    @Test
    fun `the signing service signs captures only through signMedia`() {
        val rel = "src/main/kotlin"
        val dir = listOf(File(rel), File("app/$rel")).firstOrNull { it.isDirectory }
            ?: error("$rel not found from ${File(".").absolutePath}")
        val service = dir.walkTopDown().single { it.name == "MediaSigningService.kt" }.readText()
        assertTrue("the service signs through signMedia", "XmpMetadataHelper.signMedia(" in service)
        assertTrue("the service never writes a path directly", "XmpMetadataHelper.writeSignature(" !in service)
    }

    private fun segment(marker: Int, payload: ByteArray): ByteArray {
        val length = payload.size + 2
        return byteArrayOf(0xFF.toByte(), marker.toByte(), (length shr 8).toByte(), length.toByte()) + payload
    }

    private val latitude = 37.42
    private val longitude = -122.08

    /** A camera JPEG whose EXIF carries the place it was taken. */
    private fun geotaggedJpeg(): ByteArray {
        val file = File.createTempFile("geotagged-", ".jpg", folder.root)
        file.writeBytes(
            byteArrayOf(0xFF.toByte(), 0xD8.toByte()) +
                segment(0xE0, "JFIF\u0000\u0001\u0001".toByteArray()) +
                segment(0xDB, ByteArray(65) { it.toByte() }) +
                segment(0xDA, byteArrayOf(1, 1, 0, 0, 63, 0)) +
                byteArrayOf(0x12, 0x34, 0x56, 0x78, 0x9A.toByte(), 0xBC.toByte()) +
                byteArrayOf(0xFF.toByte(), 0xD9.toByte())
        )
        ExifInterface(file.path).apply {
            setLatLong(latitude, longitude)
            saveAttributes()
        }
        return file.readBytes().also { file.delete() }
    }

    /** [bytes] as MediaStore shows them to an app without ACCESS_MEDIA_LOCATION: no location. */
    private fun withoutLocation(bytes: ByteArray): ByteArray {
        val file = File.createTempFile("redacted-", ".jpg", folder.root)
        file.writeBytes(bytes)
        ExifInterface(file.path).apply {
            listOf(
                ExifInterface.TAG_GPS_LATITUDE, ExifInterface.TAG_GPS_LATITUDE_REF,
                ExifInterface.TAG_GPS_LONGITUDE, ExifInterface.TAG_GPS_LONGITUDE_REF
            ).forEach { setAttribute(it, null) }
            saveAttributes()
        }
        return file.readBytes().also { file.delete() }
    }

    private fun latLong(bytes: ByteArray): DoubleArray? = ExifInterface(ByteArrayInputStream(bytes)).latLong

    /** Make the capture a foreign geotagged JPEG whose location MediaStore redacts; its bytes. */
    private fun useGeotaggedJpeg(): ByteArray {
        val geotagged = geotaggedJpeg()
        check(latLong(geotagged) != null) { "the fixture must carry a location" }
        check(latLong(withoutLocation(geotagged)) == null) { "the redacted view must carry none" }
        capture = File(capture.parentFile, "IMG_0002.jpg").apply { writeBytes(geotagged) }
        media.writeBytes(geotagged)
        provider.mimeType = "image/jpeg"
        provider.redact = ::withoutLocation
        return geotagged
    }

    private fun queue(data: ContentAuthenticityData) =
        MediaWriteAuthorizations.add(context, PendingMediaWrite(uri.toString(), capture.path, "key-1", "Key", data))

    @Test
    fun `a foreign geotagged JPEG keeps its location when it is signed through its grant`() {
        useGeotaggedJpeg()
        val data = data(hash = AutoSignHash.contentHashFile(media, "image/jpeg"))
        queue(data)
        granted = true

        val signed = mutableListOf<PendingMediaWrite>()
        MediaWriteAuthorizations.publishGranted(context) { signed += it }

        assertEquals(listOf(uri.toString()), signed.map { it.uri })
        val written = media.readBytes()
        assertArrayEquals("the capture keeps where it was taken", doubleArrayOf(latitude, longitude), latLong(written), 1e-4)
        assertEquals(data.toJsonString(), XmpMetadataHelper.readSignatureFromUri(context.contentResolver, uri, "image/jpeg")?.toJsonString())
    }

    @Test
    fun `an interrupted write of a foreign geotagged JPEG puts back the capture with its location`() {
        val geotagged = useGeotaggedJpeg()
        queue(data(hash = AutoSignHash.contentHashFile(media, "image/jpeg")))
        granted = true
        var interrupts = 1
        MediaPublisher.overwriteStep = { if (it == "truncate" && interrupts-- > 0) Thread.currentThread().interrupt() }

        try {
            MediaWriteAuthorizations.publishGranted(context) {}
        } finally {
            MediaPublisher.overwriteStep = {}
            Thread.interrupted()
        }

        assertArrayEquals("the backup is the original, not the redacted view", geotagged, media.readBytes())
    }

    @Test
    fun `without location access a foreign capture is never overwritten`() {
        val geotagged = useGeotaggedJpeg()
        shadowOf(context as Application).denyPermissions(Manifest.permission.ACCESS_MEDIA_LOCATION)
        queue(data(hash = AutoSignHash.contentHashFile(media, "image/jpeg")))
        granted = true

        val signed = mutableListOf<PendingMediaWrite>()
        MediaWriteAuthorizations.publishGranted(context) { signed += it }

        assertTrue("nothing is signed from the redacted view", signed.isEmpty())
        assertArrayEquals("the capture is untouched", geotagged, media.readBytes())
    }

    @Test
    fun `a recovery that fails keeps the request queued, and a later one restores and signs the capture`() {
        val data = data()
        killMidOverwrite(data)
        val mixed = media.readBytes()
        provider.failWrites = true

        val signed = mutableListOf<PendingMediaWrite>()
        MediaWriteAuthorizations.publishGranted(context) { signed += it }

        assertTrue("nothing is signed while the capture is half-written", signed.isEmpty())
        assertArrayEquals("nothing is staged from or written over the half-written capture", mixed, media.readBytes())
        assertEquals(
            "the request stays queued, so a later grant can restore the capture",
            listOf(uri.toString()), MediaWriteAuthorizations.pending(context).map { it.uri }
        )

        provider.failWrites = false
        MediaWriteAuthorizations.publishGranted(context) { signed += it }

        assertEquals("the later recovery restores it and the retry signs it", listOf(uri.toString()), signed.map { it.uri })
        assertEquals(data.toJsonString(), embedded(media.readBytes()))
        assertTrue(MediaWriteAuthorizations.pending(context).isEmpty())
    }

    @Test
    fun `signMedia and a direct granted write both refuse while a recovery is pending`() {
        val data = data()
        killMidOverwrite(data)
        val mixed = media.readBytes()
        provider.failWrites = true
        val staged = folder.newFile("staged-direct.png").apply { writeBytes(original) }

        assertThrows(MediaPublisher.RecoveryPendingException::class.java) {
            XmpMetadataHelper.signMedia(context, uri, capture.path, data)
        }
        assertThrows(MediaPublisher.RecoveryPendingException::class.java) {
            MediaPublisher.writeGranted(context, uri, staged, data.contentHash, "image/png")
        }
        assertArrayEquals(mixed, media.readBytes())
        assertTrue("the record stays for a later recovery", MediaPublisher.recoveryPending(context, uri))
    }

    @Test
    fun `a denied request keeps a capture that is not restored yet`() {
        killMidOverwrite(data())
        granted = false

        MediaWriteAuthorizations.deny(context, listOf(uri.toString()))

        assertEquals(listOf(uri.toString()), MediaWriteAuthorizations.pending(context).map { it.uri })
    }

    @Test
    fun `a granted write called directly refuses without location access`() {
        val geotagged = useGeotaggedJpeg()
        shadowOf(context as Application).denyPermissions(Manifest.permission.ACCESS_MEDIA_LOCATION)
        granted = true
        val staged = folder.newFile("staged-direct.jpg").apply { writeBytes(geotagged) }

        assertThrows(MediaPublisher.OriginalUnavailableException::class.java) {
            MediaPublisher.writeGranted(context, uri, staged, AutoSignHash.contentHashFile(media, "image/jpeg"), "image/jpeg")
        }
        assertArrayEquals(geotagged, media.readBytes())
    }

    @Test
    fun `a capture is staged, backed up and checked only through its original`() {
        val rel = "src/main/kotlin"
        val dir = listOf(File(rel), File("app/$rel")).firstOrNull { it.isDirectory }
            ?: error("$rel not found from ${File(".").absolutePath}")
        val publisher = dir.walkTopDown().single { it.name == "MediaPublisher.kt" }.readText()
        assertEquals("the publisher reads a capture only in openOriginal", 1, Regex("openInputStream\\(").findAll(publisher).count())
        assertTrue("openOriginal reads the original URI", "openInputStream(original)" in publisher)
        val helper = dir.walkTopDown().single { it.name == "XmpMetadataHelper.kt" }.readText()
        val signMedia = helper.substringAfter("fun signMedia(").substringBefore("fun readSignature(")
        assertTrue("signMedia stages through openOriginal", "MediaPublisher.openOriginal(" in signMedia)
        assertTrue("signMedia never reads the redacted view", "openInputStream(" !in signMedia)
    }
}
