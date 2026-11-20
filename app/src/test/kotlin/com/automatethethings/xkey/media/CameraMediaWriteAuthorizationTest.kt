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
import kotlinx.coroutines.runBlocking
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import java.io.ByteArrayInputStream
import java.io.File
import java.io.IOException

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
    fun `camera-owned media asks for write access and is signed through its URI once granted`() = runBlocking<Unit> {
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
    fun `a denied request drops its media unsigned`() = runBlocking<Unit> {
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
    fun `granted media that changed since it was hashed is refused`() = runBlocking<Unit> {
        granted = true
        val stale = data(hash = "0".repeat(64))

        assertThrows(XmpMetadataHelper.SourceChangedException::class.java) {
            XmpMetadataHelper.signMedia(context, uri, capture.path, stale)
        }
        assertArrayEquals(original, media.readBytes())
        assertArrayEquals(original, capture.readBytes())
    }

    @Test
    fun `media xKey owns keeps its path`() = runBlocking<Unit> {
        owner = context.packageName
        val data = data()

        val result = XmpMetadataHelper.signMedia(context, uri, capture.path, data)

        assertEquals(XmpMetadataHelper.MediaSignResult.Signed, result)
        assertTrue(requests.isEmpty())
        assertArrayEquals(original, media.readBytes())
        assertEquals(data.toJsonString(), embedded(capture.readBytes()))
    }

    @Test
    fun `a granted write that fails mid-copy leaves the capture whole and its request queued`() = runBlocking<Unit> {
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
    fun `a granted write interrupted at its final step leaves the capture byte-for-byte whole`() = runBlocking<Unit> {
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
            runBlocking { MediaWriteAuthorizations.publishGranted(context) {} }
        } finally {
            MediaPublisher.overwriteStep = {}
        }
        media.writeBytes(mediaAtKill)
        recovery.listFiles()!!.forEach { it.delete() }
        atKill.listFiles()!!.forEach { f -> f.copyTo(File(recovery, f.name)) }
    }

    @Test
    fun `a process killed part-way through the overwrite has its capture restored at the next start`() = runBlocking<Unit> {
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
    fun `a process killed before its write's record is committed leaves nothing after the next start`() = runBlocking<Unit> {
        // An active journal: the record stays while it cannot be read yet.
        killMidOverwrite(data())
        val recovery = MediaPublisher.recoveryDirectory(context)
        val active = MediaPublisher.GrantedWriteJournal(recovery, uri)
        val activeFiles = recovery.listFiles()!!.filter { it.name.startsWith(MediaPublisher.GrantedWriteJournal.PREFIX) }
        // Another capture's write, killed inside its commit before the record's rename.
        val other = MediaPublisher.GrantedWriteJournal(recovery, Uri.parse("content://media/external/images/media/99"))
        val stem = other.backup.name.removeSuffix(".bak")
        val unrecorded = listOf(other.backup, other.written, File(recovery, "$stem.tmp")).onEach { it.writeBytes(byteArrayOf(1)) }

        MediaPublisher.GrantedWriteJournal.readRecord = { throw IOException("the record could not be read") }
        try {
            MediaPublisher.recoverInterruptedWrites(context)
        } finally {
            MediaPublisher.GrantedWriteJournal.readRecord = { it.readText() }
        }

        unrecorded.forEach { assertTrue("${it.name} has no record: the start reclaims it", !it.exists()) }
        assertTrue("the active journal stays", active.recorded())
        activeFiles.forEach { assertTrue("${it.name} belongs to the active journal", it.exists()) }
    }

    @Test
    fun `a granted write called directly, past signMedia, still refuses an edited capture`() = runBlocking<Unit> {
        granted = true
        val hash = AutoSignHash.contentHashFile(capture, "image/png")
        val staged = folder.newFile("staged.png").apply { writeBytes(original) }
        val edited = XmpFixtures.png(byteArrayOf(0x78, 0x9C.toByte(), 0x07, 0x07, 0x07))
        media.writeBytes(edited)

        assertThrows(XmpMetadataHelper.SourceChangedException::class.java) {
            MediaPublisher.writeGranted(context, uri, staged, MediaPublisher.StagedSource.of(staged, "image/png", hash))
        }
        assertArrayEquals(edited, media.readBytes())
    }

    @Test
    fun `only signMedia calls the granted write`() = runBlocking<Unit> {
        val rel = "src/main/kotlin"
        val dir = listOf(File(rel), File("app/$rel")).firstOrNull { it.isDirectory }
            ?: error("$rel not found from ${File(".").absolutePath}")
        val callers = dir.walkTopDown().filter { it.isFile && it.extension == "kt" }
            .filter { "MediaPublisher.writeGranted(" in it.readText() }.map { it.name }.toList()
        assertEquals(listOf("XmpMetadataHelper.kt"), callers)
    }

    @Test
    fun `a process killed part-way through the overwrite has its capture restored before the retry`() = runBlocking<Unit> {
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
    fun `a capture edited after it was staged is refused and keeps the edit`() = runBlocking<Unit> {
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
    fun `the signing service signs captures only through signMedia`() = runBlocking<Unit> {
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
    fun `a foreign geotagged JPEG keeps its location when it is signed through its grant`() = runBlocking<Unit> {
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
    fun `an interrupted write of a foreign geotagged JPEG puts back the capture with its location`() = runBlocking<Unit> {
        val geotagged = useGeotaggedJpeg()
        queue(data(hash = AutoSignHash.contentHashFile(media, "image/jpeg")))
        granted = true
        var interrupts = 1
        MediaPublisher.overwriteStep = { if (it == "truncate" && interrupts-- > 0) Thread.currentThread().interrupt() }

        try {
            runBlocking { MediaWriteAuthorizations.publishGranted(context) {} }
        } finally {
            MediaPublisher.overwriteStep = {}
            Thread.interrupted()
        }

        assertArrayEquals("the backup is the original, not the redacted view", geotagged, media.readBytes())
    }

    @Test
    fun `without location access a foreign capture is never overwritten`() = runBlocking<Unit> {
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
    fun `a recovery that fails keeps the request queued, and a later one restores and signs the capture`() = runBlocking<Unit> {
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
    fun `an unsigned retry is hashed and signed only once its capture is restored`() = runBlocking<Unit> {
        val wholeHash = data().contentHash
        killMidOverwrite(data())
        val mixed = media.readBytes()
        // A failed publication queued the capture unsigned for a retry.
        MediaWriteAuthorizations.add(context, PendingMediaWrite(uri.toString(), capture.path, "key-1", "Key", null))
        val signedHashes = mutableListOf<String>()
        val previousSign = AutoSigner.sign
        AutoSigner.sign = { _, _, hash -> signedHashes += hash; data(hash) }
        try {
            provider.failWrites = true
            val signed = mutableListOf<PendingMediaWrite>()
            MediaWriteAuthorizations.publishGranted(context) { signed += it }

            assertTrue("nothing is hashed or signed over the part-written capture: $signedHashes", signedHashes.isEmpty())
            assertTrue(signed.isEmpty())
            assertEquals(
                "the request stays queued, unsigned",
                listOf<ContentAuthenticityData?>(null), MediaWriteAuthorizations.pending(context).map { it.data }
            )
            assertArrayEquals(mixed, media.readBytes())

            // The auto-signer meeting the capture now hashes nothing either.
            assertEquals(
                AutoSigner.Outcome.QueuedForRetry,
                AutoSigner.signCapture(context, uri, capture.path, "key-1", "Key")
            )
            assertTrue("the auto-signer signs nothing mid-recovery: $signedHashes", signedHashes.isEmpty())

            provider.failWrites = false
            MediaWriteAuthorizations.publishGranted(context) { signed += it }

            assertEquals("signed once, over the restored bytes", listOf(wholeHash), signedHashes)
            assertEquals(listOf(uri.toString()), signed.map { it.uri })
            assertEquals(data(wholeHash).toJsonString(), embedded(media.readBytes()))
            assertTrue(MediaWriteAuthorizations.pending(context).isEmpty())
        } finally {
            AutoSigner.sign = previousSign
        }
    }

    @Test
    fun `a staging failure keeps the request queued and a later retry signs it, while a capture that is gone leaves the queue`() = runBlocking<Unit> {
        val data = data()
        queue(data)
        granted = true
        // Staging the capture fails as a full disk does: an ordinary IOException before writeGranted.
        var full = true
        provider.onOpen = { mode -> if (full && 'w' !in mode) throw IOException("No space left on device") }

        val signed = mutableListOf<PendingMediaWrite>()
        MediaWriteAuthorizations.publishGranted(context) { signed += it }

        assertTrue("nothing is signed", signed.isEmpty())
        assertArrayEquals("nothing is written over the capture", original, media.readBytes())
        assertEquals(
            "the request stays queued, so the capture is retried once space is free",
            listOf(uri.toString()), MediaWriteAuthorizations.pending(context).map { it.uri }
        )

        full = false
        MediaWriteAuthorizations.publishGranted(context) { signed += it }

        assertEquals("the retry signs it", listOf(uri.toString()), signed.map { it.uri })
        assertEquals(data.toJsonString(), embedded(media.readBytes()))
        assertTrue(MediaWriteAuthorizations.pending(context).isEmpty())

        // A transient failure keeps the request; a capture that no longer exists is a permanent refusal.
        queue(data)
        provider.onOpen = { mode -> if ('w' !in mode) throw java.io.FileNotFoundException("deleted") }
        MediaWriteAuthorizations.publishGranted(context) { signed += it }

        assertEquals("a gone capture is not signed", 1, signed.size)
        assertTrue("a capture that is gone leaves the queue", MediaWriteAuthorizations.pending(context).isEmpty())
    }

    @Test
    fun `signMedia and a direct granted write both refuse while a recovery is pending`() = runBlocking<Unit> {
        val data = data()
        killMidOverwrite(data)
        val mixed = media.readBytes()
        provider.failWrites = true
        val staged = folder.newFile("staged-direct.png").apply { writeBytes(original) }

        assertThrows(MediaPublisher.RecoveryPendingException::class.java) {
            XmpMetadataHelper.signMedia(context, uri, capture.path, data)
        }
        assertThrows(MediaPublisher.RecoveryPendingException::class.java) {
            MediaPublisher.writeGranted(context, uri, staged, MediaPublisher.StagedSource.of(staged, "image/png", data.contentHash))
        }
        assertArrayEquals(mixed, media.readBytes())
        assertTrue("the record stays for a later recovery", MediaPublisher.recoveryPending(context, uri))
    }

    @Test
    fun `a denied request keeps a capture that is not restored yet`() = runBlocking<Unit> {
        killMidOverwrite(data())
        granted = false

        MediaWriteAuthorizations.deny(context, listOf(uri.toString()))

        assertEquals(listOf(uri.toString()), MediaWriteAuthorizations.pending(context).map { it.uri })
    }

    /** [bytes] with only its EXIF location changed, as a gallery's "edit location" saves it. */
    private fun relocated(bytes: ByteArray): ByteArray {
        val file = File.createTempFile("relocated-", ".jpg", folder.root)
        file.writeBytes(bytes)
        ExifInterface(file.path).apply {
            setLatLong(latitude + 1.0, longitude + 1.0)
            saveAttributes()
        }
        return file.readBytes().also { file.delete() }
    }

    @Test
    fun `a capture whose EXIF alone was edited after it was staged is refused and keeps the edit`() = runBlocking<Unit> {
        val geotagged = useGeotaggedJpeg()
        val edited = relocated(geotagged)
        check(!edited.contentEquals(geotagged)) { "the edit must change the file" }
        check(AutoSignHash.contentHashFile(media, "image/jpeg") == run {
            val f = File.createTempFile("edited-", ".jpg", folder.root).apply { writeBytes(edited) }
            AutoSignHash.contentHashFile(f, "image/jpeg").also { f.delete() }
        }) { "the edit must leave the signed content hash as it was" }
        granted = true
        val data = data(hash = AutoSignHash.contentHashFile(media, "image/jpeg"))
        var reads = 0
        // The first read stages the capture; the editor saves before the backup is read.
        provider.onOpen = { mode -> if (mode == "r" && ++reads == 2) media.writeBytes(edited) }

        assertThrows(XmpMetadataHelper.SourceChangedException::class.java) {
            XmpMetadataHelper.signMedia(context, uri, capture.path, data)
        }
        assertArrayEquals("the EXIF edit is never overwritten by the older snapshot", edited, media.readBytes())
    }

    @Test
    fun `a record that cannot be read leaves its recovery pending and keeps the backup`() = runBlocking<Unit> {
        val data = data()
        killMidOverwrite(data)
        val mixed = media.readBytes()
        val journal = MediaPublisher.GrantedWriteJournal(MediaPublisher.recoveryDirectory(context), uri)
        val backup = journal.backup.readBytes()
        val signed = mutableListOf<PendingMediaWrite>()
        MediaPublisher.GrantedWriteJournal.readRecord = { throw IOException("the record could not be read") }
        try {
            assertThrows(MediaPublisher.RecoveryPendingException::class.java) {
                MediaPublisher.recoverInterruptedWrite(context, uri)
            }
            MediaPublisher.recoverInterruptedWrites(context)
            MediaWriteAuthorizations.publishGranted(context) { signed += it }
        } finally {
            MediaPublisher.GrantedWriteJournal.readRecord = { it.readText() }
        }

        assertTrue("nothing is signed while the record is unreadable", signed.isEmpty())
        assertArrayEquals("nothing is staged from or written over the half-written capture", mixed, media.readBytes())
        assertTrue("the record stays", MediaPublisher.recoveryPending(context, uri))
        assertArrayEquals("the backup stays", backup, journal.backup.readBytes())

        MediaPublisher.recoverInterruptedWrites(context)
        assertArrayEquals("a later recovery puts the capture back", original, media.readBytes())
    }

    @Test
    fun `a capture edited in a gallery after a crash keeps the edit and the backup, and is not signed`() = runBlocking<Unit> {
        killMidOverwrite(data())
        val recovery = MediaPublisher.recoveryDirectory(context)
        val backup = MediaPublisher.GrantedWriteJournal(recovery, uri).backup.readBytes()
        // Before xKey runs again, the user saves an edit of the capture in a gallery.
        val edited = XmpFixtures.png(XmpFixtures.bytes(0x78, 0x9C, 0x07, 0x08, 0x09))
        media.writeBytes(edited)

        val signed = mutableListOf<PendingMediaWrite>()
        MediaWriteAuthorizations.publishGranted(context) { signed += it }

        assertArrayEquals("the gallery edit is never overwritten by the backup", edited, media.readBytes())
        assertTrue("the edited capture is not signed", signed.isEmpty())
        assertTrue("the record is settled", !MediaPublisher.recoveryPending(context, uri))
        assertTrue(
            "the version from before the write is kept as well",
            recovery.listFiles()!!.any { it.isFile && it.readBytes().contentEquals(backup) }
        )
    }

    /**
     * [killMidOverwrite], then a recovery whose restore the process dies in
     * after it has put back only part of the backup: the capture starts with
     * the backup's bytes, then the signed bytes the write left, then the
     * backup's again. The recovery directory is put back as it stood then.
     */
    private fun killMidRestore(data: ContentAuthenticityData) {
        killMidOverwrite(data)
        val mixed = media.readBytes()
        val recovery = MediaPublisher.recoveryDirectory(context)
        val atKill = folder.newFolder("recovery-at-restore-kill")
        var mediaAtKill = ByteArray(0)
        var kills = 1
        MediaPublisher.overwriteStep = {
            if (it == "truncate" && kills-- > 0) {
                val firstDiff = mixed.indices.first { i -> mixed[i] != original[i] }
                val restored = firstDiff + 1
                mediaAtKill = original.copyOf(restored) + mixed.copyOfRange(restored, mixed.size)
                check(!mediaAtKill.contentEquals(original)) { "the kill must leave signed bytes after the restored ones" }
                recovery.listFiles()!!.forEach { f -> f.copyTo(File(atKill, f.name)) }
                throw IllegalStateException("process killed")
            }
        }
        try {
            MediaPublisher.recoverInterruptedWrites(context)
        } finally {
            MediaPublisher.overwriteStep = {}
        }
        media.writeBytes(mediaAtKill)
        recovery.listFiles()!!.forEach { it.deleteRecursively() }
        atKill.listFiles()!!.forEach { f -> f.copyTo(File(recovery, f.name)) }
    }

    @Test
    fun `a restore interrupted part-way is finished by the next recovery and the request stays queued`() = runBlocking<Unit> {
        val data = data()
        killMidRestore(data)
        assertTrue("the kill left the capture mixed", !media.readBytes().contentEquals(original))

        MediaPublisher.recoverInterruptedWrites(context)

        assertArrayEquals("the next recovery finishes the restore", original, media.readBytes())
        assertTrue("the record is settled", !MediaPublisher.recoveryPending(context, uri))
        assertEquals(
            "the request stays queued",
            listOf(uri.toString()), MediaWriteAuthorizations.pending(context).map { it.uri }
        )

        val signed = mutableListOf<PendingMediaWrite>()
        MediaWriteAuthorizations.publishGranted(context) { signed += it }
        assertEquals("the retry signs the restored capture", listOf(uri.toString()), signed.map { it.uri })
        assertEquals(data.toJsonString(), embedded(media.readBytes()))
    }

    @Test
    fun `a restore interrupted part-way, then a retry, finishes the restore before signing`() = runBlocking<Unit> {
        val data = data()
        killMidRestore(data)

        val signed = mutableListOf<PendingMediaWrite>()
        MediaWriteAuthorizations.publishGranted(context) { signed += it }

        assertEquals("the queued request is not dropped", listOf(uri.toString()), signed.map { it.uri })
        assertEquals(data.toJsonString(), embedded(media.readBytes()))
        assertTrue(MediaWriteAuthorizations.pending(context).isEmpty())
    }

    @Test
    fun `a capture edited in a gallery after an interrupted restore keeps the edit and the backup`() = runBlocking<Unit> {
        killMidRestore(data())
        val recovery = MediaPublisher.recoveryDirectory(context)
        val backup = MediaPublisher.GrantedWriteJournal(recovery, uri).backup.readBytes()
        val edited = XmpFixtures.png(XmpFixtures.bytes(0x78, 0x9C, 0x07, 0x08, 0x09))
        media.writeBytes(edited)

        val signed = mutableListOf<PendingMediaWrite>()
        MediaWriteAuthorizations.publishGranted(context) { signed += it }

        assertArrayEquals("the gallery edit is never overwritten by the backup", edited, media.readBytes())
        assertTrue("the edited capture is not signed", signed.isEmpty())
        assertTrue("the record is settled", !MediaPublisher.recoveryPending(context, uri))
        assertTrue(
            "the version from before the write is kept as well",
            recovery.listFiles()!!.any { it.isFile && it.readBytes().contentEquals(backup) }
        )
    }

    @Test
    fun `a queue that cannot be read is kept whole and add fails instead of replacing it`() = runBlocking<Unit> {
        queue(data())
        val store = File(context.filesDir, "media-write-requests.json")
        val before = store.readBytes()
        val other = PendingMediaWrite("content://media/external/images/media/4343", null, "key-1", "Key", data())

        MediaWriteAuthorizations.readStore = { throw IOException("the queue could not be read") }
        try {
            assertThrows(IOException::class.java) { MediaWriteAuthorizations.add(context, other) }
        } finally {
            MediaWriteAuthorizations.readStore = { it.readText() }
        }
        assertArrayEquals("the queue is untouched", before, store.readBytes())

        store.writeText("{not a queue")
        assertThrows(IOException::class.java) { MediaWriteAuthorizations.add(context, other) }
        assertEquals("a queue that cannot be parsed is untouched", "{not a queue", store.readText())
    }

    @Test
    fun `a queue read that fails while a request is removed keeps the queue whole`() = runBlocking<Unit> {
        queue(data())
        val store = File(context.filesDir, "media-write-requests.json")
        val before = store.readBytes()
        granted = false
        var reads = 0
        // The listing reads the queue; the removal's own read fails.
        MediaWriteAuthorizations.readStore = { if (++reads > 1) throw IOException("the queue could not be read") else it.readText() }
        try {
            assertThrows(IOException::class.java) { MediaWriteAuthorizations.deny(context, listOf(uri.toString())) }
        } finally {
            MediaWriteAuthorizations.readStore = { it.readText() }
        }
        assertArrayEquals("the queue is untouched", before, store.readBytes())
        assertEquals(listOf(uri.toString()), MediaWriteAuthorizations.pending(context).map { it.uri })
    }

    @Test
    fun `a granted write called directly refuses without location access`() = runBlocking<Unit> {
        val geotagged = useGeotaggedJpeg()
        shadowOf(context as Application).denyPermissions(Manifest.permission.ACCESS_MEDIA_LOCATION)
        granted = true
        val staged = folder.newFile("staged-direct.jpg").apply { writeBytes(geotagged) }

        assertThrows(MediaPublisher.OriginalUnavailableException::class.java) {
            MediaPublisher.writeGranted(
                context, uri, staged, MediaPublisher.StagedSource.of(staged, "image/jpeg", AutoSignHash.contentHashFile(media, "image/jpeg"))
            )
        }
        assertArrayEquals(geotagged, media.readBytes())
    }

    @Test
    fun `a capture is staged, backed up and checked only through its original`() = runBlocking<Unit> {
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
