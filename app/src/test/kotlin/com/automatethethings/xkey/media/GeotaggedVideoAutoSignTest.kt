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
import android.os.Build
import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
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
import org.robolectric.util.ReflectionHelpers
import java.io.File

/**
 * A capture is hashed and signed only from its original bytes. Without
 * ACCESS_MEDIA_LOCATION MediaStore serves a geotagged video redacted, and
 * its canonical hash covers the location, so a signature over that view
 * would match nothing once the original is readable: the capture waits in
 * the queue, unsigned, until location access is granted, and is never
 * dropped for the redaction.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class GeotaggedVideoAutoSignTest {

    @get:Rule
    val folder = TemporaryFolder()

    private lateinit var context: Context
    private val uri: Uri = Uri.parse("content://media/external/video/media/4343")
    private lateinit var media: File
    private lateinit var geotagged: ByteArray
    private lateinit var provider: FakeMediaProvider

    private var granted = false
    private val signedHashes = mutableListOf<String>()

    private val previousStore = MediaPublisher.mediaStore
    private val previousSign = AutoSigner.sign

    private val location = "+37.4200-122.0800/"

    /** A camera MP4 whose moov carries the place it was recorded (udta/©xyz). */
    private fun geotaggedMp4(): ByteArray = with(XmpFixtures) {
        box("ftyp", ascii("isom") + be32(0x200) + ascii("isommp42")) +
            box(
                "moov",
                box("mvhd", ByteArray(12) { 1 }) +
                    box("udta", box("©xyz", ascii(location)))
            ) +
            box("mdat", bytes(0x10, 0x20, 0x30, 0x40))
    }

    /** [bytes] as MediaStore shows them to an app without ACCESS_MEDIA_LOCATION: the location zeroed. */
    private fun withoutLocation(bytes: ByteArray): ByteArray {
        val needle = XmpFixtures.ascii(location)
        val out = bytes.copyOf()
        for (i in 0..out.size - needle.size) {
            if ((needle.indices).all { out[i + it] == needle[it] }) needle.indices.forEach { out[i + it] = 0 }
        }
        return out
    }

    private fun hasLocation(bytes: ByteArray): Boolean {
        val needle = XmpFixtures.ascii(location)
        return (0..bytes.size - needle.size).any { i -> needle.indices.all { bytes[i + it] == needle[it] } }
    }

    private fun data(hash: String) = ContentAuthenticityData(
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

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        geotagged = geotaggedMp4()
        media = folder.newFile("VID_0001.mp4").apply { writeBytes(geotagged) }
        provider = Robolectric.setupContentProvider(FakeMediaProvider::class.java, "media")
        provider.media = media
        provider.mimeType = "video/mp4"
        provider.redact = ::withoutLocation
        MediaPublisher.mediaStore = object : MediaPublisher.MediaStoreAccess {
            override fun ownerPackage(context: Context, uri: Uri): String? = "com.example.camera"
            override fun hasWriteGrant(context: Context, uri: Uri): Boolean = granted
            override fun createWriteRequest(context: Context, uris: List<Uri>): PendingIntent =
                PendingIntent.getActivity(context, 0, Intent(), PendingIntent.FLAG_IMMUTABLE)
        }
        AutoSigner.sign = { _, _, hash -> signedHashes += hash; data(hash) }
        MediaWriteAuthorizations.clear(context)
        shadowOf(context as Application).denyPermissions(Manifest.permission.ACCESS_MEDIA_LOCATION)
    }

    @After
    fun tearDown() {
        MediaPublisher.mediaStore = previousStore
        AutoSigner.sign = previousSign
        MediaWriteAuthorizations.clear(context)
    }

    @Test
    fun `a geotagged video captured without location access is signed from its original once access is granted`() {
        val originalHash = AutoSignHash.contentHashFile(media, "video/mp4")
        assertNotEquals(
            "the fixture's redacted view must hash differently",
            originalHash,
            AutoSignHash.contentHashUri(context.contentResolver, uri)
        )

        val outcome = AutoSigner.signCapture(context, uri, null, "key-1", "Key")

        assertEquals(AutoSigner.Outcome.AwaitingAccess, outcome)
        assertTrue("nothing is hashed or signed from the redacted view", signedHashes.isEmpty())
        val queued = MediaWriteAuthorizations.pending(context).single()
        assertEquals(uri.toString(), queued.uri)
        assertNull("it waits unsigned", queued.data)
        assertArrayEquals("nothing is written", geotagged, media.readBytes())

        // Write access alone: the original is still unreadable, so it stays queued.
        granted = true
        val signed = mutableListOf<PendingMediaWrite>()
        MediaWriteAuthorizations.publishGranted(context) { signed += it }
        assertTrue("still nothing signed", signed.isEmpty() && signedHashes.isEmpty())
        assertEquals("still queued", 1, MediaWriteAuthorizations.pending(context).size)

        shadowOf(context as Application).grantPermissions(Manifest.permission.ACCESS_MEDIA_LOCATION)
        MediaWriteAuthorizations.publishGranted(context) { signed += it }

        assertEquals(listOf(uri.toString()), signed.map { it.uri })
        assertEquals("signed once, over the original", listOf(originalHash), signedHashes)
        val written = media.readBytes()
        assertTrue("the video keeps where it was recorded", hasLocation(written))
        val embedded = XmpContainers.read(written.inputStream().buffered(), XmpContainers.Format.ISO_BMFF)
        assertEquals(data(originalHash).toJsonString(), embedded)
        assertTrue("the queue is empty", MediaWriteAuthorizations.pending(context).isEmpty())
    }

    @Test
    fun `a queued video signed over its redacted view is signed again from its original, never dropped`() {
        val redactedHash = AutoSignHash.contentHashUri(context.contentResolver, uri)
        MediaWriteAuthorizations.add(context, PendingMediaWrite(uri.toString(), null, "key-1", "Key", data(redactedHash)))
        shadowOf(context as Application).grantPermissions(Manifest.permission.ACCESS_MEDIA_LOCATION)
        granted = true

        val signed = mutableListOf<PendingMediaWrite>()
        MediaWriteAuthorizations.publishGranted(context) { signed += it }

        val originalHash = AutoSignHash.contentHashFile(geotaggedCopy(), "video/mp4")
        assertEquals(listOf(uri.toString()), signed.map { it.uri })
        assertEquals(listOf(originalHash), signedHashes)
        assertTrue(hasLocation(media.readBytes()))
        assertTrue(MediaWriteAuthorizations.pending(context).isEmpty())
    }

    @Test
    fun `on Android 10 a capture queued for location access drains once access is granted, with no write request`() {
        // Before Android 11 xKey writes media by path and MediaStore has no
        // write request (createWriteRequest needs Android 11). The unit tests
        // run on the SDK 34 runtime alone, so Android 10 is reported for this
        // test, with the platform's MediaStore in place.
        MediaPublisher.mediaStore = MediaPublisher.PlatformMediaStore
        MediaWriteAuthorizations.add(context, PendingMediaWrite(uri.toString(), media.path, "key-1", "Key", null))
        shadowOf(context as Application).grantPermissions(Manifest.permission.ACCESS_MEDIA_LOCATION)
        val sdk = Build.VERSION.SDK_INT
        ReflectionHelpers.setStaticField(Build.VERSION::class.java, "SDK_INT", Build.VERSION_CODES.Q)
        try {
            val request = MediaWriteAuthorizations.request(context)
            assertNotNull("the queued capture is offered", request)
            assertEquals(listOf(uri.toString()), request!!.uris)
            assertNull("nothing queued needs a write grant before Android 11", request.intent)

            val signed = mutableListOf<PendingMediaWrite>()
            MediaWriteAuthorizations.publishGranted(context) { signed += it }

            assertEquals(listOf(uri.toString()), signed.map { it.uri })
            assertEquals(listOf(AutoSignHash.contentHashFile(geotaggedCopy(), "video/mp4")), signedHashes)
            assertTrue("the video keeps where it was recorded", hasLocation(media.readBytes()))
            assertTrue("the queue is empty", MediaWriteAuthorizations.pending(context).isEmpty())
            assertNull("no request once nothing waits", MediaWriteAuthorizations.request(context))
        } finally {
            ReflectionHelpers.setStaticField(Build.VERSION::class.java, "SDK_INT", sdk)
        }
    }

    @Test
    fun `a signed geotagged video read without location access reports access unavailable, never a content-hash failure`() = runBlocking {
        shadowOf(context as Application).grantPermissions(Manifest.permission.ACCESS_MEDIA_LOCATION)
        granted = true
        assertEquals(AutoSigner.Outcome.Signed, AutoSigner.signCapture(context, uri, null, "key-1", "Key"))
        val stored = signedHashes.single()
        assertEquals(
            "the signed original verifies",
            MediaHasher.ContentHashCheck.MATCHES,
            MediaHasher.checkContentHashUri(context, uri, stored, MediaHasher.SignatureSource.IN_BAND)
        )

        // Revoked, or a recipient's installation without it: only the redacted view is readable.
        shadowOf(context as Application).denyPermissions(Manifest.permission.ACCESS_MEDIA_LOCATION)

        assertEquals(
            "verification reports the original unreadable, not tampering",
            MediaHasher.ContentHashCheck.ACCESS_UNAVAILABLE,
            MediaHasher.checkContentHashUri(context, uri, stored, MediaHasher.SignatureSource.IN_BAND)
        )
        // Signing and co-signing hash the same original: without access they hash nothing.
        assertThrows(MediaPublisher.OriginalUnavailableException::class.java) {
            MediaHasher.hashCanonicalUri(context, uri)
        }
        Unit
    }

    private fun geotaggedCopy(): File = folder.newFile().apply { writeBytes(geotagged) }
}
