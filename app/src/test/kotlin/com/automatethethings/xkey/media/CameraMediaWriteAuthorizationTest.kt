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

import android.app.Application
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.Uri
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

        MediaWriteAuthorizations.deny(context)

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
    fun `the signing service signs captures only through signMedia`() {
        val rel = "src/main/kotlin"
        val dir = listOf(File(rel), File("app/$rel")).firstOrNull { it.isDirectory }
            ?: error("$rel not found from ${File(".").absolutePath}")
        val service = dir.walkTopDown().single { it.name == "MediaSigningService.kt" }.readText()
        assertTrue("the service signs through signMedia", "XmpMetadataHelper.signMedia(" in service)
        assertTrue("the service never writes a path directly", "XmpMetadataHelper.writeSignature(" !in service)
    }
}
