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
import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
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
import java.io.File

/**
 * Scoped storage: a write grant for a camera capture covers that capture
 * alone, and a file created beside it in DCIM is refused. When the
 * container refuses the packet (an MP4 whose last box runs to the end of
 * the file), the signature goes to a sidecar xKey owns, never one beside
 * the capture, and the queued request is signed and leaves the queue.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class GrantedSidecarDestinationTest {

    @get:Rule
    val folder = TemporaryFolder()

    private lateinit var context: Context
    private val uri: Uri = Uri.parse("content://media/external/video/media/5151")
    private lateinit var cameraDir: File
    private lateinit var capture: File
    private lateinit var media: File
    private lateinit var owned: File
    private lateinit var original: ByteArray
    private lateinit var provider: FakeMediaProvider
    private val ownedRequests = mutableListOf<Pair<String, String>>()
    private val previousStore = MediaPublisher.mediaStore

    /** ftyp and moov, then an mdat of size 0: it runs to the end of the file, so no box may follow it. */
    private fun openEndedMp4(): ByteArray = with(XmpFixtures) {
        box("ftyp", ascii("isom") + be32(0x200) + ascii("isommp42")) +
            box("moov", box("mvhd", ByteArray(12) { 1 })) +
            be32(0) + ascii("mdat") + bytes(0x10, 0x20, 0x30, 0x40)
    }

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        cameraDir = folder.newFolder("DCIM", "Camera")
        capture = File(cameraDir, "VID_0001.mp4")
        original = openEndedMp4()
        capture.writeBytes(original)
        media = folder.newFile("media-5151.mp4").apply { writeBytes(original) }
        owned = File(folder.newFolder("owned"), "sidecar.xkeysig")
        provider = Robolectric.setupContentProvider(FakeMediaProvider::class.java, "media")
        provider.media = media
        provider.mimeType = "video/mp4"
        MediaPublisher.mediaStore = object : MediaPublisher.MediaStoreAccess {
            override fun ownerPackage(context: Context, uri: Uri): String? = "com.example.camera"
            override fun hasWriteGrant(context: Context, uri: Uri): Boolean = true
            override fun createWriteRequest(context: Context, uris: List<Uri>): PendingIntent =
                PendingIntent.getActivity(context, 0, Intent(), PendingIntent.FLAG_IMMUTABLE)
            override fun ownedFile(context: Context, relativePath: String, displayName: String): MediaPublisher.OwnedFile {
                ownedRequests += relativePath to displayName
                // MediaStore inserts the entry when none of that name exists yet.
                return MediaPublisher.OwnedFile(Uri.fromFile(owned), created = !owned.isFile)
            }
        }
        MediaWriteAuthorizations.clear(context)
        shadowOf(context as Application).grantPermissions(Manifest.permission.ACCESS_MEDIA_LOCATION)
        // Scoped storage: nothing but the granted capture is writable in DCIM.
        cameraDir.setWritable(false)
    }

    @After
    fun tearDown() {
        cameraDir.setWritable(true)
        MediaPublisher.mediaStore = previousStore
        MediaWriteAuthorizations.clear(context)
    }

    private fun data(key: String = "b") = ContentAuthenticityData(
        contentHash = AutoSignHash.contentHashFile(capture, "video/mp4"),
        signatures = listOf(
            SignatureEntry(
                keyFingerprint = key.repeat(64),
                signerName = "Test Signer",
                algorithm = "ES256",
                value = "c2lnbmF0dXJl",
                timestamp = "2026-01-01T00:00:00Z",
                role = SignerRole.CREATOR
            )
        )
    )

    @Test
    fun `a refused container's sidecar goes to a file xKey owns, never beside the capture`() {
        val signed = data()

        val result = XmpMetadataHelper.signMedia(context, uri, capture.path, signed)

        assertEquals(XmpMetadataHelper.MediaSignResult.Signed, result)
        assertTrue("nothing is created beside the capture", cameraDir.listFiles()!!.map { it.name } == listOf("VID_0001.mp4"))
        assertArrayEquals("the capture is untouched", original, media.readBytes())
        // Off primary storage: under volumes/, at the capture's full directory.
        val directory = cameraDir.canonicalFile.invariantSeparatorsPath.trim('/')
        assertEquals(listOf("Documents/xKey/volumes/$directory/" to "VID_0001.mp4.xkeysig"), ownedRequests)
        assertEquals(signed.toJsonString(), owned.readText())
    }

    @Test
    fun `the sidecar xKey owns reads back by the capture's path, and an added signature is written back to it`() {
        // Where MediaStore keeps the file it inserts: the external root and its relative path.
        @Suppress("DEPRECATION")
        val root = android.os.Environment.getExternalStorageDirectory()
        val (relativePath, name) = XmpMetadataHelper.ownedSidecarLocation(capture.path, uri)
        owned = File(File(root, relativePath).apply { mkdirs() }, name)
        val signed = data()
        try {
            XmpMetadataHelper.signMedia(context, uri, capture.path, signed)

            assertEquals(signed.toJsonString(), XmpMetadataHelper.readSignature(capture.path)?.toJsonString())
            val cosigner = signed.signatures.single().copy(keyFingerprint = "d".repeat(64), role = SignerRole.WITNESS)
            XmpMetadataHelper.appendSignature(capture.path, cosigner)

            assertEquals(listOf("VID_0001.mp4"), cameraDir.listFiles()!!.map { it.name })
            assertEquals(2, XmpMetadataHelper.readSignature(capture.path)?.signatures?.size)
            assertArrayEquals("the capture is untouched", original, media.readBytes())
        } finally {
            owned.delete()
        }
    }

    @Test
    fun `a queued capture whose container refuses the packet is signed and leaves the queue`() = runBlocking<Unit> {
        MediaWriteAuthorizations.add(context, PendingMediaWrite(uri.toString(), capture.path, "key-1", "Key", data()))
        val published = mutableListOf<PendingMediaWrite>()

        MediaWriteAuthorizations.publishGranted(context) { published += it }

        assertEquals(listOf(uri.toString()), published.map { it.uri })
        assertTrue(MediaWriteAuthorizations.pending(context).isEmpty())
        assertEquals(data().toJsonString(), owned.readText())
    }

    /** The sidecar beside the capture, written before the owned location existed. */
    private val legacy: File get() = File(XmpMetadataHelper.getSidecarPath(capture.path))

    /** Write [data] beside the capture: DCIM is writable for that one write only. */
    private fun writeLegacy(data: ContentAuthenticityData) {
        cameraDir.setWritable(true)
        try {
            legacy.writeText(data.toJsonString())
        } finally {
            cameraDir.setWritable(false)
        }
    }

    /** Place [owned] where MediaStore keeps the file it inserts: the external root and its relative path. */
    private fun ownedAtExternalRoot() {
        @Suppress("DEPRECATION")
        val root = android.os.Environment.getExternalStorageDirectory()
        val (relativePath, name) = XmpMetadataHelper.ownedSidecarLocation(capture.path, uri)
        owned = File(File(root, relativePath).apply { mkdirs() }, name)
    }

    @Test
    fun `a re-sign beside a legacy sidecar reads back the new signature by path and by URI`() {
        ownedAtExternalRoot()
        provider.dataPath = capture.path
        val stale = data("a")
        writeLegacy(stale)
        try {
            val result = XmpMetadataHelper.signMedia(context, uri, capture.path, data("b"))

            assertEquals(XmpMetadataHelper.MediaSignResult.Signed, result)
            assertEquals("b".repeat(64), XmpMetadataHelper.readSignature(capture.path)?.signatures?.single()?.keyFingerprint)
            assertEquals("b".repeat(64), XmpMetadataHelper.readSidecar(context, uri)?.signatures?.single()?.keyFingerprint)
            assertEquals("the legacy sidecar is untouched", stale.toJsonString(), legacy.readText())
        } finally {
            owned.delete()
        }
    }

    @Test
    fun `with both sidecars an added signature lands in the one xKey owns`() {
        ownedAtExternalRoot()
        val stale = data("a")
        writeLegacy(stale)
        try {
            XmpMetadataHelper.signMedia(context, uri, capture.path, data("b"))
            val cosigner = data("b").signatures.single().copy(keyFingerprint = "d".repeat(64), role = SignerRole.WITNESS)

            XmpMetadataHelper.appendSignature(capture.path, cosigner)

            val written = ContentAuthenticityData.fromJsonString(owned.readText())
            assertEquals(listOf("b".repeat(64), "d".repeat(64)), written.signatures.map { it.keyFingerprint })
            assertEquals("the legacy sidecar is untouched", stale.toJsonString(), legacy.readText())
        } finally {
            owned.delete()
        }
    }

    @Test
    fun `a legacy sidecar alone still reads back by path and by URI`() {
        ownedAtExternalRoot()
        provider.dataPath = capture.path
        writeLegacy(data("a"))

        assertTrue("no owned sidecar", !owned.exists())
        assertEquals("a".repeat(64), XmpMetadataHelper.readSignature(capture.path)?.signatures?.single()?.keyFingerprint)
        assertEquals("a".repeat(64), XmpMetadataHelper.readSidecar(context, uri)?.signatures?.single()?.keyFingerprint)
    }
}
