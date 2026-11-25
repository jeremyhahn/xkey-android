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
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
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
 * A camera JPEG its provider does not type as a JPEG is signed over its
 * canonical JPEG hash, so its signature goes where a JPEG's goes: into its
 * EXIF, replacing an earlier signer's, never into a sidecar the earlier
 * embedded signature would shadow.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class UntypedForeignJpegStorageTest {

    @get:Rule
    val folder = TemporaryFolder()

    private lateinit var context: Context
    private val uri: Uri = Uri.parse("content://media/external/images/media/4343")
    private lateinit var media: File
    private lateinit var provider: FakeMediaProvider

    /** Every sidecar xKey was asked to own: none for a JPEG. */
    private val ownedFiles = mutableListOf<String>()

    private val previousStore = MediaPublisher.mediaStore

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        media = folder.newFile("media-4343")
        provider = Robolectric.setupContentProvider(FakeMediaProvider::class.java, "media")
        provider.media = media
        MediaPublisher.mediaStore = object : MediaPublisher.MediaStoreAccess {
            override fun ownerPackage(context: Context, uri: Uri): String? = "com.example.camera"
            override fun hasWriteGrant(context: Context, uri: Uri): Boolean = true
            override fun createWriteRequest(context: Context, uris: List<Uri>): PendingIntent =
                PendingIntent.getActivity(context, 0, Intent(), PendingIntent.FLAG_IMMUTABLE)
            override fun ownedFile(context: Context, relativePath: String, displayName: String): MediaPublisher.OwnedFile? {
                ownedFiles += relativePath + displayName
                return null
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

    private fun signedBy(name: String, fingerprint: Char, hash: String) = ContentAuthenticityData(
        contentHash = hash,
        signatures = listOf(
            SignatureEntry(
                keyFingerprint = fingerprint.toString().repeat(64),
                signerName = name,
                algorithm = "ES256",
                value = "c2lnbmF0dXJl",
                timestamp = "2026-01-01T00:00:00Z",
                role = SignerRole.CREATOR
            )
        )
    )

    /** A camera JPEG named [name] whose EXIF already holds another signer's signature, served typed [mimeType]. */
    private fun cameraJpeg(name: String, mimeType: String): File {
        val capture = File(folder.newFolder("DCIM", "Camera"), name)
        capture.writeBytes(MediaSigningServiceFixture.jpeg())
        val earlier = signedBy("Earlier Signer", 'a', AutoSignHash.contentHashFile(capture, MediaHasher.JPEG_MIME_TYPE))
        XmpMetadataHelper.writeSignature(capture.path, earlier)
        check(!File(XmpMetadataHelper.getSidecarPath(capture.path)).exists()) { "the earlier signature must be embedded" }
        media.writeBytes(capture.readBytes())
        provider.mimeType = mimeType
        val found = XmpMetadataHelper.readSignatureFromUri(context.contentResolver, uri, MediaHasher.JPEG_MIME_TYPE)
        check(found?.signatures?.single()?.signerName == "Earlier Signer") { "the fixture must carry the earlier signer" }
        return capture
    }

    private fun assertSignedIntoExif(filePath: String?, mimeType: String) {
        val data = signedBy("New Signer", 'b', AutoSignHash.contentHashOriginal(context, uri))

        val result = XmpMetadataHelper.signMedia(context, uri, filePath, data)

        assertEquals(XmpMetadataHelper.MediaSignResult.Signed, result)
        assertTrue("a JPEG gets no owned sidecar: $ownedFiles", ownedFiles.isEmpty())
        if (filePath != null) {
            assertFalse("a JPEG gets no sidecar beside it", File(XmpMetadataHelper.getSidecarPath(filePath)).exists())
        }
        val found = XmpMetadataHelper.readSignatureFromUri(context.contentResolver, uri, mimeType)
        assertEquals("the EXIF holds the new signature", data.toJsonString(), found?.toJsonString())
        val verified = MediaHasher.checkInBandUri(context, uri, mimeType)
        assertEquals("verification sees the new signer", "New Signer", verified?.data?.signatures?.single()?.signerName)
        assertEquals("the stored hash verifies the published bytes", MediaHasher.ContentHashCheck.MATCHES, verified?.check)
    }

    @Test
    fun `a camera JPEG typed application octet-stream is signed into its EXIF over the earlier signer`() {
        cameraJpeg("IMG_0001", "application/octet-stream")

        assertSignedIntoExif(null, "application/octet-stream")
    }

    @Test
    fun `a camera jpg typed with a wrong MIME type is signed into its EXIF over the earlier signer`() {
        val capture = cameraJpeg("IMG_0002.jpg", "text/plain")

        assertSignedIntoExif(capture.path, "text/plain")
    }
}
