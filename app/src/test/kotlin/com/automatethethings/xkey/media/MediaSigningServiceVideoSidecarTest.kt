/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
 *
 * This file is part of xkey-android.
 *
 * xkey-android is dual-licensed:
 *
 * 1. GNU Affero General Public License v3.0 (AGPL-3.0)
 *    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
 *
 * 2. Commercial License
 *    Contact licensing@automatethethings.com for commercial licensing options.
 */

package com.automatethethings.xkey.media

import android.app.Application
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.media.MediaSigningServiceFixture.Companion.IMAGES
import com.automatethethings.xkey.media.MediaSigningServiceFixture.Companion.KEY_ALGORITHM
import com.automatethethings.xkey.media.MediaSigningServiceFixture.Companion.KEY_ID
import com.automatethethings.xkey.media.MediaSigningServiceFixture.Companion.KEY_LABEL
import com.automatethethings.xkey.media.MediaSigningServiceFixture.Companion.PUBLIC_KEY_DER
import com.automatethethings.xkey.media.MediaSigningServiceFixture.Companion.SIGNATURE
import com.automatethethings.xkey.media.MediaSigningServiceFixture.Companion.VIDEOS
import io.mockk.verify
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * What [MediaSigningService] writes for a new capture: a video or a photo
 * other than JPEG gets a `.xkeysig` sidecar over the whole file, a JPEG gets
 * the signature embedded over its canonical hash, and the stored hash is one
 * the matching verifier source accepts.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class MediaSigningServiceVideoSidecarTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    private lateinit var fixture: MediaSigningServiceFixture

    @Before
    fun setUp() {
        fixture = MediaSigningServiceFixture(tempFolder.newFolder("media"))
        fixture.setUp()
        fixture.start()
    }

    @After
    fun tearDown() = fixture.tearDown()

    /** The one signature on [capture], checked against the mocked key; returns it. */
    private fun assertSignedByKey(capture: MediaSigningServiceFixture.Capture): ContentAuthenticityData {
        val data = XmpMetadataHelper.readSignature(capture.file.path)
        assertNotNull("${capture.file.name} must be signed", data)
        val entry = data!!.signatures.single()
        assertEquals(SignerRole.CREATOR, entry.role)
        assertEquals(KEY_LABEL, entry.signerName)
        assertEquals(KEY_ALGORITHM, entry.algorithm)
        assertEquals(MediaHasher.hashBytes(PUBLIC_KEY_DER), entry.keyFingerprint)
        assertEquals(java.util.Base64.getEncoder().encodeToString(SIGNATURE), entry.value)

        val call = fixture.signCalls.single()
        assertEquals(KeystoreManager.generalKeyAlias(KEY_ID), call.alias)
        assertArrayEquals(PUBLIC_KEY_DER, call.publicKeyDer)
        assertArrayEquals(SignatureVerifier.hexToBytes(data.contentHash), call.data)
        assertEquals(KeystoreManager.jcaSignatureAlgorithm(KEY_ALGORITHM), call.jcaAlgorithm)

        verify(exactly = 1) { AuditLogger.logMediaAutoSigned(any(), any(), any()) }
        verify(exactly = 1) { AuditLogger.logMediaAutoSigned(KEY_ID, KEY_LABEL, capture.uri.toString()) }
        return data
    }

    /** A new capture [name] of [mimeType] is signed into a sidecar over the whole file. */
    private fun assertSignedIntoSidecar(collection: android.net.Uri, name: String, mimeType: String, bytes: ByteArray) {
        val capture = fixture.addCapture(collection, name, bytes, mimeType)

        fixture.deliver(capture.uri)

        assertTrue("$name must get a sidecar", capture.sidecar.isFile)
        assertArrayEquals("$name itself must be unchanged", bytes, capture.file.readBytes())
        val data = assertSignedByKey(capture)
        assertEquals(MediaHasher.hashBytes(bytes), data.contentHash)
        assertTrue(
            "a sidecar verifier must accept the stored hash",
            MediaHasher.contentHashMatches(
                data.contentHash, capture.file.readBytes(), mimeType, MediaHasher.SignatureSource.SIDECAR
            )
        )
    }

    @Test
    fun `a new mp4 video is signed into a sidecar over the whole file`() {
        assertSignedIntoSidecar(VIDEOS, "VID_0001.mp4", "video/mp4", MediaSigningServiceFixture.video())
    }

    @Test
    fun `a new mov video is signed into a sidecar over the whole file`() {
        assertSignedIntoSidecar(VIDEOS, "VID_0002.mov", "video/quicktime", MediaSigningServiceFixture.video(2))
    }

    @Test
    fun `a new mkv video is signed into a sidecar over the whole file`() {
        assertSignedIntoSidecar(VIDEOS, "VID_0003.mkv", "video/x-matroska", MediaSigningServiceFixture.video(3))
    }

    @Test
    fun `a new PNG photo is signed into a sidecar over the whole file`() {
        assertSignedIntoSidecar(IMAGES, "IMG_0001.png", "image/png", MediaSigningServiceFixture.png())
    }

    @Test
    fun `a new JPEG photo is signed in place over its canonical hash`() {
        val bytes = MediaSigningServiceFixture.jpeg()
        val capture = fixture.addCapture(IMAGES, "IMG_0002.jpg", bytes, "image/jpeg")

        fixture.deliver(capture.uri)

        assertFalse("a JPEG carries its own signature, no sidecar", capture.sidecar.exists())
        val signed = capture.file.readBytes()
        assertFalse("the signature must be embedded in the file", bytes.contentEquals(signed))
        val data = assertSignedByKey(capture)
        assertEquals(MediaHasher.hashCanonical(bytes, "image/jpeg"), data.contentHash)
        assertNotEquals(MediaHasher.hashBytes(bytes), data.contentHash)
        assertTrue(
            "an in-band verifier must accept the stored hash of the signed file",
            MediaHasher.contentHashMatches(
                data.contentHash, signed, "image/jpeg", MediaHasher.SignatureSource.IN_BAND
            )
        )
    }

    @Test
    fun `a second event for a signed capture signs nothing more`() {
        val capture = fixture.addCapture(VIDEOS, "VID_0004.mp4", MediaSigningServiceFixture.video(4), "video/mp4")
        fixture.deliver(capture.uri)
        val sidecar = capture.sidecar.readText()

        fixture.deliver(capture.uri)

        assertEquals(1, fixture.signCalls.size)
        verify(exactly = 1) { AuditLogger.logMediaAutoSigned(any(), any(), any()) }
        assertEquals("the sidecar must not be rewritten", sidecar, capture.sidecar.readText())
    }

    /**
     * A JPEG file the resolver does not type as JPEG is still a JPEG: it is
     * signed in place over its canonical hash, and the app finds and checks
     * that signature through its URI with the resolver's own type.
     */
    @Test
    fun `a jpg file the resolver does not type as JPEG gets a hash its embedded signature accepts`() {
        val bytes = MediaSigningServiceFixture.jpeg()
        val capture = fixture.addCapture(IMAGES, "IMG_0005.jpg", bytes, "application/octet-stream")

        fixture.deliver(capture.uri)

        assertFalse("a .jpg carries its own signature, no sidecar", capture.sidecar.exists())
        val data = assertSignedByKey(capture)
        val resolver = fixture.resolver
        assertEquals("application/octet-stream", resolver.getType(capture.uri))
        val found = XmpMetadataHelper.readSignatureFromUri(resolver, capture.uri, resolver.getType(capture.uri))
        assertNotNull("the embedded signature must be found through the URI", found)
        assertEquals(data.contentHash, found!!.contentHash)
        assertTrue(
            "an in-band verifier must accept the stored hash of the signed file",
            MediaHasher.contentHashMatchesUri(
                resolver, capture.uri, data.contentHash, MediaHasher.SignatureSource.IN_BAND
            )
        )
    }
}
