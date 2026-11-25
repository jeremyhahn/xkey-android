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
import androidx.test.core.app.ApplicationProvider
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.media.MediaSigningServiceFixture.Capture
import com.automatethethings.xkey.media.MediaSigningServiceFixture.Companion.IMAGES
import com.automatethethings.xkey.media.MediaSigningServiceFixture.Companion.KEY_ID
import com.automatethethings.xkey.media.MediaSigningServiceFixture.Companion.KEY_LABEL
import com.automatethethings.xkey.media.MediaSigningServiceFixture.Companion.KEY_TYPE
import com.automatethethings.xkey.media.MediaSigningServiceFixture.Companion.PUBLIC_KEY_DER
import com.automatethethings.xkey.media.MediaSigningServiceFixture.Companion.VIDEOS
import io.mockk.verify
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File
import java.io.InputStream

/**
 * What [MediaSigningService] does when a capture cannot be signed: nothing
 * is written, nothing is recorded as auto-signed, the process survives and
 * the next good capture still signs.
 *
 * A refused EXIF or sidecar write is asserted only that far: whether it is
 * audited and whether a later event retries it is being changed elsewhere.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class MediaSigningServiceFailureTest {

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

    /** [remaining] zero bytes, generated as they are read: no array of that size exists. */
    private class GeneratedStream(private var remaining: Long) : InputStream() {
        override fun read(): Int {
            if (remaining <= 0) return -1
            remaining--
            return 0
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (remaining <= 0) return -1
            val n = minOf(len.toLong(), remaining).toInt()
            java.util.Arrays.fill(b, off, off + n, 0)
            remaining -= n
            return n
        }
    }

    /** A stream whose first read runs the heap out. */
    private class OutOfMemoryStream : InputStream() {
        override fun read(): Int = throw OutOfMemoryError("test: capture too large for the heap")

        override fun read(b: ByteArray, off: Int, len: Int): Int =
            throw OutOfMemoryError("test: capture too large for the heap")
    }

    private var seed = 0

    private fun video(withPath: Boolean = true): Capture = fixture.addCapture(
        VIDEOS, "VID_${++seed}.mp4", MediaSigningServiceFixture.video(seed), "video/mp4", withPath
    )

    private fun assertNotAutoSigned(capture: Capture) {
        fixture.assertUnsigned(capture)
        verify(exactly = 0) { AuditLogger.logMediaAutoSigned(any(), any(), capture.uri.toString()) }
    }

    /** A new good capture after a failure is still signed: the service survived it. */
    private fun assertNextCaptureSigns() {
        val next = video()
        fixture.deliver(next.uri)
        assertTrue("the next capture must still be signed", next.sidecar.isFile)
        verify(exactly = 1) { AuditLogger.logMediaAutoSigned(KEY_ID, KEY_LABEL, next.uri.toString()) }
        verify(exactly = 1) { AuditLogger.logMediaAutoSigned(any(), any(), any()) }
    }

    @Test
    fun `a JPEG above 32 MiB is refused once with a failed key-use audit`() {
        val capture = fixture.addCapture(IMAGES, "IMG_big.jpg", MediaSigningServiceFixture.jpeg(), "image/jpeg")
        fixture.registerStream(capture.uri, GeneratedStream(AutoSignHash.MAX_CANONICAL_JPEG_BYTES + 1L))

        fixture.deliver(capture.uri)

        verify(exactly = 1) {
            AuditLogger.logKeyUsed(KEY_ID, KEY_LABEL, KEY_TYPE, "media_auto_sign", false, any(), any())
        }
        verify(exactly = 1) { AuditLogger.logKeyUsed(any(), any(), any(), any(), any(), any(), any()) }
        assertNotAutoSigned(capture)
        assertTrue("nothing may be signed", fixture.signCalls.isEmpty())

        fixture.deliver(capture.uri)

        verify(exactly = 1) { AuditLogger.logKeyUsed(any(), any(), any(), any(), any(), any(), any()) }
        assertTrue(fixture.signCalls.isEmpty())
        assertNextCaptureSigns()
    }

    @Test
    fun `a capture the provider cannot open is not signed and the next one is`() {
        val capture = video()
        capture.readable = false

        fixture.deliver(capture.uri)

        assertNotAutoSigned(capture)
        assertTrue(fixture.signCalls.isEmpty())
        assertNextCaptureSigns()
    }

    @Test
    fun `a missing public key is not signed and the next capture is`() {
        fixture.publicKeyDer = null
        val capture = video()

        fixture.deliver(capture.uri)

        assertNotAutoSigned(capture)
        assertTrue(fixture.signCalls.isEmpty())

        fixture.publicKeyDer = PUBLIC_KEY_DER
        assertNextCaptureSigns()
    }

    @Test
    fun `a signing failure writes no signature and the next capture signs`() {
        fixture.signFailure = IllegalStateException("test: the key store refused")
        val capture = video()

        fixture.deliver(capture.uri)

        assertNotAutoSigned(capture)

        fixture.signFailure = null
        assertNextCaptureSigns()
    }

    @Test
    fun `an out-of-memory error while hashing does not take the process down`() {
        val capture = video()
        fixture.registerStream(capture.uri, OutOfMemoryStream())

        fixture.deliver(capture.uri)

        assertNotAutoSigned(capture)
        assertTrue(fixture.signCalls.isEmpty())
        assertNextCaptureSigns()
    }

    @Test
    fun `a capture without a file path writes nothing beside its file and the queue is its retry`() {
        val capture = video(withPath = false)

        fixture.deliver(capture.uri)

        fixture.assertUnsigned(capture)
        val context = ApplicationProvider.getApplicationContext<Application>()
        val queued = MediaWriteAuthorizations.pending(context).map { it.uri }
        val signedInBand = XmpMetadataHelper.readSidecar(context, capture.uri) != null
        assertTrue("signed through its URI or queued: $queued", signedInBand || capture.uri.toString() in queued)

        // Handled once: a later event for the same URI starts no second job.
        capture.path = capture.file.path
        fixture.deliver(capture.uri)

        assertEquals(1, MediaSigningServiceFixture.queries[capture.uri])
        fixture.assertUnsigned(capture)
    }

    @Test
    fun `a refused sidecar write records no auto-signature and the service survives`() {
        val capture = video()
        // A non-empty directory where the sidecar goes: the write throws.
        assertTrue(capture.sidecar.mkdir())
        assertTrue(File(capture.sidecar, "keep").createNewFile())

        fixture.deliver(capture.uri)

        assertTrue("the sidecar path must still be the directory", capture.sidecar.isDirectory)
        verify(exactly = 0) { AuditLogger.logMediaAutoSigned(any(), any(), capture.uri.toString()) }
        assertNextCaptureSigns()
    }

    /**
     * MediaStore may notify the collection URI itself, without an item id.
     * The service treats it as a capture: it reads the settings and the key
     * row, finds the DATA path of the collection's first row, and then fails
     * to open the collection URI as a file, so nothing is signed or audited,
     * not even the capture whose path the query returned.
     */
    @Test
    fun `an event for the bare collection URI signs nothing`() {
        val bystander = fixture.addCapture(IMAGES, "IMG_bystander.png", MediaSigningServiceFixture.png(), "image/png")

        fixture.deliver(IMAGES)

        fixture.assertUnsigned(bystander)
        assertTrue(fixture.signCalls.isEmpty())
        verify(exactly = 0) { AuditLogger.logMediaAutoSigned(any(), any(), any()) }
        verify(exactly = 0) { AuditLogger.logKeyUsed(any(), any(), any(), any(), any(), any(), any()) }
    }
}
