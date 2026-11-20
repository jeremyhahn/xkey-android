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
import android.app.Activity
import android.app.Application
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Looper
import androidx.test.core.app.ApplicationProvider
import org.junit.After
import org.junit.Assert.assertArrayEquals
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
import org.robolectric.android.controller.ActivityController
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowToast
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * The write request screen: the grant a MediaStore write request gives
 * lives only as long as the activity that asked for it, so the screen stays
 * until publication ends; and a refusal drops only the captures it asked
 * for, never one queued while the dialog was open.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class MediaWriteRequestActivityTest {

    @get:Rule
    val folder = TemporaryFolder()

    private lateinit var context: Context
    private val first: Uri = Uri.parse("content://media/external/images/media/101")
    private val later: Uri = Uri.parse("content://media/external/images/media/102")
    private lateinit var capture: File
    private lateinit var media: File

    private var granted = false

    /** Held shut, it keeps publication inside its grant check. */
    private var gate = CountDownLatch(0)
    private val previousStore = MediaPublisher.mediaStore

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        capture = File(folder.newFolder("DCIM", "Camera"), "IMG_0101.png").apply { writeBytes(XmpFixtures.png()) }
        media = folder.newFile("media.png").apply { writeBytes(capture.readBytes()) }
        Robolectric.setupContentProvider(FakeMediaProvider::class.java, "media").media = media
        MediaPublisher.mediaStore = object : MediaPublisher.MediaStoreAccess {
            override fun ownerPackage(context: Context, uri: Uri): String? = "com.example.camera"
            override fun hasWriteGrant(context: Context, uri: Uri): Boolean {
                if (Looper.myLooper() != Looper.getMainLooper()) gate.await(10, TimeUnit.SECONDS)
                return granted
            }
            override fun createWriteRequest(context: Context, uris: List<Uri>): PendingIntent =
                PendingIntent.getActivity(context, 0, Intent(), PendingIntent.FLAG_IMMUTABLE)
        }
        MediaWriteAuthorizations.clear(context)
        shadowOf(context as Application).grantPermissions(Manifest.permission.ACCESS_MEDIA_LOCATION)
    }

    @After
    fun tearDown() {
        gate.countDown()
        MediaPublisher.mediaStore = previousStore
        MediaWriteAuthorizations.clear(context)
    }

    private fun queue(uri: Uri) = MediaWriteAuthorizations.add(
        context,
        PendingMediaWrite(
            uri.toString(), capture.path, "key-1", "Key",
            ContentAuthenticityData(
                contentHash = AutoSignHash.contentHashFile(capture, "image/png"),
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
        )
    )

    /** The screen, opened and showing its write request; answer it with [answer]. */
    private fun open(): ActivityController<MediaWriteRequestActivity> =
        Robolectric.buildActivity(MediaWriteRequestActivity::class.java).setup()

    private fun answer(controller: ActivityController<MediaWriteRequestActivity>, resultCode: Int) {
        val shadow = shadowOf(controller.get())
        val request = shadow.lastIntentSenderRequest ?: error("no write request was launched")
        shadow.callOnActivityResult(request.requestCode, resultCode, Intent())
    }

    /** Run the main looper until [done] or ten seconds pass. */
    private fun awaitMain(done: () -> Boolean): Boolean {
        val end = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
        while (System.nanoTime() < end) {
            shadowOf(Looper.getMainLooper()).idle()
            if (done()) return true
            Thread.sleep(20)
        }
        return done()
    }

    @Test
    fun `without location access the screen asks for it before the write request`() {
        val app = context as Application
        shadowOf(app).denyPermissions(Manifest.permission.ACCESS_MEDIA_LOCATION)
        queue(first)
        val controller = open()
        val shadow = shadowOf(controller.get())

        val asked = shadow.lastRequestedPermission ?: error("location access was not asked for")
        assertEquals(listOf(Manifest.permission.ACCESS_MEDIA_LOCATION), asked.requestedPermissions.toList())
        assertEquals("no write request before location access is answered", null, shadow.lastIntentSenderRequest)

        shadowOf(app).grantPermissions(Manifest.permission.ACCESS_MEDIA_LOCATION)
        @Suppress("DEPRECATION")
        controller.get().onRequestPermissionsResult(asked.requestCode, asked.requestedPermissions, intArrayOf(0))

        assertTrue("the write request follows", shadow.lastIntentSenderRequest != null)
    }

    /**
     * Opens the screen without location access, recreates it (a rotation)
     * while the location-access dialog is open, then answers that dialog in
     * the new instance with [result].
     */
    private fun recreateWhileAskingThenAnswer(result: Int): ActivityController<MediaWriteRequestActivity> {
        val app = context as Application
        shadowOf(app).denyPermissions(Manifest.permission.ACCESS_MEDIA_LOCATION)
        queue(first)
        val controller = open()
        val asked = shadowOf(controller.get()).lastRequestedPermission ?: error("location access was not asked for")
        assertEquals(null, shadowOf(controller.get()).lastIntentSenderRequest)

        controller.recreate()
        assertEquals(
            "the recreated screen joins the open dialog, it does not ask again",
            null,
            shadowOf(controller.get()).lastRequestedPermission
        )

        if (result == PackageManager.PERMISSION_GRANTED) {
            shadowOf(app).grantPermissions(Manifest.permission.ACCESS_MEDIA_LOCATION)
        }
        @Suppress("DEPRECATION")
        controller.get().onRequestPermissionsResult(asked.requestCode, asked.requestedPermissions, intArrayOf(result))
        shadowOf(Looper.getMainLooper()).idle()
        return controller
    }

    @Test
    fun `recreated while location access is asked, a grant still launches the write request`() {
        val controller = recreateWhileAskingThenAnswer(PackageManager.PERMISSION_GRANTED)

        assertTrue("the write request follows the grant", shadowOf(controller.get()).lastIntentSenderRequest != null)
        granted = true
        answer(controller, Activity.RESULT_OK)
        assertTrue("it finishes once publication ends", awaitMain { controller.get().isFinishing })
        assertTrue("the capture was published", MediaWriteAuthorizations.pending(context).isEmpty())
    }

    @Test
    fun `recreated while location access is asked, a denial still launches the write request and never strands the capture`() {
        val controller = recreateWhileAskingThenAnswer(PackageManager.PERMISSION_DENIED)

        assertTrue("the write request follows the answer", shadowOf(controller.get()).lastIntentSenderRequest != null)
        answer(controller, Activity.RESULT_CANCELED)
        assertTrue(awaitMain { controller.get().isFinishing })
        assertTrue(
            "the refused capture is dropped, not left queued",
            awaitMain { MediaWriteAuthorizations.pending(context).isEmpty() }
        )
    }

    @Test
    fun `the screen holding the grant stays open until publication ends`() {
        queue(first)
        // Not yet granted, so the screen asks; the user grants it in the dialog.
        val controller = open()
        granted = true
        gate = CountDownLatch(1)

        answer(controller, Activity.RESULT_OK)
        shadowOf(Looper.getMainLooper()).idle()

        assertFalse("finishing now would end the grant mid-publication", controller.get().isFinishing)
        assertEquals(1, MediaWriteAuthorizations.pending(context).size)

        gate.countDown()

        assertTrue("it finishes once publication ends", awaitMain { controller.get().isFinishing })
        assertTrue("the capture was published", MediaWriteAuthorizations.pending(context).isEmpty())
    }

    @Test
    fun `a refusal spares a capture queued while the dialog was open`() {
        queue(first)
        val controller = open()
        queue(later)

        answer(controller, Activity.RESULT_CANCELED)

        assertTrue(awaitMain { controller.get().isFinishing })
        assertTrue(
            "the refused capture is dropped and the later one kept",
            awaitMain { MediaWriteAuthorizations.pending(context).map { it.uri } == listOf(later.toString()) }
        )
    }

    @Test
    fun `a queue that cannot be read is reported, kept whole and never crashes the screen`() {
        queue(first)
        val store = File(context.filesDir, "media-write-requests.json")
        val before = store.readBytes()

        MediaWriteAuthorizations.readStore = { throw java.io.IOException("the queue could not be read") }
        val controller = try {
            open()
        } finally {
            MediaWriteAuthorizations.readStore = { it.readText() }
        }
        assertTrue("the screen ends without a request", controller.get().isFinishing)
        assertEquals(
            "the user is told",
            "Captures waiting for access cannot be loaded",
            ShadowToast.getTextOfLatestToast()
        )
        assertArrayEquals("the queue is untouched", before, store.readBytes())

        store.writeText("{not a queue")
        val malformed = open()
        assertTrue(malformed.get().isFinishing)
        assertEquals("a malformed queue is untouched", "{not a queue", store.readText())
    }
}
