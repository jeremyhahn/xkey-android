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
package com.automatethethings.xkey.ui

import android.Manifest
import android.app.Activity
import android.app.Application
import android.content.Intent
import android.net.Uri
import android.os.Looper
import android.view.View
import android.widget.TextView
import com.automatethethings.xkey.R
import com.automatethethings.xkey.media.AutoSignHash
import com.automatethethings.xkey.media.FakeMediaProvider
import com.automatethethings.xkey.media.MediaHasher
import com.automatethethings.xkey.media.MediaPublisher
import com.automatethethings.xkey.media.XmpFixtures
import com.google.android.material.button.MaterialButton
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowActivity
import java.io.File

/**
 * Location access guards only what carries a location: MediaStore images and
 * videos. With ACCESS_MEDIA_LOCATION declined, an audio item or a PDF,
 * whether a MediaStore item or a media document, still reads whole, so the
 * share screen signs, encrypts and verifies it without asking; an image
 * still asks.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class FileOperationNonVisualLocationTest {

    @get:Rule
    val folder = TemporaryFolder()

    private lateinit var db: TestDatabase
    private lateinit var media: FakeMediaProvider
    private lateinit var documents: FakeMediaProvider

    private val audio = Uri.parse("content://media/external/audio/media/3")
    private val pdf = Uri.parse("content://media/external/file/5")
    private val pdfDocument = Uri.parse("content://com.android.providers.media.documents/document/document%3A5")
    private val image = Uri.parse("content://media/external/images/media/7")
    private val imageFile = Uri.parse("content://media/external/file/9")

    private val bytes = "%PDF-1.4 not a capture".toByteArray()

    @Before
    fun setUp() {
        db = TestDatabase()
        val file = File(folder.root, "item").apply { writeBytes(bytes) }
        media = Robolectric.setupContentProvider(FakeMediaProvider::class.java, "media").apply {
            this.media = file
            mimeType = "application/pdf"
        }
        documents = Robolectric.setupContentProvider(
            FakeMediaProvider::class.java, "com.android.providers.media.documents"
        ).apply {
            this.media = file
            mimeType = "application/pdf"
        }
        shadowOf(RuntimeEnvironment.getApplication()).denyPermissions(Manifest.permission.ACCESS_MEDIA_LOCATION)
    }

    @After
    fun tearDown() {
        db.close()
    }

    private val context get() = RuntimeEnvironment.getApplication()

    private fun idleUntil(condition: () -> Boolean) {
        val deadline = System.currentTimeMillis() + 10_000
        while (!condition()) {
            assertTrue("timed out", System.currentTimeMillis() < deadline)
            shadowOf(Looper.getMainLooper()).idle()
            Thread.sleep(10)
        }
    }

    private fun field(name: String) =
        FileOperationActivity::class.java.getDeclaredField(name).apply { isAccessible = true }

    /** Opens the share screen on [uri] and presses [operation]'s button. */
    private fun press(uri: Uri, type: String, operation: Int): FileOperationActivity {
        val intent = Intent(Intent.ACTION_SEND).setType(type).putExtra(Intent.EXTRA_STREAM, uri)
        val activity = Robolectric.buildActivity(FileOperationActivity::class.java, intent).setup().get()
        shadowOf(Looper.getMainLooper()).idle()
        field("selectedOperation").setInt(activity, operation)
        (field("processButton").get(activity) as MaterialButton).performClick()
        shadowOf(Looper.getMainLooper()).idle()
        return activity
    }

    private fun shown(activity: FileOperationActivity): String {
        val resultCard = field("resultCard").get(activity) as View
        idleUntil { resultCard.visibility == View.VISIBLE }
        return (field("resultText").get(activity) as TextView).text.toString()
    }

    @Test
    fun `audio and PDF items read whole without location access`() {
        for ((uri, type) in listOf(audio to "audio/mpeg", pdf to "application/pdf", pdfDocument to "application/pdf")) {
            media.mimeType = type
            documents.mimeType = type
            assertFalse("$uri needs no location access", MediaPublisher.needsLocationAccess(context, uri))
            // Encrypting and signing read the original whole.
            val read = MediaPublisher.openOriginal(context, uri).use { it.readBytes() }
            assertArrayEquals("$uri reads whole", bytes, read)
            assertEquals(AutoSignHash.contentHash(bytes, type), AutoSignHash.contentHashOriginal(context, uri))
            // Verifying hashes it too.
            assertEquals(
                MediaHasher.ContentHashCheck.MATCHES,
                MediaHasher.checkContentHashUri(
                    context, uri, AutoSignHash.contentHash(bytes, type), MediaHasher.SignatureSource.SIDECAR
                )
            )
        }
    }

    @Test
    fun `an image still needs location access`() {
        media.mimeType = "image/png"
        assertTrue(MediaPublisher.needsLocationAccess(context, image))
        assertTrue("an image in the files collection too", MediaPublisher.needsLocationAccess(context, imageFile))
        val activity = press(image, "image/png", 1) // OP_VERIFY
        assertNotNull("an image asks for location access", shadowOf(activity).lastRequestedPermission)
    }

    @Test
    fun `signing and encrypting an audio item run without asking for location access`() {
        media.mimeType = "audio/mpeg"
        val signing = press(audio, "audio/mpeg", 0) // OP_SIGN
        assertNull("no location request", shadowOf(signing).lastRequestedPermission)
        assertEquals(signing.getString(R.string.file_operation_no_keys), shown(signing))

        val encrypting = press(audio, "audio/mpeg", 2) // OP_ENCRYPT
        assertNull("no location request", shadowOf(encrypting).lastRequestedPermission)
        assertEquals(encrypting.getString(R.string.file_operation_no_contacts), shown(encrypting))
    }

    @Test
    fun `verifying a PDF reads it without asking for location access`() {
        val sidecar = File(folder.root, "item.pdf.xkeysig").apply {
            writeText(XmpFixtures.json(AutoSignHash.contentHash(bytes, "application/pdf")))
        }
        val activity = press(pdf, "application/pdf", 1) // OP_VERIFY
        assertNull("no location request", shadowOf(activity).lastRequestedPermission)

        var picker: ShadowActivity.IntentForResult? = null
        idleUntil {
            picker = generateSequence { shadowOf(activity).nextStartedActivityForResult }
                .firstOrNull { it.intent.action == Intent.ACTION_OPEN_DOCUMENT }
            picker != null
        }
        activity.activityResultRegistry.dispatchResult(
            picker!!.requestCode, Activity.RESULT_OK, Intent().setData(Uri.fromFile(sidecar))
        )

        val result = shown(activity)
        assertFalse("checked, not access unavailable: $result", result.contains(MediaHasher.ACCESS_UNAVAILABLE_MESSAGE))
        assertFalse("the hash matches: $result", result.contains("Content hash mismatch"))
    }
}
