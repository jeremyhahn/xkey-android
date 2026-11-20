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
import androidx.activity.result.ActivityResultLauncher
import com.automatethethings.xkey.media.ContentAuthenticityData
import com.automatethethings.xkey.media.FakeMediaProvider
import com.automatethethings.xkey.media.MediaHasher
import com.automatethethings.xkey.media.SignedCopyDocument
import com.automatethethings.xkey.media.XmpFixtures
import com.automatethethings.xkey.media.XmpMetadataHelper
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
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
import java.io.File

/**
 * A signed copy saved from the Share sheet stages the capture's original
 * bytes, the ones its signature covers, never MediaStore's redacted view.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class FileOperationShareSaveTest {

    @get:Rule
    val folder = TemporaryFolder()

    private lateinit var db: TestDatabase
    private lateinit var provider: FakeMediaProvider
    private val capture = Uri.parse("content://media/external/images/media/7")

    @Before
    fun setUp() {
        db = TestDatabase()
        val redacted = XmpFixtures.png(XmpFixtures.bytes(0x78, 0x9C, 0x00, 0x00, 0x00))
        provider = Robolectric.setupContentProvider(FakeMediaProvider::class.java, "media").apply {
            media = folder.newFile("capture.png").apply { writeBytes(XmpFixtures.png()) }
            mimeType = "image/png"
            redact = { redacted }
        }
        shadowOf(RuntimeEnvironment.getApplication()).grantPermissions(Manifest.permission.ACCESS_MEDIA_LOCATION)
    }

    @After
    fun tearDown() {
        db.close()
    }

    private fun field(name: String) =
        FileOperationActivity::class.java.getDeclaredField(name).apply { isAccessible = true }

    private fun idleUntil(condition: () -> Boolean) {
        val deadline = System.currentTimeMillis() + 10_000
        while (!condition()) {
            assertTrue("timed out", System.currentTimeMillis() < deadline)
            shadowOf(Looper.getMainLooper()).idle()
            Thread.sleep(10)
        }
    }

    @Test
    @Suppress("UNCHECKED_CAST")
    fun `a Share-sheet signed copy of a capture is written from its original, not the redacted view`() {
        val intent = Intent(Intent.ACTION_SEND).setType("image/png").putExtra(Intent.EXTRA_STREAM, capture)
        val activity = Robolectric.buildActivity(FileOperationActivity::class.java, intent).setup().get()
        shadowOf(Looper.getMainLooper()).idle()

        // performSign signed the original's bytes and left the copy waiting for a document.
        val originalHash = MediaHasher.hashStreamed({ provider.media.inputStream() }, "image/png").canonical
        val signature = ContentAuthenticityData.fromJsonString(XmpFixtures.json(originalHash))
        val type = Class.forName(FileOperationActivity::class.java.name + "\$PendingSignedCopy")
        val pending = type.getDeclaredConstructor(Uri::class.java, String::class.java, ContentAuthenticityData::class.java)
            .apply { isAccessible = true }
            .newInstance(capture, "image/png", signature)
        field("pendingSignedCopy").set(activity, pending)
        (field("createSignedCopyLauncher").get(activity) as ActivityResultLauncher<SignedCopyDocument>)
            .launch(SignedCopyDocument("capture-signed.png", "image/png"))
        val picker = shadowOf(activity).nextStartedActivityForResult
        assertNotNull("the save picker opened", picker)

        val output = folder.newFile("capture-signed.png")
        activity.activityResultRegistry.dispatchResult(
            picker.requestCode, Activity.RESULT_OK, Intent().setData(Uri.fromFile(output))
        )
        val resultCard = field("resultCard").get(activity) as View
        idleUntil { resultCard.visibility == View.VISIBLE && field("runningSave").get(activity) == null }

        val shown = (field("resultText").get(activity) as TextView).text.toString()
        assertFalse("the original is not reported changed: $shown", shown.contains("changed after it was signed"))
        assertNotNull(
            "the copy carries the signature",
            XmpMetadataHelper.readSignatureFromUri(activity.contentResolver, Uri.fromFile(output), "image/png")
        )
        assertEquals(
            "the copy holds the original's content",
            originalHash,
            MediaHasher.hashStreamed({ output.inputStream() }, "image/png").canonical
        )
        assertTrue(
            "the capture was read whole",
            provider.openUris.any { it.getQueryParameter("requireOriginal") == "1" }
        )
    }
}
