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
import android.view.ViewGroup
import android.widget.Button
import com.automatethethings.xkey.R
import com.automatethethings.xkey.media.AutoSignHash
import com.automatethethings.xkey.media.ContentAuthenticityData
import com.automatethethings.xkey.media.FakeMediaProvider
import com.automatethethings.xkey.media.MediaPublisher
import com.automatethethings.xkey.media.XmpFixtures
import com.automatethethings.xkey.media.XmpMetadataHelper
import kotlinx.coroutines.Job
import org.junit.After
import org.junit.Assert.assertEquals
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
import org.robolectric.android.controller.ActivityController
import org.robolectric.annotation.Config
import java.io.File

/**
 * Loading a capture's signatures copies its original bytes, which for a
 * large video takes long. Leaving or recreating the co-sign screen cancels
 * that load: the read of the original is interrupted and its snapshot
 * deleted, so a recreation never leaves a second full copy running.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class CoSignLoadCancellationTest {

    @get:Rule
    val folder = TemporaryFolder()

    private lateinit var db: TestDatabase
    private lateinit var provider: FakeMediaProvider
    private var controller: ActivityController<CoSignActivity>? = null
    private val capture = Uri.parse("content://media/external/images/media/7")

    private val originalHash: String = AutoSignHash.contentHash(XmpFixtures.png(), "image/png")

    private fun signedPng(name: String): File =
        File(folder.root, name).apply {
            writeBytes(XmpFixtures.png())
            XmpMetadataHelper.writeSignature(path, ContentAuthenticityData.fromJsonString(XmpFixtures.json(originalHash)))
        }

    @Before
    fun setUp() {
        db = TestDatabase()
        provider = Robolectric.setupContentProvider(FakeMediaProvider::class.java, "media").apply {
            media = signedPng("capture.png")
            mimeType = "image/png"
            stall = true
        }
        shadowOf(RuntimeEnvironment.getApplication()).grantPermissions(Manifest.permission.ACCESS_MEDIA_LOCATION)
    }

    @After
    fun tearDown() {
        provider.release()
        runCatching { controller?.pause()?.stop()?.destroy() }
        db.close()
    }

    private fun field(name: String) =
        CoSignActivity::class.java.getDeclaredField(name).apply { isAccessible = true }

    private fun mediaLoad(activity: CoSignActivity) = field("mediaLoad").get(activity) as Job?

    private fun findButton(view: View, text: String): Button? = when (view) {
        is Button -> view.takeIf { it.text == text }
        is ViewGroup -> (0 until view.childCount).firstNotNullOfOrNull { findButton(view.getChildAt(it), text) }
        else -> null
    }

    /** Waits up to 5 s for [condition], idling the main looper. */
    private fun within5s(message: String, condition: () -> Boolean) {
        val deadline = System.currentTimeMillis() + 5_000
        while (!condition()) {
            assertTrue(message, System.currentTimeMillis() < deadline)
            shadowOf(Looper.getMainLooper()).idle()
            Thread.sleep(10)
        }
    }

    private fun snapshots(): List<String> =
        MediaPublisher.recoveryDirectory(RuntimeEnvironment.getApplication()).listFiles().orEmpty()
            .map { it.name }.filter { it.endsWith(".read") }

    /** Picks [capture] on a fresh co-sign screen and waits until its read stalls in the provider. */
    private fun pickAndStall(): CoSignActivity {
        val built = Robolectric.buildActivity(CoSignActivity::class.java).setup()
        controller = built
        val activity = built.get()
        shadowOf(Looper.getMainLooper()).idle()
        val select = findButton(activity.window.decorView, activity.getString(R.string.cosign_select_media))
        assertNotNull("the select media button", select)
        select!!.performClick()
        val picker = shadowOf(activity).nextStartedActivityForResult
        assertNotNull("the media picker started", picker)
        activity.activityResultRegistry.dispatchResult(
            picker.requestCode,
            Activity.RESULT_OK,
            Intent().setData(capture)
        )
        shadowOf(Looper.getMainLooper()).idle()
        within5s("the load reads the original") { provider.inStall.get() == 1 }
        return activity
    }

    @Test
    fun `leaving the co-sign screen during a load interrupts the read of the original`() {
        val activity = pickAndStall()

        controller!!.pause().stop().destroy()
        controller = null

        within5s("the read of the original is interrupted when the screen goes") {
            provider.stallInterrupted.get() == 1
        }
        within5s("no read is left inside the provider") { provider.inStall.get() == 0 }
        val load = mediaLoad(activity)
        within5s("the load ends") { load?.isCompleted == true }
        within5s("the snapshot is deleted: ${snapshots()}") { snapshots().isEmpty() }
    }

    @Test
    fun `a recreation during a load leaves one read of the original`() {
        pickAndStall()

        controller = controller!!.recreate()
        shadowOf(Looper.getMainLooper()).idle()

        within5s("the first screen's read is interrupted by the recreation") {
            provider.stallInterrupted.get() == 1
        }
        // The new screen's restore may start its own read; never more than one.
        Thread.sleep(200)
        shadowOf(Looper.getMainLooper()).idle()
        assertTrue("at most one read of the original: ${provider.inStall.get()}", provider.inStall.get() <= 1)
        assertEquals("one read was interrupted", 1, provider.stallInterrupted.get())
    }

    @Test
    fun `leaving the co-sign screen cancels the open of the original`() {
        provider.stallAcrossProcess = true
        val activity = pickAndStall()

        controller!!.pause().stop().destroy()
        controller = null

        within5s("the open of the original is cancelled when the screen goes") {
            provider.stallCancelled.get() == 1
        }
        within5s("no read is left inside the provider") { provider.inStall.get() == 0 }
        val load = mediaLoad(activity)
        within5s("the load ends") { load?.isCompleted == true }
        within5s("the snapshot is deleted: ${snapshots()}") { snapshots().isEmpty() }
        assertTrue("every read open carries a cancel signal: ${provider.readSignals}", provider.readSignals.all { it })
    }

    @Test
    fun `a recreation during a load cancels the first screen's open`() {
        provider.stallAcrossProcess = true
        pickAndStall()

        controller = controller!!.recreate()
        shadowOf(Looper.getMainLooper()).idle()

        within5s("the first screen's open is cancelled by the recreation") {
            provider.stallCancelled.get() == 1
        }
        Thread.sleep(200)
        shadowOf(Looper.getMainLooper()).idle()
        assertTrue("at most one read of the original: ${provider.inStall.get()}", provider.inStall.get() <= 1)
    }
}
