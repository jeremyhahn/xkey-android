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

import android.app.Activity
import android.app.Application
import android.content.Intent
import android.net.Uri
import android.os.Looper
import android.view.View
import androidx.activity.result.ActivityResultLauncher
import com.automatethethings.xkey.media.ContentAuthenticityData
import com.automatethethings.xkey.media.XmpContainers
import com.automatethethings.xkey.media.XmpFixtures
import com.automatethethings.xkey.media.XmpMetadataHelper
import com.google.android.material.button.MaterialButton
import org.junit.After
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
import org.robolectric.Shadows.shadowOf
import org.robolectric.android.controller.ActivityController
import org.robolectric.annotation.Config
import java.io.File
import java.io.OutputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * A save picker FileOperationActivity opens outlives the screen that opened
 * it: the output it writes survives the activity's recreation, and a cancel
 * drops that output and frees the screen.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class FileOperationSavePickerTest {

    @get:Rule
    val folder = TemporaryFolder()

    private lateinit var db: TestDatabase
    private lateinit var source: File

    @Before
    fun setUp() {
        db = TestDatabase()
        source = folder.newFile("clip.png").apply { writeBytes(XmpFixtures.png()) }
    }

    @After
    fun tearDown() {
        db.close()
    }

    private fun launch(): ActivityController<FileOperationActivity> {
        val intent = Intent(Intent.ACTION_SEND)
            .setType("image/png")
            .putExtra(Intent.EXTRA_STREAM, Uri.fromFile(source))
        val controller = Robolectric.buildActivity(FileOperationActivity::class.java, intent).setup()
        shadowOf(Looper.getMainLooper()).idle()
        return controller
    }

    private fun field(name: String) =
        FileOperationActivity::class.java.getDeclaredField(name).apply { isAccessible = true }

    private fun signature(hash: String): ContentAuthenticityData =
        ContentAuthenticityData.fromJsonString(XmpFixtures.json(hash))

    /** The signed copy [performSign] leaves waiting for the user's document. */
    private fun pendSignedCopy(activity: FileOperationActivity, data: ContentAuthenticityData) {
        val type = Class.forName(FileOperationActivity::class.java.name + "\$PendingSignedCopy")
        val constructor = type.getDeclaredConstructor(Uri::class.java, XmpContainers.Format::class.java, ContentAuthenticityData::class.java)
            .apply { isAccessible = true }
        field("pendingSignedCopy").set(activity, constructor.newInstance(Uri.fromFile(source), XmpContainers.Format.PNG, data))
    }

    private fun busy(activity: FileOperationActivity) {
        FileOperationActivity::class.java.getDeclaredMethod("showProgress", Boolean::class.javaPrimitiveType)
            .apply { isAccessible = true }
            .invoke(activity, true)
    }

    /** Open the save picker [launcher] names; its request code. */
    @Suppress("UNCHECKED_CAST")
    private fun openPicker(activity: FileOperationActivity, launcher: String): Int {
        (field(launcher).get(activity) as ActivityResultLauncher<String>).launch("clip-signed.png")
        val started = shadowOf(activity).nextStartedActivityForResult
        assertNotNull("$launcher opened a picker", started)
        assertEquals(Intent.ACTION_CREATE_DOCUMENT, started.intent.action)
        return started.requestCode
    }

    private fun processButton(activity: FileOperationActivity): MaterialButton =
        field("processButton").get(activity) as MaterialButton

    private fun idleUntil(condition: () -> Boolean) {
        val deadline = System.currentTimeMillis() + 10_000
        while (!condition()) {
            assertTrue("timed out", System.currentTimeMillis() < deadline)
            shadowOf(Looper.getMainLooper()).idle()
            Thread.sleep(10)
        }
    }

    @Test
    fun `a signed copy survives recreation while its picker is open`() {
        val controller = launch()
        val data = signature("b".repeat(64))
        pendSignedCopy(controller.get(), data)
        busy(controller.get())
        val requestCode = openPicker(controller.get(), "createSignedCopyLauncher")

        controller.recreate()
        shadowOf(Looper.getMainLooper()).idle()
        val activity = controller.get()

        val output = folder.newFile("clip-signed.png")
        activity.activityResultRegistry.dispatchResult(
            requestCode, Activity.RESULT_OK, Intent().setData(Uri.fromFile(output))
        )
        val resultCard = field("resultCard").get(activity) as View
        idleUntil { resultCard.visibility == View.VISIBLE && field("pendingSignedCopy").get(activity) == null }

        val written = XmpMetadataHelper.readSignatureFromUri(activity.contentResolver, Uri.fromFile(output), "image/png")
        assertNotNull("the signed copy was written after recreation", written)
        assertEquals(data.contentHash, written!!.contentHash)
        assertTrue(processButton(activity).isEnabled)
    }

    @Test
    fun `a sidecar signature survives recreation while its picker is open`() {
        val controller = launch()
        val json = XmpFixtures.json("c".repeat(64))
        field("pendingSignatureJson").set(controller.get(), json)
        val requestCode = openPicker(controller.get(), "createSignatureFileLauncher")

        controller.recreate()
        shadowOf(Looper.getMainLooper()).idle()
        val activity = controller.get()

        val output = folder.newFile("clip.png.xkeysig")
        activity.activityResultRegistry.dispatchResult(
            requestCode, Activity.RESULT_OK, Intent().setData(Uri.fromFile(output))
        )
        idleUntil { field("pendingSignatureJson").get(activity) == null }
        assertEquals(json, output.readText())
    }

    @Test
    fun `cancelling a signed-copy picker clears it and frees the screen`() {
        val activity = launch().get()
        pendSignedCopy(activity, signature("d".repeat(64)))
        busy(activity)
        val requestCode = openPicker(activity, "createSignedCopyLauncher")

        activity.activityResultRegistry.dispatchResult(requestCode, Activity.RESULT_CANCELED, null)
        shadowOf(Looper.getMainLooper()).idle()

        assertNull(field("pendingSignedCopy").get(activity))
        assertTrue("the process button is enabled again", processButton(activity).isEnabled)
    }

    @Test
    fun `cancelling any save picker frees the screen`() {
        for (launcher in listOf(
            "createSignatureFileLauncher",
            "createSignedCopyLauncher",
            "createEncryptedFileLauncher",
            "createDecryptedFileLauncher"
        )) {
            val activity = launch().get()
            busy(activity)
            val requestCode = openPicker(activity, launcher)

            activity.activityResultRegistry.dispatchResult(requestCode, Activity.RESULT_CANCELED, null)
            shadowOf(Looper.getMainLooper()).idle()

            assertTrue("$launcher: the process button is enabled again", processButton(activity).isEnabled)
        }
    }

    /** An output stream whose first write blocks until [release]. */
    private class HeldOutput : OutputStream() {
        val writing = CountDownLatch(1)
        private val released = CountDownLatch(1)
        val bytes = java.io.ByteArrayOutputStream()

        fun release() = released.countDown()

        override fun write(b: Int) = write(byteArrayOf(b.toByte()), 0, 1)

        override fun write(b: ByteArray, off: Int, len: Int) {
            writing.countDown()
            check(released.await(10, TimeUnit.SECONDS)) { "never released" }
            bytes.write(b, off, len)
        }
    }

    private fun tap(view: View) {
        val now = android.os.SystemClock.uptimeMillis()
        for (action in listOf(android.view.MotionEvent.ACTION_DOWN, android.view.MotionEvent.ACTION_UP)) {
            val event = android.view.MotionEvent.obtain(now, now, action, 1f, 1f, 0)
            view.dispatchTouchEvent(event)
            event.recycle()
        }
    }

    @Test
    fun `a save restored after recreation keeps the screen busy until its write ends`() {
        val controller = launch()
        val json = XmpFixtures.json("e".repeat(64))
        field("pendingSignatureJson").set(controller.get(), json)
        busy(controller.get())
        val requestCode = openPicker(controller.get(), "createSignatureFileLauncher")

        controller.recreate()
        shadowOf(Looper.getMainLooper()).idle()
        val activity = controller.get()
        assertFalse("a restored save keeps Process disabled", processButton(activity).isEnabled)

        // The restored writer is held open mid-write.
        val output = Uri.parse("content://xkey.test/clip.png.xkeysig")
        val held = HeldOutput()
        shadowOf(activity.contentResolver).registerOutputStream(output, held)
        activity.activityResultRegistry.dispatchResult(requestCode, Activity.RESULT_OK, Intent().setData(output))
        shadowOf(Looper.getMainLooper()).idle()
        assertTrue("the restored write started", held.writing.await(10, TimeUnit.SECONDS))
        shadowOf(Looper.getMainLooper()).idle()

        // A second operation is attempted while it writes: a tap on Process.
        // Were it enabled, the sign it starts (no keys here) would report and
        // free the screen mid-write.
        val process = processButton(activity)
        assertFalse("Process is disabled while the restored save writes", process.isEnabled)
        tap(process)
        shadowOf(Looper.getMainLooper()).idle()
        val resultCard = field("resultCard").get(activity) as View
        assertEquals("no second operation ran", View.GONE, resultCard.visibility)
        assertFalse(processButton(activity).isEnabled)
        assertEquals(View.VISIBLE, (field("progressIndicator").get(activity) as View).visibility)

        held.release()
        idleUntil { resultCard.visibility == View.VISIBLE && field("pendingSignatureJson").get(activity) == null }
        assertEquals(json, held.bytes.toString(Charsets.UTF_8.name()))
        assertTrue("Process is enabled once the write ends", processButton(activity).isEnabled)
    }

    @Test
    fun `a restored signed copy keeps the screen busy until its picker returns`() {
        val controller = launch()
        pendSignedCopy(controller.get(), signature("f".repeat(64)))
        busy(controller.get())
        val requestCode = openPicker(controller.get(), "createSignedCopyLauncher")

        controller.recreate()
        shadowOf(Looper.getMainLooper()).idle()
        val activity = controller.get()
        assertFalse(processButton(activity).isEnabled)

        activity.activityResultRegistry.dispatchResult(requestCode, Activity.RESULT_CANCELED, null)
        shadowOf(Looper.getMainLooper()).idle()
        assertTrue("a cancel frees the restored screen", processButton(activity).isEnabled)
    }
}
