/*
 * Copyright (c) 2025 Jeremy Hahn
 * Copyright (c) 2025 Automate The Things, LLC
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

import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.net.Uri
import android.view.View
import android.widget.ImageView
import androidx.core.content.FileProvider
import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.espresso.Espresso.pressBackUnconditionally
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.io.FileOutputStream

/**
 * Instrumented UI tests for [VerifiedMediaViewerActivity].
 *
 * The screen accepts a media URI through either ACTION_VIEW data or
 * ACTION_SEND's EXTRA_STREAM and finishes immediately when neither is present.
 * Once a URI resolves it decodes the image, then verifies embedded signatures on
 * a background dispatcher and swaps the overlay between a signer list and a
 * "no signatures" placeholder.
 *
 * These tests write a real PNG to the cache directory (deleted in @After). A
 * plain PNG carries no xKey signature, which is exactly the unsigned-media path
 * the placeholder exists for.
 *
 * Tests cover:
 * - Launch behavior: finishes with no URI, opens for ACTION_SEND and ACTION_VIEW
 * - Image branch selected: the image view is shown and the player stays hidden
 * - Verification overlay reporting "no signatures" for unsigned media
 * - Back navigation finishing the activity
 */
@RunWith(AndroidJUnit4::class)
class VerifiedMediaViewerActivityUiTest {

    private lateinit var imageFile: File

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        imageFile = File(context.cacheDir, IMAGE_NAME).apply {
            FileOutputStream(this).use { output ->
                val bitmap = Bitmap.createBitmap(100, 100, Bitmap.Config.ARGB_8888)
                bitmap.compress(Bitmap.CompressFormat.PNG, 100, output)
                bitmap.recycle()
            }
        }
    }

    @After
    fun tearDown() {
        imageFile.delete()
    }

    // -----------------------------------------------------------------
    // Launch behavior
    // -----------------------------------------------------------------

    /** Neither ACTION_VIEW data nor EXTRA_STREAM resolves, so onCreate finishes. */
    @Test
    fun activity_finishesWithoutAMediaUri() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = "image/png"
            setClass(context, VerifiedMediaViewerActivity::class.java)
        }

        val scenario = ActivityScenario.launch<VerifiedMediaViewerActivity>(intent)

        assertTrue(
            "Activity should finish when no media URI is supplied",
            scenario.state == Lifecycle.State.DESTROYED
        )
    }

    @Test
    fun activityLaunches_forAShareIntent() {
        val scenario = launchSend()

        assertFalse(
            "Activity should stay open for a valid media URI",
            withActivity(scenario) { it.isFinishing }
        )
    }

    @Test
    fun activityLaunches_forAViewIntent() {
        val scenario = launchView()

        assertFalse(
            "ACTION_VIEW data should resolve just like EXTRA_STREAM",
            withActivity(scenario) { it.isFinishing }
        )
    }

    // -----------------------------------------------------------------
    // Media rendering
    // -----------------------------------------------------------------

    @Test
    fun toolbar_showsVerifiedMediaTitle() {
        val scenario = launchSend()

        assertShownTextInTree(scenario, withString(scenario, R.string.verified_viewer_title))
    }

    @Test
    fun imageMedia_showsTheImageViewAndHidesThePlayer() {
        val scenario = launchSend()

        assertTrue(
            "The image view should become visible for image media",
            awaitActivity(scenario) {
                it.findViewById<View>(R.id.imageView).visibility == View.VISIBLE
            }
        )
        assertEquals(
            View.GONE,
            withActivity(scenario) { it.findViewById<View>(R.id.playerView).visibility }
        )
    }

    @Test
    fun imageMedia_decodesABitmapIntoTheImageView() {
        val scenario = launchSend()

        assertTrue(
            "The image view should become visible for image media",
            awaitActivity(scenario) {
                it.findViewById<View>(R.id.imageView).visibility == View.VISIBLE
            }
        )
        assertNotNull(
            "A bitmap should have been decoded into the image view",
            withActivity(scenario) { it.findViewById<ImageView>(R.id.imageView).drawable }
        )
    }

    // -----------------------------------------------------------------
    // Verification overlay
    // -----------------------------------------------------------------

    /**
     * A plain PNG has no xKey signature, so verification settles on the
     * placeholder and the signer list is hidden.
     */
    @Test
    fun unsignedMedia_showsTheNoSignaturesPlaceholder() {
        val scenario = launchSend()

        assertTrue(
            "Unsigned media should reveal the no-signatures placeholder",
            awaitActivity(scenario) {
                it.findViewById<View>(R.id.textNoSignatures).visibility == View.VISIBLE
            }
        )
        assertEquals(
            View.GONE,
            withActivity(scenario) { it.findViewById<View>(R.id.signerListContainer).visibility }
        )
        assertShownTextInTree(
            scenario,
            withString(scenario, R.string.verified_viewer_no_signatures)
        )
    }

    @Test
    fun verificationOverlay_isAlwaysVisible() {
        val scenario = launchSend()

        assertEquals(
            View.VISIBLE,
            withActivity(scenario) { it.findViewById<View>(R.id.verificationOverlay).visibility }
        )
    }

    // -----------------------------------------------------------------
    // Back navigation
    // -----------------------------------------------------------------

    @Test
    fun backNavigation_finishesActivity() {
        val scenario = launchSend()

        // pressBack() throws NoActivityResumedException when back closes the
        // last activity in the task, which is exactly what we assert here.
        pressBackUnconditionally()

        assertActivityDestroyed(scenario)
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private fun launchSend(): ActivityScenario<VerifiedMediaViewerActivity> {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = "image/png"
            putExtra(Intent.EXTRA_STREAM, mediaUri())
            setClass(context, VerifiedMediaViewerActivity::class.java)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        return ActivityScenario.launch(intent)
    }

    private fun launchView(): ActivityScenario<VerifiedMediaViewerActivity> {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val intent = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(mediaUri(), "image/png")
            setClass(context, VerifiedMediaViewerActivity::class.java)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        return ActivityScenario.launch(intent)
    }

    private fun mediaUri(): Uri {
        val context = ApplicationProvider.getApplicationContext<Context>()
        return FileProvider.getUriForFile(
            context,
            "${context.packageName}.fileprovider",
            imageFile
        )
    }

    private fun withString(
        scenario: ActivityScenario<VerifiedMediaViewerActivity>,
        resId: Int
    ): String = withActivity(scenario) { it.getString(resId) }

    private companion object {
        const val IMAGE_NAME = "xkey_ui_test_image.png"
    }
}
