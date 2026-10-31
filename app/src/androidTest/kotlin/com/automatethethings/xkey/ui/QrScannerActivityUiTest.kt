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

import android.Manifest
import android.app.Activity
import androidx.camera.view.PreviewView
import androidx.test.core.app.ActivityScenario
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.Espresso.pressBackUnconditionally
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.withId
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.rule.GrantPermissionRule
import com.automatethethings.xkey.R
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented UI tests for [QrScannerActivity].
 *
 * QrScannerActivity uses the camera (CameraX) via QrCodeScannerHelper, so the
 * CAMERA permission is granted up-front with [GrantPermissionRule]. Camera
 * binding happens asynchronously, so the activity launches immediately and its
 * static overlay UI (from R.layout.activity_qr_scanner) renders regardless of
 * whether the emulator has a working camera. These tests therefore assert on
 * the instruction text / overlay / known view IDs rather than the (possibly
 * blank) camera preview surface itself, plus the result contract the caller
 * relies on -- a scan that never happens must leave RESULT_CANCELED behind.
 *
 * Tests cover:
 * - Instruction text renders
 * - Semi-transparent overlay renders
 * - Preview view is present and is a CameraX PreviewView
 * - Starting the scanner does not finish the activity
 * - Backing out returns RESULT_CANCELED with no scanned URI
 */
@RunWith(AndroidJUnit4::class)
class QrScannerActivityUiTest {

    @get:Rule
    val cameraPermission: GrantPermissionRule =
        GrantPermissionRule.grant(Manifest.permission.CAMERA)

    // ---------------------------------------------------------------
    // Scanner UI
    // ---------------------------------------------------------------

    @Test
    fun scanner_showsInstructionText() {
        ActivityScenario.launch(QrScannerActivity::class.java)

        onView(withText(R.string.oath_qr_instruction))
            .check(matches(isDisplayed()))
    }

    @Test
    fun scanner_overlay_isDisplayed() {
        ActivityScenario.launch(QrScannerActivity::class.java)

        onView(withId(R.id.overlay))
            .check(matches(isDisplayed()))
    }

    @Test
    fun scanner_previewView_isDisplayed() {
        ActivityScenario.launch(QrScannerActivity::class.java)

        onView(withId(R.id.previewView))
            .check(matches(isDisplayed()))
    }

    /** The helper needs a CameraX PreviewView, not a bare surface. */
    @Test
    fun scanner_previewView_isACameraXPreviewView() {
        val scenario = ActivityScenario.launch(QrScannerActivity::class.java)

        assertNotNull(
            "R.id.previewView should be a CameraX PreviewView",
            withActivity(scenario) { it.findViewById<PreviewView>(R.id.previewView) }
        )
    }

    /**
     * Starting CameraX must not tear the activity down, even on an emulator with
     * no usable camera.
     */
    @Test
    fun scanner_staysOpenAfterStartingTheCamera() {
        val scenario = ActivityScenario.launch(QrScannerActivity::class.java)

        assertFalse(
            "QrScannerActivity should stay open while scanning",
            withActivity(scenario) { it.isFinishing }
        )
    }

    // ---------------------------------------------------------------
    // Result contract
    // ---------------------------------------------------------------

    /**
     * Callers launch this screen for a result; dismissing it without a scan must
     * yield RESULT_CANCELED and no [QrScannerActivity.EXTRA_SCANNED_URI].
     */
    @Test
    fun backNavigation_returnsCancelledWithNoScannedUri() {
        val scenario = ActivityScenario.launchActivityForResult(QrScannerActivity::class.java)

        // pressBack() throws NoActivityResumedException when back closes the
        // last activity in the task, which is exactly what we assert here.
        pressBackUnconditionally()

        assertActivityDestroyed(scenario)
        val result = scenario.result
        assertEquals(Activity.RESULT_CANCELED, result.resultCode)
        assertNull(
            "No URI should be returned when nothing was scanned",
            result.resultData?.getStringExtra(QrScannerActivity.EXTRA_SCANNED_URI)
        )
    }
}
