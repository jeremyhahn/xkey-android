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

import android.content.Context
import android.view.MenuItem
import androidx.appcompat.widget.PopupMenu
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.automatethethings.xkey.ca.AndroidCA
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeFalse
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The toolbar and the CA prerequisite guard on [SettingsActivity].
 *
 * The four `Settings*FlowTest` suites between them drive every toggle, radio,
 * field and spinner this screen builds, but none of them touches
 * `onOptionsItemSelected` — it is 0% covered, because `SettingsActivityUiTest`
 * navigates back with the system back button — and none clicks "Generate
 * Intermediate CA", whose first act is to refuse when no root CA exists.
 *
 * That refusal is the only part of the CA generation flow a test can drive
 * safely: everything past it writes Android Keystore aliases that
 * `SettingsCertificateAuthorityFlowTest` and `AndroidCATest` both read, so this
 * suite asserts the guard and stops. It is skipped rather than failed when a
 * root CA already exists on the device.
 *
 * Menu items are built with a throwaway [PopupMenu]: the screen inflates no menu
 * resource, so `home` is the only item that exists and an unrecognised id has no
 * affordance at all.
 *
 * Nothing here writes a setting, so there is nothing to restore.
 */
@RunWith(AndroidJUnit4::class)
class SettingsMenuTest {

    private lateinit var context: Context
    private lateinit var androidCA: AndroidCA
    private lateinit var scenario: ActivityScenario<SettingsActivity>

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        androidCA = AndroidCA(context)
        scenario = ActivityScenario.launch(SettingsActivity::class.java)
        SettingsFlowSupport.awaitInitialized(scenario)
    }

    @After
    fun tearDown() {
        scenario.close()
    }

    // ---------------------------------------------------------------
    // Options menu
    // ---------------------------------------------------------------

    /** The `home` item routes through the back dispatcher and closes the screen. */
    @Test
    fun homeMenuItem_finishesTheActivity() {
        val handled = selectMenuItem(android.R.id.home)

        assertTrue("The home item should be handled by the activity", handled)
        assertActivityDestroyed(scenario)
    }

    /** Any other item falls through to the superclass and is left unhandled. */
    @Test
    fun anUnrecognisedMenuItem_isNotHandled() {
        val handled = selectMenuItem(UNRECOGNISED_ITEM_ID)

        assertFalse("An unknown menu item must not be claimed", handled)
        assertFalse(
            "An unhandled menu item must not close the screen",
            withActivity(scenario) { it.isFinishing }
        )
    }

    // ---------------------------------------------------------------
    // CA prerequisite
    // ---------------------------------------------------------------

    /**
     * An intermediate CA cannot be generated before the root, and the refusal
     * generates nothing.
     *
     * The button starts disabled, but [android.view.View.performClick] runs the
     * listener regardless — which is exactly what makes the guard testable
     * without first creating a root CA this suite would then have to clean up.
     */
    @Test
    fun generatingAnIntermediateCaWithoutARoot_isRefused() {
        assumeFalse(
            "This device already has a root CA, so the guard cannot be reached",
            androidCA.isRootCAGenerated()
        )

        SettingsFlowSupport.clickView(scenario, "the Generate Intermediate CA button") {
            SettingsFlowSupport.button(it, context.getString(R.string.ca_generate_intermediate))
        }

        SettingsFlowSupport.assertEventuallyShows(
            scenario,
            context.getString(R.string.ca_root_required)
        )
        assertFalse(
            "Refusing must not generate an intermediate CA",
            androidCA.isIntermediateCAGenerated()
        )
        assertEquals(
            "The button label should be untouched by a refusal",
            context.getString(R.string.ca_generate_intermediate),
            withActivity(scenario) {
                SettingsFlowSupport
                    .button(it.window.decorView, context.getString(R.string.ca_generate_intermediate))
                    ?.text
                    ?.toString()
            }
        )
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    /** Passes a synthesised [MenuItem] with [itemId] to the activity's handler. */
    private fun selectMenuItem(itemId: Int): Boolean {
        val handled = withActivity(scenario) { activity ->
            val item: MenuItem = PopupMenu(activity, activity.window.decorView)
                .menu
                .add(0, itemId, 0, "synthetic")
            activity.onOptionsItemSelected(item)
        }
        waitForIdle()
        return handled
    }

    private companion object {

        /** An id no resource in this app can collide with. */
        const val UNRECOGNISED_ITEM_ID = 0x7EEE0004
    }
}
