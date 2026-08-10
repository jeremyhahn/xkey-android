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
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.Espresso.pressBackUnconditionally
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.intent.Intents
import androidx.test.espresso.intent.matcher.IntentMatchers.hasComponent
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.automatethethings.xkey.settings.BootstrapSettingsRepository
import com.google.android.material.materialswitch.MaterialSwitch
import kotlinx.coroutines.runBlocking
import org.hamcrest.Matchers.containsString
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented UI tests for [SettingsActivity].
 *
 * SettingsActivity builds every card programmatically in `buildSettingsUI()`
 * (the XML-declared cards are hidden), so there are no ids to match on and the
 * assertions use the same string resources the screen renders.
 *
 * The Auto-Bootstrap toggle writes through to DataStore, so this suite records
 * the persisted value in @Before and restores it in @After; nothing else here
 * mutates settings.
 *
 * Tests cover:
 * - Toolbar title
 * - Every section header being built
 * - Connectivity section content (Native USB title, description, explanation)
 * - Auto-Bootstrap toggling actually revealing and hiding the bootstrap methods
 * - PIN Management section status lines and its navigation button
 * - String content guards: no "(least secure)" wording, CA URL copy intact
 * - Back navigation finishing the activity
 */
@RunWith(AndroidJUnit4::class)
class SettingsActivityUiTest {

    private lateinit var bootstrapRepository: BootstrapSettingsRepository
    private var originalAutoBootstrap: Boolean = true

    @Before
    fun setUp() {
        Intents.init()
        val context = ApplicationProvider.getApplicationContext<Context>()
        bootstrapRepository = BootstrapSettingsRepository(context)
        originalAutoBootstrap = runBlocking {
            bootstrapRepository.getSettings().autoBootstrapEnabled
        }
    }

    @After
    fun tearDown() {
        runBlocking { bootstrapRepository.updateAutoBootstrapEnabled(originalAutoBootstrap) }
        Intents.release()
    }

    // ---------------------------------------------------------------
    // Toolbar
    // ---------------------------------------------------------------

    @Test
    fun toolbar_showsSettingsTitle() {
        val scenario = ActivityScenario.launch(SettingsActivity::class.java)

        awaitText(
            scenario,
            ApplicationProvider.getApplicationContext<Context>()
                .getString(R.string.settings_title)
        )
    }

    // ---------------------------------------------------------------
    // Section Structure
    // ---------------------------------------------------------------

    @Test
    fun allSections_arePresent() {
        val scenario = ActivityScenario.launch(SettingsActivity::class.java)
        val context = ApplicationProvider.getApplicationContext<Context>()

        listOf(
            R.string.settings_section_auth,
            R.string.settings_section_ca,
            R.string.settings_section_trust,
            R.string.settings_media_signing_title,
            R.string.settings_section_connectivity
        ).forEach { header ->
            awaitText(scenario, context.getString(header))
        }
    }

    @Test
    fun sectionDescriptions_arePresent() {
        val scenario = ActivityScenario.launch(SettingsActivity::class.java)
        val context = ApplicationProvider.getApplicationContext<Context>()

        awaitText(scenario, context.getString(R.string.settings_section_auth_desc))
        awaitText(scenario, context.getString(R.string.settings_section_connectivity_desc))
    }

    // ---------------------------------------------------------------
    // Connectivity Section
    // ---------------------------------------------------------------

    @Test
    fun connectivitySection_isDisplayed() {
        ActivityScenario.launch(SettingsActivity::class.java)

        onView(withText(R.string.settings_section_connectivity))
            .perform(scrollToView())
            .check(matches(isDisplayed()))
    }

    @Test
    fun nativeUsbToggle_isDisplayed() {
        ActivityScenario.launch(SettingsActivity::class.java)

        onView(withText(R.string.settings_usb_native_title))
            .perform(scrollToView())
            .check(matches(isDisplayed()))
    }

    @Test
    fun nativeUsbDescription_isDisplayed() {
        ActivityScenario.launch(SettingsActivity::class.java)

        onView(withText(R.string.settings_usb_native_description))
            .perform(scrollToView())
            .check(matches(isDisplayed()))
    }

    @Test
    fun nativeUsbExplanation_isDisplayed() {
        ActivityScenario.launch(SettingsActivity::class.java)

        onView(withText(containsString("Native USB connects your phone directly")))
            .perform(scrollToView())
            .check(matches(isDisplayed()))
    }

    // ---------------------------------------------------------------
    // Bootstrap Section
    // ---------------------------------------------------------------

    @Test
    fun autoBootstrapToggle_isDisplayed() {
        ActivityScenario.launch(SettingsActivity::class.java)

        onView(withText(R.string.bootstrap_auto_enabled))
            .perform(scrollToView())
            .check(matches(isDisplayed()))
    }

    /**
     * Turning Auto-Bootstrap on reveals the bootstrap method sections
     * (DANE / Noise / SPKI / Direct HTTPS) and turning it off hides them again.
     *
     * The toggle is a programmatic [MaterialSwitch] with no id, so it is located
     * from its row label and driven on the main thread; the persisted value is
     * restored in @After.
     */
    @Test
    fun autoBootstrapToggle_revealsAndHidesBootstrapMethods() {
        val scenario = ActivityScenario.launch(SettingsActivity::class.java)
        val context = ApplicationProvider.getApplicationContext<Context>()
        awaitText(scenario, context.getString(R.string.bootstrap_auto_enabled))

        setAutoBootstrap(scenario, enabled = true)
        awaitCondition("Bootstrap method sections should be visible when auto-bootstrap is on") {
            isMethodSectionShown(scenario)
        }

        setAutoBootstrap(scenario, enabled = false)
        awaitCondition("Bootstrap method sections should be hidden when auto-bootstrap is off") {
            !isMethodSectionShown(scenario)
        }
    }

    /** The persisted flag follows the toggle, so the choice survives a restart. */
    @Test
    fun autoBootstrapToggle_persistsThroughRecreate() {
        val scenario = ActivityScenario.launch(SettingsActivity::class.java)
        val context = ApplicationProvider.getApplicationContext<Context>()
        awaitText(scenario, context.getString(R.string.bootstrap_auto_enabled))

        setAutoBootstrap(scenario, enabled = true)
        awaitCondition("Auto-bootstrap should be persisted as enabled") {
            runBlocking { bootstrapRepository.getSettings().autoBootstrapEnabled }
        }

        scenario.recreate()

        awaitCondition("Bootstrap methods should still be revealed after recreate") {
            isMethodSectionShown(scenario)
        }
        assertEquals(
            true,
            runBlocking { bootstrapRepository.getSettings().autoBootstrapEnabled }
        )
    }

    // ---------------------------------------------------------------
    // PIN Management Section
    // ---------------------------------------------------------------

    @Test
    fun pinSection_showsStatusLinesForBothPins() {
        val scenario = ActivityScenario.launch(SettingsActivity::class.java)

        awaitText(scenario, "SO PIN:")
        awaitText(scenario, "User PIN:")
    }

    @Test
    fun managePinsButton_opensPinManagementActivity() {
        val scenario = ActivityScenario.launch(SettingsActivity::class.java)
        awaitText(scenario, MANAGE_PINS_BUTTON)

        onView(withText(MANAGE_PINS_BUTTON)).perform(scrollToView(), click())

        Intents.intended(hasComponent(PinManagementActivity::class.java.name))
    }

    // ---------------------------------------------------------------
    // String content guards
    // ---------------------------------------------------------------

    @Test
    fun directHttps_doesNotContainLeastSecure() {
        val scenario = ActivityScenario.launch(SettingsActivity::class.java)
        val context = ApplicationProvider.getApplicationContext<Context>()
        awaitText(scenario, context.getString(R.string.bootstrap_auto_enabled))

        // Reveal every method section so the guard covers their copy too.
        setAutoBootstrap(scenario, enabled = true)
        awaitCondition("Bootstrap method sections should be visible") {
            isMethodSectionShown(scenario)
        }

        scenario.onActivity { activity ->
            val leastSecure = findTextView(activity.window.decorView, "least secure")
            assertEquals(
                "'(least secure)' should have been removed from the Direct HTTPS description",
                null,
                leastSecure
            )
        }
    }

    @Test
    fun caUrlDescription_containsEnterpriseText() {
        val scenario = ActivityScenario.launch(SettingsActivity::class.java)

        awaitText(scenario, "Enterprise or Privacy CA")
    }

    // ---------------------------------------------------------------
    // Back navigation
    // ---------------------------------------------------------------

    @Test
    fun backNavigation_finishesActivity() {
        val scenario = ActivityScenario.launch(SettingsActivity::class.java)

        // pressBack() throws NoActivityResumedException when back closes the
        // last activity in the task, which is exactly what we assert here.
        pressBackUnconditionally()

        assertActivityDestroyed(scenario)
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    /**
     * Drives the Auto-Bootstrap switch to [enabled] on the main thread.
     *
     * The switch carries no id, so it is found as the toggle sitting next to
     * the row's title; a no-op is skipped so the listener only fires on a real
     * state change.
     */
    private fun setAutoBootstrap(
        scenario: ActivityScenario<SettingsActivity>,
        enabled: Boolean
    ) {
        scenario.onActivity { activity ->
            val toggle = switchForLabel(
                activity.window.decorView,
                activity.getString(R.string.bootstrap_auto_enabled),
                MaterialSwitch::class.java
            )
            assertNotNull("Auto-Bootstrap switch should be present", toggle)
            if (toggle!!.isChecked != enabled) toggle.performClick()
        }
        waitForIdle()
    }

    /** True when the DANE method section (inside the methods container) is shown. */
    private fun isMethodSectionShown(scenario: ActivityScenario<SettingsActivity>): Boolean {
        var shown = false
        scenario.onActivity { activity ->
            val dane = collectViews(activity.window.decorView) {
                it is android.widget.TextView && it.text?.toString() == DANE_METHOD_NAME
            }.firstOrNull()
            shown = dane != null && dane.isShown
        }
        return shown
    }

    private companion object {
        /** Still an inline literal in SettingsActivity's PIN section. */
        const val MANAGE_PINS_BUTTON = "Manage PINs"

        /** Method-section checkbox label, an inline literal in SettingsActivity. */
        const val DANE_METHOD_NAME = "DANE"
    }
}
