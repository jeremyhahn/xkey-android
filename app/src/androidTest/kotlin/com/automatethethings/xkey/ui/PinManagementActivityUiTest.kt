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
import android.widget.EditText
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.espresso.Espresso.closeSoftKeyboard
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.Espresso.pressBackUnconditionally
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.action.ViewActions.replaceText
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.RootMatchers.isDialog
import androidx.test.espresso.matcher.ViewMatchers.isAssignableFrom
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.automatethethings.xkey.settings.PinSettingsData
import com.automatethethings.xkey.settings.PinSettingsRepository
import kotlinx.coroutines.runBlocking
import org.hamcrest.Matchers.allOf
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented UI tests for [PinManagementActivity].
 *
 * The screen is programmatic (no XML ids): a gradient toolbar, a hero card with
 * SO PIN / User PIN / Initialized status rows and badges, an optional lockout
 * card, and a set of action cards whose composition depends on the persisted
 * PIN state. Assertions therefore use string resources for matching and read
 * [PinSettingsRepository] to decide which action card should be present.
 *
 * No PIN is ever provisioned: only the mismatch validation path is driven,
 * which returns before [com.automatethethings.xkey.pin.PinManager] is called,
 * so the shared device state is never mutated by this suite.
 *
 * Tests cover:
 * - Gradient toolbar title and subtitle
 * - Hero status card: title and the three status rows
 * - Status badges agreeing with the persisted settings
 * - Actions section header and the state-dependent action card set
 * - The SO PIN dialog opening and cancelling without side effects
 * - The mismatched-PIN error path surfacing "PINs do not match"
 * - Back navigation finishing the activity
 */
@RunWith(AndroidJUnit4::class)
class PinManagementActivityUiTest {

    private lateinit var settings: PinSettingsData

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        settings = runBlocking { PinSettingsRepository(context).getSettings() }
    }

    // ---------------------------------------------------------------
    // Gradient Toolbar
    // ---------------------------------------------------------------

    @Test
    fun gradientToolbar_showsTitle() {
        ActivityScenario.launch(PinManagementActivity::class.java)

        onView(withText(R.string.pin_management_title))
            .check(matches(isDisplayed()))
    }

    @Test
    fun gradientToolbar_showsSubtitle() {
        ActivityScenario.launch(PinManagementActivity::class.java)

        onView(withText(R.string.pin_management_subtitle))
            .check(matches(isDisplayed()))
    }

    // ---------------------------------------------------------------
    // Hero Status Card
    // ---------------------------------------------------------------

    @Test
    fun heroCard_showsStatusTitle() {
        ActivityScenario.launch(PinManagementActivity::class.java)

        onView(withText(R.string.pin_status_title))
            .check(matches(isDisplayed()))
    }

    @Test
    fun heroCard_showsAllThreeStatusRows() {
        val scenario = ActivityScenario.launch(PinManagementActivity::class.java)
        val context = ApplicationProvider.getApplicationContext<Context>()

        listOf(
            R.string.pin_label_so,
            R.string.pin_label_user,
            R.string.pin_label_initialized
        ).forEach { label ->
            awaitText(scenario, context.getString(label))
        }
    }

    /** The SO PIN row's badge reflects whether an SO PIN is persisted. */
    @Test
    fun soPinBadge_reflectsPersistedSetting() {
        val scenario = ActivityScenario.launch(PinManagementActivity::class.java)
        val context = ApplicationProvider.getApplicationContext<Context>()
        val expected = context.getString(
            if (settings.soPinSet) R.string.pin_badge_set else R.string.pin_badge_not_set
        )

        awaitBadgeForRow(scenario, context.getString(R.string.pin_label_so), expected)
    }

    /** The User PIN row's badge reflects whether a User PIN is persisted. */
    @Test
    fun userPinBadge_reflectsPersistedSetting() {
        val scenario = ActivityScenario.launch(PinManagementActivity::class.java)
        val context = ApplicationProvider.getApplicationContext<Context>()
        val expected = context.getString(
            if (settings.userPinSet) R.string.pin_badge_set else R.string.pin_badge_not_set
        )

        awaitBadgeForRow(scenario, context.getString(R.string.pin_label_user), expected)
    }

    // ---------------------------------------------------------------
    // Actions Section
    // ---------------------------------------------------------------

    @Test
    fun actionsSection_isDisplayed() {
        ActivityScenario.launch(PinManagementActivity::class.java)

        onView(withText(R.string.pin_actions_header))
            .perform(scrollToView())
            .check(matches(isDisplayed()))
    }

    /**
     * The action cards are rebuilt from the persisted state: "Set SO PIN" is
     * offered only while no SO PIN exists, "Change SO PIN" only once one does.
     */
    @Test
    fun actionCards_matchPersistedPinState() {
        val scenario = ActivityScenario.launch(PinManagementActivity::class.java)
        val context = ApplicationProvider.getApplicationContext<Context>()

        if (settings.soPinSet) {
            awaitText(scenario, context.getString(R.string.pin_action_change_so_title))
            awaitTextAbsent(
                scenario,
                context.getString(R.string.pin_action_set_so_title),
                timeoutMs = 1_500L
            )
        } else {
            awaitText(scenario, context.getString(R.string.pin_action_set_so_title))
            awaitTextAbsent(
                scenario,
                context.getString(R.string.pin_action_change_so_title),
                timeoutMs = 1_500L
            )
        }
    }

    // ---------------------------------------------------------------
    // SO PIN dialog
    // ---------------------------------------------------------------

    @Test
    fun soPinActionCard_opensDialogWithConfirmAndCancel() {
        val scenario = ActivityScenario.launch(PinManagementActivity::class.java)
        val context = ApplicationProvider.getApplicationContext<Context>()
        awaitText(scenario, context.getString(soPinActionTitle()))

        onView(withText(soPinActionTitle())).perform(scrollToView(), click())

        onView(withText(soPinConfirmButton())).inRoot(isDialog())
            .check(matches(isDisplayed()))
        onView(withText(R.string.button_cancel)).inRoot(isDialog())
            .check(matches(isDisplayed()))
    }

    /** Cancelling the SO PIN dialog must not change the persisted PIN state. */
    @Test
    fun soPinDialog_cancel_leavesSettingsUnchanged() {
        val scenario = ActivityScenario.launch(PinManagementActivity::class.java)
        val context = ApplicationProvider.getApplicationContext<Context>()
        awaitText(scenario, context.getString(soPinActionTitle()))

        onView(withText(soPinActionTitle())).perform(scrollToView(), click())
        onView(withText(R.string.button_cancel)).inRoot(isDialog()).perform(click())

        waitForIdle()
        assertEquals(
            "Cancelling must not provision or change a PIN",
            settings.soPinSet,
            runBlocking { PinSettingsRepository(context).getSettings().soPinSet }
        )
    }

    /**
     * Entering a new PIN and a different confirmation is rejected before the
     * PIN manager is reached, so nothing is persisted and an error is shown.
     */
    @Test
    fun soPinDialog_mismatchedConfirmation_showsErrorAndPersistsNothing() {
        val scenario = ActivityScenario.launch(PinManagementActivity::class.java)
        val context = ApplicationProvider.getApplicationContext<Context>()
        awaitText(scenario, context.getString(soPinActionTitle()))

        onView(withText(soPinActionTitle())).perform(scrollToView(), click())

        // "Set SO PIN" has [new, confirm]; "Change SO PIN" adds a leading
        // "current" field, shifting the new/confirm pair by one.
        val firstIndex = if (settings.soPinSet) 1 else 0
        typeDialogField(firstIndex, "correct-horse-1")
        typeDialogField(firstIndex + 1, "correct-horse-2")
        onView(withText(soPinConfirmButton())).inRoot(isDialog()).perform(click())

        onView(withText(R.string.pin_error_mismatch)).check(matches(isDisplayed()))
        assertEquals(
            "A mismatched confirmation must not change the persisted PIN state",
            settings.soPinSet,
            runBlocking { PinSettingsRepository(context).getSettings().soPinSet }
        )
    }

    // ---------------------------------------------------------------
    // Back Navigation
    // ---------------------------------------------------------------

    @Test
    fun backNavigation_finishesActivity() {
        val scenario = ActivityScenario.launch(PinManagementActivity::class.java)

        // pressBack() throws NoActivityResumedException when back closes the
        // last activity in the task, which is exactly what we assert here.
        pressBackUnconditionally()

        assertActivityDestroyed(scenario)
    }

    @Test
    fun activityLaunches_withoutFinishing() {
        val scenario = ActivityScenario.launch(PinManagementActivity::class.java)

        scenario.onActivity { activity ->
            assertTrue(
                "PinManagementActivity should not be finishing after launch",
                !activity.isFinishing
            )
        }
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    /**
     * Polls until the badge sitting next to the status row labelled [label]
     * reads [expectedBadge].
     *
     * Status rows are built as `[label][badge]`, so the badge is the sibling
     * TextView of the label. The badge text is written by a settings-flow
     * collector, hence the poll.
     */
    private fun awaitBadgeForRow(
        scenario: ActivityScenario<PinManagementActivity>,
        label: String,
        expectedBadge: String
    ) {
        awaitCondition("Badge next to '$label' should read '$expectedBadge'") {
            var matched = false
            scenario.onActivity { activity ->
                val labelView = collectViews(activity.window.decorView) {
                    it is android.widget.TextView && it.text?.toString() == label
                }.firstOrNull()
                val row = labelView?.parent as? android.view.ViewGroup
                matched = row != null && collectViews(row) {
                    it is android.widget.TextView && it !== labelView &&
                        it.text?.toString() == expectedBadge
                }.isNotEmpty()
            }
            matched
        }
    }

    /** The SO PIN action card offered for the current persisted state. */
    private fun soPinActionTitle(): Int =
        if (settings.soPinSet) R.string.pin_action_change_so_title
        else R.string.pin_action_set_so_title

    /** The confirm button of the SO PIN dialog for the current state. */
    private fun soPinConfirmButton(): Int =
        if (settings.soPinSet) R.string.pin_button_change else R.string.pin_button_set

    /**
     * Replaces the text of the dialog's [index]-th EditText. PIN dialogs wrap
     * their fields in TextInputLayouts whose hints Espresso cannot match, so
     * fields are addressed by build order.
     */
    private fun typeDialogField(index: Int, text: String) {
        onView(
            nthMatch(
                allOf(isAssignableFrom(EditText::class.java), isDisplayed()),
                index
            )
        )
            .inRoot(isDialog())
            .perform(replaceText(text))
        closeSoftKeyboard()
    }
}
