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

import android.app.Activity
import android.app.Instrumentation
import android.content.Context
import android.view.View
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.Espresso.pressBackUnconditionally
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.intent.Intents
import androidx.test.espresso.intent.Intents.intended
import androidx.test.espresso.intent.Intents.intending
import androidx.test.espresso.intent.matcher.IntentMatchers.hasComponent
import androidx.test.espresso.intent.matcher.IntentMatchers.hasExtra
import androidx.test.espresso.matcher.RootMatchers.isDialog
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.automatethethings.xkey.R
import com.automatethethings.xkey.piv.PivAlgorithm
import com.automatethethings.xkey.piv.PivSlot
import com.automatethethings.xkey.piv.PivSlotDao
import com.automatethethings.xkey.piv.PivSlotEntity
import com.automatethethings.xkey.storage.XKeyDatabase
import kotlinx.coroutines.runBlocking
import org.hamcrest.Matchers.allOf
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented UI tests for [PivActivity].
 *
 * PivActivity builds its UI programmatically and rebuilds every slot card each
 * time the `piv_slots` Room `Flow` emits: a populated slot gets an algorithm
 * badge, a creation date and a "View Details" action, while an empty slot gets
 * "Generate Key". These tests seed one populated primary slot (9C) and one
 * populated retired slot (82) so both sections can be asserted, and delete both
 * rows in @After. Slot 9A is deliberately left alone because other suites use it.
 *
 * The hero count is read back from the DAO rather than assumed, since other
 * suites may leave slots populated.
 *
 * Tests cover:
 * - Gradient toolbar and section headers
 * - Hero count reflecting the number of populated slots
 * - Populated vs empty slot card rendering, including the algorithm badge
 * - Empty state hidden once a slot holds a key
 * - Retired-slots section collapsed by default and expanding on tap
 * - Generate-key dialog contents and cancellation
 * - "View Details" navigating to [PivSlotDetailActivity] with the slot id
 * - Back navigation finishing the activity
 */
@RunWith(AndroidJUnit4::class)
class PivActivityUiTest {

    private lateinit var dao: PivSlotDao

    @Before
    fun setUp() {
        Intents.init()
        // Keep "View Details" from actually launching the detail screen.
        intending(hasComponent(PivSlotDetailActivity::class.java.name)).respondWith(
            Instrumentation.ActivityResult(Activity.RESULT_OK, null)
        )

        val context = ApplicationProvider.getApplicationContext<Context>()
        dao = XKeyDatabase.getInstance(context).pivSlotDao()
        runBlocking {
            dao.upsert(
                PivSlotEntity(
                    slotId = PRIMARY_SLOT,
                    algorithm = SEEDED_ALGORITHM.name,
                    hasKey = true
                )
            )
            dao.upsert(
                PivSlotEntity(
                    slotId = RETIRED_SLOT,
                    algorithm = SEEDED_ALGORITHM.name,
                    hasKey = true
                )
            )
        }
    }

    @After
    fun tearDown() {
        runBlocking {
            dao.deleteBySlotId(PRIMARY_SLOT)
            dao.deleteBySlotId(RETIRED_SLOT)
        }
        Intents.release()
    }

    // ---------------------------------------------------------------
    // Gradient Toolbar and sections
    // ---------------------------------------------------------------

    @Test
    fun gradientToolbar_showsTitleAndSubtitle() {
        launch()

        onView(withText(R.string.piv_title)).check(matches(isDisplayed()))
        onView(withText(R.string.piv_subtitle)).check(matches(isDisplayed()))
    }

    @Test
    fun primarySlotsSection_headerDisplayed() {
        launch()

        onView(withText(R.string.piv_section_primary)).check(matches(isDisplayed()))
    }

    @Test
    fun retiredSlotsSection_headerCountsAllTwentySlots() {
        val scenario = launch()

        val expected = withActivity(scenario) {
            it.getString(
                R.string.piv_section_retired_toggle,
                PivSlot.entries.count { slot -> !slot.isPrimarySlot }
            )
        }
        assertShownTextInTree(scenario, expected)
    }

    // ---------------------------------------------------------------
    // Hero Summary Card
    // ---------------------------------------------------------------

    /**
     * The hero label counts populated slots. The expected value is read from the
     * DAO because other suites may leave slots populated on the same device.
     */
    @Test
    fun heroSummaryCard_countReflectsPopulatedSlots() {
        val scenario = launch()

        val populated = runBlocking { dao.getAll().count { it.hasKey } }
        val expected = withActivity(scenario) {
            when (populated) {
                0 -> it.getString(R.string.piv_count_zero)
                1 -> it.getString(R.string.piv_count_one)
                else -> it.getString(R.string.piv_count, populated)
            }
        }
        assertShownTextInTree(scenario, expected)
    }

    // ---------------------------------------------------------------
    // Slot cards
    // ---------------------------------------------------------------

    /**
     * The badge renders the stored algorithm token (the enum name), not the
     * human-readable display name.
     */
    @Test
    fun populatedSlot_showsAlgorithmBadgeAndViewDetailsAction() {
        val scenario = launch()

        assertShownTextInTree(scenario, PivSlot.DIGITAL_SIGNATURE.label)
        assertShownTextInTree(scenario, SEEDED_ALGORITHM.name)
        assertShownTextInTree(scenario, withString(scenario, R.string.piv_view_details))
    }

    @Test
    fun populatedSlot_showsTheCreationDateRow() {
        val scenario = launch()
        assertShownTextInTree(scenario, PivSlot.DIGITAL_SIGNATURE.label)

        val createdPrefix = withString(scenario, R.string.piv_slot_created, "").trim()
        assertShownTextInTree(scenario, createdPrefix)
    }

    /**
     * A slot with no stored key offers key generation rather than details. The
     * slot is chosen from live DAO state so a slot populated by another suite
     * cannot invalidate the expectation.
     */
    @Test
    fun emptySlot_offersGenerateKeyInstead() {
        val scenario = launch()
        val slot = emptyPrimarySlot()

        assertShownTextInTree(scenario, slot.label)
        assertTrue(
            "Slot ${slot.hexId} should offer Generate Key",
            actionLabelFor(scenario, slot) == withString(scenario, R.string.piv_generate_key)
        )
    }

    @Test
    fun populatedSlot_offersViewDetailsRatherThanGenerate() {
        val scenario = launch()

        assertShownTextInTree(scenario, PivSlot.DIGITAL_SIGNATURE.label)
        assertTrue(
            "A populated slot should offer View Details",
            actionLabelFor(scenario, PivSlot.DIGITAL_SIGNATURE) ==
                withString(scenario, R.string.piv_view_details)
        )
    }

    @Test
    fun emptyState_isHiddenOnceASlotHoldsAKey() {
        val scenario = launch()
        assertShownTextInTree(scenario, PivSlot.DIGITAL_SIGNATURE.label)

        val emptyTitle = withString(scenario, R.string.piv_empty_title)
        assertFalse(
            "The empty state must be hidden when any slot holds a key",
            withActivity(scenario) {
                findShownTextViewContaining(it.window.decorView, emptyTitle) != null
            }
        )
    }

    // ---------------------------------------------------------------
    // Retired slots section
    // ---------------------------------------------------------------

    @Test
    fun retiredSlots_areCollapsedUntilTheHeaderIsTapped() {
        val scenario = launch()
        assertShownTextInTree(scenario, PivSlot.DIGITAL_SIGNATURE.label)

        assertFalse(
            "Retired slot cards should start collapsed",
            withActivity(scenario) {
                findShownTextViewContaining(
                    it.window.decorView,
                    PivSlot.RETIRED_1.label
                ) != null
            }
        )

        clickTextInTree(
            scenario,
            withString(
                scenario,
                R.string.piv_section_retired_toggle,
                PivSlot.entries.count { slot -> !slot.isPrimarySlot }
            )
        )

        assertShownTextInTree(scenario, PivSlot.RETIRED_1.label)
    }

    // ---------------------------------------------------------------
    // Generate key dialog
    // ---------------------------------------------------------------

    @Test
    fun generateKeyDialog_opensForTheSelectedSlotAndCancelsWithoutGeneratingAKey() {
        val scenario = launch()
        val slot = emptyPrimarySlot()
        assertShownTextInTree(scenario, slot.label)
        val before = runBlocking { dao.getAll().count { it.hasKey } }

        clickSlotAction(scenario, slot, withString(scenario, R.string.piv_generate_key))

        onView(withText(withString(scenario, R.string.piv_generate_title, slot.hexId)))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
        onView(withText(R.string.piv_generate_key)).inRoot(isDialog()).check(matches(isDisplayed()))

        onView(withText(android.R.string.cancel)).inRoot(isDialog()).perform(click())

        Thread.sleep(SETTLE_MS)
        assertEquals(
            "Cancelling the dialog must not generate a key",
            before,
            runBlocking { dao.getAll().count { it.hasKey } }
        )
    }

    /**
     * Every supported algorithm must be selectable.
     *
     * The dialog previously called both `setMessage(...)` and
     * `setSingleChoiceItems(...)`. `AlertController.setupContent` only swaps
     * its scroll view for the choice list when the message is null, so the
     * list was built but never attached: the user saw a prompt with nothing
     * to choose, `selectedIndex` stayed 0, and every PIV key was silently
     * generated as ES256 with ES384 and RS2048 unreachable.
     */
    @Test
    fun generateKeyDialog_offersEverySupportedAlgorithm() {
        val scenario = launch()
        val slot = emptyPrimarySlot()
        assertShownTextInTree(scenario, slot.label)

        clickSlotAction(scenario, slot, withString(scenario, R.string.piv_generate_key))
        onView(withText(withString(scenario, R.string.piv_generate_title, slot.hexId)))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))

        val missing = PivAlgorithm.entries.filterNot { isDisplayedInDialog(it.displayName) }

        onView(withText(android.R.string.cancel)).inRoot(isDialog()).perform(click())

        assertTrue(
            "the generate-key dialog must offer every algorithm, missing: " +
                missing.map { it.displayName },
            missing.isEmpty()
        )
    }

    /** A non-default algorithm must be selectable and actually used. */
    @Test
    fun generateKeyDialog_honoursASelectedNonDefaultAlgorithm() {
        val scenario = launch()
        val slot = emptyPrimarySlot()
        assertShownTextInTree(scenario, slot.label)

        // Anything other than entries[0], which was the only reachable choice
        // while the chooser was suppressed.
        val target = PivAlgorithm.entries.last()

        clickSlotAction(scenario, slot, withString(scenario, R.string.piv_generate_key))
        onView(withText(target.displayName)).inRoot(isDialog()).perform(click())
        onView(withText(R.string.piv_generate_key)).inRoot(isDialog()).perform(click())

        Thread.sleep(SETTLE_MS)
        val stored = runBlocking { dao.getBySlotId(slot.hexId) }
        // The dialog lists displayName; the store records the enum name.
        assertEquals(
            "the algorithm chosen in the dialog must be the one generated",
            target.name,
            stored?.algorithm
        )
    }

    // ---------------------------------------------------------------
    // Navigation
    // ---------------------------------------------------------------

    @Test
    fun viewDetails_opensSlotDetailWithTheSlotId() {
        val scenario = launch()
        assertShownTextInTree(scenario, PivSlot.DIGITAL_SIGNATURE.label)

        clickSlotAction(
            scenario,
            PivSlot.DIGITAL_SIGNATURE,
            withString(scenario, R.string.piv_view_details)
        )

        intended(
            allOf(
                hasComponent(PivSlotDetailActivity::class.java.name),
                hasExtra(PivSlotDetailActivity.EXTRA_SLOT_ID, PRIMARY_SLOT)
            )
        )
    }

    // ---------------------------------------------------------------
    // Launch & Back Navigation
    // ---------------------------------------------------------------

    @Test
    fun backNavigation_finishesActivity() {
        val scenario = launch()

        // pressBack() throws NoActivityResumedException when back closes the
        // last activity in the task, which is exactly what we assert here.
        pressBackUnconditionally()

        assertActivityDestroyed(scenario)
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    private fun launch(): ActivityScenario<PivActivity> =
        ActivityScenario.launch(PivActivity::class.java)

    private fun withString(
        scenario: ActivityScenario<PivActivity>,
        resId: Int,
        vararg args: Any
    ): String = withActivity(scenario) {
        if (args.isEmpty()) it.getString(resId) else it.getString(resId, *args)
    }

    /**
     * Reports whether [text] is currently displayed inside the open dialog.
     *
     * Espresso signals absence by throwing, so the check is wrapped rather than
     * asserted; callers decide what the answer means.
     */
    private fun isDisplayedInDialog(text: String): Boolean =
        runCatching {
            onView(withText(text)).inRoot(isDialog()).check(matches(isDisplayed()))
        }.isSuccess

    /** Returns the first primary slot the database reports as having no key. */
    private fun emptyPrimarySlot(): PivSlot {
        val populated = runBlocking {
            dao.getAll().filter { it.hasKey }.map { it.slotId.uppercase() }.toSet()
        }
        return PivSlot.entries.first { it.isPrimarySlot && it.hexId !in populated }
    }

    /**
     * Returns the label of the action button on [slot]'s card.
     *
     * Every card carries an identically-labelled button, so the card is located
     * by its slot label first and the button is searched for beneath the nearest
     * ancestor that contains one.
     */
    private fun actionLabelFor(
        scenario: ActivityScenario<PivActivity>,
        slot: PivSlot
    ): String = withActivity(scenario) { activity ->
        val generate = activity.getString(R.string.piv_generate_key)
        val details = activity.getString(R.string.piv_view_details)
        val button = findSlotAction(activity.window.decorView, slot, listOf(generate, details))
            ?: throw AssertionError("No action button on the card for slot ${slot.hexId}")
        button.text.toString()
    }

    /** Clicks the button labelled [actionText] on [slot]'s card. */
    private fun clickSlotAction(
        scenario: ActivityScenario<PivActivity>,
        slot: PivSlot,
        actionText: String
    ) {
        scenario.onActivity { activity ->
            val button = findSlotAction(activity.window.decorView, slot, listOf(actionText))
                ?: throw AssertionError("No '$actionText' button for slot ${slot.hexId}")
            button.performClick()
        }
        InstrumentationRegistry.getInstrumentation().waitForIdleSync()
    }

    private fun findSlotAction(
        root: View,
        slot: PivSlot,
        candidates: List<String>
    ): android.widget.TextView? {
        val label = findTextViewContaining(root, slot.label) ?: return null
        var ancestor: View? = label.parent as? View
        while (ancestor != null) {
            candidates.forEach { text ->
                findTextViewContaining(ancestor, text)?.let { return it }
            }
            ancestor = ancestor.parent as? View
        }
        return null
    }

    private companion object {
        /** Digital Signature slot; seeded as populated. */
        const val PRIMARY_SLOT = "9C"

        /** Retired slot 1; seeded as populated to exercise the retired section. */
        const val RETIRED_SLOT = "82"

        /** Algorithm token stored on the seeded slots. */
        val SEEDED_ALGORITHM = PivAlgorithm.ES256

        /** Time to let a cancelled dialog settle before re-reading the DAO. */
        const val SETTLE_MS = 300L
    }
}
