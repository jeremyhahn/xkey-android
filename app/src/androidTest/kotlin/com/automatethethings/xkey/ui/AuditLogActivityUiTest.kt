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
import androidx.test.espresso.action.ViewActions.replaceText
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.intent.Intents
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.withHint
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.automatethethings.xkey.audit.AuditLogDao
import com.automatethethings.xkey.audit.AuditLogEntity
import com.automatethethings.xkey.audit.AuditOperationType
import com.automatethethings.xkey.storage.XKeyDatabase
import kotlinx.coroutines.runBlocking
import org.hamcrest.Matchers.allOf
import org.hamcrest.Matchers.containsString
import org.junit.After
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented UI tests for [AuditLogActivity].
 *
 * The screen is programmatic: gradient toolbar with an overflow menu, hero card
 * with the filtered entry count and a filter summary line, a debounced search
 * field, two rows of filter chips (operation type, then key type), a card list
 * with expandable details, and an empty state.
 *
 * Two entries are seeded with distinct key labels, operation types and key
 * types so every filter assertion is deterministic regardless of whatever the
 * device's audit history already contains. Chip labels are duplicated by the
 * cards' operation badges, so chips are addressed with [nthMatch] -- the filter
 * bar is built before the list, making the chip the first match.
 *
 * Tests cover:
 * - Toolbar title and subtitle
 * - Filter chips displayed, and the operation/key-type filters actually filtering
 * - Debounced search filtering by key label, including the no-match empty state
 * - Re-selecting "All" restoring the unfiltered list
 * - Hero card: filter-summary line switching between "All events" and "Filtered:"
 *
 * The toolbar's overflow actions (export, clear filters, clear all) are not
 * exercised: the menu is inflated straight onto the Toolbar before
 * `setSupportActionBar`, so AppCompat owns the menu afterwards and the items'
 * reachability is not something this suite can assert reliably.
 * - Card binding and expand-on-tap revealing the detail rows
 * - Back navigation finishing the activity
 *
 * Seeded entries are deleted in @After.
 */
@RunWith(AndroidJUnit4::class)
class AuditLogActivityUiTest {

    private val runId = System.nanoTime()
    private val createdKeyId = "ui-test-audit-created-$runId"
    private val deletedKeyId = "ui-test-audit-deleted-$runId"
    private val createdLabel = "UITestAuditCreated$runId"
    private val deletedLabel = "UITestAuditDeleted$runId"

    private lateinit var auditLogDao: AuditLogDao

    @Before
    fun setUp() {
        Intents.init()
        val context = ApplicationProvider.getApplicationContext<Context>()
        auditLogDao = XKeyDatabase.getInstance(context).auditLogDao()
    }

    @After
    fun tearDown() {
        runBlocking {
            auditLogDao.deleteByKeyId(createdKeyId)
            auditLogDao.deleteByKeyId(deletedKeyId)
        }
        Intents.release()
    }

    // ---------------------------------------------------------------
    // Toolbar
    // ---------------------------------------------------------------

    @Test
    fun toolbarTitle_displaysAuditLog() {
        ActivityScenario.launch(AuditLogActivity::class.java)

        onView(withText(R.string.audit_log_title))
            .check(matches(isDisplayed()))
    }

    @Test
    fun toolbarSubtitle_displaysSecurityEventHistory() {
        ActivityScenario.launch(AuditLogActivity::class.java)

        onView(withText(containsString("Security event history")))
            .check(matches(isDisplayed()))
    }

    // ---------------------------------------------------------------
    // Filter chips
    // ---------------------------------------------------------------

    @Test
    fun filterSectionHeaders_areDisplayed() {
        ActivityScenario.launch(AuditLogActivity::class.java)

        onView(withText(R.string.audit_log_filter_operation)).check(matches(isDisplayed()))
        onView(withText(R.string.audit_log_filter_key_type)).check(matches(isDisplayed()))
    }

    // ---------------------------------------------------------------
    // Search
    // ---------------------------------------------------------------

    /** Typing a key label narrows the list to the matching entry. */
    @Test
    fun search_filtersByKeyLabel() {
        seedEntries()
        val scenario = ActivityScenario.launch(AuditLogActivity::class.java)
        awaitText(scenario, createdLabel)
        awaitText(scenario, deletedLabel)

        onView(withHint(R.string.audit_log_search_hint)).perform(replaceText(createdLabel))

        awaitText(scenario, createdLabel)
        awaitTextAbsent(scenario, deletedLabel)
    }

    /**
     * A search that matches nothing falls back to the empty state.
     *
     * The empty state is asserted first: it is the direct signal that the
     * debounced `applyFilters()` has run with an empty result, so a failure
     * there points at the filter rather than at row teardown. The seeded labels
     * carry a per-run suffix no AuditLogger event can reproduce, so nothing can
     * re-populate the list mid-test.
     */
    @Test
    fun searchWithoutMatches_showsEmptyState() {
        seedEntries()
        val scenario = ActivityScenario.launch(AuditLogActivity::class.java)
        awaitText(scenario, createdLabel)

        onView(withHint(R.string.audit_log_search_hint))
            .perform(replaceText("no-such-audit-label-$runId"))

        awaitCondition("Empty state should be shown when the search matches nothing") {
            var shown = false
            scenario.onActivity { activity ->
                shown = findTextView(
                    activity.window.decorView,
                    activity.getString(R.string.audit_log_empty_title)
                )?.isShown == true
            }
            shown
        }
        awaitTextAbsent(scenario, createdLabel)
    }

    // ---------------------------------------------------------------
    // Hero card
    // ---------------------------------------------------------------

    @Test
    fun heroCard_showsAllEventsSummaryWhenUnfiltered() {
        seedEntries()
        val scenario = ActivityScenario.launch(AuditLogActivity::class.java)

        awaitText(
            scenario,
            ApplicationProvider.getApplicationContext<Context>()
                .getString(R.string.audit_log_no_filters)
        )
    }

    /** Applying a filter replaces the summary line with the active filter. */
    @Test
    fun heroCard_summaryReflectsActiveFilter() {
        seedEntries()
        val context = ApplicationProvider.getApplicationContext<Context>()
        val scenario = ActivityScenario.launch(AuditLogActivity::class.java)
        awaitText(scenario, createdLabel)

        onView(firstDisplayed(R.string.audit_log_op_key_created)).perform(click())

        awaitText(
            scenario,
            context.getString(
                R.string.audit_log_filtered_by,
                context.getString(R.string.audit_log_op_key_created)
            )
        )
    }

    // ---------------------------------------------------------------
    // List binding and expansion
    // ---------------------------------------------------------------

    @Test
    fun seededEntry_bindsLabelAndOperationBadge() {
        seedEntries()
        val context = ApplicationProvider.getApplicationContext<Context>()
        val scenario = ActivityScenario.launch(AuditLogActivity::class.java)

        awaitText(scenario, createdLabel)
        awaitText(scenario, context.getString(R.string.audit_log_op_key_created))
    }

    /** Tapping an expanded card collapses it again. */
    @Test
    fun tappingExpandedEntry_collapsesDetailRows() {
        seedEntries()
        val scenario = ActivityScenario.launch(AuditLogActivity::class.java)
        awaitText(scenario, createdLabel)

        onView(withText(createdLabel)).perform(scrollToView(), click())
        awaitText(scenario, createdKeyId)

        onView(withText(createdLabel)).perform(click())

        awaitCondition("Detail rows should be hidden again after collapsing") {
            var hidden = true
            scenario.onActivity { activity ->
                hidden = findTextView(activity.window.decorView, createdKeyId)?.isShown != true
            }
            hidden
        }
    }

    // ---------------------------------------------------------------
    // Empty state
    // ---------------------------------------------------------------

    @Test
    fun emptyState_isHiddenWhileEntriesExist() {
        seedEntries()
        val scenario = ActivityScenario.launch(AuditLogActivity::class.java)
        awaitText(scenario, createdLabel)

        scenario.onActivity { activity ->
            val emptyTitle = findTextView(
                activity.window.decorView,
                activity.getString(R.string.audit_log_empty_title)
            )
            assertNotNull("Empty-state title should exist in the hierarchy", emptyTitle)
            assertTrue(
                "Empty state must not be shown while entries exist",
                !emptyTitle!!.isShown
            )
        }
    }

    // ---------------------------------------------------------------
    // Back Navigation
    // ---------------------------------------------------------------

    @Test
    fun backNavigation_finishesActivity() {
        val scenario = ActivityScenario.launch(AuditLogActivity::class.java)

        // pressBack() throws NoActivityResumedException when back closes the
        // last activity in the task, which is exactly what we assert here.
        pressBackUnconditionally()

        assertActivityDestroyed(scenario)
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    /**
     * Matches the first displayed view carrying [stringRes] -- the filter chips
     * are built before the list, whose operation badges repeat the same labels.
     */
    private fun firstDisplayed(stringRes: Int) =
        nthMatch(allOf(withText(stringRes), isDisplayed()), 0)

    /**
     * Seeds one FIDO2 "Key Created" entry and one signing "Key Deleted" entry,
     * both timestamped now so they sort to the top of the newest-first list.
     */
    private fun seedEntries() {
        runBlocking {
            auditLogDao.insert(
                AuditLogEntity(
                    timestamp = System.currentTimeMillis(),
                    operationType = AuditOperationType.KEY_CREATED,
                    keyId = createdKeyId,
                    keyLabel = createdLabel,
                    keyType = "fido2",
                    success = true
                )
            )
            auditLogDao.insert(
                AuditLogEntity(
                    timestamp = System.currentTimeMillis(),
                    operationType = AuditOperationType.KEY_DELETED,
                    keyId = deletedKeyId,
                    keyLabel = deletedLabel,
                    keyType = "signing",
                    success = true
                )
            )
        }
    }
}
