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
import android.view.View
import android.widget.EditText
import android.widget.HorizontalScrollView
import android.widget.ImageView
import android.widget.TextView
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.espresso.Espresso.pressBack
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.automatethethings.xkey.audit.AuditLogDao
import com.automatethethings.xkey.audit.AuditLogEntity
import com.automatethethings.xkey.audit.AuditOperationType
import com.automatethethings.xkey.storage.XKeyDatabase
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * End-to-end filter, search and detail flows for [AuditLogActivity].
 *
 * `AuditLogActivityUiTest` establishes that the screen renders and that a
 * single operation/key-type chip filters. This suite drives what that one
 * skips: every chip in both rows, the chips combined with each other and with
 * the search box, the resulting empty state, the singular/plural summary
 * wording, the full expanded-detail row set (including the error and
 * malformed-JSON branches), the date-range picker, and a sweep that binds one
 * row for every [AuditOperationType] so the screen's badge label and colour
 * tables are exercised end to end.
 *
 * Determinism comes from a per-run search token: every seeded entry's key label
 * starts with a `nanoTime`-derived prefix that nothing else on the device can
 * produce, so typing the token into the search box reduces the list to exactly
 * this suite's rows no matter how much history the device already carries. No
 * assertion uses an absolute count of the whole table -- the unfiltered
 * assertions read the live value from [AuditLogDao] instead.
 *
 * Chips are addressed by their container rather than their text: the operation
 * row and the key-type row both contain a chip reading "All", and
 * `audit_log_op_signing` and `key_filter_signing` are both "Signing", so a text
 * matcher is ambiguous by construction. The two chip rows are the only
 * [HorizontalScrollView]s on the screen and are built operation-first.
 *
 * The toolbar's overflow actions (export JSON/CSV, clear filters, clear all,
 * delete older) are *not* covered, and cannot be: see the suite's report notes.
 *
 * Every seeded row is deleted by key id in @After.
 */
@RunWith(AndroidJUnit4::class)
class AuditLogFlowTest {

    private val runId = System.nanoTime()

    /** Unique to this run, so a search on it isolates exactly the seeded rows. */
    private val token = "UITestAuditFlow$runId"

    /** Separate token for the per-operation-type sweep. */
    private val sweepToken = "UITestAuditSweep$runId"

    private lateinit var context: Context
    private lateinit var auditLogDao: AuditLogDao

    /** Key ids seeded by this suite, removed wholesale in teardown. */
    private val seededKeyIds = mutableListOf<String>()

    // Core fixture: one row per operation-filter chip, with distinct key types.
    private val createdLabel = "$token-created"
    private val deletedLabel = "$token-deleted"
    private val signingLabel = "$token-signing"
    private val fido2Label = "$token-fido2auth"
    private val pairingLabel = "$token-pairing"
    private val connectionLabel = "$token-connection"
    private val richLabel = "$token-rich"
    private val rawDetailsLabel = "$token-rawdetails"

    private val richKeyId = "$token-rich-key"
    private val richDeviceId = "$token-rich-device"
    private val richDeviceName = "$token-rich-devicename"
    private val richError = "$token-boom"
    private val richDetailValue = "$token-detailvalue"
    private val rawDetails = "$token not json at all"

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        auditLogDao = XKeyDatabase.getInstance(context).auditLogDao()
        seedCoreFixture()
    }

    @After
    fun tearDown() {
        runBlocking {
            seededKeyIds.forEach { auditLogDao.deleteByKeyId(it) }
        }
        seededKeyIds.clear()
    }

    // ---------------------------------------------------------------
    // Operation-type chips
    // ---------------------------------------------------------------

    /**
     * Each operation chip keeps only its own event, and the hero summary names
     * both the operation and the active search term.
     */
    @Test
    fun everyOperationChip_narrowsTheSearchResultsToItsOwnEvent() {
        val scenario = launchFiltered()

        val expectations = listOf(
            Triple(R.string.audit_log_op_key_created, createdLabel, deletedLabel),
            Triple(R.string.audit_log_op_key_deleted, deletedLabel, createdLabel),
            Triple(R.string.audit_log_op_signing, signingLabel, createdLabel),
            Triple(R.string.audit_log_op_fido2, fido2Label, createdLabel),
            Triple(R.string.audit_log_op_pairing, pairingLabel, createdLabel),
            Triple(R.string.audit_log_op_connection, connectionLabel, createdLabel)
        )

        expectations.forEach { (chipRes, expected, excluded) ->
            val chipLabel = context.getString(chipRes)
            clickOperationChip(scenario, chipLabel)

            awaitFilteredCount(scenario, 1)
            assertShownTextInList(scenario, expected)
            awaitTextAbsent(scenario, excluded)
            awaitText(
                scenario,
                context.getString(
                    R.string.audit_log_filtered_by,
                    "$chipLabel, \"$token\""
                )
            )
        }
    }

    /** Re-selecting "All" in the operation row restores every searched row. */
    @Test
    fun allOperationChip_restoresTheWholeSearchResultSet() {
        val scenario = launchFiltered()
        clickOperationChip(scenario, context.getString(R.string.audit_log_op_key_created))
        awaitFilteredCount(scenario, 1)

        clickOperationChip(scenario, context.getString(R.string.audit_log_filter_all))

        awaitFilteredCount(scenario, CORE_FIXTURE_SIZE)
        awaitText(
            scenario,
            context.getString(R.string.audit_log_filtered_by, "\"$token\"")
        )
    }

    // ---------------------------------------------------------------
    // Key-type chips
    // ---------------------------------------------------------------

    /** Each key-type chip keeps only the rows recorded against that key type. */
    @Test
    fun everyKeyTypeChip_narrowsTheSearchResultsToItsOwnKeyType() {
        val scenario = launchFiltered()

        val expectations = listOf(
            R.string.key_filter_fido2 to fido2KeyTypeLabels(),
            R.string.key_filter_signing to signingKeyTypeLabels(),
            R.string.key_filter_encryption to listOf(pairingLabel),
            R.string.key_filter_secret to listOf(connectionLabel)
        )

        expectations.forEach { (chipRes, expectedLabels) ->
            val chipLabel = context.getString(chipRes)
            clickKeyTypeChip(scenario, chipLabel)

            awaitFilteredCount(scenario, expectedLabels.size)
            expectedLabels.forEach { assertShownTextInList(scenario, it) }
        }
    }

    /** Re-selecting "All" in the key-type row restores every searched row. */
    @Test
    fun allKeyTypeChip_restoresTheWholeSearchResultSet() {
        val scenario = launchFiltered()
        clickKeyTypeChip(scenario, context.getString(R.string.key_filter_secret))
        awaitFilteredCount(scenario, 1)

        clickKeyTypeChip(scenario, context.getString(R.string.key_filter_all))

        awaitFilteredCount(scenario, CORE_FIXTURE_SIZE)
    }

    // ---------------------------------------------------------------
    // Combined filters
    // ---------------------------------------------------------------

    /**
     * The operation and key-type filters intersect rather than replace each
     * other, and the hero card lists both alongside the search term.
     */
    @Test
    fun operationAndKeyTypeChips_intersect() {
        val scenario = launchFiltered()

        clickOperationChip(scenario, context.getString(R.string.audit_log_op_key_created))
        clickKeyTypeChip(scenario, context.getString(R.string.key_filter_fido2))

        awaitFilteredCount(scenario, 1)
        assertShownTextInList(scenario, createdLabel)
        awaitTextAbsent(scenario, fido2Label)
        awaitText(
            scenario,
            context.getString(
                R.string.audit_log_filtered_by,
                "${context.getString(R.string.audit_log_op_key_created)}, fido2, \"$token\""
            )
        )
    }

    /**
     * A combination that matches nothing collapses to the empty state, and the
     * list is genuinely hidden rather than merely re-bound: the activity marks
     * the RecyclerView GONE, which leaves its already-bound rows attached.
     */
    @Test
    fun aFilterCombinationWithNoMatches_showsTheEmptyState() {
        val scenario = launchFiltered()

        clickOperationChip(scenario, context.getString(R.string.audit_log_op_key_created))
        clickKeyTypeChip(scenario, context.getString(R.string.key_filter_secret))

        awaitFilteredCount(scenario, 0)
        awaitText(scenario, context.getString(R.string.audit_log_empty_title))
        assertShownTextInTree(scenario, context.getString(R.string.audit_log_empty_description))
        awaitTextAbsent(scenario, createdLabel)
        assertExactTextShown(scenario, "0")
    }

    // ---------------------------------------------------------------
    // Search
    // ---------------------------------------------------------------

    /** The search box also matches the device name, not just the key label. */
    @Test
    fun search_matchesTheDeviceNameAsWellAsTheKeyLabel() {
        val scenario = launch()

        search(scenario, richDeviceName)

        awaitFilteredCount(scenario, 1)
        assertShownTextInList(scenario, richLabel)
    }

    /**
     * A single match switches the hero label to its singular form; clearing the
     * search restores the full table, whose size is read from the DAO rather
     * than assumed (other suites write to this table constantly).
     */
    @Test
    fun searchNarrowingToOneRow_usesTheSingularHeroLabel_andClearingRestoresTheTable() {
        val scenario = launch()

        search(scenario, richLabel)

        awaitFilteredCount(scenario, 1)
        assertExactTextShown(scenario, "1")
        assertExactTextShown(scenario, context.getString(R.string.audit_log_entry_label))

        search(scenario, "")

        val liveCount = runBlocking { auditLogDao.getCount() }.toInt()
        assertTrue(
            "Clearing the search should restore the whole table (expected at least $liveCount rows)",
            awaitActivity(scenario) {
                (findFirstRecyclerView(it.window.decorView)?.adapter?.itemCount ?: -1) >= liveCount
            }
        )
        awaitText(scenario, context.getString(R.string.audit_log_no_filters))
    }

    // ---------------------------------------------------------------
    // Expandable detail rows
    // ---------------------------------------------------------------

    /**
     * Tapping a row expands it and renders one detail row per populated field,
     * including the failure message and the parsed `details` JSON.
     */
    @Test
    fun expandingAnEntry_rendersEveryPopulatedDetailRow() {
        val scenario = launch()
        search(scenario, richLabel)
        awaitFilteredCount(scenario, 1)

        clickRowContaining(scenario, richLabel)

        listOf(
            context.getString(R.string.key_detail_id),
            richKeyId,
            context.getString(R.string.key_detail_type),
            context.getString(R.string.audit_log_device_id),
            richDeviceId,
            context.getString(R.string.audit_log_error),
            richError,
            context.getString(R.string.audit_log_duration),
            DETAIL_JSON_KEY,
            richDetailValue
        ).forEach { awaitText(scenario, it) }
    }

    /** A `details` payload that is not JSON falls back to one raw row. */
    @Test
    fun expandingAnEntryWithNonJsonDetails_fallsBackToARawDetailsRow() {
        val scenario = launch()
        search(scenario, rawDetailsLabel)
        awaitFilteredCount(scenario, 1)

        clickRowContaining(scenario, rawDetailsLabel)

        awaitText(scenario, context.getString(R.string.audit_log_details))
        awaitText(scenario, rawDetails)
    }

    /**
     * The row subtitle concatenates key type, device name and duration with the
     * pipe separator, and is only built for the fields the entry actually has.
     */
    @Test
    fun rowSubtitle_combinesKeyTypeDeviceNameAndDuration() {
        val scenario = launch()

        search(scenario, richLabel)

        awaitFilteredCount(scenario, 1)
        assertShownTextInList(scenario, "signing | $richDeviceName | ${RICH_DURATION_MS}ms")
    }

    // ---------------------------------------------------------------
    // Date range picker
    // ---------------------------------------------------------------

    /**
     * The calendar affordance in the search bar opens the Material date-range
     * picker, and dismissing it leaves the activity and its filters intact.
     *
     * The picker lives in its own window, so it is asserted through the
     * fragment the activity adds rather than through Espresso's root
     * selection -- a fullscreen `DialogFragment` is not an `isDialog()` root.
     */
    @Test
    fun dateRangeButton_opensThePickerAndDismissingItLeavesTheScreenIntact() {
        val scenario = launchFiltered()

        clickDateRangeButton(scenario)

        awaitCondition("The date-range picker should be shown with its title") {
            withActivity(scenario) { activity ->
                val picker = activity.supportFragmentManager
                    .findFragmentByTag(DATE_PICKER_TAG)
                picker?.view != null && findShownTextViewContaining(
                    picker.view,
                    activity.getString(R.string.audit_log_select_date_range)
                ) != null
            }
        }
        // The picker is attached and drawn some time before its window is
        // granted focus, and Espresso's pressBack() refuses to inject into a
        // hierarchy that has none ("Waited for the root of the view hierarchy to
        // have window focus"). Waiting for the transfer is the difference
        // between a stable test and one that fails whenever the emulator is busy.
        awaitCondition("The date-range picker's window should take focus") {
            withActivity(scenario) { activity ->
                activity.supportFragmentManager
                    .findFragmentByTag(DATE_PICKER_TAG)
                    ?.view
                    ?.hasWindowFocus() == true
            }
        }

        pressBack()
        waitForIdle()

        awaitCondition("Pressing back should dismiss the date-range picker") {
            withActivity(scenario) {
                it.supportFragmentManager.findFragmentByTag(DATE_PICKER_TAG) == null
            }
        }
        assertTrue(
            "Dismissing the date picker must not finish the activity",
            !withActivity(scenario) { it.isFinishing }
        )
        awaitFilteredCount(scenario, CORE_FIXTURE_SIZE)
    }

    // ---------------------------------------------------------------
    // Operation-type sweep
    // ---------------------------------------------------------------

    /**
     * Binds one row for every [AuditOperationType].
     *
     * The card binder resolves a display name and a badge colour per operation
     * type through two exhaustive `when` tables. Scrolling every seeded row to
     * the top forces each to bind at least once, so a newly added enum constant
     * that the tables do not handle fails here rather than at runtime.
     */
    @Test
    fun everyOperationType_bindsARow() {
        val expectedLabels = seedOneEntryPerOperationType()
        val scenario = launch()

        search(scenario, sweepToken)
        awaitFilteredCount(scenario, expectedLabels.size)

        val seen = mutableSetOf<String>()
        for (position in 0 until expectedLabels.size) {
            withActivity(scenario) {
                findFirstRecyclerView(it.window.decorView)?.scrollToPosition(position)
            }
            waitForIdle()
            withActivity(scenario) { activity ->
                val recycler = findFirstRecyclerView(activity.window.decorView)
                collectViews(recycler) { view ->
                    view is TextView && view.text?.toString()?.startsWith(sweepToken) == true
                }.forEach { seen.add((it as TextView).text.toString()) }
            }
        }

        assertEquals(
            "Every seeded operation type should have bound a row",
            expectedLabels.toSet(),
            seen
        )
    }

    // ---------------------------------------------------------------
    // Helpers: launching and searching
    // ---------------------------------------------------------------

    private fun launch(): ActivityScenario<AuditLogActivity> =
        ActivityScenario.launch(AuditLogActivity::class.java)

    /** Launches and immediately reduces the list to this run's seeded rows. */
    private fun launchFiltered(): ActivityScenario<AuditLogActivity> {
        val scenario = launch()
        search(scenario, token)
        awaitFilteredCount(scenario, CORE_FIXTURE_SIZE)
        return scenario
    }

    /**
     * Types [query] into the search field.
     *
     * The text is set on the main thread rather than through Espresso so no
     * soft keyboard is involved; the activity's own `TextWatcher` and its
     * 300 ms debounce still run exactly as they would for a real keystroke.
     */
    private fun search(scenario: ActivityScenario<AuditLogActivity>, query: String) {
        scenario.onActivity { activity ->
            val hint = activity.getString(R.string.audit_log_search_hint)
            val input = collectViews(activity.window.decorView) {
                it is EditText && it.hint?.toString() == hint
            }.firstOrNull() as? EditText
            if (input == null) {
                fail("No search field with the audit-log hint")
                return@onActivity
            }
            input.setText(query)
        }
        waitForIdle()
    }

    /** Asserts the filtered list settles on exactly [expected] rows. */
    private fun awaitFilteredCount(scenario: ActivityScenario<AuditLogActivity>, expected: Int) {
        assertTrue(
            "Expected the filtered audit list to hold exactly $expected rows, " +
                "was ${recyclerItemCount(scenario)}",
            awaitExactRecyclerItemCount(scenario, expected)
        )
    }

    // ---------------------------------------------------------------
    // Helpers: chips
    // ---------------------------------------------------------------

    /** Clicks the chip reading [label] in the operation-type row. */
    private fun clickOperationChip(scenario: ActivityScenario<AuditLogActivity>, label: String) {
        clickChipInRow(scenario, OPERATION_CHIP_ROW, label)
    }

    /** Clicks the chip reading [label] in the key-type row. */
    private fun clickKeyTypeChip(scenario: ActivityScenario<AuditLogActivity>, label: String) {
        clickChipInRow(scenario, KEY_TYPE_CHIP_ROW, label)
    }

    /**
     * Clicks the chip reading [label] inside the [rowIndex]-th chip row.
     *
     * Both rows repeat "All", and "Signing" is both an operation and a key
     * type, so the chip has to be located by container. The two rows are the
     * screen's only [HorizontalScrollView]s and are added operation row first.
     */
    private fun clickChipInRow(
        scenario: ActivityScenario<AuditLogActivity>,
        rowIndex: Int,
        label: String
    ) {
        scenario.onActivity { activity ->
            val rows = collectViews(activity.window.decorView) { it is HorizontalScrollView }
            val row = rows.getOrNull(rowIndex)
            if (row == null) {
                fail("No chip row at index $rowIndex (found ${rows.size} rows)")
                return@onActivity
            }
            val chip = collectViews(row) {
                it is TextView && it.text?.toString() == label
            }.firstOrNull()
            if (chip == null) {
                fail("No chip reading '$label' in chip row $rowIndex")
                return@onActivity
            }
            chip.performClick()
        }
        waitForIdle()
    }

    /**
     * Expands the card whose bound label contains [text].
     *
     * The click has to be scoped to the list: the hero card's filter-summary
     * line echoes the active search term, so a whole-tree search for a seeded
     * label finds the summary first and clicks the hero card instead of a row.
     */
    private fun clickRowContaining(scenario: ActivityScenario<AuditLogActivity>, text: String) {
        scenario.onActivity { activity ->
            val recycler = findFirstRecyclerView(activity.window.decorView)
            val target = findShownTextViewContaining(recycler, text)
            if (target == null) {
                fail("No bound row containing '$text'")
                return@onActivity
            }
            var candidate: View? = target
            while (candidate != null && !candidate.isClickable) {
                candidate = candidate.parent as? View
            }
            (candidate ?: target).performClick()
        }
        waitForIdle()
    }

    /** Clicks the calendar icon that opens the date-range picker. */
    private fun clickDateRangeButton(scenario: ActivityScenario<AuditLogActivity>) {
        scenario.onActivity { activity ->
            val description = activity.getString(R.string.audit_log_date_range)
            val button: View? = collectViews(activity.window.decorView) {
                it is ImageView && it.contentDescription?.toString() == description
            }.firstOrNull()
            if (button == null) {
                fail("No date-range button with content description '$description'")
                return@onActivity
            }
            button.performClick()
        }
        waitForIdle()
    }

    // ---------------------------------------------------------------
    // Helpers: seeding
    // ---------------------------------------------------------------

    /**
     * Seeds one row per operation-filter chip plus the two detail fixtures.
     *
     * Key types are spread across the key-type chips so the two filter rows can
     * be intersected: `created` is the only fido2 "Key Created" row, while
     * `fido2auth` is a fido2 row under a different operation.
     */
    private fun seedCoreFixture() {
        seed(
            label = createdLabel,
            operationType = AuditOperationType.KEY_CREATED,
            keyType = "fido2"
        )
        seed(
            label = deletedLabel,
            operationType = AuditOperationType.KEY_DELETED,
            keyType = "signing"
        )
        seed(
            label = signingLabel,
            operationType = AuditOperationType.SIGNING_REQUEST,
            keyType = "signing"
        )
        seed(
            label = fido2Label,
            operationType = AuditOperationType.FIDO2_AUTHENTICATION,
            keyType = "fido2"
        )
        seed(
            label = pairingLabel,
            operationType = AuditOperationType.PAIRING_APPROVED,
            keyType = "encryption"
        )
        seed(
            label = connectionLabel,
            operationType = AuditOperationType.CONNECTION_ESTABLISHED,
            keyType = "secret"
        )
        seed(
            label = richLabel,
            operationType = AuditOperationType.HMAC_REQUEST,
            keyType = "signing",
            keyId = richKeyId,
            deviceId = richDeviceId,
            deviceName = richDeviceName,
            success = false,
            errorMessage = richError,
            details = """{"$DETAIL_JSON_KEY":"$richDetailValue"}""",
            durationMs = RICH_DURATION_MS
        )
        seed(
            label = rawDetailsLabel,
            operationType = AuditOperationType.KEY_USED,
            keyType = "signing",
            details = rawDetails
        )
    }

    /** Seeds one entry per [AuditOperationType]; returns the labels used. */
    private fun seedOneEntryPerOperationType(): List<String> =
        AuditOperationType.entries.map { type ->
            val label = "$sweepToken-${type.name}"
            seed(label = label, operationType = type, keyType = "signing")
            label
        }

    /**
     * Inserts one audit row and records its key id for teardown.
     *
     * The key id defaults to the label so every row is individually deletable;
     * rows are timestamped now so they sort to the head of the newest-first
     * list, which keeps the scroll scans short.
     */
    private fun seed(
        label: String,
        operationType: AuditOperationType,
        keyType: String,
        keyId: String = label,
        deviceId: String? = null,
        deviceName: String? = null,
        success: Boolean = true,
        errorMessage: String? = null,
        details: String? = null,
        durationMs: Long? = null
    ) {
        seededKeyIds.add(keyId)
        runBlocking {
            auditLogDao.insert(
                AuditLogEntity(
                    timestamp = System.currentTimeMillis(),
                    operationType = operationType,
                    keyId = keyId,
                    keyLabel = label,
                    keyType = keyType,
                    deviceId = deviceId,
                    deviceName = deviceName,
                    success = success,
                    errorMessage = errorMessage,
                    details = details,
                    durationMs = durationMs
                )
            )
        }
    }

    private fun fido2KeyTypeLabels() = listOf(createdLabel, fido2Label)

    private fun signingKeyTypeLabels() =
        listOf(deletedLabel, signingLabel, richLabel, rawDetailsLabel)

    private companion object {

        /** Number of rows [seedCoreFixture] inserts. */
        const val CORE_FIXTURE_SIZE = 8

        /** Depth-first index of the operation-type chip row among the scrollers. */
        const val OPERATION_CHIP_ROW = 0

        /** Depth-first index of the key-type chip row among the scrollers. */
        const val KEY_TYPE_CHIP_ROW = 1

        const val DETAIL_JSON_KEY = "reason"
        const val RICH_DURATION_MS = 4242L

        /** Fragment tag the activity uses for the Material date-range picker. */
        const val DATE_PICKER_TAG = "date_picker"
    }
}
