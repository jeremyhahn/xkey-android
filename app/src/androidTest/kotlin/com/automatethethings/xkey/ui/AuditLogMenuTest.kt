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
import android.app.Instrumentation
import android.content.Context
import android.content.Intent
import android.view.Menu
import android.view.View
import android.widget.EditText
import android.widget.HorizontalScrollView
import android.widget.ImageButton
import android.widget.TextView
import androidx.appcompat.widget.Toolbar
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.intent.Intents
import androidx.test.espresso.intent.matcher.IntentMatchers.hasAction
import androidx.test.espresso.intent.matcher.IntentMatchers.hasExtraWithKey
import androidx.test.espresso.matcher.RootMatchers.isDialog
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.withId
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.automatethethings.xkey.audit.AuditLogDao
import com.automatethethings.xkey.audit.AuditLogEntity
import com.automatethethings.xkey.audit.AuditOperationType
import com.automatethethings.xkey.storage.XKeyDatabase
import kotlinx.coroutines.runBlocking
import org.hamcrest.Matchers.allOf
import org.json.JSONArray
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * Overflow-menu coverage for [AuditLogActivity].
 *
 * `AuditLogActivityUiTest` and `AuditLogFlowTest` between them drive the chips,
 * the search box, the hero summary and the expandable rows, but both explicitly
 * skip the toolbar's overflow: the menu used to be inflated straight onto the
 * `Toolbar` *before* `setSupportActionBar`, which made AppCompat throw it away
 * and left export, clear-filters and both delete actions unreachable. The
 * activity now overrides `onCreateOptionsMenu`/`onOptionsItemSelected`, so this
 * suite covers the block that unlocked:
 *
 * - the menu itself: every documented action is inflated with the right id
 * - `exportToJson` / `exportToCsv` / `shareFile`, driven all the way to a real
 *   file in `cacheDir` whose contents are parsed and asserted
 * - export honouring the active chip filters (the export re-queries the DAO
 *   rather than reusing the on-screen list)
 * - `clearAllFilters` resetting chips, search text and the hero summary together
 * - both destructive confirmations, driven to their CANCEL branch only -- their
 *   positive branches delete rows this test does not own, so they are asserted
 *   as *not* having run
 * - the `android.R.id.home` branch of `onOptionsItemSelected`
 *
 * Menu items are invoked through [Menu.performIdentifierAction] on the toolbar's
 * own menu rather than by opening the overflow popup. That still travels the
 * production path (`MenuBuilder` -> AppCompat window callback ->
 * `onOptionsItemSelected`) but does not depend on a popup window's animation
 * settling, which is the flakiest thing on an emulator.
 *
 * Determinism: every seeded row carries a `nanoTime` token, teardown deletes
 * them by key id, and no assertion uses an absolute row count -- the counts that
 * matter are read live from [AuditLogDao]. Export files this run creates are
 * deleted in teardown too.
 */
@RunWith(AndroidJUnit4::class)
class AuditLogMenuTest {

    private val runId = System.nanoTime()

    /** Unique to this run, so a search on it isolates exactly the seeded rows. */
    private val token = "UITestAuditMenu$runId"

    /**
     * Deliberately embeds two double quotes: the CSV writer has to double each
     * of them, and nothing else on the device produces a label like this.
     */
    private val quotedLabel = "$token-say-${QUOTE}hi$QUOTE"

    /** The same label as the CSV writer must escape it. */
    private val csvEscapedLabel = "$token-say-$QUOTE$QUOTE" + "hi" + "$QUOTE$QUOTE"

    private val createdLabel = "$token-created"
    private val deletedLabel = "$token-deleted"

    private val quotedKeyId = "$token-quoted-key"
    private val quotedDeviceId = "$token-quoted-device"
    private val quotedDeviceName = "$token-quoted-devicename"
    private val quotedError = "$token-boom"

    private lateinit var context: Context
    private lateinit var auditLogDao: AuditLogDao
    private lateinit var scenario: ActivityScenario<AuditLogActivity>

    /** Key ids seeded by this suite, removed wholesale in teardown. */
    private val seededKeyIds = mutableListOf<String>()

    /** Export files that existed before the test, so new ones can be told apart. */
    private lateinit var preExistingExports: Set<String>

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        auditLogDao = XKeyDatabase.getInstance(context).auditLogDao()
        seedFixture()
        preExistingExports = exportFiles().map { it.name }.toSet()

        // The activity is launched before Intents is initialised so the launch
        // itself is not recorded; only the intents the menu produces are.
        scenario = ActivityScenario.launch(AuditLogActivity::class.java)
        Intents.init()
        Intents.intending(hasAction(Intent.ACTION_CHOOSER))
            .respondWith(Instrumentation.ActivityResult(Activity.RESULT_OK, null))
    }

    @After
    fun tearDown() {
        Intents.release()
        scenario.close()
        exportFiles()
            .filterNot { preExistingExports.contains(it.name) }
            .forEach { it.delete() }
        runBlocking {
            seededKeyIds.forEach { auditLogDao.deleteByKeyId(it) }
        }
        seededKeyIds.clear()
    }

    // ---------------------------------------------------------------
    // The menu itself
    // ---------------------------------------------------------------

    /**
     * Every action the menu resource declares reaches the inflated menu.
     *
     * This is the regression guard for the ordering bug: an inflation that
     * AppCompat discards leaves the menu empty, and every other test in this
     * file would then fail for a confusing reason.
     */
    @Test
    fun overflowMenu_inflatesEveryDocumentedAction() {
        val titles = withMenu { menu ->
            (0 until menu.size()).map { menu.getItem(it).title?.toString().orEmpty() }
        }

        assertEquals(
            "The audit log overflow should offer exactly its five documented actions",
            listOf(
                context.getString(R.string.audit_log_export_json),
                context.getString(R.string.audit_log_export_csv),
                context.getString(R.string.audit_log_clear_filters),
                context.getString(R.string.audit_clear_all),
                context.getString(R.string.audit_delete_older)
            ),
            titles
        )

        listOf(
            R.id.menu_export_json,
            R.id.menu_export_csv,
            R.id.menu_clear_filters,
            R.id.menu_clear_all_logs,
            R.id.menu_delete_older
        ).forEach { id ->
            assertNotNull(
                "Menu item ${context.resources.getResourceEntryName(id)} should be inflated",
                withMenu { it.findItem(id) }
            )
        }
    }

    // ---------------------------------------------------------------
    // Export
    // ---------------------------------------------------------------

    /**
     * "Export as JSON" writes a parseable array to the cache directory and hands
     * it to a share chooser.
     *
     * The exported object is located by key id rather than by position: the
     * export re-queries the whole table, so this run's rows sit among whatever
     * history the device already carries.
     */
    @Test
    fun exportAsJson_writesEveryFieldOfTheEntryAndSharesTheFile() {
        selectMenuItem(R.id.menu_export_json)

        val file = awaitNewExport(".json")
        val entries = JSONArray(file.readText())

        var found: org.json.JSONObject? = null
        for (index in 0 until entries.length()) {
            val entry = entries.getJSONObject(index)
            if (entry.optString("keyId") == quotedKeyId) {
                found = entry
                break
            }
        }
        assertNotNull("The exported JSON should contain the seeded entry", found)

        val entry = found!!
        assertEquals(quotedLabel, entry.getString("keyLabel"))
        assertEquals(AuditOperationType.HMAC_REQUEST.name, entry.getString("operationType"))
        assertEquals("signing", entry.getString("keyType"))
        assertEquals(quotedDeviceId, entry.getString("deviceId"))
        assertEquals(quotedDeviceName, entry.getString("deviceName"))
        assertEquals(false, entry.getBoolean("success"))
        assertEquals(quotedError, entry.getString("errorMessage"))
        assertEquals(DURATION_MS, entry.getLong("durationMs"))
        assertTrue(
            "The raw details payload should survive the export verbatim",
            entry.getString("details").contains(DETAIL_VALUE)
        )

        Intents.intended(
            allOf(hasAction(Intent.ACTION_CHOOSER), hasExtraWithKey(Intent.EXTRA_INTENT))
        )
    }

    /**
     * "Export as CSV" writes the documented header row and escapes embedded
     * double quotes by doubling them.
     */
    @Test
    fun exportAsCsv_writesTheHeaderRowAndEscapesQuotedFields() {
        selectMenuItem(R.id.menu_export_csv)

        val file = awaitNewExport(".csv")
        val lines = file.readLines()

        assertEquals(
            "CSV export should lead with the documented header row",
            "ID,Timestamp,Operation,Key ID,Key Label,Key Type,Device ID,Device Name," +
                "Success,Error,Details,Duration (ms)",
            lines.first()
        )

        val row = lines.firstOrNull { it.contains(quotedKeyId) }
        assertNotNull("The exported CSV should contain the seeded entry", row)
        assertTrue(
            "A double quote inside a field must be doubled, was: $row",
            row!!.contains(csvEscapedLabel)
        )
        assertTrue(row.contains(AuditOperationType.HMAC_REQUEST.name))
        assertTrue(row.contains(quotedDeviceName))
        assertTrue(row.contains(quotedError))
        assertTrue(row.endsWith(DURATION_MS.toString()))

        Intents.intended(
            allOf(hasAction(Intent.ACTION_CHOOSER), hasExtraWithKey(Intent.EXTRA_INTENT))
        )
    }

    /**
     * The export re-queries the DAO with the active chip filters rather than
     * dumping the whole table.
     *
     * Both seeded rows share this run's token, so the operation chip is the only
     * thing that can separate them.
     */
    @Test
    fun exportWithAnOperationFilter_omitsTheRowsThatChipHides() {
        clickChipInRow(OPERATION_CHIP_ROW, context.getString(R.string.audit_log_op_key_deleted))

        selectMenuItem(R.id.menu_export_json)

        val exported = awaitNewExport(".json").readText()
        assertTrue(
            "The filtered export should keep the row matching the active chip",
            exported.contains(deletedLabel)
        )
        assertTrue(
            "The filtered export should drop rows the active chip hides",
            !exported.contains(createdLabel)
        )
    }

    // ---------------------------------------------------------------
    // Clear filters
    // ---------------------------------------------------------------

    /**
     * "Clear Filters" resets both chip rows, the search field and the date range
     * in one action, and the hero card falls back to its unfiltered wording.
     */
    @Test
    fun clearFilters_resetsTheChipsSearchAndHeroSummaryTogether() {
        search(token)
        clickChipInRow(OPERATION_CHIP_ROW, context.getString(R.string.audit_log_op_key_created))
        clickChipInRow(KEY_TYPE_CHIP_ROW, context.getString(R.string.key_filter_fido2))
        awaitFilteredCount(1)

        selectMenuItem(R.id.menu_clear_filters)

        assertExactTextShown(scenario, context.getString(R.string.audit_log_no_filters))
        assertEquals(
            "The search field should have been emptied",
            "",
            withActivity(scenario) { searchField(it).text?.toString().orEmpty() }
        )

        val liveCount = runBlocking { auditLogDao.getCount() }.toInt()
        assertTrue(
            "Clearing the filters should restore the whole table (at least $liveCount rows)",
            awaitActivity(scenario) {
                (findFirstRecyclerView(it.window.decorView)?.adapter?.itemCount ?: -1) >= liveCount
            }
        )
    }

    // ---------------------------------------------------------------
    // Destructive confirmations -- cancel branch only
    // ---------------------------------------------------------------

    /**
     * "Clear All Logs" asks first, and cancelling leaves the table untouched.
     *
     * The positive branch is deliberately not driven: it would wipe rows owned
     * by every other suite on the device.
     */
    @Test
    fun clearAllLogs_cancelling_leavesEveryEntryInPlace() {
        val before = runBlocking { auditLogDao.getCount() }

        selectMenuItem(R.id.menu_clear_all_logs)

        onView(withText(R.string.audit_clear_all)).inRoot(isDialog()).check(matches(isDisplayed()))
        onView(withText(R.string.audit_clear_all_confirm))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
        onView(withId(android.R.id.button2)).inRoot(isDialog()).perform(click())
        waitForIdle()

        assertEquals(
            "Cancelling the clear-all confirmation must not delete anything",
            before,
            runBlocking { auditLogDao.getCount() }
        )
        assertTrue(
            "The seeded rows should survive a cancelled clear-all",
            runBlocking { auditLogDao.getByKeyId(quotedKeyId) }.isNotEmpty()
        )
        assertTextNotInTree(scenario, context.getString(R.string.audit_logs_cleared))
    }

    /**
     * "Delete Older Than 30 Days" asks first, and cancelling deletes nothing --
     * including the rows this run seeded, which are new enough to be safe either
     * way but prove the dialog never reached its action.
     */
    @Test
    fun deleteOlderLogs_cancelling_leavesEveryEntryInPlace() {
        val before = runBlocking { auditLogDao.getCount() }

        selectMenuItem(R.id.menu_delete_older)

        onView(withText(R.string.audit_delete_older))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
        onView(withText(R.string.audit_delete_older_confirm))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
        onView(withId(android.R.id.button2)).inRoot(isDialog()).perform(click())
        waitForIdle()

        assertEquals(
            "Cancelling the delete-older confirmation must not delete anything",
            before,
            runBlocking { auditLogDao.getCount() }
        )
    }

    // ---------------------------------------------------------------
    // Home
    // ---------------------------------------------------------------

    /**
     * The toolbar's up affordance routes through the `android.R.id.home` branch
     * of `onOptionsItemSelected` and finishes the screen.
     */
    @Test
    fun toolbarUpButton_finishesTheActivity() {
        scenario.onActivity { activity ->
            val toolbar = toolbarOf(activity)
            val up = collectViews(toolbar) { it is ImageButton }.firstOrNull()
            if (up == null) {
                fail("The audit log toolbar should render an up affordance")
                return@onActivity
            }
            up.performClick()
        }

        assertActivityDestroyed(scenario)
    }

    // ---------------------------------------------------------------
    // Helpers: the menu
    // ---------------------------------------------------------------

    /**
     * Runs [block] against the toolbar's inflated options menu.
     *
     * `setSupportActionBar` populates the menu on a posted runnable, so the menu
     * is empty for the first frame or two after launch; this polls rather than
     * reading once.
     */
    private fun <T> withMenu(block: (Menu) -> T): T {
        awaitCondition("The toolbar's options menu should be populated") {
            withActivity(scenario) { toolbarOf(it).menu.size() > 0 }
        }
        return withActivity(scenario) { block(toolbarOf(it).menu) }
    }

    /** Invokes the menu action [itemId] exactly as AppCompat would on a tap. */
    private fun selectMenuItem(itemId: Int) {
        val handled = withMenu { it.performIdentifierAction(itemId, 0) }
        assertTrue(
            "The activity should handle menu item " +
                context.resources.getResourceEntryName(itemId),
            handled
        )
        waitForIdle()
    }

    /** The activity's single [Toolbar]; it is the support action bar. */
    private fun toolbarOf(activity: AuditLogActivity): Toolbar =
        collectViews(activity.window.decorView) { it is Toolbar }.first() as Toolbar

    // ---------------------------------------------------------------
    // Helpers: export files
    // ---------------------------------------------------------------

    /** Every audit-log export currently sitting in the app's cache directory. */
    private fun exportFiles(): List<File> =
        context.cacheDir.listFiles()
            ?.filter { it.name.startsWith(EXPORT_FILE_PREFIX) }
            ?: emptyList()

    /**
     * Waits for an export with the given [extension] that this test created.
     *
     * The export runs in `lifecycleScope`, so the file appears some time after
     * the menu action returns; and the file name carries a whole-second
     * timestamp, so a name from an earlier test in the same second would be
     * indistinguishable without the pre-existing snapshot taken in `@Before`.
     */
    private fun awaitNewExport(extension: String): File {
        var found: File? = null
        awaitCondition("An audit log export ending in '$extension' should be written") {
            found = exportFiles().firstOrNull {
                it.name.endsWith(extension) &&
                    !preExistingExports.contains(it.name) &&
                    it.length() > 0
            }
            found != null
        }
        return found!!
    }

    // ---------------------------------------------------------------
    // Helpers: filters
    // ---------------------------------------------------------------

    /** The activity's debounced search field, matched by its hint. */
    private fun searchField(activity: AuditLogActivity): EditText {
        val hint = activity.getString(R.string.audit_log_search_hint)
        return collectViews(activity.window.decorView) {
            it is EditText && it.hint?.toString() == hint
        }.first() as EditText
    }

    /** Types [query] into the search field on the main thread. */
    private fun search(query: String) {
        scenario.onActivity { searchField(it).setText(query) }
        waitForIdle()
    }

    /**
     * Clicks the chip reading [label] inside the [rowIndex]-th chip row.
     *
     * Both rows contain a chip reading "All" and "Signing" is both an operation
     * and a key type, so chips have to be addressed by container. The two rows
     * are the screen's only [HorizontalScrollView]s, operation row first.
     */
    private fun clickChipInRow(rowIndex: Int, label: String) {
        scenario.onActivity { activity ->
            val rows = collectViews(activity.window.decorView) { it is HorizontalScrollView }
            val row = rows.getOrNull(rowIndex)
            if (row == null) {
                fail("No chip row at index $rowIndex (found ${rows.size} rows)")
                return@onActivity
            }
            val chip: View? = collectViews(row) {
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

    /** Asserts the filtered list settles on exactly [expected] rows. */
    private fun awaitFilteredCount(expected: Int) {
        assertTrue(
            "Expected the filtered audit list to hold exactly $expected rows, " +
                "was ${recyclerItemCount(scenario)}",
            awaitExactRecyclerItemCount(scenario, expected)
        )
    }

    // ---------------------------------------------------------------
    // Helpers: seeding
    // ---------------------------------------------------------------

    /**
     * Seeds three rows: the fully-populated one the export assertions read, and
     * one per operation chip used by the filtered-export test.
     */
    private fun seedFixture() {
        seed(
            label = quotedLabel,
            operationType = AuditOperationType.HMAC_REQUEST,
            keyType = "signing",
            keyId = quotedKeyId,
            deviceId = quotedDeviceId,
            deviceName = quotedDeviceName,
            success = false,
            errorMessage = quotedError,
            details = """{"reason":"$DETAIL_VALUE"}""",
            durationMs = DURATION_MS
        )
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
    }

    /** Inserts one audit row and records its key id for teardown. */
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

    private companion object {

        /** Depth-first index of the operation-type chip row among the scrollers. */
        const val OPERATION_CHIP_ROW = 0

        /** Depth-first index of the key-type chip row among the scrollers. */
        const val KEY_TYPE_CHIP_ROW = 1

        /** Prefix the activity gives every export it writes to `cacheDir`. */
        const val EXPORT_FILE_PREFIX = "xkey_audit_log_"

        /** A single double quote, spelled out so the labels stay readable. */
        const val QUOTE = "\""

        const val DETAIL_VALUE = "menu-export-detail"
        const val DURATION_MS = 4243L
    }
}
