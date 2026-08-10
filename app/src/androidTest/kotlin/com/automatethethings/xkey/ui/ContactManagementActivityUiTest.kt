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
import androidx.test.espresso.matcher.RootMatchers.isDialog
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.withHint
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.ContactDao
import com.automatethethings.xkey.storage.entity.ContactEntity
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented UI tests for [ContactManagementActivity].
 *
 * The screen observes `contacts` through a Room `Flow` and swaps a RecyclerView
 * for an empty state depending on the result. These tests seed two contacts so
 * that adapter binding, the summary card, the contact detail dialog and the
 * delete flow can be asserted against known rows; both are removed in @After.
 *
 * Import is asserted only at its stable entry points (the bottom sheet options
 * and the paste dialog). The QR import/export implementation is deliberately not
 * exercised here: it depends on the camera and is being reworked.
 *
 * Tests cover:
 * - Toolbar rendering
 * - Adapter binding, including the truncated fingerprint preview
 * - Summary count derived from live database state
 * - Empty state hidden while contacts exist
 * - Contact detail dialog contents
 * - Delete: cancel keeps the contact, confirm removes it from the database
 * - Import bottom sheet offering file / QR / paste, and the paste dialog
 * - Back navigation finishing the activity
 */
@RunWith(AndroidJUnit4::class)
class ContactManagementActivityUiTest {

    private lateinit var dao: ContactDao

    private val aliceFingerprint = "aa${System.nanoTime()}"
    private val bobFingerprint = "bb${System.nanoTime()}"

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        dao = XKeyDatabase.getInstance(context).contactDao()

        runBlocking {
            dao.insert(contact(ALICE_NAME, aliceFingerprint, "EC P-256", "file"))
            dao.insert(contact(BOB_NAME, bobFingerprint, "RSA 2048", "paste"))
        }
    }

    @After
    fun tearDown() {
        runBlocking {
            dao.deleteByFingerprint(aliceFingerprint)
            dao.deleteByFingerprint(bobFingerprint)
        }
    }

    // -----------------------------------------------------------------
    // Chrome
    // -----------------------------------------------------------------

    @Test
    fun toolbar_showsTitleAndSubtitle() {
        val scenario = launch()

        assertShownTextInTree(scenario, withString(scenario, R.string.contact_management_title))
        assertShownTextInTree(scenario, withString(scenario, R.string.contact_management_subtitle))
    }

    // -----------------------------------------------------------------
    // List binding
    // -----------------------------------------------------------------

    @Test
    fun contactList_bindsSeededContacts() {
        val scenario = launch()

        assertShownTextInTree(scenario, ALICE_NAME)
        assertShownTextInTree(scenario, BOB_NAME)
    }

    @Test
    fun contactList_showsAlgorithmForEachContact() {
        val scenario = launch()
        assertShownTextInTree(scenario, ALICE_NAME)

        assertShownTextInTree(scenario, "EC P-256")
        assertShownTextInTree(scenario, "RSA 2048")
    }

    /** Rows show only the leading 14 characters of the formatted fingerprint. */
    @Test
    fun contactList_showsTruncatedFingerprintPreview() {
        val scenario = launch()
        assertShownTextInTree(scenario, ALICE_NAME)

        val formatted = aliceFingerprint.uppercase().chunked(2).joinToString(":")
        val expected = if (formatted.length > 14) formatted.substring(0, 14) + "..." else formatted
        assertShownTextInTree(scenario, expected)
    }

    @Test
    fun contactList_itemCountMatchesDatabase() {
        val scenario = launch()
        assertShownTextInTree(scenario, ALICE_NAME)

        val expected = runBlocking { dao.getAll().size }
        assertTrue(
            "The adapter should bind every stored contact",
            awaitExactRecyclerItemCount(scenario, expected)
        )
    }

    // -----------------------------------------------------------------
    // Summary card and empty state
    // -----------------------------------------------------------------

    @Test
    fun summaryCard_countMatchesDatabase() {
        val scenario = launch()
        assertShownTextInTree(scenario, ALICE_NAME)

        val expected = runBlocking { dao.getAll().size }
        assertExactTextShown(scenario, expected.toString())
    }

    @Test
    fun summaryCard_usesThePluralLabelWhenContactsExist() {
        val scenario = launch()
        assertShownTextInTree(scenario, ALICE_NAME)

        val expected = runBlocking { dao.getAll().size }
        val label = withActivity(scenario) {
            it.resources.getQuantityString(R.plurals.contact_summary_count, expected, expected)
        }
        assertShownTextInTree(scenario, label)
    }

    @Test
    fun emptyState_isHiddenWhileContactsExist() {
        val scenario = launch()
        assertShownTextInTree(scenario, ALICE_NAME)

        val emptyTitle = withString(scenario, R.string.contact_empty_title)
        assertFalse(
            "The empty state must be hidden once contacts are bound",
            withActivity(scenario) {
                findShownTextViewContaining(it.window.decorView, emptyTitle) != null
            }
        )
    }

    // -----------------------------------------------------------------
    // Contact detail dialog
    // -----------------------------------------------------------------

    @Test
    fun contactTap_opensDetailDialogWithFingerprintAlgorithmAndSource() {
        val scenario = launch()
        assertShownTextInTree(scenario, ALICE_NAME)

        clickTextInTree(scenario, ALICE_NAME)

        val formatted = aliceFingerprint.uppercase().chunked(2).joinToString(":")
        onView(withText(withString(scenario, R.string.contact_fingerprint, formatted)))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
        onView(withText(withString(scenario, R.string.contact_algorithm, "EC P-256")))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
        onView(withText(withString(scenario, R.string.contact_source, "file")))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
    }

    // -----------------------------------------------------------------
    // Delete flow
    // -----------------------------------------------------------------

    @Test
    fun deleteCancelled_keepsTheContact() {
        val scenario = launch()
        assertShownTextInTree(scenario, ALICE_NAME)

        clickTextInTree(scenario, ALICE_NAME)
        onView(withText(R.string.contact_delete_confirm)).inRoot(isDialog()).perform(click())

        onView(withText(withString(scenario, R.string.contact_delete_message, ALICE_NAME)))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
        onView(withText(R.string.button_cancel)).inRoot(isDialog()).perform(click())

        assertTrue(
            "Cancelling the confirmation must keep the contact",
            runBlocking { dao.getByFingerprint(aliceFingerprint) != null }
        )
        assertShownTextInTree(scenario, ALICE_NAME)
    }

    @Test
    fun deleteConfirmed_removesTheContactFromDatabaseAndList() {
        val scenario = launch()
        assertShownTextInTree(scenario, ALICE_NAME)

        clickTextInTree(scenario, ALICE_NAME)
        onView(withText(R.string.contact_delete_confirm)).inRoot(isDialog()).perform(click())

        // Wait for the confirmation dialog before pressing its identically
        // labelled positive button.
        onView(withText(withString(scenario, R.string.contact_delete_message, ALICE_NAME)))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
        onView(withText(R.string.contact_delete_confirm)).inRoot(isDialog()).perform(click())

        assertTrue(
            "Confirming the dialog must delete the contact",
            awaitCondition { runBlocking { dao.getByFingerprint(aliceFingerprint) == null } }
        )
        assertTextNotInTree(scenario, ALICE_NAME)
        assertShownTextInTree(scenario, BOB_NAME)
    }

    // -----------------------------------------------------------------
    // Import entry points
    // -----------------------------------------------------------------

    @Test
    fun fab_opensImportBottomSheetWithAllThreeSources() {
        val scenario = launch()
        assertShownTextInTree(scenario, ALICE_NAME)

        clickClickableWithExactText(scenario, withString(scenario, R.string.contact_import_file))

        onView(withText(R.string.contact_import_file))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
        onView(withText(R.string.contact_import_qr))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
        onView(withText(R.string.contact_import_paste))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
    }

    @Test
    fun pasteOption_opensPasteDialogAndCancelAddsNoContact() {
        val scenario = launch()
        assertShownTextInTree(scenario, ALICE_NAME)
        val before = runBlocking { dao.getAll().size }

        clickClickableWithExactText(scenario, withString(scenario, R.string.contact_import_file))
        onView(withText(R.string.contact_import_paste)).inRoot(isDialog()).perform(click())

        onView(withHint(R.string.contact_paste_hint))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
        onView(withText(R.string.button_cancel)).inRoot(isDialog()).perform(click())

        assertEquals(before, runBlocking { dao.getAll().size })
    }

    // -----------------------------------------------------------------
    // Back navigation
    // -----------------------------------------------------------------

    @Test
    fun backNavigation_finishesActivity() {
        val scenario = launch()

        // pressBack() throws NoActivityResumedException when back closes the
        // last activity in the task, which is exactly what we assert here.
        pressBackUnconditionally()

        assertActivityDestroyed(scenario)
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private fun launch(): ActivityScenario<ContactManagementActivity> =
        ActivityScenario.launch(ContactManagementActivity::class.java)

    private fun withString(
        scenario: ActivityScenario<ContactManagementActivity>,
        resId: Int,
        vararg args: Any
    ): String = withActivity(scenario) {
        if (args.isEmpty()) it.getString(resId) else it.getString(resId, *args)
    }

    private fun awaitCondition(condition: () -> Boolean): Boolean {
        val deadline = System.currentTimeMillis() + UI_AWAIT_TIMEOUT_MS
        while (System.currentTimeMillis() < deadline) {
            if (condition()) return true
            Thread.sleep(50)
        }
        return false
    }

    private fun contact(
        name: String,
        fingerprint: String,
        algorithm: String,
        source: String
    ) = ContactEntity(
        name = name,
        publicKeyDer = ByteArray(32) { it.toByte() },
        publicKeyFingerprint = fingerprint,
        algorithm = algorithm,
        source = source
    )

    private companion object {
        const val ALICE_NAME = "UI Contact Alice"
        const val BOB_NAME = "UI Contact Bob"
    }
}
