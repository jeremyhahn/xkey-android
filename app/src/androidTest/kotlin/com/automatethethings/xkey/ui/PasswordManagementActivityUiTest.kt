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
import android.view.View
import android.widget.EditText
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.espresso.Espresso.closeSoftKeyboard
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.Espresso.pressBackUnconditionally
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.action.ViewActions.replaceText
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.intent.Intents
import androidx.test.espresso.matcher.RootMatchers.isDialog
import androidx.test.espresso.matcher.ViewMatchers.isAssignableFrom
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.automatethethings.xkey.password.PasswordRecord
import com.automatethethings.xkey.password.PasswordRepository
import com.automatethethings.xkey.storage.XKeyDatabase
import kotlinx.coroutines.runBlocking
import org.hamcrest.Matchers.allOf
import org.hamcrest.Matchers.containsString
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented UI tests for [PasswordManagementActivity].
 *
 * The screen is built entirely in code (gradient toolbar, a
 * [PasswordAdapter]-backed RecyclerView, an "empty" TextView and an Add FAB),
 * so everything is matched by displayed text taken from string resources.
 * Dialog fields have neither ids nor hints, so they are addressed positionally
 * with [nthMatch] inside the dialog root: name, username, password, URL, notes.
 *
 * Tests cover:
 * - Static structure: toolbar title/subtitle, FAB, launch
 * - Add dialog: open, cancel, required-field rejection, successful save
 * - List binding: seeded record renders its title and username/URL subtitle
 * - Detail dialog: reveals the stored values for the tapped row
 * - Delete flow: confirmation cancel keeps the record, confirm removes it
 * - Empty view visibility tracks the live store contents
 * - Back navigation finishes the activity
 *
 * Every record this suite writes is removed in @After so the shared on-device
 * store is left exactly as it was found.
 */
@RunWith(AndroidJUnit4::class)
class PasswordManagementActivityUiTest {

    private val runId = System.nanoTime()
    private val seededName = "UITestPwd-Seeded-$runId"
    private val seededId = "ui-test-pwd-$runId"
    private val typedName = "UITestPwd-Typed-$runId"

    private lateinit var repository: PasswordRepository

    @Before
    fun setUp() {
        Intents.init()
        val context = ApplicationProvider.getApplicationContext<Context>()
        repository = PasswordRepository(XKeyDatabase.getInstance(context).passwordDao())
    }

    @After
    fun tearDown() {
        runBlocking {
            repository.list()
                .filter { it.name.startsWith("UITestPwd-") }
                .forEach { repository.delete(it.passwordId) }
        }
        Intents.release()
    }

    // ---------------------------------------------------------------
    // Static structure
    // ---------------------------------------------------------------

    @Test
    fun toolbar_showsTitleAndSubtitle() {
        ActivityScenario.launch(PasswordManagementActivity::class.java)

        onView(withText(R.string.passwords_title)).check(matches(isDisplayed()))
        onView(withText(R.string.passwords_card_desc)).check(matches(isDisplayed()))
    }

    @Test
    fun addButton_isDisplayed() {
        ActivityScenario.launch(PasswordManagementActivity::class.java)

        onView(withText(R.string.password_add_fab))
            .check(matches(isDisplayed()))
    }

    @Test
    fun activityLaunches_successfully() {
        val scenario = ActivityScenario.launch(PasswordManagementActivity::class.java)

        scenario.onActivity { activity ->
            assertTrue(
                "PasswordManagementActivity should not be finishing after launch",
                !activity.isFinishing
            )
        }
    }

    // ---------------------------------------------------------------
    // Add dialog
    // ---------------------------------------------------------------

    @Test
    fun addButton_opensAddDialog() {
        ActivityScenario.launch(PasswordManagementActivity::class.java)

        onView(withText(R.string.password_add_fab)).perform(click())

        onView(withText(R.string.password_add_title))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
        onView(withText(R.string.password_field_name))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
    }

    /** Cancelling the add dialog must leave the store untouched. */
    @Test
    fun addDialog_cancel_doesNotCreateRecord() {
        val before = countStored()
        val scenario = ActivityScenario.launch(PasswordManagementActivity::class.java)

        onView(withText(R.string.password_add_fab)).perform(click())
        typeDialogField(index = 0, text = typedName)
        typeDialogField(index = 2, text = "cancelled-secret")
        onView(withText(R.string.button_cancel)).inRoot(isDialog()).perform(click())

        awaitTextAbsent(scenario, typedName)
        assertEquals("Cancelling must not persist a password", before, countStored())
    }

    /**
     * Saving with a username but no name and no password is rejected: the
     * activity requires both, so nothing is written.
     */
    @Test
    fun addDialog_saveWithoutRequiredFields_isRejected() {
        val before = countStored()
        val scenario = ActivityScenario.launch(PasswordManagementActivity::class.java)

        onView(withText(R.string.password_add_fab)).perform(click())
        typeDialogField(index = 1, text = "user-without-name")
        onView(withText(R.string.password_save)).inRoot(isDialog()).perform(click())

        awaitTextAbsent(scenario, "user-without-name")
        assertEquals(
            "Name and password are required, so nothing should be stored",
            before,
            countStored()
        )
    }

    /** A fully filled add dialog persists the record and lists it immediately. */
    @Test
    fun addDialog_save_persistsAndListsRecord() {
        val scenario = ActivityScenario.launch(PasswordManagementActivity::class.java)

        onView(withText(R.string.password_add_fab)).perform(click())
        typeDialogField(index = 0, text = typedName)
        typeDialogField(index = 1, text = "typed-user")
        typeDialogField(index = 2, text = "typed-secret")
        onView(withText(R.string.password_save)).inRoot(isDialog()).perform(click())

        awaitText(scenario, typedName)
        awaitText(scenario, "typed-user")

        val stored = runBlocking { repository.list().firstOrNull { it.name == typedName } }
        assertNotNull("Saved password should be readable from the store", stored)
        assertEquals("typed-secret", stored!!.password)
    }

    // ---------------------------------------------------------------
    // List binding
    // ---------------------------------------------------------------

    @Test
    fun seededRecord_rendersTitleAndSubtitle() {
        seedRecord(username = "seed-user", url = "https://seed.example.com")

        val scenario = ActivityScenario.launch(PasswordManagementActivity::class.java)

        awaitText(scenario, seededName)
        awaitText(scenario, "seed-user")
        awaitText(scenario, "https://seed.example.com")
    }

    /** With at least one record present the "no passwords yet" view must be hidden. */
    @Test
    fun emptyView_visibilityTracksStoreContents() {
        seedRecord()

        val scenario = ActivityScenario.launch(PasswordManagementActivity::class.java)
        awaitText(scenario, seededName)

        scenario.onActivity { activity ->
            val emptyView = findTextView(
                activity.window.decorView,
                activity.getString(R.string.password_empty_message)
            )
            assertNotNull("The empty view should exist in the hierarchy", emptyView)
            assertEquals(
                "Empty view must be GONE while the store has records",
                View.GONE,
                emptyView!!.visibility
            )
        }
    }

    // ---------------------------------------------------------------
    // Detail dialog
    // ---------------------------------------------------------------

    @Test
    fun tappingRecord_opensDetailDialogWithStoredValues() {
        seedRecord(username = "detail-user")
        val context = ApplicationProvider.getApplicationContext<Context>()

        val scenario = ActivityScenario.launch(PasswordManagementActivity::class.java)
        awaitText(scenario, seededName)

        onView(withText(seededName)).perform(click())

        onView(
            withText(
                containsString(
                    context.getString(R.string.password_detail_username, "detail-user")
                )
            )
        ).inRoot(isDialog()).check(matches(isDisplayed()))
        onView(
            withText(
                containsString(
                    context.getString(R.string.password_detail_password, SEEDED_SECRET)
                )
            )
        ).inRoot(isDialog()).check(matches(isDisplayed()))
    }

    // ---------------------------------------------------------------
    // Delete flow
    // ---------------------------------------------------------------

    @Test
    fun delete_cancelledInConfirmation_keepsRecord() {
        seedRecord()

        val scenario = ActivityScenario.launch(PasswordManagementActivity::class.java)
        awaitText(scenario, seededName)

        onView(withText(seededName)).perform(click())
        onView(withText(R.string.password_delete)).inRoot(isDialog()).perform(click())
        onView(withText(R.string.password_delete_title)).inRoot(isDialog())
            .check(matches(isDisplayed()))
        onView(withText(R.string.button_cancel)).inRoot(isDialog()).perform(click())

        assertNotNull(
            "Cancelling the confirmation must keep the record",
            runBlocking { repository.get(seededId) }
        )
    }

    @Test
    fun delete_confirmed_removesRecordFromStoreAndList() {
        seedRecord()

        val scenario = ActivityScenario.launch(PasswordManagementActivity::class.java)
        awaitText(scenario, seededName)

        onView(withText(seededName)).perform(click())
        onView(withText(R.string.password_delete)).inRoot(isDialog()).perform(click())
        onView(withText(R.string.password_delete)).inRoot(isDialog()).perform(click())

        awaitCondition("Confirmed delete should remove the record from the store") {
            runBlocking { repository.get(seededId) } == null
        }
        awaitTextAbsent(scenario, seededName)
        assertNull(runBlocking { repository.get(seededId) })
    }

    // ---------------------------------------------------------------
    // Back navigation
    // ---------------------------------------------------------------

    @Test
    fun backNavigation_finishesActivity() {
        val scenario = ActivityScenario.launch(PasswordManagementActivity::class.java)

        // pressBack() throws NoActivityResumedException when back closes the
        // last activity in the task, which is exactly what we assert here.
        pressBackUnconditionally()

        assertActivityDestroyed(scenario)
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    /**
     * Inserts the suite's record so list assertions never rely on ambient rows.
     *
     * A username is always supplied by default: [PasswordAdapter] falls back to
     * the record name for the subtitle when username and URL are both blank,
     * which would render the same string twice and make text matchers ambiguous.
     */
    private fun seedRecord(username: String? = "row-user", url: String? = null) {
        runBlocking {
            repository.upsert(
                PasswordRecord(
                    passwordId = seededId,
                    name = seededName,
                    title = seededName,
                    username = username,
                    password = SEEDED_SECRET,
                    url = url,
                    source = "local"
                )
            )
        }
    }

    private fun countStored(): Int = runBlocking { repository.list().size }

    /**
     * Replaces the text of the dialog's [index]-th EditText. The add dialog has
     * no ids or hints, so fields are addressed by their build order:
     * 0 name, 1 username, 2 password, 3 URL, 4 notes.
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

    private companion object {
        const val SEEDED_SECRET = "seeded-secret-value"
    }
}
