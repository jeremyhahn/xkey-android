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
import android.widget.ImageButton
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.matcher.RootMatchers.isDialog
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.automatethethings.xkey.R
import com.automatethethings.xkey.password.PasswordRecord
import com.automatethethings.xkey.password.PasswordRepository
import com.automatethethings.xkey.storage.XKeyDatabase
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented tests for the [PasswordManagementActivity] paths the basic suite
 * leaves out.
 *
 * `PasswordManagementActivityUiTest` covers add, list, detail and delete for a
 * record that has a title, a username and a password. What is left is the
 * optional half of the record — URL and notes, on both the add and the detail
 * side — the two fallbacks for a record with no title or no subtitle material,
 * the clipboard copy (the only reason the detail dialog reveals the secret at
 * all) and the toolbar's up affordance.
 *
 * The detail dialog renders one multi-line message, so its content is asserted
 * by substring against the dialog window rather than by matching separate views.
 *
 * Tests cover:
 * - Copy putting the stored password on the clipboard
 * - Detail dialog including URL and notes, and omitting them when blank
 * - Detail title and row title falling back to the record name
 * - Row subtitle falling back to the name when there is no username or URL
 * - Add dialog persisting URL and notes
 * - The toolbar's up button finishing the screen
 *
 * Every record this suite writes is prefixed with `UITestPwdFlow-` and removed
 * in @After.
 */
@RunWith(AndroidJUnit4::class)
class PasswordManagementFlowTest {

    private val runId = System.nanoTime()

    private lateinit var repository: PasswordRepository

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        repository = PasswordRepository(XKeyDatabase.getInstance(context).passwordDao())
    }

    @After
    fun tearDown() {
        runBlocking {
            repository.list()
                .filter { it.name.startsWith(NAME_PREFIX) }
                .forEach { repository.delete(it.passwordId) }
        }
    }

    // ---------------------------------------------------------------
    // Clipboard
    // ---------------------------------------------------------------

    @Test
    fun detailDialogCopy_putsTheStoredPasswordOnTheClipboard() {
        val name = seed()

        val scenario = ActivityScenario.launch(PasswordManagementActivity::class.java)
        assertShownTextInList(scenario, name)

        clickTextInTree(scenario, name)
        onView(withText(R.string.password_copy)).inRoot(isDialog()).perform(click())
        waitForIdle()

        assertEquals(SECRET, DialogFlowSupport.clipboardText(scenario))
    }

    // ---------------------------------------------------------------
    // Detail dialog
    // ---------------------------------------------------------------

    @Test
    fun detailDialog_showsTheUrlAndNotes() {
        val url = "https://flow.example.com"
        val notes = "flow notes $runId"
        val name = seed(url = url, notes = notes)
        val context = ApplicationProvider.getApplicationContext<Context>()

        val scenario = ActivityScenario.launch(PasswordManagementActivity::class.java)
        assertShownTextInList(scenario, name)

        clickTextInTree(scenario, name)

        DialogFlowSupport.assertContains(context.getString(R.string.password_detail_url, url))
        DialogFlowSupport.assertContains(context.getString(R.string.password_detail_notes, notes))
    }

    /** Blank optional fields are dropped from the message entirely. */
    @Test
    fun detailDialog_omitsTheOptionalFieldsThatAreBlank() {
        val name = seed(username = null, url = null, notes = null)
        val context = ApplicationProvider.getApplicationContext<Context>()

        val scenario = ActivityScenario.launch(PasswordManagementActivity::class.java)
        assertShownTextInList(scenario, name)

        clickTextInTree(scenario, name)

        DialogFlowSupport.assertContains(
            context.getString(R.string.password_detail_password, SECRET)
        )
        DialogFlowSupport.assertDoesNotContain(
            context.getString(R.string.password_detail_url, "")
        )
        DialogFlowSupport.assertDoesNotContain(
            context.getString(R.string.password_detail_notes, "")
        )
        DialogFlowSupport.assertDoesNotContain(
            context.getString(R.string.password_detail_username, "")
        )
    }

    /** With no title the record name is both the row title and the dialog title. */
    @Test
    fun recordWithoutATitle_fallsBackToItsName() {
        val name = seed(withTitle = false)

        val scenario = ActivityScenario.launch(PasswordManagementActivity::class.java)
        assertShownTextInList(scenario, name)

        clickTextInTree(scenario, name)

        DialogFlowSupport.assertShowsExactly(name)
    }

    /** With neither username nor URL the subtitle repeats the record name. */
    @Test
    fun rowWithoutAUsernameOrUrl_showsTheNameAsItsSubtitle() {
        val name = seed(username = null, url = null)

        val scenario = ActivityScenario.launch(PasswordManagementActivity::class.java)
        assertShownTextInList(scenario, name)

        val rendered = withActivity(scenario) { activity ->
            collectViews(activity.window.decorView) {
                it is android.widget.TextView && it.text?.toString() == name
            }.size
        }
        assertEquals("Title and subtitle should both render the name", 2, rendered)
    }

    // ---------------------------------------------------------------
    // Add dialog
    // ---------------------------------------------------------------

    @Test
    fun addDialog_persistsTheOptionalUrlAndNotes() {
        val name = "$NAME_PREFIX-Typed-$runId"

        ActivityScenario.launch(PasswordManagementActivity::class.java)
        onView(withText(R.string.password_add_fab)).perform(click())

        DialogFlowSupport.setText(FIELD_NAME, name)
        DialogFlowSupport.setText(FIELD_USERNAME, "flow-user")
        DialogFlowSupport.setText(FIELD_PASSWORD, SECRET)
        DialogFlowSupport.setText(FIELD_URL, "https://typed.example.com")
        DialogFlowSupport.setText(FIELD_NOTES, "typed notes")
        onView(withText(R.string.password_save)).inRoot(isDialog()).perform(click())

        awaitCondition("The typed record should reach the store") {
            runBlocking { repository.list().any { it.name == name } }
        }
        val stored = runBlocking { repository.list().first { it.name == name } }
        assertEquals("https://typed.example.com", stored.url)
        assertEquals("typed notes", stored.notes)
        assertEquals("flow-user", stored.username)
    }

    // ---------------------------------------------------------------
    // Navigation
    // ---------------------------------------------------------------

    /**
     * The gradient toolbar's up button calls `finish()` directly rather than
     * going through the back dispatcher, so it needs its own coverage.
     */
    @Test
    fun toolbarUpButton_finishesTheActivity() {
        val scenario = ActivityScenario.launch(PasswordManagementActivity::class.java)
        val title = withActivity(scenario) { it.getString(R.string.passwords_title) }
        assertShownTextInTree(scenario, title)

        scenario.onActivity { activity ->
            collectViews(activity.window.decorView) { it is ImageButton }
                .firstOrNull()
                ?.performClick()
        }
        InstrumentationRegistry.getInstrumentation().waitForIdleSync()

        assertActivityDestroyed(scenario)
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    /**
     * Writes a record and returns its name, which is unique per call so several
     * rows can coexist without making text matchers ambiguous.
     */
    private fun seed(
        withTitle: Boolean = true,
        username: String? = "flow-row-user",
        url: String? = null,
        notes: String? = null
    ): String {
        val name = "$NAME_PREFIX-${System.nanoTime()}-$runId"
        runBlocking {
            repository.upsert(
                PasswordRecord(
                    passwordId = "ui-test-pwd-flow-$name",
                    name = name,
                    title = if (withTitle) name else null,
                    username = username,
                    password = SECRET,
                    url = url,
                    notes = notes,
                    source = "local"
                )
            )
        }
        return name
    }

    private companion object {
        const val NAME_PREFIX = "UITestPwdFlow"
        const val SECRET = "flow-secret-value"

        /** Add-dialog field positions, in build order. */
        const val FIELD_NAME = 0
        const val FIELD_USERNAME = 1
        const val FIELD_PASSWORD = 2
        const val FIELD_URL = 3
        const val FIELD_NOTES = 4
    }
}
