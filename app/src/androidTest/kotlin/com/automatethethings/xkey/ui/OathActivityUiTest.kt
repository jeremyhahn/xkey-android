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

import android.content.ClipboardManager
import android.content.Context
import android.view.View
import android.widget.TextView
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.Espresso.pressBackUnconditionally
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.action.ViewActions.longClick
import androidx.test.espresso.assertion.ViewAssertions.doesNotExist
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.intent.Intents
import androidx.test.espresso.intent.Intents.intended
import androidx.test.espresso.intent.matcher.IntentMatchers.hasComponent
import androidx.test.espresso.intent.matcher.IntentMatchers.hasExtra
import androidx.test.espresso.matcher.RootMatchers.isDialog
import androidx.test.espresso.matcher.ViewMatchers.isCompletelyDisplayed
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.automatethethings.xkey.audit.AuditOperationType
import com.automatethethings.xkey.oath.OathCredentialDao
import com.automatethethings.xkey.oath.OathRepository
import com.automatethethings.xkey.oath.OathSecretManager
import com.automatethethings.xkey.storage.XKeyDatabase
import kotlinx.coroutines.runBlocking
import org.hamcrest.Matchers.allOf
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented UI tests for [OathActivity].
 *
 * The authenticator screen is fully programmatic: gradient toolbar, hero card
 * with the live credential count and TOTP/HOTP badges, an
 * [OathAdapter]-backed list of live OTP codes, an empty state and an
 * "Add Credential" FAB. Everything is matched by displayed text.
 *
 * Credentials are seeded through [OathRepository] (which encrypts the shared
 * secret with the Android Keystore, exactly as the app does) and are listed
 * ordered by issuer, so the suite's issuer sorts to the top of the list.
 *
 * Tests cover:
 * - Gradient toolbar title and subtitle
 * - Hero card: live count, TOTP/HOTP badges
 * - Adapter binding: issuer, account and a formatted live OTP code
 * - Empty state hidden once a credential exists
 * - Tapping a row copies the code and confirms with a snackbar
 * - Long-press menu: Copy, Delete, Details; Copy copies, Details opens
 *   [OathCredentialDetailActivity]
 * - A 60+ character account leaves the code completely displayed
 * - Delete confirmation: cancel keeps the credential, confirm removes it
 * - The FAB's add-method chooser and the manual-entry dialog's cancel path
 * - Back navigation finishing the activity
 *
 * Every seeded credential is deleted in @After.
 */
@RunWith(AndroidJUnit4::class)
class OathActivityUiTest {

    private val runId = System.nanoTime()
    private val testAccount = "uitest-$runId@example.com"
    private val deletableAccount = "uitest-doomed-$runId@example.com"

    private lateinit var repository: OathRepository
    private lateinit var oathDao: OathCredentialDao
    private var testOathId: String? = null
    private var deletableOathId: String? = null
    private var longOathId: String? = null

    /** 60+ characters, RFC 2606 domain. */
    private val longAccount =
        "a.very.long.account.name.for.narrow.screens.$runId@subdomain.example.com"

    @Before
    fun setUp() {
        Intents.init()
        val context = ApplicationProvider.getApplicationContext<Context>()
        oathDao = XKeyDatabase.getInstance(context).oathCredentialDao()
        repository = OathRepository(oathDao, OathSecretManager())
    }

    @After
    fun tearDown() {
        runBlocking {
            testOathId?.let { repository.deleteCredential(it) }
            deletableOathId?.let { repository.deleteCredential(it) }
            longOathId?.let { repository.deleteCredential(it) }
        }
        Intents.release()
    }

    // ---------------------------------------------------------------
    // Gradient Toolbar
    // ---------------------------------------------------------------

    @Test
    fun gradientToolbar_showsTitle() {
        ActivityScenario.launch(OathActivity::class.java)

        onView(withText(R.string.oath_title))
            .check(matches(isDisplayed()))
    }

    @Test
    fun gradientToolbar_showsSubtitle() {
        ActivityScenario.launch(OathActivity::class.java)

        onView(withText(R.string.oath_card_description))
            .check(matches(isDisplayed()))
    }

    // ---------------------------------------------------------------
    // Hero Summary Card
    // ---------------------------------------------------------------

    /** The hero count mirrors the live credential store, not a literal. */
    @Test
    fun heroCard_showsLiveCredentialCount() {
        seedCredential()
        val expected = runBlocking { oathDao.count() }.toString()

        val scenario = ActivityScenario.launch(OathActivity::class.java)
        awaitText(scenario, testAccount)

        onView(withText(expected)).check(matches(isDisplayed()))
    }

    // ---------------------------------------------------------------
    // Adapter binding
    // ---------------------------------------------------------------

    @Test
    fun seededCredential_bindsIssuerAndAccount() {
        seedCredential()

        val scenario = ActivityScenario.launch(OathActivity::class.java)

        awaitText(scenario, TEST_ISSUER)
        awaitText(scenario, testAccount)
    }

    /** The row renders a live six-digit TOTP code split into two groups. */
    @Test
    fun seededCredential_showsFormattedLiveCode() {
        seedCredential()

        val scenario = ActivityScenario.launch(OathActivity::class.java)
        awaitText(scenario, testAccount)

        awaitCondition("A formatted six-digit OTP code should be rendered") {
            var found = false
            scenario.onActivity { activity ->
                found = collectViews(activity.window.decorView) { view ->
                    view is TextView && CODE_PATTERN.matches(view.text?.toString().orEmpty())
                }.isNotEmpty()
            }
            found
        }
    }

    /** Tapping a row copies a generated code, which writes one audit row. */
    @Test
    fun tapCopy_recordsOneOathCodeGeneratedRow() {
        seedCredential()
        val auditDao = XKeyDatabase.getInstance(
            ApplicationProvider.getApplicationContext<Context>()
        ).auditLogDao()

        val scenario = ActivityScenario.launch(OathActivity::class.java)
        awaitText(scenario, testAccount)

        onView(withText(testAccount)).perform(click())

        awaitCondition("A phone copy should write one OATH_CODE_GENERATED row") {
            runBlocking { auditDao.getByKeyId(testOathId!!) }
                .count { it.operationType == AuditOperationType.OATH_CODE_GENERATED } == 1
        }
    }

    @Test
    fun emptyState_isHiddenWhileCredentialsExist() {
        seedCredential()

        val scenario = ActivityScenario.launch(OathActivity::class.java)
        awaitText(scenario, testAccount)

        scenario.onActivity { activity ->
            val emptyTitle = findTextView(
                activity.window.decorView,
                activity.getString(R.string.oath_empty_title)
            )
            assertNotNull("Empty-state title should exist in the hierarchy", emptyTitle)
            assertTrue(
                "Empty state must not be shown while credentials exist",
                !emptyTitle!!.isShown
            )
        }
    }

    // ---------------------------------------------------------------
    // Row interaction
    // ---------------------------------------------------------------

    /** A tap copies the row's code (no group space) and confirms with a snackbar. */
    @Test
    fun tap_copiesCodeAndShowsSnackbar() {
        seedCredential()

        val scenario = ActivityScenario.launch(OathActivity::class.java)
        awaitText(scenario, testAccount)

        val before = rowCode(scenario, testAccount)
        onView(withText(testAccount)).perform(click())

        onView(withText(R.string.oath_code_copied)).check(matches(isDisplayed()))
        assertCopiedRowCode(scenario, testAccount, before)
    }

    @Test
    fun longPress_opensMenuWithCopyDeleteAndDetails() {
        seedCredential()

        val scenario = ActivityScenario.launch(OathActivity::class.java)
        awaitText(scenario, testAccount)

        onView(withText(testAccount)).perform(longClick())

        onView(withText(R.string.oath_context_copy))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
        onView(withText(R.string.oath_context_delete))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
        onView(withText(R.string.oath_context_details))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
    }

    @Test
    fun menuCopy_copiesCode() {
        seedCredential()

        val scenario = ActivityScenario.launch(OathActivity::class.java)
        awaitText(scenario, testAccount)

        val before = rowCode(scenario, testAccount)
        onView(withText(testAccount)).perform(longClick())
        onView(withText(R.string.oath_context_copy)).inRoot(isDialog()).perform(click())

        onView(withText(R.string.oath_code_copied)).check(matches(isDisplayed()))
        assertCopiedRowCode(scenario, testAccount, before)
    }

    @Test
    fun menuDetails_opensDetailsScreen() {
        seedCredential()

        val scenario = ActivityScenario.launch(OathActivity::class.java)
        awaitText(scenario, testAccount)

        onView(withText(testAccount)).perform(longClick())
        onView(withText(R.string.oath_context_details)).inRoot(isDialog()).perform(click())

        intended(
            allOf(
                hasComponent(OathCredentialDetailActivity::class.java.name),
                hasExtra(OathCredentialDetailActivity.EXTRA_OATH_ID, testOathId)
            )
        )
        onView(withText(R.string.oath_detail_code)).check(matches(isDisplayed()))
    }

    /**
     * A 60+ character account is a small ellipsized title; the code sits on
     * its own line below it, whole and on screen.
     */
    @Test
    fun longAccount_codeIsCompletelyDisplayed() {
        seedLongAccountCredential()

        val scenario = ActivityScenario.launch(OathActivity::class.java)
        awaitText(scenario, longAccount)

        awaitCondition("The code under a long account should be on screen") {
            var shown = false
            scenario.onActivity { activity ->
                shown = rowCodeView(activity.window.decorView, longAccount)?.isShown == true
            }
            shown
        }
        scenario.onActivity { activity ->
            val code = rowCodeView(activity.window.decorView, longAccount)!!
            assertTrue("Code must be completely displayed", isCompletelyDisplayed().matches(code))
            assertEquals("Code must stay on one line", 1, code.lineCount)
            assertEquals("Code must not be ellipsized", 0, code.layout.getEllipsisCount(0))
            assertTrue(
                "Code text must fit its view",
                code.paint.measureText(code.text.toString()) <=
                    code.width - code.totalPaddingLeft - code.totalPaddingRight + 1
            )
            val shown = code.layout.text.toString()
            assertEquals("Code text must be shown in full", code.text.toString(), shown)

            val decor = activity.window.decorView
            val codeTop = IntArray(2).also { code.getLocationOnScreen(it) }[1]
            for (title in listOf(rowTitleView(decor, "issuer"), rowTitleView(decor, "account"))) {
                val titleTop = IntArray(2).also { title.getLocationOnScreen(it) }[1]
                assertTrue(
                    "Code (top $codeTop) must sit below the ${title.tag} (bottom ${titleTop + title.height})",
                    codeTop >= titleTop + title.height
                )
            }
        }
    }

    /** The issuer or account TextView in the row showing [longAccount]. */
    private fun rowTitleView(decor: View, tag: String): TextView {
        var view: View? = findTextView(decor, longAccount)
        while (view != null && view !is OathRowLayout) view = view.parent as? View
        return view!!.findViewWithTag(tag)
    }

    // ---------------------------------------------------------------
    // Delete flow
    // ---------------------------------------------------------------

    @Test
    fun delete_cancelled_keepsCredential() {
        seedCredential()

        val scenario = ActivityScenario.launch(OathActivity::class.java)
        awaitText(scenario, testAccount)

        onView(withText(testAccount)).perform(longClick())
        onView(withText(R.string.oath_context_delete)).inRoot(isDialog()).perform(click())

        // The confirmation replaces the item list with a Delete/Cancel pair.
        onView(withText(R.string.oath_context_details)).check(doesNotExist())
        onView(withText(CONFIRM_DELETE_BUTTON)).inRoot(isDialog()).check(matches(isDisplayed()))
        onView(withText(CANCEL_BUTTON)).inRoot(isDialog()).perform(click())

        assertNotNull(
            "Cancelling the confirmation must keep the credential",
            runBlocking { oathDao.getByOathId(testOathId!!) }
        )
    }

    @Test
    fun delete_confirmed_removesCredential() {
        seedDeletableCredential()

        val scenario = ActivityScenario.launch(OathActivity::class.java)
        awaitText(scenario, deletableAccount)

        onView(withText(deletableAccount)).perform(longClick())
        onView(withText(R.string.oath_context_delete)).inRoot(isDialog()).perform(click())

        // "Delete" is both the context-menu entry and the confirmation's
        // positive button. The context menu is the only dialog carrying
        // "Details", so its disappearance proves the confirmation has
        // replaced it before the button is clicked.
        onView(withText(R.string.oath_context_details)).check(doesNotExist())
        onView(withText(CONFIRM_DELETE_BUTTON)).inRoot(isDialog()).perform(click())

        awaitCondition("Confirmed delete should remove the credential") {
            runBlocking { oathDao.getByOathId(deletableOathId!!) } == null
        }
        awaitTextAbsent(scenario, deletableAccount)
        assertNull(runBlocking { oathDao.getByOathId(deletableOathId!!) })
    }

    // ---------------------------------------------------------------
    // Add flow
    // ---------------------------------------------------------------

    /** Dismissing the manual-entry dialog must not create a credential. */
    @Test
    fun manualEntryDialog_cancel_addsNothing() {
        val before = runBlocking { oathDao.count() }
        ActivityScenario.launch(OathActivity::class.java)

        onView(fabMatcher()).perform(click())
        onView(withText(R.string.oath_add_enter_manually)).inRoot(isDialog()).perform(click())
        onView(withText(CANCEL_BUTTON)).inRoot(isDialog()).perform(click())

        waitForIdle()
        assertEquals(
            "Cancelling manual entry must not add a credential",
            before,
            runBlocking { oathDao.count() }
        )
    }

    // ---------------------------------------------------------------
    // Back Navigation
    // ---------------------------------------------------------------

    @Test
    fun backNavigation_finishesActivity() {
        val scenario = ActivityScenario.launch(OathActivity::class.java)

        // pressBack() throws NoActivityResumedException when back closes the
        // last activity in the task, which is exactly what we assert here.
        pressBackUnconditionally()

        assertActivityDestroyed(scenario)
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    /**
     * Matches the extended FAB.
     *
     * Its label ("Add Credential") is reused as the chooser dialog's title, and
     * the FAB is added to the root frame after the content, so restricting the
     * match to the first displayed view keeps it unambiguous before the dialog
     * opens.
     */
    private fun fabMatcher() =
        nthMatch(allOf(withText(R.string.oath_add_choose_method), isDisplayed()), 0)

    private fun seedCredential() {
        testOathId = runBlocking {
            repository.addCredential(
                issuer = TEST_ISSUER,
                accountName = testAccount,
                secret = TEST_SECRET.toByteArray(Charsets.US_ASCII)
            )
        }
    }

    private fun seedLongAccountCredential() {
        longOathId = runBlocking {
            repository.addCredential(
                issuer = TEST_ISSUER,
                accountName = longAccount,
                secret = TEST_SECRET.toByteArray(Charsets.US_ASCII)
            )
        }
    }

    /** The code TextView in the row showing [account], or null when not bound. */
    private fun rowCodeView(decor: View, account: String): TextView? {
        var view: View? = findTextView(decor, account)
        while (view != null && view !is OathRowLayout) view = view.parent as? View
        return view?.findViewWithTag("code")
    }

    /** The digits of the code shown in [account]'s row, group space removed. */
    private fun rowCode(scenario: ActivityScenario<OathActivity>, account: String): String {
        var code = ""
        scenario.onActivity { activity ->
            code = rowCodeView(activity.window.decorView, account)!!.text.toString().replace(" ", "")
        }
        return code
    }

    /**
     * The clipboard holds the row's code: the one read before the copy, or the
     * next period's code when the copy ran just after a rollover.
     */
    private fun assertCopiedRowCode(
        scenario: ActivityScenario<OathActivity>,
        account: String,
        before: String
    ) {
        val after = rowCode(scenario, account)
        var clip = ""
        scenario.onActivity { activity ->
            val clipboard = activity.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            clip = clipboard.primaryClip?.getItemAt(0)?.text?.toString().orEmpty()
        }
        assertTrue("Clipboard '$clip' should hold the row code ($before or $after)", clip == before || clip == after)
    }

    private fun seedDeletableCredential() {
        deletableOathId = runBlocking {
            repository.addCredential(
                issuer = TEST_ISSUER,
                accountName = deletableAccount,
                secret = TEST_SECRET.toByteArray(Charsets.US_ASCII)
            )
        }
    }

    private companion object {
        /** Sorts to the front of the issuer-ordered list so the row is on screen. */
        const val TEST_ISSUER = "AAA UI Test"

        /** RFC 4226 test secret; any byte array works for HMAC-SHA1. */
        const val TEST_SECRET = "12345678901234567890"

        /**
         * Button labels on OathActivity's delete confirmation. These are still
         * inline literals in the activity rather than string resources.
         */
        const val CONFIRM_DELETE_BUTTON = "Delete"
        const val CANCEL_BUTTON = "Cancel"

        /** OathAdapter splits the code in half, e.g. "123 456". */
        val CODE_PATTERN = Regex("""\d{3} \d{3}""")
    }
}
