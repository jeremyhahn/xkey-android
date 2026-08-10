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
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.RootMatchers.isDialog
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.automatethethings.xkey.oath.OathCredentialDao
import com.automatethethings.xkey.oath.OathCredentialEntity
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
 * Instrumented tests for the manual add path in [OathActivity] and
 * [AddOathDialog].
 *
 * The activity does not pass the typed values to the repository directly: it
 * assembles an `otpauth://` URI and re-parses it. That URI used to be built by
 * string concatenation, so any `&`, `?`, `#`, or `=` in the issuer or the
 * account — all of them ordinary in a company name or an email address — was
 * read back as URI structure. An issuer of `Corp & Co` truncated itself at the
 * ampersand and everything after it in the URI became garbage, and a `#`
 * discarded the rest of the label entirely. The failure was silent: a
 * credential appeared, under the wrong name.
 *
 * The dialog also submitted whatever was on screen, including nothing at all,
 * leaving the importer to reject the empty secret with a parser's error message
 * in a snackbar after the form had already closed.
 *
 * Every credential created here carries the run id in its account name and is
 * deleted in `@After`.
 */
@RunWith(AndroidJUnit4::class)
class OathManualEntryFlowTest {

    private val runId = System.nanoTime()

    private lateinit var context: Context
    private lateinit var dao: OathCredentialDao

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        dao = XKeyDatabase.getInstance(context).oathCredentialDao()
    }

    @After
    fun tearDown() {
        runBlocking {
            dao.getAll()
                .filter { it.accountName.contains(runId.toString()) }
                .forEach { dao.deleteByOathId(it.oathId) }
        }
    }

    // -------------------------------------------------------------------------
    // URI-unsafe input
    // -------------------------------------------------------------------------

    @Test
    fun manualEntry_withAnAmpersandInTheIssuer_storesTheIssuerWhole() {
        val issuer = "Corp & Co"
        val account = "amp-$runId@example.com"

        ActivityScenario.launch(OathActivity::class.java)
        addManually(issuer = issuer, account = account)

        val stored = awaitCredential(account)
        assertNotNull("the credential should have been imported", stored)
        assertEquals("an ampersand must not end the issuer", issuer, stored!!.issuer)
    }

    @Test
    fun manualEntry_withUriPunctuationInTheIssuer_storesItVerbatim() {
        // Each of these characters means something to a URI parser: '&'
        // separates parameters, '=' splits one, '?' opens the query and '#'
        // opens the fragment.
        val issuer = "A&B=C?D#E"
        val account = "punct-$runId@example.com"

        ActivityScenario.launch(OathActivity::class.java)
        addManually(issuer = issuer, account = account)

        val stored = awaitCredential(account)
        assertNotNull(stored)
        assertEquals(issuer, stored!!.issuer)
    }

    @Test
    fun manualEntry_withAnAmpersandInTheAccount_storesTheAccountWhole() {
        val account = "tag&more=x-$runId@example.com"

        ActivityScenario.launch(OathActivity::class.java)
        addManually(issuer = "Plain", account = account)

        assertNotNull(
            "an account name is a label, not URI structure",
            awaitCredential(account)
        )
    }

    @Test
    fun manualEntry_withAHashInTheIssuer_keepsTheAccount() {
        // A '#' opens the fragment, so under concatenation everything after it
        // — including the account and every parameter — left the URI.
        val account = "hash-$runId@example.com"

        ActivityScenario.launch(OathActivity::class.java)
        addManually(issuer = "Sharp # Ltd", account = account, algorithm = "SHA256", digits = "8")

        val stored = awaitCredential(account)
        assertNotNull(stored)
        assertEquals("SHA256", stored!!.algorithm)
        assertEquals(8, stored.digits)
    }

    @Test
    fun manualEntry_withAPlainIssuer_stillRoundTrips() {
        // The encoding must not disturb the ordinary case.
        val issuer = "PlainCo"
        val account = "plain-$runId@example.com"

        ActivityScenario.launch(OathActivity::class.java)
        addManually(issuer = issuer, account = account)

        val stored = awaitCredential(account)
        assertNotNull(stored)
        assertEquals(issuer, stored!!.issuer)
        assertEquals(account, stored.accountName)
        assertEquals("TOTP", stored.oathType)
    }

    // -------------------------------------------------------------------------
    // Validation
    // -------------------------------------------------------------------------

    @Test
    fun addWithNoAccount_keepsTheFormOpenAndSaysWhatIsMissing() {
        val before = runBlocking { dao.count() }

        ActivityScenario.launch(OathActivity::class.java)
        openManualEntryDialog()
        DialogFlowSupport.setText(FIELD_SECRET, BASE32_SECRET)
        onView(withText(ADD_BUTTON)).inRoot(isDialog()).perform(click())
        waitForIdle()

        onView(withText(ADD_BUTTON)).inRoot(isDialog()).check(matches(isDisplayed()))
        assertDialogSays(R.string.oath_account_required)
        assertEquals("an incomplete form must not store anything", before, runBlocking { dao.count() })
    }

    @Test
    fun addWithNoSecret_keepsTheFormOpenAndSaysWhatIsMissing() {
        val account = "nosecret-$runId@example.com"
        val before = runBlocking { dao.count() }

        ActivityScenario.launch(OathActivity::class.java)
        openManualEntryDialog()
        DialogFlowSupport.setText(FIELD_ACCOUNT, account)
        onView(withText(ADD_BUTTON)).inRoot(isDialog()).perform(click())
        waitForIdle()

        onView(withText(ADD_BUTTON)).inRoot(isDialog()).check(matches(isDisplayed()))
        assertDialogSays(R.string.oath_secret_required)
        assertNull(credential(account))
        assertEquals(before, runBlocking { dao.count() })
    }

    @Test
    fun addWithAnEmptyForm_reportsBothMissingFieldsAtOnce() {
        ActivityScenario.launch(OathActivity::class.java)
        openManualEntryDialog()
        onView(withText(ADD_BUTTON)).inRoot(isDialog()).perform(click())
        waitForIdle()

        assertDialogSays(R.string.oath_account_required)
        assertDialogSays(R.string.oath_secret_required)
    }

    @Test
    fun completingTheFormAfterAnErrorSubmitsIt() {
        val account = "recovered-$runId@example.com"

        ActivityScenario.launch(OathActivity::class.java)
        openManualEntryDialog()
        onView(withText(ADD_BUTTON)).inRoot(isDialog()).perform(click())
        waitForIdle()

        DialogFlowSupport.setText(FIELD_ACCOUNT, account)
        DialogFlowSupport.setText(FIELD_SECRET, BASE32_SECRET)
        onView(withText(ADD_BUTTON)).inRoot(isDialog()).perform(click())
        waitForIdle()

        assertNotNull("a corrected form must go through", awaitCredential(account))
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private fun addManually(
        issuer: String,
        account: String,
        algorithm: String? = null,
        digits: String? = null
    ) {
        openManualEntryDialog()
        DialogFlowSupport.setText(FIELD_ISSUER, issuer)
        DialogFlowSupport.setText(FIELD_ACCOUNT, account)
        DialogFlowSupport.setText(FIELD_SECRET, BASE32_SECRET)
        algorithm?.let { DialogFlowSupport.setDropdown(FIELD_ALGORITHM, it) }
        digits?.let { DialogFlowSupport.setDropdown(FIELD_DIGITS, it) }
        onView(withText(ADD_BUTTON)).inRoot(isDialog()).perform(click())
        waitForIdle()
    }

    private fun openManualEntryDialog() {
        // The FAB shares its label with the chooser's title, so the click is
        // pinned to the first match, which is the FAB itself.
        onView(
            nthMatch(allOf(withText(R.string.oath_add_choose_method), isDisplayed()), 0)
        ).perform(click())
        waitForIdle()
        onView(withText(R.string.oath_add_enter_manually)).inRoot(isDialog()).perform(click())
        waitForIdle()
    }

    private fun assertDialogSays(messageId: Int) {
        val message = context.getString(messageId)
        assertTrue(
            "the dialog should explain the problem: '$message'",
            DialogFlowSupport.texts().any { it.contains(message) }
        )
    }

    private fun credential(accountName: String): OathCredentialEntity? =
        runBlocking { dao.getAll().firstOrNull { it.accountName == accountName } }

    /** Polls the store, since the import runs on the activity's coroutine scope. */
    private fun awaitCredential(accountName: String): OathCredentialEntity? {
        awaitCondition("Expected '$accountName' to reach the OATH store") {
            credential(accountName) != null
        }
        return credential(accountName)
    }

    private companion object {
        /** The Google Authenticator sample secret; any valid Base32 works. */
        const val BASE32_SECRET = "JBSWY3DPEHPK3PXP"

        /** AddOathDialog field positions. */
        const val FIELD_ISSUER = 1
        const val FIELD_ACCOUNT = 2
        const val FIELD_SECRET = 3
        const val FIELD_ALGORITHM = 5
        const val FIELD_DIGITS = 6

        const val ADD_BUTTON = "Add"
    }
}
