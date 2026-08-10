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

import android.Manifest
import android.app.Activity
import android.app.Instrumentation
import android.content.Context
import android.content.Intent
import android.view.View
import android.widget.TextView
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.assertion.ViewAssertions.doesNotExist
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.intent.Intents
import androidx.test.espresso.intent.Intents.intended
import androidx.test.espresso.intent.Intents.intending
import androidx.test.espresso.intent.matcher.IntentMatchers.hasComponent
import androidx.test.espresso.matcher.RootMatchers.isDialog
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.rule.GrantPermissionRule
import com.automatethethings.xkey.R
import com.automatethethings.xkey.oath.OathCredentialDao
import com.automatethethings.xkey.oath.OathCredentialEntity
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
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented tests for the [OathActivity] flows the basic suite does not
 * reach.
 *
 * `OathActivityUiTest` covers the chrome, a single seeded TOTP credential and
 * the delete confirmation. What is left is everything that varies with the
 * credential itself or writes to the store: the HOTP rendering branch, the
 * issuer-less row, the whole add pipeline (manual entry and QR import, both the
 * success and the rejected-secret path) and the clipboard copy.
 *
 * Two things drive the design:
 * - Codes are time-based, so no literal code is ever asserted. The row's code is
 *   read and the row is clicked inside the *same* main-thread block, which is
 *   the only way to compare the clipboard against what the user actually saw.
 * - The detail dialog is a tall column of rows, most of them below the fold.
 *   Assertions therefore read the dialog window's view tree ([dialogTexts])
 *   instead of requiring `isDisplayed()`.
 *
 * Tests cover:
 * - HOTP: counter row instead of period, and the hero's HOTP badge count
 * - A credential with no issuer: account promoted to the title, account row hidden
 * - Context-menu title, detail dialog contents and its dismissal
 * - Tapping a row placing the displayed code on the clipboard
 * - Manual entry persisting the chosen parameters, and an invalid Base32 secret
 *   being reported without writing anything
 * - QR import: an `otpauth://` scan result persisted, a foreign result ignored
 *
 * Every credential this suite creates carries the run id in its account name and
 * is deleted in @After.
 */
@RunWith(AndroidJUnit4::class)
class OathFlowTest {

    @get:Rule
    val cameraPermission: GrantPermissionRule =
        GrantPermissionRule.grant(Manifest.permission.CAMERA)

    private val runId = System.nanoTime()

    private lateinit var repository: OathRepository
    private lateinit var dao: OathCredentialDao

    @Before
    fun setUp() {
        Intents.init()
        val context = ApplicationProvider.getApplicationContext<Context>()
        dao = XKeyDatabase.getInstance(context).oathCredentialDao()
        repository = OathRepository(dao, OathSecretManager())
    }

    @After
    fun tearDown() {
        runBlocking {
            dao.getAll()
                .filter { it.accountName.contains(runId.toString()) }
                .forEach { dao.deleteByOathId(it.oathId) }
        }
        Intents.release()
    }

    // ---------------------------------------------------------------
    // HOTP rendering
    // ---------------------------------------------------------------

    /**
     * A counter-based credential has no period, so the detail dialog swaps the
     * "Period" row for "Counter".
     */
    @Test
    fun hotpCredential_detailDialogShowsTheCounterInsteadOfThePeriod() {
        val account = seed(type = "HOTP")
        val scenario = ActivityScenario.launch(OathActivity::class.java)
        assertShownTextInList(scenario, account)

        openDetailDialog(scenario, account)

        val counterLabel = withActivity(scenario) { it.getString(R.string.oath_detail_counter) }
        val periodLabel = withActivity(scenario) { it.getString(R.string.oath_detail_period) }
        DialogFlowSupport.assertShowsExactly(counterLabel)
        DialogFlowSupport.assertDoesNotContain(periodLabel)
        DialogFlowSupport.assertShowsExactly("HOTP")
    }

    /** The hero badges count the two OATH types independently. */
    @Test
    fun heroCard_badgesCountTotpAndHotpSeparately() {
        seed(type = "HOTP")
        seed(type = "TOTP")

        val scenario = ActivityScenario.launch(OathActivity::class.java)

        val stored = runBlocking { dao.getAll() }
        val expectedTotp = stored.count { it.oathType == "TOTP" }
        val expectedHotp = stored.count { it.oathType == "HOTP" }
        assertTrue("The suite seeds at least one HOTP credential", expectedHotp >= 1)

        assertExactTextShown(scenario, "$expectedTotp TOTP")
        assertExactTextShown(scenario, "$expectedHotp HOTP")
    }

    // ---------------------------------------------------------------
    // Issuer-less rendering
    // ---------------------------------------------------------------

    /**
     * With no issuer the adapter promotes the account name to the title row and
     * hides the subtitle rather than printing the same string twice.
     */
    @Test
    fun credentialWithoutAnIssuer_hidesTheDuplicateAccountRow() {
        val account = seed(issuer = null)

        val scenario = ActivityScenario.launch(OathActivity::class.java)
        assertShownTextInList(scenario, account)

        val accountRows = withActivity(scenario) { activity ->
            collectViews(activity.window.decorView) { view ->
                view is TextView &&
                    view.tag == "account" &&
                    view.text?.toString() == account
            }
        }
        assertTrue("The credential's row should be bound", accountRows.isNotEmpty())
        assertTrue(
            "The account row must be hidden when it duplicates the title",
            accountRows.all { it.visibility == View.GONE }
        )
    }

    // ---------------------------------------------------------------
    // Context menu and detail dialog
    // ---------------------------------------------------------------

    @Test
    fun contextMenu_titleCombinesIssuerAndAccount() {
        val account = seed()

        val scenario = ActivityScenario.launch(OathActivity::class.java)
        assertShownTextInList(scenario, account)
        RowFlowInteractions.longClickText(scenario, account)

        DialogFlowSupport.assertShowsExactly("$ISSUER: $account")
    }

    @Test
    fun detailDialog_reportsTheStoredParameters() {
        val account = seed(algorithm = "SHA256", digits = 8, periodSeconds = 60)

        val scenario = ActivityScenario.launch(OathActivity::class.java)
        assertShownTextInList(scenario, account)
        openDetailDialog(scenario, account)

        DialogFlowSupport.assertShowsExactly("SHA256")
        DialogFlowSupport.assertShowsExactly("8")
        DialogFlowSupport.assertShowsExactly(
            withActivity(scenario) { it.getString(R.string.oath_detail_period_value, 60) }
        )
        // Source is stored lowercase and title-cased for display.
        DialogFlowSupport.assertShowsExactly("Local")
        DialogFlowSupport.assertShowsExactly(
            withActivity(scenario) { it.getString(R.string.oath_detail_never_used) }
        )
    }

    @Test
    fun detailDialog_isDismissedByItsOkButton() {
        val account = seed()

        val scenario = ActivityScenario.launch(OathActivity::class.java)
        assertShownTextInList(scenario, account)
        openDetailDialog(scenario, account)

        onView(withText(android.R.string.ok)).inRoot(isDialog()).perform(click())
        waitForIdle()

        onView(withText(R.string.oath_detail_title)).check(doesNotExist())
    }

    // ---------------------------------------------------------------
    // Clipboard
    // ---------------------------------------------------------------

    /**
     * The row is read and clicked in one main-thread block: the ticker rebinds
     * the list every second, so reading the code in a separate step would race
     * the very value being copied.
     */
    @Test
    fun tappingARow_copiesTheDisplayedCodeToTheClipboard() {
        val account = seed()

        val scenario = ActivityScenario.launch(OathActivity::class.java)
        assertShownTextInList(scenario, account)

        val displayedCode = withActivity(scenario) { activity ->
            val accountView = collectViews(activity.window.decorView) { view ->
                view is TextView && view.tag == "account" && view.text?.toString() == account
            }.first()
            val row = generateSequence(accountView.parent as? View) { it.parent as? View }
                .first { it.isClickable }
            val codeView = collectViews(row) { it is TextView && it.tag == "code" }
                .first() as TextView
            val code = codeView.text.toString()
            row.performClick()
            code
        }
        waitForIdle()

        assertEquals(
            "The clipboard must hold exactly the code the row displayed",
            displayedCode.replace(" ", ""),
            DialogFlowSupport.clipboardText(scenario)
        )
        onView(withText(R.string.oath_code_copied)).check(matches(isDisplayed()))
    }

    // ---------------------------------------------------------------
    // Manual entry
    // ---------------------------------------------------------------

    @Test
    fun manualEntry_persistsTheChosenParameters() {
        val account = "oath-flow-manual-$runId@example.com"

        val scenario = ActivityScenario.launch(OathActivity::class.java)
        openManualEntryDialog()

        DialogFlowSupport.setText(FIELD_ISSUER, URI_ISSUER)
        DialogFlowSupport.setText(FIELD_ACCOUNT, account)
        DialogFlowSupport.setText(FIELD_SECRET, BASE32_SECRET)
        DialogFlowSupport.setDropdown(FIELD_ALGORITHM, "SHA256")
        DialogFlowSupport.setDropdown(FIELD_DIGITS, "8")
        DialogFlowSupport.setText(FIELD_PERIOD, "60")
        onView(withText(ADD_BUTTON)).inRoot(isDialog()).perform(click())

        val stored = awaitCredential(account)
        assertNotNull("Manual entry should persist a credential", stored)
        assertEquals(URI_ISSUER, stored!!.issuer)
        assertEquals("SHA256", stored.algorithm)
        assertEquals(8, stored.digits)
        assertEquals(60, stored.periodSeconds)
        assertShownTextInList(scenario, account)
    }

    /** A secret outside the Base32 alphabet is rejected by the importer. */
    @Test
    fun manualEntry_withAnInvalidSecret_reportsAnErrorAndStoresNothing() {
        val account = "oath-flow-badsecret-$runId@example.com"
        val before = runBlocking { dao.count() }

        val scenario = ActivityScenario.launch(OathActivity::class.java)
        openManualEntryDialog()

        DialogFlowSupport.setText(FIELD_ACCOUNT, account)
        DialogFlowSupport.setText(FIELD_SECRET, "!!!not-base32!!!")
        onView(withText(ADD_BUTTON)).inRoot(isDialog()).perform(click())

        assertTrue(
            "An import failure must surface as an error message",
            awaitShownTextInTree(scenario, "Error:")
        )
        assertNull("Nothing may be stored when the secret is rejected", credential(account))
        assertEquals(before, runBlocking { dao.count() })
    }

    // ---------------------------------------------------------------
    // QR import
    // ---------------------------------------------------------------

    @Test
    fun scanningAQrCode_importsTheScannedCredential() {
        val account = "oath-flow-scan-$runId@example.com"
        stubScannerResult(
            "otpauth://totp/$URI_ISSUER:$account?secret=$BASE32_SECRET&issuer=$URI_ISSUER&digits=7"
        )

        val scenario = ActivityScenario.launch(OathActivity::class.java)
        openAddMethodChooser()
        onView(withText(R.string.oath_add_scan_qr)).inRoot(isDialog()).perform(click())

        intended(hasComponent(QrScannerActivity::class.java.name))
        val stored = awaitCredential(account)
        assertNotNull("A scanned otpauth URI should be imported", stored)
        assertEquals(7, stored!!.digits)
        assertShownTextInList(scenario, account)
    }

    /** A scan result that is not an `otpauth://` URI is discarded silently. */
    @Test
    fun scanningANonOtpauthCode_importsNothing() {
        val before = runBlocking { dao.count() }
        stubScannerResult("https://example.com/not-a-credential")

        val scenario = ActivityScenario.launch(OathActivity::class.java)
        openAddMethodChooser()
        onView(withText(R.string.oath_add_scan_qr)).inRoot(isDialog()).perform(click())

        waitForIdle()
        assertEquals(
            "A foreign QR payload must not create a credential",
            before,
            runBlocking { dao.count() }
        )
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    /**
     * Seeds a credential through [OathRepository] so the shared secret is
     * encrypted exactly as the app encrypts it.
     *
     * @return the generated account name, unique to this run.
     */
    private fun seed(
        issuer: String? = ISSUER,
        type: String = "TOTP",
        algorithm: String = "SHA1",
        digits: Int = 6,
        periodSeconds: Int = 30
    ): String {
        val account = "oath-flow-${type.lowercase()}-${System.nanoTime()}-$runId@example.com"
        runBlocking {
            repository.addCredential(
                issuer = issuer,
                accountName = account,
                secret = RAW_SECRET.toByteArray(Charsets.US_ASCII),
                type = type,
                algorithm = algorithm,
                digits = digits,
                periodSeconds = periodSeconds
            )
        }
        return account
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

    private fun openAddMethodChooser() {
        // The FAB shares its label with the chooser's title, so the click is
        // pinned to the first match, which is the FAB itself.
        onView(
            nthMatch(allOf(withText(R.string.oath_add_choose_method), isDisplayed()), 0)
        ).perform(click())
        waitForIdle()
    }

    private fun openManualEntryDialog() {
        openAddMethodChooser()
        onView(withText(R.string.oath_add_enter_manually)).inRoot(isDialog()).perform(click())
        waitForIdle()
    }

    private fun openDetailDialog(scenario: ActivityScenario<OathActivity>, account: String) {
        RowFlowInteractions.longClickText(scenario, account)
        onView(withText(R.string.oath_context_view_details)).inRoot(isDialog()).perform(click())
        waitForIdle()
    }

    /** Answers the QR scanner launch with [uri] instead of opening the camera. */
    private fun stubScannerResult(uri: String) {
        val data = Intent().putExtra(QrScannerActivity.EXTRA_SCANNED_URI, uri)
        intending(hasComponent(QrScannerActivity::class.java.name)).respondWith(
            Instrumentation.ActivityResult(Activity.RESULT_OK, data)
        )
    }

    private companion object {
        const val ISSUER = "AAA Flow Test"

        /** Issuer used inside otpauth:// URIs, where a space would be ambiguous. */
        const val URI_ISSUER = "FlowUriCo"

        /** RFC 4226 test secret; any bytes work for HMAC. */
        const val RAW_SECRET = "12345678901234567890"

        /** The same secret Base32-encoded, for the URI-based entry paths. */
        const val BASE32_SECRET = "JBSWY3DPEHPK3PXP"

        /** AddOathDialog field positions. */
        const val FIELD_ISSUER = 1
        const val FIELD_ACCOUNT = 2
        const val FIELD_SECRET = 3
        const val FIELD_ALGORITHM = 5
        const val FIELD_DIGITS = 6
        const val FIELD_PERIOD = 7

        const val ADD_BUTTON = "Add"
    }
}
