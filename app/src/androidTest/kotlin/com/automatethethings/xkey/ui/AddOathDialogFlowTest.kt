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

import androidx.test.core.app.ActivityScenario
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.RootMatchers.isDialog
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented tests for [AddOathDialog], driven directly rather than through
 * [OathActivity]'s FAB.
 *
 * The dialog is the app's only `otpauth://` entry point besides the QR scanner,
 * and almost all of its logic sits in two places the surrounding screen cannot
 * reach: the `TextWatcher` that auto-fills every field from a pasted URI, and
 * the positive button that reads the eight fields back out. Showing the dialog
 * on a host activity and supplying the `onAdd` callback ourselves makes both
 * observable — the callback arguments are the dialog's entire contract.
 *
 * Fields are addressed by their build order (see [DialogFlowSupport.setText]):
 * 0 URI, 1 issuer, 2 account, 3 secret, 4 type, 5 algorithm, 6 digits, 7 period.
 *
 * Tests cover:
 * - The industry-standard defaults the dialog opens with
 * - Every option each exposed dropdown offers, and a non-default selection
 *   actually reaching the callback
 * - Manual entry reported verbatim, including blank numeric fields falling back
 * - Cancel never invoking the callback
 * - URI auto-fill for TOTP and HOTP, issuer from the query or from the label,
 *   spec defaults for absent parameters
 * - URIs the parser must reject: no secret, unsupported type, and plain text
 *
 * Nothing is persisted: the callback records its arguments instead of writing to
 * the OATH store, so this suite leaves no state behind.
 */
@RunWith(AndroidJUnit4::class)
class AddOathDialogFlowTest {

    /** The arguments the dialog handed to its `onAdd` callback. */
    private data class AddArguments(
        val issuer: String?,
        val accountName: String,
        val secret: String,
        val type: String,
        val algorithm: String,
        val digits: Int,
        val period: Int
    )

    @Volatile
    private var reported: AddArguments? = null

    // ---------------------------------------------------------------
    // Defaults
    // ---------------------------------------------------------------

    @Test
    fun dialog_opensWithIndustryStandardDefaults() {
        showDialog()

        val fields = DialogFlowSupport.fieldTexts()
        assertEquals("URI field starts empty", "", fields[FIELD_URI])
        assertEquals("Issuer field starts empty", "", fields[FIELD_ISSUER])
        assertEquals("Account field starts empty", "", fields[FIELD_ACCOUNT])
        assertEquals("Secret field starts empty", "", fields[FIELD_SECRET])
        assertEquals("TOTP", fields[FIELD_TYPE])
        assertEquals("SHA1", fields[FIELD_ALGORITHM])
        assertEquals("6", fields[FIELD_DIGITS])
        assertEquals("30", fields[FIELD_PERIOD])
    }

    /**
     * A dropdown that renders no options is a failure mode this project has
     * shipped before (the PIV generate-key chooser), so the option lists are
     * asserted rather than assumed.
     */
    @Test
    fun dropdowns_offerEverySupportedValue() {
        showDialog()

        assertEquals(listOf("TOTP", "HOTP"), DialogFlowSupport.dropdownOptions(FIELD_TYPE))
        assertEquals(
            listOf("SHA1", "SHA256", "SHA512"),
            DialogFlowSupport.dropdownOptions(FIELD_ALGORITHM)
        )
        assertEquals(listOf("6", "7", "8"), DialogFlowSupport.dropdownOptions(FIELD_DIGITS))
    }

    // ---------------------------------------------------------------
    // Manual entry
    // ---------------------------------------------------------------

    @Test
    fun manualEntry_reportsTypedValuesWithTheDefaultParameters() {
        showDialog()

        DialogFlowSupport.setText(FIELD_ISSUER, "Manual Issuer")
        DialogFlowSupport.setText(FIELD_ACCOUNT, "manual@example.com")
        DialogFlowSupport.setText(FIELD_SECRET, SECRET)
        clickAdd()

        assertEquals(
            AddArguments(
                issuer = "Manual Issuer",
                accountName = "manual@example.com",
                secret = SECRET,
                type = "TOTP",
                algorithm = "SHA1",
                digits = 6,
                period = 30
            ),
            reported
        )
    }

    /** Choosing a non-default value in every dropdown must reach the callback. */
    @Test
    fun manualEntry_honoursNonDefaultDropdownSelections() {
        showDialog()

        DialogFlowSupport.setText(FIELD_ACCOUNT, "counter@example.com")
        DialogFlowSupport.setText(FIELD_SECRET, SECRET)
        DialogFlowSupport.setDropdown(FIELD_TYPE, "HOTP")
        DialogFlowSupport.setDropdown(FIELD_ALGORITHM, "SHA512")
        DialogFlowSupport.setDropdown(FIELD_DIGITS, "8")
        DialogFlowSupport.setText(FIELD_PERIOD, "60")
        clickAdd()

        val arguments = requireNotNull(reported)
        assertEquals("HOTP", arguments.type)
        assertEquals("SHA512", arguments.algorithm)
        assertEquals(8, arguments.digits)
        assertEquals(60, arguments.period)
    }

    /** An empty issuer is reported as absent rather than as an empty string. */
    @Test
    fun manualEntry_withoutAnIssuer_reportsNull() {
        showDialog()

        DialogFlowSupport.setText(FIELD_ACCOUNT, "lonely@example.com")
        DialogFlowSupport.setText(FIELD_SECRET, SECRET)
        clickAdd()

        assertNull("A blank issuer must be reported as null", reported?.issuer)
    }

    /** Blank numeric fields fall back to the six-digit / thirty-second standard. */
    @Test
    fun manualEntry_blankNumericFields_fallBackToTheStandardDefaults() {
        showDialog()

        DialogFlowSupport.setText(FIELD_ACCOUNT, "defaults@example.com")
        DialogFlowSupport.setText(FIELD_SECRET, SECRET)
        DialogFlowSupport.setText(FIELD_DIGITS, "")
        DialogFlowSupport.setText(FIELD_PERIOD, "")
        clickAdd()

        val arguments = requireNotNull(reported)
        assertEquals(6, arguments.digits)
        assertEquals(30, arguments.period)
    }

    @Test
    fun cancel_neverInvokesTheCallback() {
        showDialog()

        DialogFlowSupport.setText(FIELD_ACCOUNT, "discarded@example.com")
        DialogFlowSupport.setText(FIELD_SECRET, SECRET)
        onView(withText(CANCEL_BUTTON)).inRoot(isDialog()).perform(click())
        waitForIdle()

        assertNull("Cancelling must not report anything", reported)
    }

    // ---------------------------------------------------------------
    // URI auto-fill
    // ---------------------------------------------------------------

    @Test
    fun pastingATotpUri_autofillsEveryField() {
        showDialog()

        DialogFlowSupport.setText(
            FIELD_URI,
            "otpauth://totp/Example:alice@example.com?secret=$SECRET" +
                "&issuer=Example&algorithm=SHA256&digits=8&period=60"
        )

        val fields = DialogFlowSupport.fieldTexts()
        assertEquals("Example", fields[FIELD_ISSUER])
        assertEquals("alice@example.com", fields[FIELD_ACCOUNT])
        assertEquals(SECRET, fields[FIELD_SECRET])
        assertEquals("TOTP", fields[FIELD_TYPE])
        assertEquals("SHA256", fields[FIELD_ALGORITHM])
        assertEquals("8", fields[FIELD_DIGITS])
        assertEquals("60", fields[FIELD_PERIOD])
    }

    /** The auto-filled values are what the callback receives on Add. */
    @Test
    fun pastedUri_isReportedToTheCallback() {
        showDialog()

        DialogFlowSupport.setText(
            FIELD_URI,
            "otpauth://totp/Example:alice@example.com?secret=$SECRET&issuer=Example"
        )
        clickAdd()

        assertEquals(
            AddArguments(
                issuer = "Example",
                accountName = "alice@example.com",
                secret = SECRET,
                type = "TOTP",
                algorithm = "SHA1",
                digits = 6,
                period = 30
            ),
            reported
        )
    }

    @Test
    fun pastingAHotpUri_switchesTheTypeDropdown() {
        showDialog()

        DialogFlowSupport.setText(
            FIELD_URI,
            "otpauth://hotp/Counter:bob@example.com?secret=$SECRET&issuer=Counter&counter=7"
        )

        assertEquals("HOTP", DialogFlowSupport.fieldTexts()[FIELD_TYPE])
    }

    /** With no `issuer` parameter the label's `Issuer:` prefix is used instead. */
    @Test
    fun uriWithTheIssuerOnlyInTheLabel_usesTheLabelIssuer() {
        showDialog()

        DialogFlowSupport.setText(
            FIELD_URI,
            "otpauth://totp/LabelCo:carol@example.com?secret=$SECRET"
        )

        val fields = DialogFlowSupport.fieldTexts()
        assertEquals("LabelCo", fields[FIELD_ISSUER])
        assertEquals("carol@example.com", fields[FIELD_ACCOUNT])
    }

    /** A label without a colon is entirely the account name. */
    @Test
    fun uriWithoutAnIssuer_leavesTheIssuerFieldEmpty() {
        showDialog()

        DialogFlowSupport.setText(FIELD_URI, "otpauth://totp/dave@example.com?secret=$SECRET")

        val fields = DialogFlowSupport.fieldTexts()
        assertEquals("", fields[FIELD_ISSUER])
        assertEquals("dave@example.com", fields[FIELD_ACCOUNT])
    }

    @Test
    fun uriWithoutOptionalParameters_appliesTheSpecDefaults() {
        showDialog()

        DialogFlowSupport.setText(FIELD_URI, "otpauth://totp/erin@example.com?secret=$SECRET")

        val fields = DialogFlowSupport.fieldTexts()
        assertEquals("SHA1", fields[FIELD_ALGORITHM])
        assertEquals("6", fields[FIELD_DIGITS])
        assertEquals("30", fields[FIELD_PERIOD])
    }

    // ---------------------------------------------------------------
    // URIs the parser rejects
    // ---------------------------------------------------------------

    /** `secret` is mandatory; without it nothing may be auto-filled. */
    @Test
    fun uriWithoutASecret_leavesTheFormUntouched() {
        showDialog()

        DialogFlowSupport.setText(
            FIELD_URI,
            "otpauth://totp/Example:frank@example.com?issuer=Example"
        )

        val fields = DialogFlowSupport.fieldTexts()
        assertEquals("", fields[FIELD_ISSUER])
        assertEquals("", fields[FIELD_ACCOUNT])
        assertEquals("", fields[FIELD_SECRET])
    }

    @Test
    fun uriWithAnUnsupportedType_leavesTheFormUntouched() {
        showDialog()

        DialogFlowSupport.setText(
            FIELD_URI,
            "otpauth://steam/Example:grace@example.com?secret=$SECRET"
        )

        val fields = DialogFlowSupport.fieldTexts()
        assertEquals("", fields[FIELD_ACCOUNT])
        assertEquals("", fields[FIELD_SECRET])
    }

    /** Text that is not an `otpauth://` URI never triggers the watcher. */
    @Test
    fun plainTextInTheUriField_isIgnored() {
        showDialog()

        DialogFlowSupport.setText(FIELD_URI, "this is not a uri")

        val fields = DialogFlowSupport.fieldTexts()
        assertEquals("", fields[FIELD_ACCOUNT])
        assertEquals("TOTP", fields[FIELD_TYPE])
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    /**
     * Shows the dialog on a host activity, recording its callback arguments.
     *
     * [OathActivity] is the dialog's real caller, which keeps the theme and
     * context identical to production; nothing about the host screen is asserted
     * here.
     */
    private fun showDialog() {
        val scenario = ActivityScenario.launch(OathActivity::class.java)
        scenario.onActivity { activity ->
            AddOathDialog.show(activity) { issuer, account, secret, type, algo, digits, period ->
                reported = AddArguments(issuer, account, secret, type, algo, digits, period)
            }
        }
        waitForIdle()
        onView(withText(ADD_BUTTON)).inRoot(isDialog()).check(matches(isDisplayed()))
    }

    private fun clickAdd() {
        // Dispatched on the main thread rather than tapped: filling a field
        // programmatically can leave the IME window departing, and a real tap
        // aimed at the dialog is swallowed by it while Espresso reports success.
        DialogFlowSupport.clickButton(android.R.id.button1)
        waitForIdle()
        assertNotNull("The Add button should have invoked the callback", reported)
    }

    private companion object {
        const val FIELD_URI = 0
        const val FIELD_ISSUER = 1
        const val FIELD_ACCOUNT = 2
        const val FIELD_SECRET = 3
        const val FIELD_TYPE = 4
        const val FIELD_ALGORITHM = 5
        const val FIELD_DIGITS = 6
        const val FIELD_PERIOD = 7

        /** Valid Base32, so the same values also survive a real import. */
        const val SECRET = "JBSWY3DPEHPK3PXP"

        /** Button labels; still inline literals in the dialog. */
        const val ADD_BUTTON = "Add"
        const val CANCEL_BUTTON = "Cancel"
    }
}
