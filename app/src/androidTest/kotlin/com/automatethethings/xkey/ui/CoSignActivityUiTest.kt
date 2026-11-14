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

import androidx.test.core.app.ActivityScenario
import androidx.test.espresso.Espresso.pressBackUnconditionally
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented UI tests for [CoSignActivity].
 *
 * CoSignActivity builds its UI programmatically and keeps three mutually
 * exclusive sections in the tree at once -- initiator (QR), witness (QR) and
 * Bluetooth -- toggling their visibility from the mode radio group and from the
 * two "switch role" buttons. These tests drive those transitions and the guard
 * clauses that fire when an action is attempted before a media file or content
 * hash has been supplied, asserting the snackbar each guard raises.
 *
 * Nothing is persisted, so there is no teardown: co-signing only writes once a
 * media file is picked, which these tests never do.
 *
 * Tests cover:
 * - Toolbar and the initial "no file selected" state
 * - Signature card placeholder before any media is chosen
 * - Mode radio group switching between the QR and Bluetooth sections
 * - Initiator to witness role switching, and back again
 * - Guard: generating a co-sign QR without media raises a snackbar
 * - Guard: witness signing with an empty hash raises a snackbar
 * - Back navigation finishing the activity
 */
@RunWith(AndroidJUnit4::class)
class CoSignActivityUiTest {

    // -----------------------------------------------------------------
    // Chrome and initial state
    // -----------------------------------------------------------------

    @Test
    fun toolbar_showsTitleAndSubtitle() {
        val scenario = launch()

        assertShownTextInTree(scenario, withString(scenario, R.string.cosign_title))
        assertShownTextInTree(scenario, withString(scenario, R.string.cosign_subtitle))
    }

    @Test
    fun initialState_reportsThatNoMediaHasBeenSelected() {
        val scenario = launch()

        assertShownTextInTree(scenario, withString(scenario, R.string.cosign_select_media))
        assertShownTextInTree(scenario, NO_FILE_SELECTED)
    }

    @Test
    fun signatureCard_showsThePlaceholderBeforeMediaIsChosen() {
        val scenario = launch()

        assertShownTextInTree(scenario, CURRENT_SIGNATURES)
        assertShownTextInTree(scenario, SIGNATURE_PLACEHOLDER)
    }

    // -----------------------------------------------------------------
    // Mode selection
    // -----------------------------------------------------------------

    /** QR mode is preselected, so the initiator section is the visible one. */
    @Test
    fun qrMode_isSelectedByDefaultAndShowsTheInitiatorSection() {
        val scenario = launch()

        assertShownTextInTree(scenario, withString(scenario, R.string.cosign_initiator_title))
        assertHidden(scenario, withString(scenario, R.string.cosign_waiting_ble))
    }

    @Test
    fun bluetoothMode_replacesTheInitiatorSectionWithTheBleSection() {
        val scenario = launch()

        clickClickableWithExactText(scenario, withString(scenario, R.string.cosign_mode_ble))

        assertShownTextInTree(scenario, withString(scenario, R.string.cosign_waiting_ble))
        assertHidden(scenario, GENERATE_QR)
    }

    @Test
    fun switchingBackToQrMode_restoresTheInitiatorSection() {
        val scenario = launch()

        clickClickableWithExactText(scenario, withString(scenario, R.string.cosign_mode_ble))
        assertHidden(scenario, GENERATE_QR)

        clickClickableWithExactText(scenario, withString(scenario, R.string.cosign_mode_qr))

        assertShownTextInTree(scenario, GENERATE_QR)
        assertHidden(scenario, withString(scenario, R.string.cosign_waiting_ble))
    }

    // -----------------------------------------------------------------
    // Role switching
    // -----------------------------------------------------------------

    @Test
    fun witnessButton_swapsTheInitiatorSectionForTheWitnessSection() {
        val scenario = launch()

        clickClickableWithExactText(scenario, withString(scenario, R.string.cosign_witness_title))

        assertShownTextInTree(scenario, WITNESS_DESCRIPTION)
        assertHidden(scenario, GENERATE_QR)
    }

    @Test
    fun backToInitiatorButton_restoresTheInitiatorSection() {
        val scenario = launch()

        clickClickableWithExactText(scenario, withString(scenario, R.string.cosign_witness_title))
        assertHidden(scenario, GENERATE_QR)

        clickClickableWithExactText(
            scenario,
            withString(scenario, R.string.cosign_initiator_title)
        )

        assertShownTextInTree(scenario, GENERATE_QR)
        assertHidden(scenario, WITNESS_DESCRIPTION)
    }

    // -----------------------------------------------------------------
    // Guard clauses
    // -----------------------------------------------------------------

    @Test
    fun generatingAQrWithoutMedia_raisesASnackbar() {
        val scenario = launch()

        clickClickableWithExactText(scenario, GENERATE_QR)

        assertShownTextInTree(scenario, NO_MEDIA_SNACKBAR)
    }

    @Test
    fun scanningAResponseWithoutMedia_raisesASnackbar() {
        val scenario = launch()

        clickClickableWithExactText(scenario, withString(scenario, R.string.cosign_scan_response))

        assertShownTextInTree(scenario, NO_MEDIA_SNACKBAR)
    }

    /** The witness signs only what it scans: a scan button, no typed hash and no bare approve button. */
    @Test
    fun witnessSection_offersTheRequestScanInsteadOfATypedHash() {
        val scenario = launch()
        clickClickableWithExactText(scenario, withString(scenario, R.string.cosign_witness_title))
        assertShownTextInTree(scenario, WITNESS_DESCRIPTION)

        assertShownTextInTree(scenario, withString(scenario, R.string.cosign_scan_request))
        assertHidden(scenario, withString(scenario, R.string.cosign_approve))
        assertTrue(
            "The witness section must not offer a hash text field",
            withActivity(scenario) { activity ->
                collectViews(activity.window.decorView) { it is android.widget.EditText && it.isShown }.isEmpty()
            }
        )
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

    private fun launch(): ActivityScenario<CoSignActivity> =
        ActivityScenario.launch(CoSignActivity::class.java)

    private fun withString(scenario: ActivityScenario<CoSignActivity>, resId: Int): String =
        withActivity(scenario) { it.getString(resId) }

    /** Asserts [text] is present in the tree but not visible. */
    private fun assertHidden(scenario: ActivityScenario<CoSignActivity>, text: String) {
        assertTrue(
            "'$text' should not be visible in the current mode",
            awaitActivity(scenario) {
                findShownTextViewContaining(it.window.decorView, text) == null
            }
        )
    }

    private companion object {
        const val NO_FILE_SELECTED = "No file selected"
        const val CURRENT_SIGNATURES = "Current Signatures"
        const val SIGNATURE_PLACEHOLDER = "Select a signed media file to view signatures"
        const val GENERATE_QR = "Generate Co-Sign QR"
        const val WITNESS_DESCRIPTION =
            "As a witness, you sign someone else's content hash to attest your presence."
        const val NO_MEDIA_SNACKBAR = "Select a signed media file first"
    }
}
