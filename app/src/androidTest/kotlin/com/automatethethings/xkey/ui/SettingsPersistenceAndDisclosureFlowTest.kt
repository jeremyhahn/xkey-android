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
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.automatethethings.xkey.settings.BiometricSettingsData
import com.automatethethings.xkey.settings.BiometricSettingsRepository
import com.automatethethings.xkey.settings.CertificateAuthoritySource
import com.automatethethings.xkey.settings.TrustedComputingSettingsData
import com.automatethethings.xkey.settings.TrustedComputingSettingsRepository
import com.automatethethings.xkey.settings.UserVerificationPolicy
import com.automatethethings.xkey.ui.SettingsFlowSupport.assertEventuallyHides
import com.automatethethings.xkey.ui.SettingsFlowSupport.assertEventuallyShows
import com.automatethethings.xkey.ui.SettingsFlowSupport.awaitInitialized
import com.automatethethings.xkey.ui.SettingsFlowSupport.editTextNearLabel
import com.automatethethings.xkey.ui.SettingsFlowSupport.rowSwitch
import com.automatethethings.xkey.ui.SettingsFlowSupport.setFieldAndBlur
import com.automatethethings.xkey.ui.SettingsFlowSupport.shows
import com.automatethethings.xkey.usb.UsbHsmSettingsData
import com.automatethethings.xkey.usb.UsbHsmSettingsRepository
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented tests for three behaviours of [SettingsActivity] that no other
 * suite covers:
 *
 * 1. The xkms endpoint persists on focus loss, like every other text field on
 *    the screen. It used to be written only as a side effect of "Fetch CA
 *    Bundle", so typing a URL and navigating away lost it.
 * 2. The screen *observes* the biometric settings instead of reading them once
 *    in `onCreate`, so a change made by another writer (the credential-provider
 *    flow, another screen, a paired desktop) is reflected while it is open.
 * 3. The TCP-over-ADB transport sits behind the Developer Options disclosure and
 *    is collapsed until the user opens it.
 *
 * The activity is launched per test, and the biometric, trusted-computing and
 * USB settings are snapshotted in @Before and restored in @After because other
 * suites read all three.
 */
@RunWith(AndroidJUnit4::class)
class SettingsPersistenceAndDisclosureFlowTest {

    private lateinit var context: Context
    private lateinit var biometricRepository: BiometricSettingsRepository
    private lateinit var trustedComputingRepository: TrustedComputingSettingsRepository
    private lateinit var usbRepository: UsbHsmSettingsRepository

    private lateinit var originalBiometric: BiometricSettingsData
    private lateinit var originalTrustedComputing: TrustedComputingSettingsData
    private lateinit var originalUsb: UsbHsmSettingsData

    private var scenario: ActivityScenario<SettingsActivity>? = null

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        biometricRepository = BiometricSettingsRepository(context)
        trustedComputingRepository = TrustedComputingSettingsRepository(context)
        usbRepository = UsbHsmSettingsRepository(context)
        runBlocking {
            originalBiometric = biometricRepository.getSettings()
            originalTrustedComputing = trustedComputingRepository.getSettings()
            originalUsb = usbRepository.getSettings()
        }
    }

    @After
    fun tearDown() {
        scenario?.close()
        scenario = null
        runBlocking {
            biometricRepository.updateSettings(originalBiometric)
            trustedComputingRepository.updateSettings(originalTrustedComputing)
            usbRepository.setNativeUsbEnabled(originalUsb.nativeUsbEnabled)
            usbRepository.setTcpHsmEnabled(originalUsb.tcpHsmEnabled)
        }
    }

    // ---------------------------------------------------------------
    // xkms endpoint
    // ---------------------------------------------------------------

    /**
     * Leaving the field is what commits it. Pressing "Fetch CA Bundle" is a
     * network action the user may never take, and it used to be the only writer.
     */
    @Test
    fun xkmsEndpoint_persistsOnFocusLoss() {
        seedTrustedComputing(xkmsEndpoint = null)
        val scenario = launch()

        setFieldAndBlur(scenario, "xkms endpoint", CA_URL) { caUrlField(it) }

        awaitCondition("The xkms endpoint should be persisted on focus loss") {
            currentTrustedComputing().xkmsEndpoint == CA_URL
        }
    }

    /** What was typed is what comes back, without pressing anything. */
    @Test
    fun xkmsEndpoint_isRestoredAfterLeavingTheScreen() {
        seedTrustedComputing(xkmsEndpoint = null)
        val scenario = launch()

        setFieldAndBlur(scenario, "xkms endpoint", CA_URL) { caUrlField(it) }
        awaitCondition("Precondition: the endpoint reached the repository") {
            currentTrustedComputing().xkmsEndpoint == CA_URL
        }

        scenario.recreate()
        awaitInitialized(scenario)

        val restored = withActivity(scenario) { caUrlField(it.window.decorView)?.text?.toString() }
        assertEquals(CA_URL, restored)
    }

    /** Clearing the field clears the stored endpoint rather than storing "". */
    @Test
    fun xkmsEndpoint_blankFieldClearsTheStoredEndpoint() {
        seedTrustedComputing(xkmsEndpoint = CA_URL)
        val scenario = launch()

        setFieldAndBlur(scenario, "xkms endpoint", "  ") { caUrlField(it) }

        awaitCondition("A blank field should clear the stored endpoint") {
            currentTrustedComputing().xkmsEndpoint == null
        }
    }

    // ---------------------------------------------------------------
    // Observing the biometric settings
    // ---------------------------------------------------------------

    /**
     * A write by any other component has to reach the open screen: the switch is
     * the user's only view of a policy the whole FIDO2 stack reads, and a stale
     * one invites them to "fix" a setting that is already off.
     */
    @Test
    fun biometricSwitch_followsAChangeMadeElsewhereWhileTheScreenIsOpen() {
        seedBiometric(BiometricSettingsData(uvPolicy = UserVerificationPolicy.REQUIRED))
        val scenario = launch()
        assertTrue(
            "Precondition: the switch starts on for a REQUIRED policy",
            biometricSwitchChecked(scenario) == true
        )

        // Stands in for the credential-provider flow, another screen or a paired
        // desktop writing the policy while this screen is showing.
        seedBiometric(BiometricSettingsData(uvPolicy = UserVerificationPolicy.DISABLED))

        assertTrue(
            "The switch should follow the externally written policy",
            awaitActivity(scenario) { biometricSwitchOf(it)?.isChecked == false }
        )
    }

    /** The conditional mode picker follows the same external change. */
    @Test
    fun authModeSection_collapsesWhenThePolicyIsDisabledElsewhere() {
        seedBiometric(BiometricSettingsData(uvPolicy = UserVerificationPolicy.REQUIRED))
        val scenario = launch()
        assertTrue(
            "Precondition: the mode picker starts expanded",
            shows(scenario, AUTH_MODE_LABEL)
        )

        seedBiometric(BiometricSettingsData(uvPolicy = UserVerificationPolicy.DISABLED))

        assertEventuallyHides(scenario, AUTH_MODE_LABEL)
    }

    /**
     * Reflecting an external change must not be mistaken for a user choice.
     *
     * Populating the switch fires its listener, and the listener writes; without
     * the guard covering the whole population pass the screen would write the
     * value it has just read, defeating whoever made the change.
     */
    @Test
    fun followingAnExternalChange_doesNotWriteItBack() {
        seedBiometric(BiometricSettingsData(uvPolicy = UserVerificationPolicy.REQUIRED))
        val scenario = launch()

        seedBiometric(BiometricSettingsData(uvPolicy = UserVerificationPolicy.DISABLED))
        assertTrue(
            "Precondition: the screen followed the change",
            awaitActivity(scenario) { biometricSwitchOf(it)?.isChecked == false }
        )

        // A write-back would restore REQUIRED. The switch's listener launches it
        // synchronously while the switch is populated, so once the main loop is
        // idle any write-back is recorded; wait for it to land before reading.
        waitForIdle()
        assertTrue(
            "A policy write launched by the switch should have finished",
            awaitActivity(scenario) { it.uvPolicyWriteJob?.isCompleted != false }
        )
        assertEquals(
            "The screen must not write the value it has just read",
            UserVerificationPolicy.DISABLED,
            currentBiometric().uvPolicy
        )
    }

    // ---------------------------------------------------------------
    // Developer Options disclosure
    // ---------------------------------------------------------------

    /**
     * The ADB transport is a development affordance; it is built but not offered
     * until the user opens the disclosure that names it as such.
     */
    @Test
    fun developerOptions_startCollapsed() {
        val scenario = launch()

        assertTrue(
            "The disclosure itself should be offered",
            shows(scenario, context.getString(R.string.settings_developer_options))
        )
        assertFalse(
            "TCP pairing should not be offered before the disclosure is opened",
            shows(scenario, context.getString(R.string.settings_usb_tcp_title))
        )
    }

    @Test
    fun developerOptions_revealTcpPairingWhenOpened() {
        val scenario = launch()

        clickTextInTree(scenario, context.getString(R.string.settings_developer_options))

        assertEventuallyShows(scenario, context.getString(R.string.settings_usb_tcp_title))
        assertEventuallyShows(scenario, context.getString(R.string.settings_usb_tcp_description))
        assertEventuallyShows(scenario, context.getString(R.string.explain_usb_tcp))
    }

    /** Opening and closing again puts the transport back out of the way. */
    @Test
    fun developerOptions_collapseAgainOnASecondTap() {
        val scenario = launch()
        val label = context.getString(R.string.settings_developer_options)

        clickTextInTree(scenario, label)
        assertEventuallyShows(scenario, context.getString(R.string.settings_usb_tcp_title))

        clickTextInTree(scenario, label)
        assertEventuallyHides(scenario, context.getString(R.string.settings_usb_tcp_title))
    }

    /**
     * The disclosure hides the toggle, not the setting: a TCP transport that was
     * already enabled still reads as enabled once revealed.
     */
    @Test
    fun developerOptions_revealTheStoredTcpState() {
        runBlocking { usbRepository.setTcpHsmEnabled(true) }
        val scenario = launch()

        clickTextInTree(scenario, context.getString(R.string.settings_developer_options))

        val toggle = withActivity(scenario) {
            rowSwitch(it.window.decorView, context.getString(R.string.settings_usb_tcp_title))
        }
        assertNotNull("The TCP pairing toggle should be built", toggle)
        assertTrue("The revealed toggle should show the stored state", toggle!!.isChecked)
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    private fun launch(): ActivityScenario<SettingsActivity> {
        val launched = ActivityScenario.launch(SettingsActivity::class.java)
        scenario = launched
        awaitInitialized(launched)
        return launched
    }

    /**
     * The xkms endpoint field.
     *
     * Located through its subsection label: three bootstrap fields share this
     * field's example URL, so a hint match alone would be ambiguous.
     */
    private fun caUrlField(root: View): EditText? =
        editTextNearLabel(root, context.getString(R.string.settings_trusted_computing_ca_url))

    private fun biometricSwitchOf(activity: SettingsActivity) =
        rowSwitch(
            activity.window.decorView,
            context.getString(R.string.settings_biometric_required_title)
        )

    private fun biometricSwitchChecked(scenario: ActivityScenario<SettingsActivity>): Boolean? =
        withActivity(scenario) { biometricSwitchOf(it)?.isChecked }

    /**
     * Seeds trusted computing with the endpoint container on screen.
     *
     * The endpoint field is revealed only for the xkms authority, and a field
     * inside a GONE container cannot take focus — so it could never be blurred,
     * and the write these tests are about would never fire.
     */
    private fun seedTrustedComputing(xkmsEndpoint: String?) {
        runBlocking {
            trustedComputingRepository.updateSettings(
                originalTrustedComputing.copy(
                    enabled = true,
                    caSource = CertificateAuthoritySource.XKMS,
                    xkmsEndpoint = xkmsEndpoint
                )
            )
        }
    }

    private fun seedBiometric(settings: BiometricSettingsData) {
        runBlocking { biometricRepository.updateSettings(settings) }
    }

    private fun currentBiometric(): BiometricSettingsData =
        runBlocking { biometricRepository.getSettings() }

    private fun currentTrustedComputing(): TrustedComputingSettingsData =
        runBlocking { trustedComputingRepository.getSettings() }

    private companion object {
        const val CA_URL = "https://ca.settings-flow-test.example.com"

        /** Inline literal in `buildAuthPasskeysSection`, not a string resource. */
        const val AUTH_MODE_LABEL = "Authentication Mode"
    }
}
