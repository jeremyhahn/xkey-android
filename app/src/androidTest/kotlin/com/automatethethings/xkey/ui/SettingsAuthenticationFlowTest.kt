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
import android.os.Build
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.automatethethings.xkey.credential.CredentialProviderSettingsRepository
import com.automatethethings.xkey.settings.AttestationBiometricPolicy
import com.automatethethings.xkey.settings.AuthTimeWindow
import com.automatethethings.xkey.settings.BiometricAuthMode
import com.automatethethings.xkey.settings.BiometricSettingsData
import com.automatethethings.xkey.settings.BiometricSettingsRepository
import com.automatethethings.xkey.settings.UserVerificationPolicy
import com.automatethethings.xkey.ui.SettingsFlowSupport.assertEventuallyHides
import com.automatethethings.xkey.ui.SettingsFlowSupport.assertEventuallyShows
import com.automatethethings.xkey.ui.SettingsFlowSupport.awaitInitialized
import com.automatethethings.xkey.ui.SettingsFlowSupport.clickView
import com.automatethethings.xkey.ui.SettingsFlowSupport.radioOption
import com.automatethethings.xkey.ui.SettingsFlowSupport.rowSwitch
import com.automatethethings.xkey.ui.SettingsFlowSupport.selectSpinnerItem
import com.automatethethings.xkey.ui.SettingsFlowSupport.setToggle
import com.automatethethings.xkey.ui.SettingsFlowSupport.shows
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * End-to-end tests for the Authentication & Passkeys section of
 * [SettingsActivity]: the biometric master switch, the three authentication
 * modes and their conditional time-window spinner, the attestation policy, and
 * the Android 14 platform passkey provider toggle.
 *
 * Every test drives the real control and then asserts the *persisted* effect in
 * DataStore, not merely that a row rendered — these listeners are the only
 * writers of the settings the FIDO2 stack reads at ceremony time.
 *
 * Each test seeds the precondition into DataStore before launch (the screen's
 * conditional containers are driven by `loadSettings()`), and the whole
 * biometric + credential-provider state is snapshotted in @Before and restored
 * in @After because other suites read it.
 */
@RunWith(AndroidJUnit4::class)
class SettingsAuthenticationFlowTest {

    private lateinit var context: Context
    private lateinit var biometricRepository: BiometricSettingsRepository
    private lateinit var credentialProviderRepository: CredentialProviderSettingsRepository

    private lateinit var originalBiometric: BiometricSettingsData
    private var originalCredentialProvider: Boolean = false

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        biometricRepository = BiometricSettingsRepository(context)
        credentialProviderRepository = CredentialProviderSettingsRepository(context)
        runBlocking {
            originalBiometric = biometricRepository.getSettings()
            originalCredentialProvider = credentialProviderRepository.getSettings().isEnabled
        }
    }

    @After
    fun tearDown() {
        runBlocking {
            biometricRepository.updateSettings(originalBiometric)
            credentialProviderRepository.setEnabled(originalCredentialProvider)
        }
    }

    // ---------------------------------------------------------------
    // Biometric master switch
    // ---------------------------------------------------------------

    /**
     * Turning the master switch off must both collapse the mode picker and
     * persist [UserVerificationPolicy.DISABLED]; the policy is what the
     * credential handlers consult, so a UI-only change would be silent.
     */
    @Test
    fun biometricToggle_off_persistsDisabledPolicyAndCollapsesAuthMode() {
        seedBiometric(BiometricSettingsData(uvPolicy = UserVerificationPolicy.REQUIRED))

        val scenario = ActivityScenario.launch(SettingsActivity::class.java)
        awaitInitialized(scenario)
        assertTrue(
            "The mode picker should start expanded while biometric is required",
            shows(scenario, AUTH_MODE_LABEL)
        )

        setToggle(scenario, desired = false, describe = "Biometric Authentication") {
            rowSwitch(it, context.getString(R.string.settings_biometric_required_title))
        }

        awaitCondition("User verification policy should be persisted as DISABLED") {
            currentBiometric().uvPolicy == UserVerificationPolicy.DISABLED
        }
        assertEventuallyHides(scenario, AUTH_MODE_LABEL)
    }

    @Test
    fun biometricToggle_on_persistsRequiredPolicyAndRevealsAuthMode() {
        seedBiometric(BiometricSettingsData(uvPolicy = UserVerificationPolicy.DISABLED))

        val scenario = ActivityScenario.launch(SettingsActivity::class.java)
        awaitInitialized(scenario)
        assertFalse(
            "The mode picker should start collapsed while biometric is disabled",
            shows(scenario, AUTH_MODE_LABEL)
        )

        setToggle(scenario, desired = true, describe = "Biometric Authentication") {
            rowSwitch(it, context.getString(R.string.settings_biometric_required_title))
        }

        awaitCondition("User verification policy should be persisted as REQUIRED") {
            currentBiometric().uvPolicy == UserVerificationPolicy.REQUIRED
        }
        assertEventuallyShows(scenario, AUTH_MODE_LABEL)
    }

    /** The collapsed state is rebuilt from DataStore, not from in-memory state. */
    @Test
    fun biometricDisabled_survivesRecreate() {
        seedBiometric(BiometricSettingsData(uvPolicy = UserVerificationPolicy.DISABLED))

        val scenario = ActivityScenario.launch(SettingsActivity::class.java)
        awaitInitialized(scenario)
        scenario.recreate()
        awaitInitialized(scenario)

        assertFalse(
            "The mode picker should still be collapsed after a recreate",
            shows(scenario, AUTH_MODE_LABEL)
        )
    }

    // ---------------------------------------------------------------
    // Authentication mode
    // ---------------------------------------------------------------

    @Test
    fun authMode_timeWindow_persistsAndRevealsDurationPicker() {
        seedBiometric(
            BiometricSettingsData(
                uvPolicy = UserVerificationPolicy.REQUIRED,
                authMode = BiometricAuthMode.PER_OPERATION
            )
        )

        val scenario = ActivityScenario.launch(SettingsActivity::class.java)
        awaitInitialized(scenario)
        assertFalse(
            "The duration picker should be hidden for per-operation mode",
            shows(scenario, context.getString(R.string.settings_time_window_title))
        )

        clickView(scenario, "the Time window option") {
            radioOption(it, context.getString(R.string.settings_auth_mode_time_window))
        }

        awaitCondition("Auth mode should be persisted as TIME_WINDOW") {
            currentBiometric().authMode == BiometricAuthMode.TIME_WINDOW
        }
        assertEventuallyShows(scenario, context.getString(R.string.settings_time_window_title))
    }

    @Test
    fun authMode_perSession_persistsAndHidesDurationPicker() {
        seedBiometric(
            BiometricSettingsData(
                uvPolicy = UserVerificationPolicy.REQUIRED,
                authMode = BiometricAuthMode.TIME_WINDOW
            )
        )

        val scenario = ActivityScenario.launch(SettingsActivity::class.java)
        awaitInitialized(scenario)
        assertTrue(
            "The duration picker should be visible for time-window mode",
            shows(scenario, context.getString(R.string.settings_time_window_title))
        )

        clickView(scenario, "the Per session option") {
            radioOption(it, context.getString(R.string.settings_auth_mode_per_session))
        }

        awaitCondition("Auth mode should be persisted as PER_SESSION") {
            currentBiometric().authMode == BiometricAuthMode.PER_SESSION
        }
        assertEventuallyHides(scenario, context.getString(R.string.settings_time_window_title))
    }

    @Test
    fun authMode_perOperation_persists() {
        seedBiometric(
            BiometricSettingsData(
                uvPolicy = UserVerificationPolicy.REQUIRED,
                authMode = BiometricAuthMode.PER_SESSION
            )
        )

        val scenario = ActivityScenario.launch(SettingsActivity::class.java)
        awaitInitialized(scenario)

        clickView(scenario, "the Per operation option") {
            radioOption(it, context.getString(R.string.settings_auth_mode_per_operation))
        }

        awaitCondition("Auth mode should be persisted as PER_OPERATION") {
            currentBiometric().authMode == BiometricAuthMode.PER_OPERATION
        }
    }

    /**
     * The duration spinner maps its position onto [AuthTimeWindow]; picking the
     * five-minute row must store 300 seconds and not the position.
     */
    @Test
    fun timeWindowSpinner_persistsSelectedDuration() {
        seedBiometric(
            BiometricSettingsData(
                uvPolicy = UserVerificationPolicy.REQUIRED,
                authMode = BiometricAuthMode.TIME_WINDOW,
                timeWindowSeconds = AuthTimeWindow.MINUTES_2.seconds
            )
        )

        val scenario = ActivityScenario.launch(SettingsActivity::class.java)
        awaitInitialized(scenario)

        selectSpinnerItem(scenario, anchorItem = "30 seconds", targetItem = "5 minutes")

        awaitCondition("The five minute window should be persisted as 300 seconds") {
            currentBiometric().timeWindowSeconds == AuthTimeWindow.MINUTES_5.seconds
        }
    }

    /** The spinner starts on the persisted window rather than on position 0. */
    @Test
    fun timeWindowSpinner_startsOnThePersistedDuration() {
        seedBiometric(
            BiometricSettingsData(
                uvPolicy = UserVerificationPolicy.REQUIRED,
                authMode = BiometricAuthMode.TIME_WINDOW,
                timeWindowSeconds = AuthTimeWindow.MINUTES_10.seconds
            )
        )

        val scenario = ActivityScenario.launch(SettingsActivity::class.java)
        awaitInitialized(scenario)

        val selected = withActivity(scenario) { activity ->
            SettingsFlowSupport.spinnerWithItem(activity.window.decorView, "30 seconds")
                ?.selectedItem?.toString()
        }
        assertEquals("10 minutes", selected)
    }

    // ---------------------------------------------------------------
    // Attestation policy
    // ---------------------------------------------------------------

    @Test
    fun attestationPolicy_never_persists() {
        seedBiometric(
            BiometricSettingsData(
                attestationBiometricPolicy = AttestationBiometricPolicy.ALWAYS
            )
        )

        val scenario = ActivityScenario.launch(SettingsActivity::class.java)
        awaitInitialized(scenario)

        clickView(scenario, "the Never require option") {
            radioOption(it, context.getString(R.string.settings_attestation_policy_never))
        }

        awaitCondition("Attestation policy should be persisted as NEVER") {
            currentBiometric().attestationBiometricPolicy == AttestationBiometricPolicy.NEVER
        }
    }

    @Test
    fun attestationPolicy_skipForPairedDevices_persists() {
        seedBiometric(
            BiometricSettingsData(
                attestationBiometricPolicy = AttestationBiometricPolicy.NEVER
            )
        )

        val scenario = ActivityScenario.launch(SettingsActivity::class.java)
        awaitInitialized(scenario)

        clickView(scenario, "the Skip for paired devices option") {
            radioOption(it, context.getString(R.string.settings_attestation_policy_paired_skip))
        }

        awaitCondition("Attestation policy should be persisted as PAIRED_DEVICES_SKIP") {
            currentBiometric().attestationBiometricPolicy ==
                AttestationBiometricPolicy.PAIRED_DEVICES_SKIP
        }
    }

    @Test
    fun attestationPolicy_always_persists() {
        seedBiometric(
            BiometricSettingsData(
                attestationBiometricPolicy = AttestationBiometricPolicy.NEVER
            )
        )

        val scenario = ActivityScenario.launch(SettingsActivity::class.java)
        awaitInitialized(scenario)

        clickView(scenario, "the Always require option") {
            radioOption(it, context.getString(R.string.settings_attestation_policy_always))
        }

        awaitCondition("Attestation policy should be persisted as ALWAYS") {
            currentBiometric().attestationBiometricPolicy == AttestationBiometricPolicy.ALWAYS
        }
    }

    /** The persisted policy selects the matching radio on load. */
    @Test
    fun attestationPolicy_restoresPersistedSelection() {
        seedBiometric(
            BiometricSettingsData(
                attestationBiometricPolicy = AttestationBiometricPolicy.PAIRED_DEVICES_SKIP
            )
        )

        val scenario = ActivityScenario.launch(SettingsActivity::class.java)
        awaitInitialized(scenario)

        val checked = withActivity(scenario) { activity ->
            radioOption(
                activity.window.decorView,
                context.getString(R.string.settings_attestation_policy_paired_skip)
            )?.isChecked
        }
        assertEquals(true, checked)
    }

    // ---------------------------------------------------------------
    // Platform passkey provider (Android 14+)
    // ---------------------------------------------------------------

    /**
     * Only the disable direction is driven here: enabling the provider also
     * opens the system credential settings screen, which would leave a
     * foreign activity on top of the task for every later test.
     */
    @Test
    fun credentialProvider_disable_persistsAndHidesSystemSettingsButton() {
        assumeTrue(
            "Platform passkey provider needs Android 14",
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE
        )
        runBlocking { credentialProviderRepository.setEnabled(true) }

        val scenario = ActivityScenario.launch(SettingsActivity::class.java)
        awaitInitialized(scenario)
        assertTrue(
            "The system settings shortcut should be offered while the provider is on",
            shows(scenario, context.getString(R.string.settings_credential_provider_system_settings))
        )

        setToggle(scenario, desired = false, describe = "Platform Passkey Provider") {
            rowSwitch(it, context.getString(R.string.settings_credential_provider_title))
        }

        awaitCondition("The credential provider preference should be persisted as off") {
            runBlocking { !credentialProviderRepository.getSettings().isEnabled }
        }
        assertEventuallyHides(
            scenario,
            context.getString(R.string.settings_credential_provider_system_settings)
        )
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    private fun seedBiometric(settings: BiometricSettingsData) {
        runBlocking { biometricRepository.updateSettings(settings) }
    }

    private fun currentBiometric(): BiometricSettingsData =
        runBlocking { biometricRepository.getSettings() }

    private companion object {
        /** Inline literal in `buildAuthPasskeysSection`, not a string resource. */
        const val AUTH_MODE_LABEL = "Authentication Mode"
    }
}
