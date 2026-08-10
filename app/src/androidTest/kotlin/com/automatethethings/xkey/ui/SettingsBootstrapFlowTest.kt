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
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.automatethethings.xkey.settings.BootstrapSettingsData
import com.automatethethings.xkey.settings.BootstrapSettingsRepository
import com.automatethethings.xkey.settings.BootstrapTimeout
import com.automatethethings.xkey.settings.CertificateAuthoritySource
import com.automatethethings.xkey.settings.TrustedComputingSettingsData
import com.automatethethings.xkey.settings.TrustedComputingSettingsRepository
import com.automatethethings.xkey.ui.SettingsFlowSupport.assertEventuallyMethodShown
import com.automatethethings.xkey.ui.SettingsFlowSupport.assertEventuallyShows
import com.automatethethings.xkey.ui.SettingsFlowSupport.assertMethodConfigShown
import com.automatethethings.xkey.ui.SettingsFlowSupport.awaitInitialized
import com.automatethethings.xkey.ui.SettingsFlowSupport.button
import com.automatethethings.xkey.ui.SettingsFlowSupport.clickView
import com.automatethethings.xkey.ui.SettingsFlowSupport.editTextNearLabel
import com.automatethethings.xkey.ui.SettingsFlowSupport.methodCheckBox
import com.automatethethings.xkey.ui.SettingsFlowSupport.methodSectionEditTexts
import com.automatethethings.xkey.ui.SettingsFlowSupport.methodShown
import com.automatethethings.xkey.ui.SettingsFlowSupport.rowSwitch
import com.automatethethings.xkey.ui.SettingsFlowSupport.selectSpinnerItem
import com.automatethethings.xkey.ui.SettingsFlowSupport.setFieldAndBlur
import com.automatethethings.xkey.ui.SettingsFlowSupport.setToggle
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * End-to-end tests for the Bootstrap Methods sub-section of [SettingsActivity].
 *
 * Each of the four methods (DANE, Noise, SPKI, Direct HTTPS) is a
 * `createMethodSection` triple: a checkbox that persists the method's enabled
 * flag and expands a config container whose fields persist on focus loss. The
 * container holds only unlabelled `EditText`s, so "did it expand" is asserted
 * from the field's `isShown` rather than from any text.
 *
 * The two buttons that can reach the network are exercised on their refusal
 * paths only — no method configured, and a blank CA URL — so the suite never
 * depends on connectivity.
 *
 * Bootstrap and trusted-computing settings are snapshotted in @Before and
 * restored in @After.
 */
@RunWith(AndroidJUnit4::class)
class SettingsBootstrapFlowTest {

    private lateinit var context: Context
    private lateinit var bootstrapRepository: BootstrapSettingsRepository
    private lateinit var trustedComputingRepository: TrustedComputingSettingsRepository

    private lateinit var originalBootstrap: BootstrapSettingsData
    private lateinit var originalTrustedComputing: TrustedComputingSettingsData

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        bootstrapRepository = BootstrapSettingsRepository(context)
        trustedComputingRepository = TrustedComputingSettingsRepository(context)
        runBlocking {
            originalBootstrap = bootstrapRepository.getSettings()
            originalTrustedComputing = trustedComputingRepository.getSettings()
        }
    }

    @After
    fun tearDown() {
        runBlocking {
            bootstrapRepository.updateSettings(originalBootstrap)
            trustedComputingRepository.updateSettings(originalTrustedComputing)
        }
    }

    // ---------------------------------------------------------------
    // Method checkboxes
    // ---------------------------------------------------------------

    @Test
    fun daneCheckbox_expandsConfigurationAndPersists() {
        seedBootstrap(BootstrapSettingsData(autoBootstrapEnabled = true, daneEnabled = false))

        val scenario = launchWithMethodsVisible()
        assertMethodConfigShown(scenario, DANE, expected = false)

        setToggle(scenario, desired = true, describe = "the DANE method") {
            methodCheckBox(it, DANE)
        }

        awaitCondition("DANE should be persisted as enabled") { currentBootstrap().daneEnabled }
        assertMethodConfigShown(scenario, DANE, expected = true)
    }

    @Test
    fun daneCheckbox_collapsesConfigurationAndPersists() {
        seedBootstrap(BootstrapSettingsData(autoBootstrapEnabled = true, daneEnabled = true))

        val scenario = launchWithMethodsVisible()
        assertMethodConfigShown(scenario, DANE, expected = true)

        setToggle(scenario, desired = false, describe = "the DANE method") {
            methodCheckBox(it, DANE)
        }

        awaitCondition("DANE should be persisted as disabled") { !currentBootstrap().daneEnabled }
        assertMethodConfigShown(scenario, DANE, expected = false)
    }

    @Test
    fun noiseCheckbox_expandsConfigurationAndPersists() {
        seedBootstrap(BootstrapSettingsData(autoBootstrapEnabled = true, noiseEnabled = false))

        val scenario = launchWithMethodsVisible()
        assertMethodConfigShown(scenario, NOISE, expected = false)

        setToggle(scenario, desired = true, describe = "the Noise Protocol method") {
            methodCheckBox(it, NOISE)
        }

        awaitCondition("Noise should be persisted as enabled") { currentBootstrap().noiseEnabled }
        assertMethodConfigShown(scenario, NOISE, expected = true)
    }

    @Test
    fun spkiCheckbox_expandsConfigurationAndPersists() {
        seedBootstrap(BootstrapSettingsData(autoBootstrapEnabled = true, spkiEnabled = false))

        val scenario = launchWithMethodsVisible()
        assertMethodConfigShown(scenario, SPKI, expected = false)

        setToggle(scenario, desired = true, describe = "the SPKI Pinning method") {
            methodCheckBox(it, SPKI)
        }

        awaitCondition("SPKI should be persisted as enabled") { currentBootstrap().spkiEnabled }
        assertMethodConfigShown(scenario, SPKI, expected = true)
    }

    @Test
    fun directCheckbox_expandsConfigurationAndPersists() {
        seedBootstrap(BootstrapSettingsData(autoBootstrapEnabled = true, directEnabled = false))

        val scenario = launchWithMethodsVisible()
        assertMethodConfigShown(scenario, DIRECT, expected = false)

        setToggle(scenario, desired = true, describe = "the Direct HTTPS method") {
            methodCheckBox(it, DIRECT)
        }

        awaitCondition("Direct HTTPS should be persisted as enabled") {
            currentBootstrap().directEnabled
        }
        assertMethodConfigShown(scenario, DIRECT, expected = true)
    }

    /** With auto-bootstrap off the whole method list stays out of the tree. */
    @Test
    fun methodList_staysHiddenWhenAutoBootstrapIsPersistedOff() {
        seedBootstrap(BootstrapSettingsData(autoBootstrapEnabled = false, daneEnabled = true))

        val scenario = ActivityScenario.launch(SettingsActivity::class.java)
        awaitInitialized(scenario)

        // Asserted on the DANE checkbox, not on the text "DANE": the
        // auto-bootstrap row's own description reads "Automatically try methods
        // in order: DANE, Noise, SPKI, Direct" and is always on screen, so a
        // substring search can never observe the collapse.
        assertFalse(
            "Bootstrap methods should be collapsed when auto-bootstrap is off",
            methodShown(scenario, DANE)
        )
    }

    // ---------------------------------------------------------------
    // Per-method configuration fields
    // ---------------------------------------------------------------

    @Test
    fun daneConfigurationFields_persistOnFocusLoss() {
        seedBootstrap(BootstrapSettingsData(autoBootstrapEnabled = true, daneEnabled = true))

        val scenario = launchWithMethodsVisible()

        setFieldAndBlur(scenario, "DANE server URL", DANE_URL) {
            methodSectionEditTexts(it, DANE).getOrNull(0)
        }
        setFieldAndBlur(scenario, "DANE DNS server", DANE_DNS) {
            methodSectionEditTexts(it, DANE).getOrNull(1)
        }

        awaitCondition("Both DANE fields should be persisted") {
            val settings = currentBootstrap()
            settings.daneServerUrl == DANE_URL && settings.daneDnsServer == DANE_DNS
        }
    }

    @Test
    fun noiseConfigurationFields_persistOnFocusLoss() {
        seedBootstrap(BootstrapSettingsData(autoBootstrapEnabled = true, noiseEnabled = true))

        val scenario = launchWithMethodsVisible()

        setFieldAndBlur(scenario, "Noise server address", NOISE_ADDR) {
            methodSectionEditTexts(it, NOISE).getOrNull(0)
        }
        setFieldAndBlur(scenario, "Noise static key", HEX_KEY) {
            methodSectionEditTexts(it, NOISE).getOrNull(1)
        }

        awaitCondition("Both Noise fields should be persisted") {
            val settings = currentBootstrap()
            settings.noiseServerAddr == NOISE_ADDR && settings.noiseServerStaticKey == HEX_KEY
        }
    }

    @Test
    fun spkiConfigurationFields_persistOnFocusLoss() {
        seedBootstrap(BootstrapSettingsData(autoBootstrapEnabled = true, spkiEnabled = true))

        val scenario = launchWithMethodsVisible()

        setFieldAndBlur(scenario, "SPKI server URL", SPKI_URL) {
            methodSectionEditTexts(it, SPKI).getOrNull(0)
        }
        setFieldAndBlur(scenario, "SPKI pin", HEX_KEY) {
            methodSectionEditTexts(it, SPKI).getOrNull(1)
        }

        awaitCondition("Both SPKI fields should be persisted") {
            val settings = currentBootstrap()
            settings.spkiServerUrl == SPKI_URL && settings.spkiPinSha256 == HEX_KEY
        }
    }

    @Test
    fun directConfigurationField_persistsOnFocusLoss() {
        seedBootstrap(BootstrapSettingsData(autoBootstrapEnabled = true, directEnabled = true))

        val scenario = launchWithMethodsVisible()

        setFieldAndBlur(scenario, "Direct HTTPS server URL", DIRECT_URL) {
            methodSectionEditTexts(it, DIRECT).getOrNull(0)
        }

        awaitCondition("The Direct HTTPS URL should be persisted") {
            currentBootstrap().directServerUrl == DIRECT_URL
        }
    }

    /** The persisted URLs are written back into the fields on load. */
    @Test
    fun daneConfigurationFields_restorePersistedValues() {
        seedBootstrap(
            BootstrapSettingsData(
                autoBootstrapEnabled = true,
                daneEnabled = true,
                daneServerUrl = DANE_URL,
                daneDnsServer = DANE_DNS
            )
        )

        val scenario = launchWithMethodsVisible()

        val values = withActivity(scenario) { activity ->
            methodSectionEditTexts(activity.window.decorView, DANE).map { it.text.toString() }
        }
        assertEquals(listOf(DANE_URL, DANE_DNS), values)
    }

    @Test
    fun daneDnsOverTlsToggle_persists() {
        seedBootstrap(
            BootstrapSettingsData(
                autoBootstrapEnabled = true,
                daneEnabled = true,
                daneDnsOverTls = false
            )
        )

        val scenario = launchWithMethodsVisible()

        setToggle(scenario, desired = true, describe = "DNS over TLS") {
            rowSwitch(it, context.getString(R.string.bootstrap_dane_dot))
        }

        awaitCondition("DNS over TLS should be persisted as on") {
            currentBootstrap().daneDnsOverTls
        }
    }

    @Test
    fun daneDnssecToggle_persists() {
        seedBootstrap(
            BootstrapSettingsData(
                autoBootstrapEnabled = true,
                daneEnabled = true,
                daneRequireDnssec = true
            )
        )

        val scenario = launchWithMethodsVisible()

        setToggle(scenario, desired = false, describe = "Require DNSSEC") {
            rowSwitch(it, context.getString(R.string.bootstrap_dane_dnssec))
        }

        awaitCondition("Require DNSSEC should be persisted as off") {
            !currentBootstrap().daneRequireDnssec
        }
    }

    // ---------------------------------------------------------------
    // Timeout
    // ---------------------------------------------------------------

    @Test
    fun perMethodTimeoutSpinner_persistsSelectedSeconds() {
        seedBootstrap(
            BootstrapSettingsData(
                autoBootstrapEnabled = true,
                perMethodTimeoutSeconds = BootstrapTimeout.SECONDS_15.seconds
            )
        )

        val scenario = launchWithMethodsVisible()

        selectSpinnerItem(scenario, anchorItem = "10s", targetItem = "60s")

        awaitCondition("The per-method timeout should be persisted as 60 seconds") {
            currentBootstrap().perMethodTimeoutSeconds == BootstrapTimeout.SECONDS_60.seconds
        }
    }

    // ---------------------------------------------------------------
    // Actions that would otherwise reach the network
    // ---------------------------------------------------------------

    @Test
    fun runBootstrapNow_withNoMethodEnabled_explainsWhyNothingHappened() {
        seedBootstrap(
            BootstrapSettingsData(
                autoBootstrapEnabled = true,
                daneEnabled = false,
                noiseEnabled = false,
                spkiEnabled = false,
                directEnabled = false
            )
        )

        val scenario = launchWithMethodsVisible()

        clickView(scenario, "the Run Bootstrap Now button") { button(it, RUN_BOOTSTRAP_BUTTON) }

        assertEventuallyShows(scenario, "No bootstrap methods configured")
    }

    @Test
    fun fetchCaBundle_withBlankUrl_refusesAndAsksForOne() {
        seedBootstrap(BootstrapSettingsData(autoBootstrapEnabled = true))
        // Fetch CA Bundle lives in the endpoint container, which only the xkms
        // authority reveals.
        runBlocking {
            trustedComputingRepository.updateSettings(
                TrustedComputingSettingsData(
                    enabled = true,
                    caSource = CertificateAuthoritySource.XKMS
                )
            )
        }

        val scenario = ActivityScenario.launch(SettingsActivity::class.java)
        awaitInitialized(scenario)

        scenario.onActivity { activity ->
            editTextNearLabel(
                activity.window.decorView,
                context.getString(R.string.settings_trusted_computing_ca_url)
            )?.setText("")
        }
        waitForIdle()

        clickView(scenario, "the Fetch CA Bundle button") {
            button(it, context.getString(R.string.settings_trusted_computing_fetch_ca))
        }

        assertEventuallyShows(scenario, "Please enter a CA server URL")
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    /**
     * Launches the screen and waits until `loadSettings()` has expanded the
     * method list, which every method assertion depends on.
     */
    private fun launchWithMethodsVisible(): ActivityScenario<SettingsActivity> {
        val scenario = ActivityScenario.launch(SettingsActivity::class.java)
        awaitInitialized(scenario)
        assertEventuallyMethodShown(scenario, DANE)
        return scenario
    }

    private fun seedBootstrap(settings: BootstrapSettingsData) {
        runBlocking { bootstrapRepository.updateSettings(settings) }
    }

    private fun currentBootstrap(): BootstrapSettingsData =
        runBlocking { bootstrapRepository.getSettings() }

    private companion object {
        // Method names are inline literals in `buildCertificateAuthoritySection`.
        const val DANE = "DANE"
        const val NOISE = "Noise Protocol"
        const val SPKI = "SPKI Pinning"
        const val DIRECT = "Direct HTTPS"

        /** Inline literal on the bootstrap action button. */
        const val RUN_BOOTSTRAP_BUTTON = "Run Bootstrap Now"

        const val DANE_URL = "https://dane.uitest.invalid"
        const val DANE_DNS = "9.9.9.9:53"
        const val NOISE_ADDR = "noise.uitest.invalid:8445"
        const val SPKI_URL = "https://spki.uitest.invalid"
        const val DIRECT_URL = "https://direct.uitest.invalid"

        /** 64 hex characters, the format both the Noise key and SPKI pin want. */
        const val HEX_KEY = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    }
}
