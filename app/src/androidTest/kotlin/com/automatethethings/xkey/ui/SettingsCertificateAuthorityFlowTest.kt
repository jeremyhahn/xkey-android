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
import com.automatethethings.xkey.ca.AndroidCA
import com.automatethethings.xkey.settings.CertificateAuthoritySource
import com.automatethethings.xkey.settings.TrustedComputingSettingsData
import com.automatethethings.xkey.settings.TrustedComputingSettingsRepository
import com.automatethethings.xkey.ui.SettingsFlowSupport.assertEventuallyHides
import com.automatethethings.xkey.ui.SettingsFlowSupport.assertEventuallyShows
import com.automatethethings.xkey.ui.SettingsFlowSupport.awaitInitialized
import com.automatethethings.xkey.ui.SettingsFlowSupport.button
import com.automatethethings.xkey.ui.SettingsFlowSupport.clickView
import com.automatethethings.xkey.ui.SettingsFlowSupport.editTextWithHint
import com.automatethethings.xkey.ui.SettingsFlowSupport.radioOption
import com.automatethethings.xkey.ui.SettingsFlowSupport.setFieldAndBlur
import com.automatethethings.xkey.ui.SettingsFlowSupport.shows
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * End-to-end tests for the Certificate Authority section of [SettingsActivity].
 *
 * The three-way "Certificate Authority" choice is what the rest of the section
 * hangs off, and each option reveals only what it needs: xKMS shows the server
 * endpoint, "This device" shows the certificate subject and the generation
 * controls, and "No certificate authority" shows neither. Each test asserts the
 * persisted `caSource` as well as which container the screen swapped in.
 *
 * Nothing here generates or resets a CA: both are destructive to the Android
 * Keystore aliases every other suite shares. The status lines and the enabled
 * state of the generate buttons are asserted against whatever [AndroidCA]
 * currently holds, and the reset dialog is only opened and cancelled.
 *
 * Trusted-computing settings are snapshotted in @Before and restored in @After.
 */
@RunWith(AndroidJUnit4::class)
class SettingsCertificateAuthorityFlowTest {

    private lateinit var context: Context
    private lateinit var trustedComputingRepository: TrustedComputingSettingsRepository
    private lateinit var androidCA: AndroidCA

    private lateinit var originalTrustedComputing: TrustedComputingSettingsData

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        trustedComputingRepository = TrustedComputingSettingsRepository(context)
        androidCA = AndroidCA(context)
        runBlocking { originalTrustedComputing = trustedComputingRepository.getSettings() }
    }

    @After
    fun tearDown() {
        runBlocking { trustedComputingRepository.updateSettings(originalTrustedComputing) }
    }

    // ---------------------------------------------------------------
    // Who signs
    // ---------------------------------------------------------------

    @Test
    fun caSourceRadio_thisDevice_swapsTheEndpointForSubjectAndGeneration_andPersists() {
        seed(TrustedComputingSettingsData(caSource = CertificateAuthoritySource.XKMS))

        val scenario = ActivityScenario.launch(SettingsActivity::class.java)
        awaitInitialized(scenario)
        assertTrue(
            "The xkms endpoint field should be offered while xkms signs",
            shows(scenario, context.getString(R.string.settings_trusted_computing_ca_url))
        )
        assertFalse(
            "The certificate subject fields belong to this device signing",
            shows(scenario, context.getString(R.string.ca_subject_title))
        )

        clickView(scenario, "the This device authority option") {
            radioOption(it, context.getString(R.string.settings_ca_source_this_device))
        }

        awaitCondition("This device should be persisted as the authority") {
            current().caSource == CertificateAuthoritySource.THIS_DEVICE
        }
        assertEventuallyShows(scenario, context.getString(R.string.ca_subject_title))
        assertEventuallyShows(scenario, context.getString(R.string.ca_status_title))
        assertEventuallyHides(
            scenario,
            context.getString(R.string.settings_trusted_computing_ca_url)
        )
    }

    @Test
    fun caSourceRadio_xkms_swapsTheSubjectForTheEndpoint_andPersists() {
        seed(TrustedComputingSettingsData(caSource = CertificateAuthoritySource.THIS_DEVICE))

        val scenario = ActivityScenario.launch(SettingsActivity::class.java)
        awaitInitialized(scenario)
        assertTrue(
            "The subject fields should be showing while this device signs",
            shows(scenario, context.getString(R.string.ca_subject_title))
        )

        clickView(scenario, "the xKMS authority option") {
            radioOption(it, context.getString(R.string.settings_ca_source_xkms))
        }

        awaitCondition("xkms should be persisted as the authority") {
            current().caSource == CertificateAuthoritySource.XKMS
        }
        assertEventuallyShows(
            scenario,
            context.getString(R.string.settings_trusted_computing_ca_url)
        )
        assertEventuallyHides(scenario, context.getString(R.string.ca_subject_title))
        assertEventuallyHides(scenario, context.getString(R.string.ca_status_title))
    }

    /**
     * The option the old two-boolean model could not express at all: nothing
     * signs, so neither the endpoint nor this device's CA controls belong on
     * screen.
     */
    @Test
    fun caSourceRadio_none_hidesEveryAuthorityControl_andPersists() {
        seed(TrustedComputingSettingsData(caSource = CertificateAuthoritySource.THIS_DEVICE))

        val scenario = ActivityScenario.launch(SettingsActivity::class.java)
        awaitInitialized(scenario)

        clickView(scenario, "the No certificate authority option") {
            radioOption(it, context.getString(R.string.settings_ca_source_none))
        }

        awaitCondition("No authority should be persisted") {
            current().caSource == CertificateAuthoritySource.NONE
        }
        assertEventuallyHides(scenario, context.getString(R.string.ca_subject_title))
        assertEventuallyHides(scenario, context.getString(R.string.ca_status_title))
        assertEventuallyHides(
            scenario,
            context.getString(R.string.settings_trusted_computing_ca_url)
        )
    }

    @Test
    fun caSourceRadio_restoresTheXkmsSelection() {
        assertRestoredSelection(
            CertificateAuthoritySource.XKMS,
            R.string.settings_ca_source_xkms
        )
    }

    @Test
    fun caSourceRadio_restoresTheThisDeviceSelection() {
        assertRestoredSelection(
            CertificateAuthoritySource.THIS_DEVICE,
            R.string.settings_ca_source_this_device
        )
    }

    @Test
    fun caSourceRadio_restoresTheNoneSelection() {
        assertRestoredSelection(
            CertificateAuthoritySource.NONE,
            R.string.settings_ca_source_none
        )
    }

    // ---------------------------------------------------------------
    // Certificate subject
    // ---------------------------------------------------------------

    /**
     * The subject fields persist from an `OnFocusChangeListener` that writes
     * all six at once, so the whole subject is filled in and then blurred.
     */
    @Test
    fun certificateSubjectFields_persistOnFocusLoss() {
        seed(TrustedComputingSettingsData(caSource = CertificateAuthoritySource.THIS_DEVICE))

        val scenario = ActivityScenario.launch(SettingsActivity::class.java)
        awaitInitialized(scenario)

        setFieldAndBlur(scenario, "Organization", ORG) { subjectField(it, R.string.ca_subject_org, R.string.ca_subject_org_hint) }
        setFieldAndBlur(scenario, "Organizational Unit", OU) { subjectField(it, R.string.ca_subject_ou, R.string.ca_subject_ou_hint) }
        setFieldAndBlur(scenario, "Locality", LOCALITY) { subjectField(it, R.string.ca_subject_locality, R.string.ca_subject_locality_hint) }
        setFieldAndBlur(scenario, "Province", PROVINCE) { subjectField(it, R.string.ca_subject_province, R.string.ca_subject_province_hint) }
        setFieldAndBlur(scenario, "Country", COUNTRY) { subjectField(it, R.string.ca_subject_country, R.string.ca_subject_country_hint) }
        setFieldAndBlur(scenario, "Common Name", COMMON_NAME) { subjectField(it, R.string.ca_subject_cn, R.string.ca_subject_cn_hint) }

        awaitCondition("The whole certificate subject should be persisted") {
            val settings = current()
            settings.caSubjectOrganization == ORG &&
                settings.caSubjectOU == OU &&
                settings.caSubjectLocality == LOCALITY &&
                settings.caSubjectProvince == PROVINCE &&
                settings.caSubjectCountry == COUNTRY &&
                settings.caSubjectCommonName == COMMON_NAME
        }
    }

    @Test
    fun certificateSubjectFields_restorePersistedValues() {
        seed(
            TrustedComputingSettingsData(
                caSource = CertificateAuthoritySource.THIS_DEVICE,
                caSubjectOrganization = ORG,
                caSubjectCommonName = COMMON_NAME
            )
        )

        val scenario = ActivityScenario.launch(SettingsActivity::class.java)
        awaitInitialized(scenario)

        val values = withActivity(scenario) { activity ->
            val root = activity.window.decorView
            Pair(
                subjectField(root, R.string.ca_subject_org, R.string.ca_subject_org_hint)
                    ?.text?.toString(),
                subjectField(root, R.string.ca_subject_cn, R.string.ca_subject_cn_hint)
                    ?.text?.toString()
            )
        }
        assertEquals(Pair(ORG, COMMON_NAME), values)
    }

    // ---------------------------------------------------------------
    // Platform CA selection
    // ---------------------------------------------------------------

    @Test
    fun platformCaRadio_root_persistsTheRootAlias() {
        seed(
            TrustedComputingSettingsData(
                caSource = CertificateAuthoritySource.THIS_DEVICE,
                platformCAAlias = AndroidCA.INTERMEDIATE_CA_ALIAS
            )
        )

        val scenario = ActivityScenario.launch(SettingsActivity::class.java)
        awaitInitialized(scenario)

        clickView(scenario, "the Root CA platform option") {
            radioOption(it, context.getString(R.string.ca_platform_root))
        }

        awaitCondition("The root alias should be persisted as the platform CA") {
            current().platformCAAlias == AndroidCA.ROOT_CA_ALIAS
        }
    }

    @Test
    fun platformCaRadio_intermediate_persistsTheIntermediateAlias() {
        seed(
            TrustedComputingSettingsData(
                caSource = CertificateAuthoritySource.THIS_DEVICE,
                platformCAAlias = AndroidCA.ROOT_CA_ALIAS
            )
        )

        val scenario = ActivityScenario.launch(SettingsActivity::class.java)
        awaitInitialized(scenario)

        clickView(scenario, "the Intermediate CA platform option") {
            radioOption(it, context.getString(R.string.ca_platform_intermediate))
        }

        awaitCondition("The intermediate alias should be persisted as the platform CA") {
            current().platformCAAlias == AndroidCA.INTERMEDIATE_CA_ALIAS
        }
    }

    @Test
    fun platformCaRadio_restoresThePersistedAlias() {
        seed(
            TrustedComputingSettingsData(
                caSource = CertificateAuthoritySource.THIS_DEVICE,
                platformCAAlias = AndroidCA.ROOT_CA_ALIAS
            )
        )

        val scenario = ActivityScenario.launch(SettingsActivity::class.java)
        awaitInitialized(scenario)

        val checked = withActivity(scenario) { activity ->
            radioOption(
                activity.window.decorView,
                context.getString(R.string.ca_platform_root)
            )?.isChecked
        }
        assertEquals(true, checked)
    }

    // ---------------------------------------------------------------
    // CA status
    // ---------------------------------------------------------------

    /**
     * The status lines are rendered from whatever the Keystore currently holds,
     * so the expectation is derived from [AndroidCA] rather than assumed: other
     * suites may or may not have left a CA behind.
     */
    @Test
    fun caStatusLines_matchTheKeystoreState() {
        seed(TrustedComputingSettingsData(caSource = CertificateAuthoritySource.THIS_DEVICE))

        val scenario = ActivityScenario.launch(SettingsActivity::class.java)
        awaitInitialized(scenario)

        assertEventuallyShows(scenario, "Root CA: ${expectedStatus(androidCA.getRootCACertificateInfo()?.isExpired)}")
        assertEventuallyShows(
            scenario,
            "Intermediate CA: ${expectedStatus(androidCA.getIntermediateCACertificateInfo()?.isExpired)}"
        )
    }

    /**
     * The generate buttons encode the CA hierarchy: the root can only be made
     * once, and the intermediate needs a root first.
     */
    @Test
    fun generateButtons_reflectTheCaHierarchy() {
        seed(TrustedComputingSettingsData(caSource = CertificateAuthoritySource.THIS_DEVICE))

        val scenario = ActivityScenario.launch(SettingsActivity::class.java)
        awaitInitialized(scenario)

        val hasRoot = androidCA.getRootCACertificateInfo() != null
        val hasIntermediate = androidCA.getIntermediateCACertificateInfo() != null

        val enabled = withActivity(scenario) { activity ->
            val root = activity.window.decorView
            Pair(
                button(root, context.getString(R.string.ca_generate_root))?.isEnabled,
                button(root, context.getString(R.string.ca_generate_intermediate))?.isEnabled
            )
        }
        assertEquals(
            "Generate Root CA should only be offered when there is no root yet",
            !hasRoot,
            enabled.first
        )
        assertEquals(
            "Generate Intermediate CA needs a root and no intermediate",
            hasRoot && !hasIntermediate,
            enabled.second
        )
    }

    // ---------------------------------------------------------------
    // Reset CA
    // ---------------------------------------------------------------

    /**
     * Reset is destructive and irreversible, so it must confirm first. Only the
     * cancel path is driven: confirming would delete Keystore aliases the rest
     * of the instrumented suite depends on.
     */
    @Test
    fun resetCa_asksForConfirmation_andCancellingKeepsTheCa() {
        seed(TrustedComputingSettingsData(caSource = CertificateAuthoritySource.THIS_DEVICE))
        val rootBefore = androidCA.isRootCAGenerated()

        val scenario = ActivityScenario.launch(SettingsActivity::class.java)
        awaitInitialized(scenario)

        clickView(scenario, "the Reset CA button") {
            button(it, context.getString(R.string.ca_reset))
        }

        onView(withText(R.string.ca_reset_title)).inRoot(isDialog())
            .check(matches(isDisplayed()))
        onView(withText(R.string.ca_reset_message)).inRoot(isDialog())
            .check(matches(isDisplayed()))

        onView(withText(R.string.button_cancel)).inRoot(isDialog()).perform(click())

        assertEquals(
            "Cancelling the reset must leave the CA alone",
            rootBefore,
            androidCA.isRootCAGenerated()
        )
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    /**
     * Launches the screen with [source] persisted and asserts that the option
     * labelled [labelRes] came back checked.
     *
     * The radio group is built with "No certificate authority" pre-checked, so
     * a screen that failed to apply the stored choice would still look
     * plausible; asserting the specific option is what catches that.
     */
    private fun assertRestoredSelection(source: CertificateAuthoritySource, labelRes: Int) {
        seed(TrustedComputingSettingsData(caSource = source))

        val scenario = ActivityScenario.launch(SettingsActivity::class.java)
        awaitInitialized(scenario)

        val checked = withActivity(scenario) { activity ->
            radioOption(activity.window.decorView, context.getString(labelRes))?.isChecked
        }
        assertEquals("The $source option should come back checked", true, checked)
    }

    /**
     * CA subject fields render as a single hint of the form
     * `"<label> (<hint>)"`, which is what makes them individually addressable.
     */
    private fun subjectField(root: android.view.View, labelRes: Int, hintRes: Int) =
        editTextWithHint(root, "${context.getString(labelRes)} (${context.getString(hintRes)})")

    private fun expectedStatus(isExpired: Boolean?): String = when (isExpired) {
        null -> context.getString(R.string.ca_status_not_generated)
        true -> context.getString(R.string.ca_status_expired)
        false -> context.getString(R.string.ca_status_active)
    }

    private fun seed(settings: TrustedComputingSettingsData) {
        runBlocking { trustedComputingRepository.updateSettings(settings) }
    }

    private fun current(): TrustedComputingSettingsData =
        runBlocking { trustedComputingRepository.getSettings() }

    private companion object {
        const val ORG = "UI Test Org"
        const val OU = "UI Test OU"
        const val LOCALITY = "UI Test City"
        const val PROVINCE = "UI Test State"
        const val COUNTRY = "US"
        const val COMMON_NAME = "UI Test Root CA"
    }
}
