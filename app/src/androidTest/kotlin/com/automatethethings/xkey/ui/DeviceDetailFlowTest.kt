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
import android.content.Intent
import android.view.ViewGroup
import android.widget.CompoundButton
import android.widget.ImageView
import android.widget.Spinner
import android.widget.TextView
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.RootMatchers.isDialog
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.withId
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.automatethethings.xkey.settings.PairedDeviceRepository
import org.junit.After
import org.junit.AfterClass
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import java.security.MessageDigest
import java.util.Date

/**
 * End-to-end flow tests for [DeviceDetailActivity].
 *
 * `DeviceDetailActivityUiTest` covers the two easy states of each card — an
 * unattested device with no IDevID, and a freshly attested one with a valid
 * certificate. This suite drives what is left: the expired variants of both
 * badges, the countdown formats the grace period produces, the connection
 * card's two branches, the grace-period spinner (which persists through the same
 * listener as the switches), the fingerprint copy action, and the re-attestation
 * dialog.
 *
 * All state is expressed through [PairedDeviceRepository] rather than by writing
 * the encrypted preference file directly:
 * - an *expired IDevID* is one whose `notAfter` is in the past;
 * - an *expired attestation* is one whose grace period has elapsed, which is
 *   reachable by storing a grace period of zero minutes (the field is a plain
 *   `Int`; only the spinner is limited to the six offered presets).
 *
 * A single device is paired per test and removed in @After, so devices the user
 * actually paired are untouched.
 */
@RunWith(AndroidJUnit4::class)
class DeviceDetailFlowTest {

    private lateinit var repository: PairedDeviceRepository

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        repository = PairedDeviceRepository(context)
        repository.removeDevice(DEVICE_KEY_HEX)
        repository.addDevice(publicKeyHex = DEVICE_KEY_HEX, deviceName = DEVICE_NAME)
    }

    @After
    fun tearDown() {
        repository.removeDevice(DEVICE_KEY_HEX)
    }

    // -----------------------------------------------------------------
    // Identity card
    // -----------------------------------------------------------------

    /** A certificate whose validity window has closed is badged EXPIRED. */
    @Test
    fun identityCard_reportsExpiredForAnOutdatedCertificate() {
        storeIdevid(notAfter = System.currentTimeMillis() - ONE_DAY_MS)
        val scenario = launch()

        assertShownTextInTree(scenario, string(R.string.device_idevid_expired))
        assertEquals(
            TRUST_LEVEL.uppercase(),
            valueForLabel(scenario, string(R.string.device_idevid_trust_level))
        )
    }

    /** A certificate still inside its window is badged VERIFIED, not EXPIRED. */
    @Test
    fun identityCard_reportsVerifiedForACurrentCertificate() {
        storeIdevid(notAfter = System.currentTimeMillis() + 365L * ONE_DAY_MS)
        val scenario = launch()

        assertShownTextInTree(scenario, string(R.string.device_idevid_verified))
        assertTextNotInTree(scenario, string(R.string.device_idevid_expired))
    }

    /** The fingerprint row shows a truncated SHA-256 of the certificate DER. */
    @Test
    fun identityCard_showsTheTruncatedCertificateFingerprint() {
        storeIdevid(notAfter = System.currentTimeMillis() + 365L * ONE_DAY_MS)
        val scenario = launch()

        assertEquals(
            expectedFingerprint(certificateDer),
            valueForLabel(scenario, string(R.string.device_idevid_fingerprint))
        )
    }

    /** The copy affordance next to the fingerprint reports what it did. */
    @Test
    fun copyingTheFingerprint_confirmsWithASnackbar() {
        storeIdevid(notAfter = System.currentTimeMillis() + 365L * ONE_DAY_MS)
        val scenario = launch()

        clickFingerprintCopyButton(scenario)

        assertShownTextInTree(scenario, string(R.string.device_fingerprint_copied))
    }

    /** Without a certificate every identity field falls back to "N/A". */
    @Test
    fun identityCard_fallsBackToNotAvailableWithoutACertificate() {
        val scenario = launch()
        val notAvailable = string(R.string.device_na)

        assertEquals(notAvailable, valueForLabel(scenario, string(R.string.device_idevid_subject)))
        assertEquals(notAvailable, valueForLabel(scenario, string(R.string.device_idevid_expires)))
        assertEquals(
            notAvailable,
            valueForLabel(scenario, string(R.string.device_idevid_trust_level))
        )
        assertEquals(
            notAvailable,
            valueForLabel(scenario, string(R.string.device_idevid_fingerprint))
        )
    }

    // -----------------------------------------------------------------
    // Attestation card
    // -----------------------------------------------------------------

    /**
     * Once the grace period has elapsed the attestation is stale, whatever the
     * device reported when it was last attested.
     */
    @Test
    fun attestationCard_reportsExpiredOnceTheGracePeriodHasElapsed() {
        storeAttestation()
        storeGracePeriod(0)
        val scenario = launch()

        assertShownTextInTree(scenario, string(R.string.device_attest_status_expired))
        assertEquals(
            string(R.string.device_attest_status_expired),
            valueForLabel(scenario, string(R.string.device_time_remaining))
        )
    }

    /** Inside a short grace period the remaining time is shown as minutes. */
    @Test
    fun attestationCard_countsDownInMinutesForAShortGracePeriod() {
        storeGracePeriod(5)
        storeAttestation()
        val scenario = launch()

        val remaining = valueForLabel(scenario, string(R.string.device_time_remaining))
        assertTrue(
            "A 5 minute grace period should count down as minutes and seconds, was '$remaining'",
            Regex("""\d+m \d+s""").matches(remaining)
        )
    }

    /** A grace period over an hour switches the countdown to hours. */
    @Test
    fun attestationCard_countsDownInHoursForALongGracePeriod() {
        storeGracePeriod(240)
        storeAttestation()
        val scenario = launch()

        val remaining = valueForLabel(scenario, string(R.string.device_time_remaining))
        assertTrue(
            "A 4 hour grace period should count down as hours, was '$remaining'",
            Regex("""\d+h \d+m \d+s""").matches(remaining)
        )
    }

    /** A device that has never attested has no last-attested timestamp. */
    @Test
    fun attestationCard_reportsNeverAttested() {
        val scenario = launch()

        assertEquals(
            string(R.string.key_detail_never),
            valueForLabel(scenario, string(R.string.device_last_attested))
        )
        assertEquals(
            string(R.string.device_na),
            valueForLabel(scenario, string(R.string.device_time_remaining))
        )
    }

    /** A just-attested device reports its attestation as recent. */
    @Test
    fun attestationCard_reportsARecentAttestationAsJustNow() {
        storeAttestation()
        val scenario = launch()

        assertEquals(
            string(R.string.device_just_now),
            valueForLabel(scenario, string(R.string.device_last_attested))
        )
    }

    // -----------------------------------------------------------------
    // Connection card
    // -----------------------------------------------------------------

    /** No GATT session is established under test, so the device reads as down. */
    @Test
    fun connectionCard_reportsDisconnected() {
        val scenario = launch()

        assertShownTextInTree(scenario, string(R.string.device_disconnected))
    }

    @Test
    fun connectionCard_reportsNeverConnected() {
        val scenario = launch()

        assertEquals(
            string(R.string.device_never_connected),
            valueForLabel(scenario, string(R.string.device_last_connected))
        )
    }

    /** A connection recorded moments ago is rendered as a relative time. */
    @Test
    fun connectionCard_reportsARecentConnectionAsJustNow() {
        repository.recordConnection(DEVICE_KEY_HEX)
        val scenario = launch()

        assertEquals(
            string(R.string.device_just_now),
            valueForLabel(scenario, string(R.string.device_last_connected))
        )
    }

    // -----------------------------------------------------------------
    // Settings
    // -----------------------------------------------------------------

    /**
     * Choosing a different preset writes through the same listener as the
     * switches, so a regression there silently drops the user's choice.
     */
    @Test
    fun changingTheGracePeriod_persistsToTheRepository() {
        storeGracePeriod(5)
        val scenario = launch()

        selectGracePeriod(scenario, ONE_HOUR_OPTION_INDEX)

        awaitCondition("The chosen grace period should be persisted") {
            repository.getDevice(DEVICE_KEY_HEX)?.attestationGracePeriodMinutes == 60
        }
    }

    @Test
    fun togglingRequireAttestationForKeyAttestation_persistsToTheRepository() {
        val scenario = launch()
        val before = repository.getDevice(DEVICE_KEY_HEX)!!.requireAttestationForKeyAttestation

        toggleSwitch(scenario, R.string.device_require_attest_key_attest)

        assertEquals(
            "Toggling the switch must persist the inverted setting",
            !before,
            repository.getDevice(DEVICE_KEY_HEX)!!.requireAttestationForKeyAttestation
        )
    }

    /** Toggling one policy must not disturb the other. */
    @Test
    fun togglingOnePolicy_leavesTheOtherUntouched() {
        repository.updateDeviceSettings(
            publicKeyHex = DEVICE_KEY_HEX,
            requireAttestationForKeyUse = true,
            requireAttestationForKeyAttestation = true,
            attestationGracePeriodMinutes = 5
        )
        val scenario = launch()

        toggleSwitch(scenario, R.string.device_require_attest_key_use)

        val stored = repository.getDevice(DEVICE_KEY_HEX)!!
        assertFalse("The toggled policy should be off", stored.requireAttestationForKeyUse)
        assertTrue(
            "The untouched policy should stay on",
            stored.requireAttestationForKeyAttestation
        )
    }

    // -----------------------------------------------------------------
    // Re-attestation
    // -----------------------------------------------------------------

    /**
     * With no BLE address stored and no desktop session, re-attestation cannot
     * proceed on its own, so the screen explains what to do instead. Both
     * branches of that fallback (service bound or not) raise the same titled
     * dialog, which is what this asserts.
     */
    @Test
    fun reattest_explainsHowToCompleteItWhenNoSessionIsAvailable() {
        val scenario = launch()

        clickTextInTree(scenario, string(R.string.device_reattest_button))

        onView(withText(R.string.device_reattest_title))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
        onView(withId(android.R.id.button1)).inRoot(isDialog()).perform(click())
        waitForIdle()
    }

    // -----------------------------------------------------------------
    // Helpers: seeding
    // -----------------------------------------------------------------

    private fun storeIdevid(notAfter: Long) {
        repository.updateDeviceIDevID(
            publicKeyHex = DEVICE_KEY_HEX,
            certificateDER = certificateDer,
            certificateChain = null,
            trustLevel = TRUST_LEVEL,
            subjectDN = IDEVID_SUBJECT_DN,
            notAfter = notAfter
        )
    }

    private fun storeAttestation() {
        repository.updateDeviceAttestation(
            publicKeyHex = DEVICE_KEY_HEX,
            bootHashHex = "00".repeat(32),
            securityLevel = "tee",
            bootStateVerified = true,
            deviceFingerprint = "11".repeat(32)
        )
    }

    /**
     * Stores a grace period directly.
     *
     * `attestationGracePeriodMinutes` is a plain `Int` on the repository; only
     * the spinner restricts it to six presets, so zero is a legitimate stored
     * value and the only way to reach the expired-attestation rendering without
     * waiting out a real grace period.
     */
    private fun storeGracePeriod(minutes: Int) {
        val device = repository.getDevice(DEVICE_KEY_HEX)!!
        repository.updateDeviceSettings(
            publicKeyHex = DEVICE_KEY_HEX,
            requireAttestationForKeyUse = device.requireAttestationForKeyUse,
            requireAttestationForKeyAttestation = device.requireAttestationForKeyAttestation,
            attestationGracePeriodMinutes = minutes
        )
    }

    // -----------------------------------------------------------------
    // Helpers: the screen
    // -----------------------------------------------------------------

    private fun launch(): ActivityScenario<DeviceDetailActivity> {
        val intent = Intent(
            ApplicationProvider.getApplicationContext(),
            DeviceDetailActivity::class.java
        ).apply {
            putExtra(DeviceDetailActivity.EXTRA_PUBLIC_KEY_HEX, DEVICE_KEY_HEX)
        }
        val scenario = ActivityScenario.launch<DeviceDetailActivity>(intent)
        assertShownTextInTree(scenario, DEVICE_NAME)
        return scenario
    }

    private fun string(resId: Int): String =
        ApplicationProvider.getApplicationContext<Context>().getString(resId)

    /**
     * Reads the value rendered beside [label].
     *
     * Info rows are built as `[label][value]` (the fingerprint row adds a copy
     * button), and none of the views carry ids, so the value is located by
     * walking up from the label to its row and taking the other TextView.
     */
    private fun valueForLabel(
        scenario: ActivityScenario<DeviceDetailActivity>,
        label: String
    ): String = withActivity(scenario) { activity ->
        val labelView = collectViews(activity.window.decorView) {
            it is TextView && it.text?.toString() == label
        }.firstOrNull() ?: throw AssertionError("No row labelled '$label'")

        val row = labelView.parent as? ViewGroup
            ?: throw AssertionError("Row for '$label' has no parent")

        collectViews(row) { it is TextView && it !== labelView }
            .map { (it as TextView).text?.toString().orEmpty() }
            .firstOrNull() ?: throw AssertionError("Row '$label' renders no value")
    }

    private fun clickFingerprintCopyButton(scenario: ActivityScenario<DeviceDetailActivity>) {
        scenario.onActivity { activity ->
            val label = activity.getString(R.string.device_idevid_fingerprint)
            val labelView = collectViews(activity.window.decorView) {
                it is TextView && it.text?.toString() == label
            }.firstOrNull() ?: throw AssertionError("No fingerprint row")
            val row = labelView.parent as ViewGroup
            val copyButton = collectViews(row) { it is ImageView }.firstOrNull()
                ?: throw AssertionError("The fingerprint row has no copy button")
            copyButton.performClick()
        }
        waitForIdle()
    }

    /**
     * The settings card holds the screen's only [Spinner].
     *
     * Resolved outside `onActivity` by the callers, because nesting a second
     * `onActivity` inside the first one would deadlock on the main thread.
     */
    private fun gracePeriodSpinner(scenario: ActivityScenario<DeviceDetailActivity>): Spinner =
        withActivity(scenario) { activity ->
            collectViews(activity.window.decorView) { it is Spinner }
                .firstOrNull() as? Spinner
                ?: throw AssertionError("The settings card has no grace period spinner")
        }

    private fun selectGracePeriod(
        scenario: ActivityScenario<DeviceDetailActivity>,
        index: Int
    ) {
        val spinner = gracePeriodSpinner(scenario)
        scenario.onActivity { spinner.setSelection(index) }
        waitForIdle()
    }

    private fun toggleSwitch(
        scenario: ActivityScenario<DeviceDetailActivity>,
        labelResId: Int
    ) {
        scenario.onActivity { activity ->
            val label = activity.getString(labelResId)
            val toggle = findTextViewContaining(activity.window.decorView, label)
                as? CompoundButton
                ?: throw AssertionError("No switch labelled '$label'")
            toggle.isChecked = !toggle.isChecked
        }
        waitForIdle()
    }

    private fun expectedFingerprint(der: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(der)
            .take(8)
            .joinToString(":") { "%02X".format(it) } + "..."

    companion object {
        private const val ONE_DAY_MS = 86_400_000L

        /** A 32-byte Noise static public key, distinct from every other suite's. */
        private const val DEVICE_KEY_HEX =
            "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"
        private const val DEVICE_NAME = "UI Flow Device Detail Laptop"

        private const val IDEVID_ALIAS = "xkey_uitest_devicedetail_flow_idevid"
        private const val IDEVID_CN = "xKey UI Flow Device"
        private const val IDEVID_SUBJECT_DN = "CN=xKey UI Flow Device,O=Automate The Things"
        private const val TRUST_LEVEL = "external-ca"

        /** Index of "1 hour" in `DeviceDetailActivity.GRACE_PERIOD_OPTIONS`. */
        private const val ONE_HOUR_OPTION_INDEX = 3

        /** DER of a real certificate, generated once for the whole class. */
        private lateinit var certificateDer: ByteArray

        @BeforeClass
        @JvmStatic
        fun generateCertificate() {
            certificateDer = TestCertificates.selfSigned(
                alias = IDEVID_ALIAS,
                commonName = IDEVID_CN,
                notAfter = Date(System.currentTimeMillis() + 365L * ONE_DAY_MS)
            ).encoded
        }

        @AfterClass
        @JvmStatic
        fun removeCertificate() {
            TestCertificates.deleteAlias(IDEVID_ALIAS)
        }
    }
}
