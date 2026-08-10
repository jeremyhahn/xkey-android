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

import android.content.Context
import android.content.Intent
import android.widget.CompoundButton
import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.Espresso.pressBackUnconditionally
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.RootMatchers.isDialog
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.automatethethings.xkey.R
import com.automatethethings.xkey.settings.PairedDeviceRepository
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.Date

/**
 * Instrumented UI tests for [DeviceDetailActivity].
 *
 * DeviceDetailActivity builds its UI programmatically, requires
 * [DeviceDetailActivity.EXTRA_PUBLIC_KEY_HEX], and reloads from
 * [PairedDeviceRepository] on every resume -- finishing immediately when the
 * extra is missing or the device is unknown. Two devices are seeded: a bare one
 * with no attestation or IDevID, and an enriched one carrying a verified IDevID
 * and a fresh attestation. Between them they cover both branches of the identity
 * and attestation cards. Only these two devices are added and removed, so any
 * device the user already paired is left alone.
 *
 * Tests cover:
 * - Launch behavior: no extra, and an unknown public key hex
 * - Toolbar, hero header and every section card
 * - Identity card: not-verified vs verified, subject DN and trust level
 * - Attestation card: never vs current
 * - Settings switches reflecting and persisting repository state
 * - Unpair: cancel keeps the device, confirm removes it and closes the screen
 * - Back navigation finishing the activity
 */
@RunWith(AndroidJUnit4::class)
class DeviceDetailActivityUiTest {

    private lateinit var repository: PairedDeviceRepository

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        repository = PairedDeviceRepository(context)

        repository.removeDevice(PLAIN_KEY_HEX)
        repository.removeDevice(VERIFIED_KEY_HEX)

        repository.addDevice(publicKeyHex = PLAIN_KEY_HEX, deviceName = PLAIN_NAME)
        repository.addDevice(publicKeyHex = VERIFIED_KEY_HEX, deviceName = VERIFIED_NAME)

        repository.updateDeviceAttestation(
            publicKeyHex = VERIFIED_KEY_HEX,
            bootHashHex = "00".repeat(32),
            securityLevel = "strongbox",
            bootStateVerified = true,
            deviceFingerprint = "44".repeat(32)
        )
        val notAfter = System.currentTimeMillis() + 365L * TestCertificates.ONE_DAY_MS
        repository.updateDeviceIDevID(
            publicKeyHex = VERIFIED_KEY_HEX,
            certificateDER = TestCertificates
                .selfSigned(IDEVID_ALIAS, IDEVID_CN, notAfter = Date(notAfter))
                .encoded,
            certificateChain = null,
            trustLevel = TRUST_LEVEL,
            subjectDN = IDEVID_SUBJECT_DN,
            notAfter = notAfter
        )
    }

    @After
    fun tearDown() {
        repository.removeDevice(PLAIN_KEY_HEX)
        repository.removeDevice(VERIFIED_KEY_HEX)
        TestCertificates.deleteAlias(IDEVID_ALIAS)
    }

    // -----------------------------------------------------------------
    // Launch Behavior
    // -----------------------------------------------------------------

    /**
     * When launched without [DeviceDetailActivity.EXTRA_PUBLIC_KEY_HEX], the
     * activity calls finish() synchronously in onCreate and reaches DESTROYED.
     */
    @Test
    fun activity_finishesWithoutPublicKeyHex() {
        val intent = Intent(
            ApplicationProvider.getApplicationContext(),
            DeviceDetailActivity::class.java
        )
        val scenario = ActivityScenario.launch<DeviceDetailActivity>(intent)

        assertTrue(
            "Activity should finish when launched without EXTRA_PUBLIC_KEY_HEX",
            scenario.state == Lifecycle.State.DESTROYED
        )
    }

    /** onResume finishes the screen when the repository has no such device. */
    @Test
    fun activity_finishesForAnUnknownPublicKeyHex() {
        val scenario = launch("deadbeef".repeat(8))

        assertActivityDestroyed(scenario)
    }

    // -----------------------------------------------------------------
    // Toolbar + Hero
    // -----------------------------------------------------------------

    @Test
    fun toolbar_showsDeviceDetailTitle() {
        val scenario = launch(PLAIN_KEY_HEX)

        assertShownTextInTree(scenario, "Device Details")
    }

    @Test
    fun heroHeader_showsDeviceName() {
        val scenario = launch(PLAIN_KEY_HEX)

        assertShownTextInTree(scenario, PLAIN_NAME)
    }

    // -----------------------------------------------------------------
    // Section Cards
    // -----------------------------------------------------------------

    @Test
    fun allSectionCards_areBuilt() {
        val scenario = launch(PLAIN_KEY_HEX)

        assertTextInTree(scenario, withString(scenario, R.string.device_section_connection))
        assertTextInTree(scenario, withString(scenario, R.string.device_section_idevid))
        assertTextInTree(scenario, withString(scenario, R.string.device_section_attestation))
        assertTextInTree(scenario, withString(scenario, R.string.device_section_settings))
        assertTextInTree(scenario, withString(scenario, R.string.device_section_danger_zone))
    }

    @Test
    fun dangerZone_offersTheUnpairAction() {
        val scenario = launch(PLAIN_KEY_HEX)

        assertTextInTree(scenario, withString(scenario, R.string.device_unpair_button))
    }

    // -----------------------------------------------------------------
    // Identity card
    // -----------------------------------------------------------------

    @Test
    fun identityCard_reportsNotVerifiedForADeviceWithoutAnIDevID() {
        val scenario = launch(PLAIN_KEY_HEX)

        assertTextInTree(scenario, withString(scenario, R.string.device_idevid_not_verified))
    }

    @Test
    fun identityCard_reportsVerifiedWithSubjectAndTrustLevel() {
        val scenario = launch(VERIFIED_KEY_HEX)
        assertShownTextInTree(scenario, VERIFIED_NAME)

        assertTextInTree(scenario, withString(scenario, R.string.device_idevid_verified))
        assertTextInTree(scenario, IDEVID_SUBJECT_DN)
        assertTextInTree(scenario, TRUST_LEVEL.uppercase())
    }

    // -----------------------------------------------------------------
    // Attestation card
    // -----------------------------------------------------------------

    @Test
    fun attestationCard_reportsNeverForANewlyPairedDevice() {
        val scenario = launch(PLAIN_KEY_HEX)

        assertTextInTree(scenario, withString(scenario, R.string.device_attest_status_never))
    }

    @Test
    fun attestationCard_reportsCurrentWithinTheGracePeriod() {
        val scenario = launch(VERIFIED_KEY_HEX)
        assertShownTextInTree(scenario, VERIFIED_NAME)

        assertTextInTree(scenario, withString(scenario, R.string.device_attest_status_current))
    }

    // -----------------------------------------------------------------
    // Settings
    // -----------------------------------------------------------------

    @Test
    fun settingsSwitches_reflectStoredDeviceSettings() {
        repository.updateDeviceSettings(
            publicKeyHex = PLAIN_KEY_HEX,
            requireAttestationForKeyUse = true,
            requireAttestationForKeyAttestation = false,
            attestationGracePeriodMinutes = 5
        )

        val scenario = launch(PLAIN_KEY_HEX)
        assertShownTextInTree(scenario, PLAIN_NAME)

        assertTrue(
            "Key-use switch should mirror the stored setting",
            switchChecked(scenario, R.string.device_require_attest_key_use)
        )
        assertFalse(
            "Key-attestation switch should mirror the stored setting",
            switchChecked(scenario, R.string.device_require_attest_key_attest)
        )
    }

    @Test
    fun togglingRequireAttestationForKeyUse_persistsToTheRepository() {
        val scenario = launch(PLAIN_KEY_HEX)
        assertShownTextInTree(scenario, PLAIN_NAME)
        val before = repository.getDevice(PLAIN_KEY_HEX)!!.requireAttestationForKeyUse

        toggleSwitch(scenario, R.string.device_require_attest_key_use)

        assertEquals(
            "Toggling the switch must persist the inverted setting",
            !before,
            repository.getDevice(PLAIN_KEY_HEX)!!.requireAttestationForKeyUse
        )
    }

    // -----------------------------------------------------------------
    // Unpair
    // -----------------------------------------------------------------

    @Test
    fun unpairCancelled_keepsTheDevicePaired() {
        val scenario = launch(PLAIN_KEY_HEX)
        assertShownTextInTree(scenario, PLAIN_NAME)

        clickTextInTree(scenario, withString(scenario, R.string.device_unpair_button))

        onView(withText(withString(scenario, R.string.device_unpair_message, PLAIN_NAME)))
            .inRoot(isDialog())
            .check(matches(isDisplayed()))
        onView(withText(R.string.button_cancel)).inRoot(isDialog()).perform(click())

        assertNotNull(
            "Cancelling the unpair dialog must keep the device",
            repository.getDevice(PLAIN_KEY_HEX)
        )
    }

    @Test
    fun unpairConfirmed_removesTheDeviceAndClosesTheScreen() {
        val scenario = launch(PLAIN_KEY_HEX)
        assertShownTextInTree(scenario, PLAIN_NAME)

        clickTextInTree(scenario, withString(scenario, R.string.device_unpair_button))
        onView(withText(R.string.device_unpair_confirm)).inRoot(isDialog()).perform(click())

        assertNull(
            "Confirming the unpair dialog must remove the device",
            repository.getDevice(PLAIN_KEY_HEX)
        )
        assertActivityDestroyed(scenario)
    }

    // -----------------------------------------------------------------
    // Back Navigation
    // -----------------------------------------------------------------

    /**
     * Pressing back finishes the activity and transitions to DESTROYED.
     */
    @Test
    fun backNavigation_finishesActivity() {
        val scenario = launch(PLAIN_KEY_HEX)
        assertShownTextInTree(scenario, PLAIN_NAME)

        // pressBack() throws NoActivityResumedException when back closes the
        // last activity in the task, which is exactly what we assert here.
        pressBackUnconditionally()

        assertActivityDestroyed(scenario)
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private fun launch(publicKeyHex: String): ActivityScenario<DeviceDetailActivity> {
        val intent = Intent(
            ApplicationProvider.getApplicationContext(),
            DeviceDetailActivity::class.java
        ).apply {
            putExtra(DeviceDetailActivity.EXTRA_PUBLIC_KEY_HEX, publicKeyHex)
        }
        return ActivityScenario.launch(intent)
    }

    private fun withString(
        scenario: ActivityScenario<DeviceDetailActivity>,
        resId: Int,
        vararg args: Any
    ): String = withActivity(scenario) {
        if (args.isEmpty()) it.getString(resId) else it.getString(resId, *args)
    }

    private fun switchChecked(
        scenario: ActivityScenario<DeviceDetailActivity>,
        labelResId: Int
    ): Boolean = withActivity(scenario) { activity ->
        val label = activity.getString(labelResId)
        val view = findTextViewContaining(activity.window.decorView, label)
        (view as? CompoundButton)?.isChecked
            ?: throw AssertionError("No switch labelled '$label'")
    }

    private fun toggleSwitch(
        scenario: ActivityScenario<DeviceDetailActivity>,
        labelResId: Int
    ) {
        scenario.onActivity { activity ->
            val label = activity.getString(labelResId)
            val view = findTextViewContaining(activity.window.decorView, label)
                as? CompoundButton
                ?: throw AssertionError("No switch labelled '$label'")
            view.isChecked = !view.isChecked
        }
        InstrumentationRegistry.getInstrumentation().waitForIdleSync()
    }

    private companion object {
        // 32-byte Noise static public keys (hex), representative of paired peers.
        const val PLAIN_KEY_HEX =
            "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
        const val VERIFIED_KEY_HEX =
            "99887766554433221100ffeeddccbbaa99887766554433221100ffeeddccbbaa"
        const val PLAIN_NAME = "UI Test Laptop"
        const val VERIFIED_NAME = "UI Test Verified Laptop"
        const val IDEVID_ALIAS = "xkey_uitest_devicedetail_idevid"
        const val IDEVID_CN = "xKey UI Test Device"
        const val IDEVID_SUBJECT_DN = "CN=xKey UI Test Device,O=Automate The Things"
        const val TRUST_LEVEL = "android-ca"
    }
}
