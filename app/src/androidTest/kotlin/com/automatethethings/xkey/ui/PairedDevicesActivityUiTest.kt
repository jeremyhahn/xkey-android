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

import android.app.Activity
import android.app.Instrumentation
import android.content.Context
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.espresso.Espresso.pressBackUnconditionally
import androidx.test.espresso.intent.Intents
import androidx.test.espresso.intent.Intents.intended
import androidx.test.espresso.intent.Intents.intending
import androidx.test.espresso.intent.matcher.IntentMatchers.hasComponent
import androidx.test.espresso.intent.matcher.IntentMatchers.hasExtra
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.automatethethings.xkey.settings.PairedDeviceRepository
import org.hamcrest.Matchers.allOf
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.Date

/**
 * Instrumented UI tests for [PairedDevicesActivity].
 *
 * The screen reads [PairedDeviceRepository] in onResume and renders either a
 * device list or an empty state. These tests add two devices with deliberately
 * different histories -- one freshly paired and never connected, one that has
 * connected, attested and presents a valid IDevID -- so that each badge branch
 * in the adapter is exercised. Only the two test devices are added and removed;
 * any device the user already had is left untouched, and expectations are
 * derived from the repository rather than hard-coded.
 *
 * Because the two seeded devices are appended to whatever the store already
 * holds, they can sit below the fold. Row assertions therefore go through
 * [assertShownTextInList], which scrolls the list: an unbound row is absent from
 * the view tree entirely, not merely invisible.
 *
 * Tests cover:
 * - Toolbar rendering
 * - Adapter binding: name, truncated fingerprint, connection history
 * - Attestation badges (never vs verified) and the IDevID trust badge
 * - Summary count derived from live repository state
 * - Empty state hidden while devices exist
 * - Row tap navigating to [DeviceDetailActivity] with the public key hex
 * - Back navigation finishing the activity
 */
@RunWith(AndroidJUnit4::class)
class PairedDevicesActivityUiTest {

    private lateinit var repository: PairedDeviceRepository

    @Before
    fun setUp() {
        Intents.init()
        // Keep row taps from actually launching the detail screen.
        intending(hasComponent(DeviceDetailActivity::class.java.name)).respondWith(
            Instrumentation.ActivityResult(Activity.RESULT_OK, null)
        )

        val context = ApplicationProvider.getApplicationContext<Context>()
        repository = PairedDeviceRepository(context)

        repository.removeDevice(FRESH_KEY_HEX)
        repository.removeDevice(ATTESTED_KEY_HEX)

        repository.addDevice(publicKeyHex = FRESH_KEY_HEX, deviceName = FRESH_NAME)
        repository.addDevice(publicKeyHex = ATTESTED_KEY_HEX, deviceName = ATTESTED_NAME)

        repository.recordConnection(ATTESTED_KEY_HEX)
        repository.updateDeviceAttestation(
            publicKeyHex = ATTESTED_KEY_HEX,
            bootHashHex = "00".repeat(32),
            securityLevel = "strongbox",
            bootStateVerified = true,
            deviceFingerprint = ATTESTED_FINGERPRINT
        )
        repository.updateDeviceIDevID(
            publicKeyHex = ATTESTED_KEY_HEX,
            certificateDER = TestCertificates
                .selfSigned(
                    alias = IDEVID_ALIAS,
                    commonName = "xKey UI Test IDevID",
                    notAfter = Date(System.currentTimeMillis() + 365L * TestCertificates.ONE_DAY_MS)
                )
                .encoded,
            certificateChain = null,
            trustLevel = "android-ca",
            subjectDN = "CN=xKey UI Test IDevID",
            notAfter = System.currentTimeMillis() + 365L * TestCertificates.ONE_DAY_MS
        )
    }

    @After
    fun tearDown() {
        repository.removeDevice(FRESH_KEY_HEX)
        repository.removeDevice(ATTESTED_KEY_HEX)
        TestCertificates.deleteAlias(IDEVID_ALIAS)
        Intents.release()
    }

    // -----------------------------------------------------------------
    // Chrome
    // -----------------------------------------------------------------

    @Test
    fun toolbar_showsTitleAndSubtitle() {
        val scenario = launch()

        assertShownTextInTree(scenario, withString(scenario, R.string.paired_devices_title))
        assertShownTextInTree(
            scenario,
            withString(scenario, R.string.settings_paired_devices_description)
        )
    }

    // -----------------------------------------------------------------
    // List binding
    // -----------------------------------------------------------------

    @Test
    fun deviceList_bindsEveryPairedDevice() {
        val scenario = launch()

        assertShownTextInList(scenario, FRESH_NAME)
        assertShownTextInList(scenario, ATTESTED_NAME)
    }

    @Test
    fun deviceList_itemCountMatchesRepository() {
        val scenario = launch()
        assertShownTextInList(scenario, FRESH_NAME)

        assertTrue(
            "The adapter should bind every paired device",
            awaitExactRecyclerItemCount(scenario, repository.getAllDevices().size)
        )
    }

    /**
     * A device that has never connected falls back to the public key hex for its
     * fingerprint preview, truncated to 24 characters.
     */
    @Test
    fun deviceList_showsTruncatedFingerprintPreview() {
        val scenario = launch()
        assertShownTextInList(scenario, FRESH_NAME)

        assertShownTextInTree(scenario, FRESH_KEY_HEX.take(24) + "...")
    }

    @Test
    fun deviceList_labelsANeverConnectedDevice() {
        val scenario = launch()
        assertShownTextInList(scenario, FRESH_NAME)

        assertShownTextInTree(
            scenario,
            withString(scenario, R.string.paired_devices_never_connected)
        )
    }

    @Test
    fun deviceList_showsLastSeenForAConnectedDevice() {
        val scenario = launch()
        assertShownTextInList(scenario, ATTESTED_NAME)

        val lastSeenPrefix = withString(scenario, R.string.paired_devices_last_seen, "").trim()
        assertShownTextInTree(scenario, lastSeenPrefix)
    }

    // -----------------------------------------------------------------
    // Badges
    // -----------------------------------------------------------------

    @Test
    fun deviceList_showsNeverAttestedBadgeForAFreshDevice() {
        val scenario = launch()
        assertShownTextInList(scenario, FRESH_NAME)

        assertShownTextInTree(
            scenario,
            withString(scenario, R.string.paired_devices_attestation_never)
        )
    }

    @Test
    fun deviceList_showsVerifiedAttestationBadgeForAnAttestedDevice() {
        val scenario = launch()
        assertShownTextInList(scenario, ATTESTED_NAME)

        assertShownTextInTree(
            scenario,
            withString(scenario, R.string.paired_devices_attestation_verified)
        )
    }

    @Test
    fun deviceList_showsTrustBadgeForADeviceWithAValidIDevID() {
        val scenario = launch()
        assertShownTextInList(scenario, ATTESTED_NAME)

        assertShownTextInTree(scenario, withString(scenario, R.string.paired_devices_trusted))
    }

    // -----------------------------------------------------------------
    // Summary and empty state
    // -----------------------------------------------------------------

    @Test
    fun summaryCard_countMatchesRepository() {
        val scenario = launch()
        assertShownTextInList(scenario, FRESH_NAME)

        assertExactTextShown(scenario, repository.getAllDevices().size.toString())
    }

    @Test
    fun summaryCard_reportsTheMostRecentConnection() {
        val scenario = launch()
        assertShownTextInList(scenario, ATTESTED_NAME)

        val prefix = withString(scenario, R.string.paired_devices_last_connection, "").trim()
        assertShownTextInTree(scenario, prefix)
    }

    @Test
    fun emptyState_isHiddenWhileDevicesArePaired() {
        val scenario = launch()
        assertShownTextInList(scenario, FRESH_NAME)

        val emptyTitle = withString(scenario, R.string.paired_devices_empty_title)
        assertFalse(
            "The empty state must be hidden once devices are bound",
            withActivity(scenario) {
                findShownTextViewContaining(it.window.decorView, emptyTitle) != null
            }
        )
    }

    // -----------------------------------------------------------------
    // Navigation
    // -----------------------------------------------------------------

    @Test
    fun deviceTap_opensDeviceDetailWithPublicKeyHex() {
        val scenario = launch()
        assertShownTextInList(scenario, FRESH_NAME)

        clickTextInTree(scenario, FRESH_NAME)

        intended(
            allOf(
                hasComponent(DeviceDetailActivity::class.java.name),
                hasExtra(DeviceDetailActivity.EXTRA_PUBLIC_KEY_HEX, FRESH_KEY_HEX)
            )
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

    private fun launch(): ActivityScenario<PairedDevicesActivity> =
        ActivityScenario.launch(PairedDevicesActivity::class.java)

    private fun withString(
        scenario: ActivityScenario<PairedDevicesActivity>,
        resId: Int,
        vararg args: Any
    ): String = withActivity(scenario) {
        if (args.isEmpty()) it.getString(resId) else it.getString(resId, *args)
    }

    private companion object {
        // 32-byte Noise static public keys (hex), representative of paired peers.
        const val FRESH_KEY_HEX =
            "1111111111111111111111111111111111111111111111111111111111111111"
        const val ATTESTED_KEY_HEX =
            "2222222222222222222222222222222222222222222222222222222222222222"
        const val ATTESTED_FINGERPRINT =
            "3333333333333333333333333333333333333333333333333333333333333333"
        const val FRESH_NAME = "UI Test Fresh Laptop"
        const val ATTESTED_NAME = "UI Test Attested Laptop"
        const val IDEVID_ALIAS = "xkey_uitest_paired_idevid"
    }
}
