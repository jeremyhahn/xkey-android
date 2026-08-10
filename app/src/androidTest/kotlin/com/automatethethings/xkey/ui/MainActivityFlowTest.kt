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
import android.content.pm.PackageManager
import android.hardware.usb.UsbManager
import android.os.Build
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.biometric.BiometricManager
import androidx.core.widget.NestedScrollView
import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.espresso.intent.Intents
import androidx.test.espresso.intent.matcher.IntentMatchers.hasComponent
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.automatethethings.xkey.oath.OathRepository
import com.automatethethings.xkey.oath.OathSecretManager
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.truststore.TrustStoreRepository
import com.google.android.material.bottomnavigation.BottomNavigationView
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * End-to-end tests for [MainActivity] covering the flows its existing suite
 * leaves out: the navigation targets nothing else reaches, the live counts and
 * device capabilities rendered on the cards, the authentication-request hero
 * state, and the bottom navigation's scroll behaviour.
 *
 * Cards are clicked through [View.performClick] on the main thread rather than
 * by injecting taps. The home screen is one long scroll view with a navigation
 * bar drawn over it, so a coordinate-based tap on a card near the bottom of a
 * tab depends on the viewport inset being right — that is worth one dedicated
 * test (see `scrollViewport_stopsAtTheTopOfTheBottomNavigation`), but it should
 * not be an implicit precondition of every navigation assertion.
 *
 * Counts are never hard-coded: each expectation is computed from the same
 * repository the screen reads, because other suites leave rows behind.
 *
 * The one seeded OATH credential is deleted in @After.
 */
@RunWith(AndroidJUnit4::class)
class MainActivityFlowTest {

    private lateinit var context: Context
    private lateinit var oathRepository: OathRepository
    private lateinit var trustStoreRepository: TrustStoreRepository
    private lateinit var pairedDeviceRepository: PairedDeviceRepository

    private var seededOathId: String? = null

    @Before
    fun setUp() {
        Intents.init()
        context = ApplicationProvider.getApplicationContext()
        oathRepository = OathRepository(
            XKeyDatabase.getInstance(context).oathCredentialDao(),
            OathSecretManager()
        )
        trustStoreRepository = TrustStoreRepository(context)
        pairedDeviceRepository = PairedDeviceRepository(context)
    }

    @After
    fun tearDown() {
        runBlocking { seededOathId?.let { oathRepository.deleteCredential(it) } }
        Intents.release()
    }

    // ---------------------------------------------------------------
    // Navigation targets not covered elsewhere
    // ---------------------------------------------------------------

    @Test
    fun pivSmartCardCard_opensPivActivity() {
        val scenario = launchOnTab(R.id.nav_applications)

        clickCard(scenario, R.id.cardPivSmartCard, "the PIV Smart Card card")

        Intents.intended(hasComponent(PivActivity::class.java.name))
    }

    @Test
    fun certificatesCard_opensCertificateManagementActivity() {
        val scenario = launchOnTab(R.id.nav_store)

        clickCard(scenario, R.id.cardCertificates, "the Certificates card")

        Intents.intended(hasComponent(CertificateManagementActivity::class.java.name))
    }

    @Test
    fun trustStoreCard_opensTrustStoreActivity() {
        val scenario = launchOnTab(R.id.nav_store)

        clickCard(scenario, R.id.cardTrustStore, "the Trust Store card")

        Intents.intended(hasComponent(TrustStoreActivity::class.java.name))
    }

    @Test
    fun contactsCard_opensContactManagementActivity() {
        val scenario = launchOnTab(R.id.nav_store)

        clickCard(scenario, R.id.cardContacts, "the Contacts card")

        Intents.intended(hasComponent(ContactManagementActivity::class.java.name))
    }

    @Test
    fun coSignCard_opensCoSignActivity() {
        val scenario = launchOnTab(R.id.nav_management)

        clickCard(scenario, R.id.cardCoSign, "the Co-Sign card")

        Intents.intended(hasComponent(CoSignActivity::class.java.name))
    }

    @Test
    fun pairedDevicesCard_opensPairedDevicesActivity() {
        val scenario = launchOnTab(R.id.nav_management)

        clickCard(scenario, R.id.cardPairedDevices, "the Paired Devices card")

        Intents.intended(hasComponent(PairedDevicesActivity::class.java.name))
    }

    /**
     * The Settings card is wired to its activity.
     *
     * This deliberately invokes the card's own click listener instead of
     * tapping it: the card sits at the very bottom of the Management tab, so a
     * coordinate-based tap also tests the scroll viewport inset. Keeping the
     * two concerns apart means a regression here can only mean the listener
     * itself is gone.
     */
    @Test
    fun settingsCard_opensSettingsActivity_whenItsListenerRuns() {
        val scenario = launchOnTab(R.id.nav_management)

        clickCard(scenario, R.id.cardSettings, "the Settings card")

        Intents.intended(hasComponent(SettingsActivity::class.java.name))
    }

    // ---------------------------------------------------------------
    // Live counts on cards
    // ---------------------------------------------------------------

    @Test
    fun pairedDevicesCard_showsTheLiveDeviceCount() {
        val count = pairedDeviceRepository.getAllDevices().size
        val expected = context.resources.getQuantityString(
            R.plurals.paired_devices_summary_count,
            count,
            count
        )

        val scenario = launchOnTab(R.id.nav_management)

        assertTextEventually(scenario, R.id.textPairedDevicesCount, expected)
    }

    @Test
    fun trustStoreCard_showsTheLiveCertificateCount() {
        val count = runBlocking { trustStoreRepository.getAllCertificates().size }
        val expected = if (count == 0) {
            context.getString(R.string.trust_store_summary_none)
        } else {
            context.resources.getQuantityString(R.plurals.trust_store_card_count, count, count)
        }

        val scenario = launchOnTab(R.id.nav_store)

        assertTextEventually(scenario, R.id.textTrustStoreCount, expected)
    }

    @Test
    fun certificatesCard_showsTheLiveCertificateCount() {
        val certificateDao = XKeyDatabase.getInstance(context).certificateDao()
        val total = runBlocking { certificateDao.countAll() }
        val expired = runBlocking { certificateDao.countExpired() }
        val expected = when {
            total == 0 -> context.getString(R.string.certificate_count_zero)
            expired > 0 ->
                context.getString(R.string.certificate_count_with_expired, total, expired)
            else -> context.getString(R.string.certificate_count, total)
        }

        val scenario = launchOnTab(R.id.nav_store)

        assertTextEventually(scenario, R.id.textCertificateCount, expected)
    }

    /**
     * Returning to the screen re-reads the counts, so a credential added while
     * the activity was stopped shows up without a relaunch.
     */
    @Test
    fun returningToTheScreen_refreshesTheAuthenticatorCount() {
        val scenario = launchOnTab(R.id.nav_applications)

        scenario.moveToState(Lifecycle.State.CREATED)
        seededOathId = runBlocking {
            oathRepository.addCredential(
                issuer = "UI Flow Test",
                accountName = "main-flow-${System.nanoTime()}@example.com",
                secret = ByteArray(20) { 0x1f }
            )
        }
        scenario.moveToState(Lifecycle.State.RESUMED)

        val count = runBlocking {
            XKeyDatabase.getInstance(context).oathCredentialDao().count()
        }
        val expected = when (count) {
            0 -> context.getString(R.string.oath_card_description)
            1 -> context.getString(R.string.oath_count_one)
            else -> context.getString(R.string.oath_count, count)
        }

        assertTextEventually(scenario, R.id.textOathCount, expected)
    }

    // ---------------------------------------------------------------
    // Device Information card
    // ---------------------------------------------------------------

    @Test
    fun deviceInformationCard_showsThisBuildsIdentity() {
        val scenario = ActivityScenario.launch(MainActivity::class.java)

        assertTextEventually(
            scenario,
            R.id.textDeviceModel,
            "${Build.MANUFACTURER} ${Build.MODEL}"
        )
        assertTextEventually(
            scenario,
            R.id.textAndroidVersion,
            "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})"
        )
        assertTextEventually(scenario, R.id.textSecurityPatch, Build.VERSION.SECURITY_PATCH)
    }

    /** MAC randomisation means the real address is never shown. */
    @Test
    fun deviceInformationCard_reportsTheBleAddressAsRandomized() {
        val scenario = ActivityScenario.launch(MainActivity::class.java)

        assertTextEventually(
            scenario,
            R.id.textBleAddress,
            context.getString(R.string.device_info_ble_address_randomized)
        )
    }

    /**
     * The capability rows are read back from the platform rather than assumed:
     * the emulator has neither StrongBox nor an enrolled biometric, and the
     * screen must say so instead of claiming both.
     */
    @Test
    fun deviceInformationCard_reportsCapabilitiesThisDeviceActuallyHas() {
        val hasStrongBox = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        val hasTee = Build.VERSION.SDK_INT >= Build.VERSION_CODES.M
        val hasBiometric = BiometricManager.from(context).canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG
        ) == BiometricManager.BIOMETRIC_SUCCESS

        val scenario = ActivityScenario.launch(MainActivity::class.java)

        assertTextEventually(scenario, R.id.textStrongBoxInfo, availability(hasStrongBox))
        assertTextEventually(scenario, R.id.textTeeInfo, availability(hasTee))
        assertTextEventually(scenario, R.id.textBiometricsInfo, availability(hasBiometric))
    }

    // ---------------------------------------------------------------
    // Authentication request hero state
    // ---------------------------------------------------------------

    @Test
    fun authenticationRequest_revealsTheCardWithItsOriginAndSwitchesStatus() {
        val scenario = ActivityScenario.launch(MainActivity::class.java)
        // The hero text cross-fades between states; let the initial transition
        // settle so this asserts the authenticating state and not a leftover.
        assertTextEventually(
            scenario,
            R.id.textStatusLarge,
            context.getString(R.string.status_disconnected)
        )

        scenario.onActivity { it.showAuthenticationRequest(REQUEST_ORIGIN) }

        assertTextEventually(scenario, R.id.textAuthRequestOrigin, REQUEST_ORIGIN)
        assertTrue(
            "The authentication request card should be revealed",
            awaitActivity(scenario) { isShown(it, R.id.cardAuthRequest) }
        )
        assertTextEventually(
            scenario,
            R.id.textStatusLarge,
            context.getString(R.string.status_authenticating)
        )
        assertTextEventually(
            scenario,
            R.id.textBleStatus,
            context.getString(R.string.ble_switch_on)
        )
    }

    @Test
    fun authenticationRequest_hidesTheCardAgain() {
        val scenario = ActivityScenario.launch(MainActivity::class.java)
        scenario.onActivity { it.showAuthenticationRequest(REQUEST_ORIGIN) }
        assertTrue(
            "The authentication request card should be revealed first",
            awaitActivity(scenario) { isShown(it, R.id.cardAuthRequest) }
        )

        scenario.onActivity { it.hideAuthenticationRequest() }

        assertTrue(
            "The authentication request card should be hidden again",
            awaitActivity(scenario) { !isShown(it, R.id.cardAuthRequest) }
        )
    }

    /**
     * The card belongs to the Dashboard tab. Leaving the tab hides it, and
     * coming back restores it because the request is still outstanding.
     */
    @Test
    fun authenticationRequest_isDashboardOnly() {
        val scenario = ActivityScenario.launch(MainActivity::class.java)
        scenario.onActivity { it.showAuthenticationRequest(REQUEST_ORIGIN) }
        assertTrue(
            "The authentication request card should be revealed first",
            awaitActivity(scenario) { isShown(it, R.id.cardAuthRequest) }
        )

        selectTab(scenario, R.id.nav_store)
        assertFalse(
            "The authentication request card is dashboard-only",
            withActivity(scenario) { isShown(it, R.id.cardAuthRequest) }
        )

        selectTab(scenario, R.id.nav_dashboard)
        assertTrue(
            "Returning to the dashboard should restore the outstanding request",
            awaitActivity(scenario) { isShown(it, R.id.cardAuthRequest) }
        )
    }

    // ---------------------------------------------------------------
    // Bottom navigation behaviour
    // ---------------------------------------------------------------

    /** Every tab starts at the top rather than inheriting the last scroll. */
    @Test
    fun switchingTabs_resetsTheScrollPosition() {
        val scenario = launchOnTab(R.id.nav_store)

        scenario.onActivity { activity ->
            activity.findViewById<NestedScrollView>(R.id.nestedScrollView).scrollTo(0, 600)
        }
        waitForIdle()
        val scrolled = withActivity(scenario) { activity ->
            activity.findViewById<NestedScrollView>(R.id.nestedScrollView).scrollY
        }
        assumeTrue("The Store tab needs to be taller than the viewport to scroll", scrolled > 0)

        selectTab(scenario, R.id.nav_management)

        assertTrue(
            "Switching tabs should scroll back to the top",
            awaitActivity(scenario) {
                it.findViewById<NestedScrollView>(R.id.nestedScrollView).scrollY == 0
            }
        )
    }

    /**
     * The navigation bar is drawn over the scroll view, so the viewport is
     * inset by the bar's measured height. Without it the last card in a tab
     * comes to rest underneath the bar and taps land on the bar instead.
     */
    @Test
    fun scrollViewport_stopsAtTheTopOfTheBottomNavigation() {
        val scenario = ActivityScenario.launch(MainActivity::class.java)

        assertTrue(
            "The scroll viewport should end where the navigation bar begins",
            awaitActivity(scenario) { activity ->
                val nav = activity.findViewById<BottomNavigationView>(R.id.bottomNavigation)
                val scroll = activity.findViewById<NestedScrollView>(R.id.nestedScrollView)
                val margin = (scroll.layoutParams as? ViewGroup.MarginLayoutParams)?.bottomMargin
                nav.height > 0 && margin == nav.height
            }
        )
    }

    // ---------------------------------------------------------------
    // USB accessory entry point
    // ---------------------------------------------------------------

    /**
     * The activity is also the launch target for `USB_ACCESSORY_ATTACHED`.
     * With no accessory attached to the intent the handler must fall through
     * quietly and still bring up the dashboard.
     */
    @Test
    fun launchedFromAUsbAccessoryIntent_stillBuildsTheDashboard() {
        val intent = Intent(context, MainActivity::class.java).apply {
            action = UsbManager.ACTION_USB_ACCESSORY_ATTACHED
        }

        val scenario = ActivityScenario.launch<MainActivity>(intent)

        assertTrue(
            "The dashboard hero should be built for a USB accessory launch",
            awaitActivity(scenario) { isShown(it, R.id.heroSection) }
        )
        assertTextEventually(
            scenario,
            R.id.textStatusLarge,
            context.getString(R.string.status_disconnected)
        )
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    private fun launchOnTab(tabId: Int): ActivityScenario<MainActivity> {
        val scenario = ActivityScenario.launch(MainActivity::class.java)
        selectTab(scenario, tabId)
        return scenario
    }

    /**
     * Selects a bottom-navigation tab through the bar's own API.
     *
     * `setSelectedItemId` dispatches the same item-selected callback a tap
     * does, without depending on where the bar happens to be laid out — the
     * existing suite already covers that the bar is tappable.
     */
    private fun selectTab(scenario: ActivityScenario<MainActivity>, tabId: Int) {
        scenario.onActivity { activity ->
            activity.findViewById<BottomNavigationView>(R.id.bottomNavigation)
                .selectedItemId = tabId
        }
        waitForIdle()
    }

    private fun clickCard(
        scenario: ActivityScenario<MainActivity>,
        cardId: Int,
        describe: String
    ) {
        scenario.onActivity { activity ->
            val card: View? = activity.findViewById(cardId)
            assertNotNull("Expected $describe to be present", card)
            card!!.performClick()
        }
        waitForIdle()
    }

    /** Polls the view [viewId] until it reads exactly [expected]. */
    private fun assertTextEventually(
        scenario: ActivityScenario<MainActivity>,
        viewId: Int,
        expected: String
    ) {
        val matched = awaitActivity(scenario) { activity ->
            activity.findViewById<TextView>(viewId)?.text?.toString() == expected
        }
        if (!matched) {
            val actual = withActivity(scenario) { activity ->
                activity.findViewById<TextView>(viewId)?.text?.toString()
            }
            assertEquals("View 0x${viewId.toString(16)} text", expected, actual)
        }
        assertTrue(matched)
    }

    private fun isShown(activity: MainActivity, viewId: Int): Boolean =
        activity.findViewById<View>(viewId)?.isShown == true

    private fun availability(available: Boolean): String =
        if (available) CAPABILITY_AVAILABLE else CAPABILITY_UNAVAILABLE

    private companion object {
        /** Inline literals in `MainActivity.updateCapabilityRow`. */
        const val CAPABILITY_AVAILABLE = "Available"
        const val CAPABILITY_UNAVAILABLE = "Not Available"

        const val REQUEST_ORIGIN = "https://ui-flow-test.example.com"
    }
}
