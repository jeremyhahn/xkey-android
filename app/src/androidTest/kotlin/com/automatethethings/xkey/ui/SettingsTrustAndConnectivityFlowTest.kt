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
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.espresso.intent.Intents
import androidx.test.espresso.intent.matcher.IntentMatchers.hasComponent
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.automatethethings.xkey.media.MediaSigningService
import com.automatethethings.xkey.settings.MediaSigningSettingsData
import com.automatethethings.xkey.settings.MediaSigningSettingsRepository
import com.automatethethings.xkey.settings.TrustedComputingSettingsData
import com.automatethethings.xkey.settings.TrustedComputingSettingsRepository
import com.automatethethings.xkey.ui.SettingsFlowSupport.assertEventuallyHides
import com.automatethethings.xkey.ui.SettingsFlowSupport.assertEventuallyShows
import com.automatethethings.xkey.ui.SettingsFlowSupport.awaitInitialized
import com.automatethethings.xkey.ui.SettingsFlowSupport.button
import com.automatethethings.xkey.ui.SettingsFlowSupport.clickView
import com.automatethethings.xkey.ui.SettingsFlowSupport.ownTextSwitch
import com.automatethethings.xkey.ui.SettingsFlowSupport.rowSwitch
import com.automatethethings.xkey.ui.SettingsFlowSupport.setToggle
import com.automatethethings.xkey.ui.SettingsFlowSupport.shows
import com.automatethethings.xkey.usb.UsbHsmSettingsData
import com.automatethethings.xkey.usb.UsbHsmSettingsRepository
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * End-to-end tests for the Device Trust, Media Signing and Connectivity
 * sections of [SettingsActivity].
 *
 * These three sections own the switches that decide whether a peer may pair at
 * all (trusted computing), whether captured media gets signed, and which
 * transports the GATT service brings up (native USB, TCP-over-ADB). Every test
 * asserts the persisted DataStore value, because that is what
 * `XKeyGattService` reads when it decides what to start.
 *
 * The trusted-computing, USB and media-signing stores are snapshotted in
 * @Before and restored in @After; the media signing service is stopped there
 * too, since the auto-sign flow really does start a foreground service.
 */
@RunWith(AndroidJUnit4::class)
class SettingsTrustAndConnectivityFlowTest {

    private lateinit var context: Context
    private lateinit var trustedComputingRepository: TrustedComputingSettingsRepository
    private lateinit var usbRepository: UsbHsmSettingsRepository
    private lateinit var mediaSigningRepository: MediaSigningSettingsRepository

    private lateinit var originalTrustedComputing: TrustedComputingSettingsData
    private lateinit var originalUsb: UsbHsmSettingsData
    private lateinit var originalMediaSigning: MediaSigningSettingsData

    @Before
    fun setUp() {
        Intents.init()
        context = ApplicationProvider.getApplicationContext()
        trustedComputingRepository = TrustedComputingSettingsRepository(context)
        usbRepository = UsbHsmSettingsRepository(context)
        mediaSigningRepository = MediaSigningSettingsRepository(context)
        runBlocking {
            originalTrustedComputing = trustedComputingRepository.getSettings()
            originalUsb = usbRepository.getSettings()
            originalMediaSigning = mediaSigningRepository.getSettings()
        }
    }

    @After
    fun tearDown() {
        runBlocking {
            trustedComputingRepository.updateSettings(originalTrustedComputing)
            usbRepository.setNativeUsbEnabled(originalUsb.nativeUsbEnabled)
            usbRepository.setTcpHsmEnabled(originalUsb.tcpHsmEnabled)
            mediaSigningRepository.updateSettings(originalMediaSigning)
        }
        context.stopService(Intent(context, MediaSigningService::class.java))
        Intents.release()
    }

    // ---------------------------------------------------------------
    // Device Trust
    // ---------------------------------------------------------------

    @Test
    fun trustedComputingToggle_on_revealsConditionalRowsAndPersists() {
        seedTrustedComputing(TrustedComputingSettingsData(enabled = false))

        val scenario = ActivityScenario.launch(SettingsActivity::class.java)
        awaitInitialized(scenario)
        assertFalse(
            "The conditional trust rows should be hidden while trusted computing is off",
            shows(scenario, requireIdevIdTitle())
        )

        setToggle(scenario, desired = true, describe = "Enable Trusted Computing") {
            rowSwitch(it, context.getString(R.string.settings_trusted_computing_enabled))
        }

        awaitCondition("Trusted computing should be persisted as enabled") {
            currentTrustedComputing().enabled
        }
        assertEventuallyShows(scenario, requireIdevIdTitle())
        assertEventuallyShows(
            scenario,
            context.getString(R.string.settings_trusted_computing_full_attestation)
        )
        assertEventuallyShows(
            scenario,
            context.getString(R.string.settings_trusted_computing_trust_new)
        )
    }

    @Test
    fun trustedComputingToggle_off_hidesConditionalRowsAndPersists() {
        seedTrustedComputing(TrustedComputingSettingsData(enabled = true))

        val scenario = ActivityScenario.launch(SettingsActivity::class.java)
        awaitInitialized(scenario)
        assertTrue(
            "The conditional trust rows should be visible while trusted computing is on",
            shows(scenario, requireIdevIdTitle())
        )

        setToggle(scenario, desired = false, describe = "Enable Trusted Computing") {
            rowSwitch(it, context.getString(R.string.settings_trusted_computing_enabled))
        }

        awaitCondition("Trusted computing should be persisted as disabled") {
            !currentTrustedComputing().enabled
        }
        assertEventuallyHides(scenario, requireIdevIdTitle())
    }

    @Test
    fun requireTrustedIdevIdToggle_persists() {
        seedTrustedComputing(
            TrustedComputingSettingsData(enabled = true, requireTrustedIDevID = false)
        )

        val scenario = ActivityScenario.launch(SettingsActivity::class.java)
        awaitInitialized(scenario)

        setToggle(scenario, desired = true, describe = "Require Trusted IDevID") {
            rowSwitch(it, requireIdevIdTitle())
        }

        awaitCondition("Require trusted IDevID should be persisted as on") {
            currentTrustedComputing().requireTrustedIDevID
        }
    }

    @Test
    fun requireFullAttestationToggle_persists() {
        seedTrustedComputing(
            TrustedComputingSettingsData(enabled = true, requireFullAttestation = false)
        )

        val scenario = ActivityScenario.launch(SettingsActivity::class.java)
        awaitInitialized(scenario)

        setToggle(scenario, desired = true, describe = "Require Full Attestation") {
            rowSwitch(it, context.getString(R.string.settings_trusted_computing_full_attestation))
        }

        awaitCondition("Require full attestation should be persisted as on") {
            currentTrustedComputing().requireFullAttestation
        }
    }

    /**
     * Turning this off is the security-relevant direction: unknown peers must
     * then be pre-provisioned in the trust store rather than trusted on first
     * pairing.
     */
    @Test
    fun trustNewDevicesToggle_off_persists() {
        seedTrustedComputing(
            TrustedComputingSettingsData(enabled = true, trustNewDevices = true)
        )

        val scenario = ActivityScenario.launch(SettingsActivity::class.java)
        awaitInitialized(scenario)

        setToggle(scenario, desired = false, describe = "Trust New Devices") {
            rowSwitch(it, context.getString(R.string.settings_trusted_computing_trust_new))
        }

        awaitCondition("Trust new devices should be persisted as off") {
            !currentTrustedComputing().trustNewDevices
        }
    }

    @Test
    fun manageTrustStoreButton_opensTrustStoreActivity() {
        seedTrustedComputing(TrustedComputingSettingsData(enabled = true))

        val scenario = ActivityScenario.launch(SettingsActivity::class.java)
        awaitInitialized(scenario)

        clickView(scenario, "the Manage Trust Store button") {
            button(it, context.getString(R.string.settings_trusted_computing_manage_trust_store))
        }

        Intents.intended(hasComponent(TrustStoreActivity::class.java.name))
    }

    // ---------------------------------------------------------------
    // Connectivity
    // ---------------------------------------------------------------

    @Test
    fun nativeUsbToggle_on_persists() {
        seedUsb(nativeUsb = false, tcp = false)

        val scenario = ActivityScenario.launch(SettingsActivity::class.java)
        awaitInitialized(scenario)

        setToggle(scenario, desired = true, describe = "Native USB Mode") {
            rowSwitch(it, context.getString(R.string.settings_usb_native_title))
        }

        awaitCondition("Native USB should be persisted as enabled") {
            currentUsb().nativeUsbEnabled
        }
    }

    @Test
    fun nativeUsbToggle_off_persists() {
        seedUsb(nativeUsb = true, tcp = false)

        val scenario = ActivityScenario.launch(SettingsActivity::class.java)
        awaitInitialized(scenario)

        setToggle(scenario, desired = false, describe = "Native USB Mode") {
            rowSwitch(it, context.getString(R.string.settings_usb_native_title))
        }

        awaitCondition("Native USB should be persisted as disabled") {
            !currentUsb().nativeUsbEnabled
        }
    }

    /**
     * The TCP transport is the development-only one; enabling it is what makes
     * `XKeyGattService` bind loopback :8444 for ADB-forwarded desktop pairing.
     */
    @Test
    fun tcpPairingToggle_on_persistsWithoutTouchingNativeUsb() {
        seedUsb(nativeUsb = true, tcp = false)

        val scenario = ActivityScenario.launch(SettingsActivity::class.java)
        awaitInitialized(scenario)

        setToggle(scenario, desired = true, describe = "TCP Pairing (ADB)") {
            rowSwitch(it, context.getString(R.string.settings_usb_tcp_title))
        }

        awaitCondition("TCP pairing should be persisted as enabled") {
            val settings = currentUsb()
            settings.tcpHsmEnabled && settings.nativeUsbEnabled
        }
    }

    @Test
    fun tcpPairingToggle_off_persists() {
        seedUsb(nativeUsb = false, tcp = true)

        val scenario = ActivityScenario.launch(SettingsActivity::class.java)
        awaitInitialized(scenario)

        setToggle(scenario, desired = false, describe = "TCP Pairing (ADB)") {
            rowSwitch(it, context.getString(R.string.settings_usb_tcp_title))
        }

        awaitCondition("TCP pairing should be persisted as disabled") {
            !currentUsb().tcpHsmEnabled
        }
    }

    /** Both transports restore their persisted state on load. */
    @Test
    fun connectivityToggles_restorePersistedState() {
        seedUsb(nativeUsb = true, tcp = true)

        val scenario = ActivityScenario.launch(SettingsActivity::class.java)
        awaitInitialized(scenario)

        val states = withActivity(scenario) { activity ->
            val root = activity.window.decorView
            Pair(
                rowSwitch(root, context.getString(R.string.settings_usb_native_title))?.isChecked,
                rowSwitch(root, context.getString(R.string.settings_usb_tcp_title))?.isChecked
            )
        }
        assertTrue("Native USB switch should restore as checked", states.first == true)
        assertTrue("TCP pairing switch should restore as checked", states.second == true)
    }

    /**
     * The ADB transport carries its own disclosure copy, which is the only
     * warning a user gets that this opens a debugging socket.
     *
     * It now lives behind the developer-options header and starts collapsed, so
     * the copy is reached by opening that rather than on load.
     */
    @Test
    fun tcpPairingRow_showsItsDevelopmentDisclosure() {
        val scenario = ActivityScenario.launch(SettingsActivity::class.java)
        awaitInitialized(scenario)

        clickTextInTree(scenario, context.getString(R.string.settings_developer_options))

        assertEventuallyShows(scenario, context.getString(R.string.settings_usb_tcp_description))
        assertEventuallyShows(scenario, context.getString(R.string.explain_usb_tcp))
    }

    // ---------------------------------------------------------------
    // Media Signing
    // ---------------------------------------------------------------

    /**
     * Auto-sign both persists and gates the rest of the section. Enabling it
     * starts the real [MediaSigningService], so the test turns it straight back
     * off and @After stops the service regardless.
     */
    @Test
    fun autoSignToggle_revealsConfigurationAndPersistsBothDirections() {
        seedMediaSigning(MediaSigningSettingsData(autoSignEnabled = false))

        val scenario = ActivityScenario.launch(SettingsActivity::class.java)
        awaitInitialized(scenario)
        assertFalse(
            "The signing configuration should be hidden while auto-sign is off",
            shows(scenario, context.getString(R.string.settings_media_signing_key))
        )

        setToggle(scenario, desired = true, describe = "Auto-Sign Media") {
            ownTextSwitch(it, context.getString(R.string.settings_media_signing_auto))
        }

        awaitCondition("Auto-sign should be persisted as enabled") {
            currentMediaSigning().autoSignEnabled
        }
        assertEventuallyShows(scenario, context.getString(R.string.settings_media_signing_key))

        setToggle(scenario, desired = false, describe = "Auto-Sign Media") {
            ownTextSwitch(it, context.getString(R.string.settings_media_signing_auto))
        }

        awaitCondition("Auto-sign should be persisted as disabled") {
            !currentMediaSigning().autoSignEnabled
        }
        assertEventuallyHides(scenario, context.getString(R.string.settings_media_signing_key))
    }

    /**
     * The photo and video switches write straight through to DataStore.
     *
     * They are driven with auto-sign left off deliberately: their listeners
     * have no service side effects, and leaving auto-sign off keeps this test
     * from starting a foreground service just to flip a boolean.
     */
    @Test
    fun signPhotosToggle_persists() {
        seedMediaSigning(
            MediaSigningSettingsData(autoSignEnabled = false, signPhotos = true)
        )

        val scenario = ActivityScenario.launch(SettingsActivity::class.java)
        awaitInitialized(scenario)

        setToggle(scenario, desired = false, describe = "Sign Photos") {
            ownTextSwitch(it, context.getString(R.string.settings_media_signing_photos))
        }

        awaitCondition("Sign photos should be persisted as off") {
            !currentMediaSigning().signPhotos
        }
    }

    @Test
    fun signVideosToggle_persists() {
        seedMediaSigning(
            MediaSigningSettingsData(autoSignEnabled = false, signVideos = true)
        )

        val scenario = ActivityScenario.launch(SettingsActivity::class.java)
        awaitInitialized(scenario)

        setToggle(scenario, desired = false, describe = "Sign Videos") {
            ownTextSwitch(it, context.getString(R.string.settings_media_signing_videos))
        }

        awaitCondition("Sign videos should be persisted as off") {
            !currentMediaSigning().signVideos
        }
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    private fun requireIdevIdTitle(): String =
        context.getString(R.string.settings_trusted_computing_require_idevid)

    private fun seedTrustedComputing(settings: TrustedComputingSettingsData) {
        runBlocking { trustedComputingRepository.updateSettings(settings) }
    }

    private fun currentTrustedComputing(): TrustedComputingSettingsData =
        runBlocking { trustedComputingRepository.getSettings() }

    private fun seedUsb(nativeUsb: Boolean, tcp: Boolean) {
        runBlocking {
            usbRepository.setNativeUsbEnabled(nativeUsb)
            usbRepository.setTcpHsmEnabled(tcp)
        }
    }

    private fun currentUsb(): UsbHsmSettingsData = runBlocking { usbRepository.getSettings() }

    private fun seedMediaSigning(settings: MediaSigningSettingsData) {
        runBlocking { mediaSigningRepository.updateSettings(settings) }
    }

    private fun currentMediaSigning(): MediaSigningSettingsData =
        runBlocking { mediaSigningRepository.getSettings() }
}
