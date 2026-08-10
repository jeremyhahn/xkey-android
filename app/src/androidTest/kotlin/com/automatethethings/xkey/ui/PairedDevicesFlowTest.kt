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
import android.widget.TextView
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.automatethethings.xkey.settings.PairedDeviceRepository
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.Date

/**
 * Instrumented tests for the [PairedDevicesActivity] badge states the basic
 * suite cannot produce.
 *
 * `PairedDevicesActivityUiTest` seeds a never-attested device and a freshly
 * attested one with a valid IDevID, which covers the "Never" and "Verified"
 * ends of the attestation badge and the trust badge's visible state. The two
 * remaining branches both depend on a *stale* record, and the repository stamps
 * its own timestamps: attestation staleness is therefore produced by setting the
 * device's grace period to zero, and IDevID staleness by storing a certificate
 * whose expiry has already passed.
 *
 * Tests cover:
 * - The expired attestation badge for a device outside its grace period
 * - The trust badge withheld from a device whose IDevID has expired, even though
 *   the certificate is present and was verified
 * - The fingerprint preview using the attestation fingerprint when there is one
 *
 * Both seeded devices are removed in @After; devices the user already had are
 * never touched.
 */
@RunWith(AndroidJUnit4::class)
class PairedDevicesFlowTest {

    private lateinit var repository: PairedDeviceRepository

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        repository = PairedDeviceRepository(context)

        repository.removeDevice(STALE_KEY_HEX)
        repository.removeDevice(EXPIRED_IDEVID_KEY_HEX)

        // Attested, but with a zero-minute grace period, so the attestation is
        // stale the instant it is recorded.
        repository.addDevice(publicKeyHex = STALE_KEY_HEX, deviceName = STALE_NAME)
        repository.updateDeviceAttestation(
            publicKeyHex = STALE_KEY_HEX,
            bootHashHex = "11".repeat(32),
            securityLevel = "tee",
            bootStateVerified = true,
            deviceFingerprint = STALE_FINGERPRINT
        )
        repository.updateDeviceSettings(
            publicKeyHex = STALE_KEY_HEX,
            requireAttestationForKeyUse = false,
            requireAttestationForKeyAttestation = true,
            attestationGracePeriodMinutes = 0
        )

        // Verified IDevID whose certificate expired yesterday.
        repository.addDevice(
            publicKeyHex = EXPIRED_IDEVID_KEY_HEX,
            deviceName = EXPIRED_IDEVID_NAME
        )
        val yesterday = System.currentTimeMillis() - TestCertificates.ONE_DAY_MS
        repository.updateDeviceIDevID(
            publicKeyHex = EXPIRED_IDEVID_KEY_HEX,
            certificateDER = TestCertificates.selfSigned(
                alias = IDEVID_ALIAS,
                commonName = "xKey Flow Expired IDevID",
                notBefore = Date(System.currentTimeMillis() - 30L * TestCertificates.ONE_DAY_MS),
                notAfter = Date(yesterday)
            ).encoded,
            certificateChain = null,
            trustLevel = "android-ca",
            subjectDN = "CN=xKey Flow Expired IDevID",
            notAfter = yesterday
        )
    }

    @After
    fun tearDown() {
        repository.removeDevice(STALE_KEY_HEX)
        repository.removeDevice(EXPIRED_IDEVID_KEY_HEX)
        TestCertificates.deleteAlias(IDEVID_ALIAS)
    }

    // ---------------------------------------------------------------
    // Attestation badge
    // ---------------------------------------------------------------

    @Test
    fun deviceOutsideItsGracePeriod_showsTheExpiredAttestationBadge() {
        val scenario = ActivityScenario.launch(PairedDevicesActivity::class.java)
        assertShownTextInList(scenario, STALE_NAME)

        val expired = withActivity(scenario) {
            it.getString(R.string.paired_devices_attestation_expired)
        }
        val texts = rowTexts(scenario, STALE_NAME)
        assertTrue(
            "A device past its grace period must be badged '$expired', found $texts",
            texts.contains(expired)
        )
    }

    // ---------------------------------------------------------------
    // Trust badge
    // ---------------------------------------------------------------

    /**
     * A present, previously verified IDevID is not enough: once the certificate
     * has expired the trust badge has to disappear.
     */
    @Test
    fun deviceWithAnExpiredIDevID_doesNotShowTheTrustBadge() {
        val scenario = ActivityScenario.launch(PairedDevicesActivity::class.java)
        assertShownTextInList(scenario, EXPIRED_IDEVID_NAME)

        val trusted = withActivity(scenario) { it.getString(R.string.paired_devices_trusted) }
        val shown = withActivity(scenario) { activity ->
            findShownTextViewContaining(
                rowCard(activity.window.decorView, EXPIRED_IDEVID_NAME),
                trusted
            )
        }
        assertTrue("An expired IDevID must not be badged '$trusted'", shown == null)
    }

    // ---------------------------------------------------------------
    // Fingerprint preview
    // ---------------------------------------------------------------

    /** With an attestation fingerprint recorded, it replaces the raw public key. */
    @Test
    fun attestedDevice_previewsItsAttestationFingerprint() {
        val scenario = ActivityScenario.launch(PairedDevicesActivity::class.java)
        assertShownTextInList(scenario, STALE_NAME)

        val texts = rowTexts(scenario, STALE_NAME)
        assertTrue(
            "The row should preview the attestation fingerprint, found $texts",
            texts.contains(STALE_FINGERPRINT.take(24) + "...")
        )
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    private fun rowTexts(
        scenario: ActivityScenario<PairedDevicesActivity>,
        deviceName: String
    ): List<String> {
        return withActivity(scenario) { activity ->
            val card = rowCard(activity.window.decorView, deviceName)
            collectViews(card) { it is TextView }
                .map { (it as TextView).text?.toString().orEmpty() }
        }
    }

    /**
     * Returns the card bound to [deviceName].
     *
     * Every row carries the same badge labels, so assertions have to be scoped
     * to one card; the device name is the only unique text on it.
     */
    private fun rowCard(root: View, deviceName: String): View {
        val matches = collectViews(root) { view ->
            view is TextView && view.text?.toString() == deviceName
        }
        val name = matches.firstOrNull()
            ?: throw AssertionError("No bound row for '$deviceName'")

        var candidate: View? = name.parent as? View
        while (candidate != null) {
            if (candidate.isClickable) return candidate
            candidate = candidate.parent as? View
        }
        throw AssertionError("No clickable card around '$deviceName'")
    }

    private companion object {
        // `val`, not `const val`: repeat() is a runtime call, and a const
        // initialised from one crashes the K2 backend rather than being
        // rejected up front.
        val STALE_KEY_HEX = "f1".repeat(32)
        val EXPIRED_IDEVID_KEY_HEX = "f2".repeat(32)
        const val STALE_FINGERPRINT =
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        const val STALE_NAME = "UI Test Flow Stale Laptop"
        const val EXPIRED_IDEVID_NAME = "UI Test Flow Expired IDevID Laptop"
        const val IDEVID_ALIAS = "xkey_uitest_pairedflow_idevid"
    }
}
