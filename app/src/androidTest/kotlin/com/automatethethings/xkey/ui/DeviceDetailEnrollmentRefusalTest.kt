/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
 *
 * This file is part of xkey-android.
 *
 * xkey-android is dual-licensed:
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
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.automatethethings.xkey.ca.EnrolledDevice
import com.automatethethings.xkey.ca.EnrolledDeviceRepository
import com.automatethethings.xkey.ca.EnrollmentRefusal
import com.automatethethings.xkey.ca.EnrollmentRefusalRecord
import com.automatethethings.xkey.settings.PairedDeviceRepository
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Why a paired laptop has no certificate, on the laptop's own screen.
 *
 * The enrollment ceremony refuses by name, but until now the name only reached
 * the audit log and logcat. A refused device is not enrolled, so the reason is
 * kept beside the enrolment list rather than on it, and the attestation card
 * reads it back from there: the case, which separates a device that answered
 * the credential challenge wrongly from one that never answered, and the
 * detail, which names what specifically failed.
 *
 * Both repositories are shared with the app, so this suite writes under a
 * per-run public key and removes the paired device and the refusal in teardown.
 * Each test launches its own scenario after seeding the state it needs; nothing
 * is scoped to the class.
 */
@RunWith(AndroidJUnit4::class)
class DeviceDetailEnrollmentRefusalTest {

    private val runId = System.nanoTime()

    /** 32 bytes of hex, unique to this run. */
    private val publicKeyHex = "ef".repeat(31) + String.format("%02x", (runId and 0xFF).toInt())

    private val deviceName = "UITestRefusal$runId"

    private lateinit var context: Context
    private lateinit var pairedDevices: PairedDeviceRepository
    private lateinit var enrolledDevices: EnrolledDeviceRepository
    private var scenario: ActivityScenario<DeviceDetailActivity>? = null

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        pairedDevices = PairedDeviceRepository(context)
        enrolledDevices = EnrolledDeviceRepository(context)
        pairedDevices.removeDevice(publicKeyHex)
        enrolledDevices.removeDevice(publicKeyHex)
        enrolledDevices.clearRefusal(publicKeyHex)
        pairedDevices.addDevice(publicKeyHex = publicKeyHex, deviceName = deviceName)
    }

    @After
    fun tearDown() {
        scenario?.close()
        scenario = null
        pairedDevices.removeDevice(publicKeyHex)
        enrolledDevices.removeDevice(publicKeyHex)
        enrolledDevices.clearRefusal(publicKeyHex)
    }

    // ---------------------------------------------------------------
    // A refusal on record
    // ---------------------------------------------------------------

    /**
     * The two activation cases must not read alike on screen either: one says
     * the device holds the wrong keys, the other that it never answered.
     */
    @Test
    fun anUnanswerableChallenge_readsDifferentlyFromAWrongSecret() {
        seedRefusal(
            EnrollmentRefusal.ActivationUnsupported(
                "EK certificate carries a EC key; credential activation needs an RSA " +
                    "endorsement key"
            )
        )

        val scenario = launch()

        assertShownTextInTree(
            scenario,
            context.getString(R.string.device_enrollment_refused_activation_unsupported)
        )
        assertTextNotInTree(
            scenario,
            context.getString(R.string.device_enrollment_refused_activation_mismatch)
        )
    }

    @Test
    fun everyCase_rendersItsOwnLabel() {
        val labels = mapOf(
            EnrollmentRefusal.MalformedPackage("TCG-CSR-IDEVID does not parse") to
                R.string.device_enrollment_refused_malformed_package,
            EnrollmentRefusal.UntrustedEndorsement("EK certificate is self-signed") to
                R.string.device_enrollment_refused_untrusted_endorsement,
            EnrollmentRefusal.ActivationMismatch("returned a different secret") to
                R.string.device_enrollment_refused_activation_mismatch,
            EnrollmentRefusal.ActivationUnsupported("could not build a credential challenge") to
                R.string.device_enrollment_refused_activation_unsupported,
            EnrollmentRefusal.QuoteInvalid("quote carries no PCR values") to
                R.string.device_enrollment_refused_quote_invalid
        )

        labels.forEach { (refusal, label) ->
            seedRefusal(refusal)
            val scenario = launch()
            assertShownTextInTree(scenario, context.getString(label))
            assertShownTextInTree(scenario, refusal.detail)
            closeScenario()
        }
    }

    @Test
    fun aRefusedDevice_labelsTheRowsSoTheCaseIsReadable() {
        seedRefusal(EnrollmentRefusal.QuoteInvalid("quote echoed a nonce this CA did not send"))

        val scenario = launch()

        assertRowShown(scenario, R.string.device_enrollment_refused_label, true)
        assertRowShown(scenario, R.string.device_enrollment_refused_detail, true)
        assertRowShown(scenario, R.string.device_enrollment_refused_when, true)
    }

    // ---------------------------------------------------------------
    // Nothing on record
    // ---------------------------------------------------------------

    /**
     * Most devices were never refused. An empty row would read as a missing
     * value rather than as "this never happened", so the rows are not there at
     * all.
     */
    @Test
    fun aDeviceThatWasNeverRefused_showsNoRefusalRows() {
        val scenario = launch()

        assertRowShown(scenario, R.string.device_enrollment_refused_label, false)
        assertRowShown(scenario, R.string.device_enrollment_refused_detail, false)
        assertRowShown(scenario, R.string.device_enrollment_refused_when, false)
    }

    /**
     * A device that enrolled after being refused holds a certificate, and the
     * old reason no longer describes it.
     */
    @Test
    fun aDeviceThatEnrolledAfterwards_showsNoRefusal() {
        seedRefusal(EnrollmentRefusal.QuoteInvalid("quote carries no PCR values"))
        enrolledDevices.enroll(
            EnrolledDevice(
                deviceId = publicKeyHex,
                publicKeyHex = publicKeyHex,
                enrolledAt = System.currentTimeMillis(),
                trustLevel = "full-attestation"
            )
        )

        val scenario = launch()

        assertRowShown(scenario, R.string.device_enrollment_refused_label, false)
        assertTextNotInTree(
            scenario,
            context.getString(R.string.device_enrollment_refused_quote_invalid)
        )
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    private fun seedRefusal(refusal: EnrollmentRefusal) {
        enrolledDevices.recordRefusal(
            EnrollmentRefusalRecord(
                deviceId = publicKeyHex,
                deviceName = deviceName,
                refusal = refusal,
                refusedAt = System.currentTimeMillis()
            )
        )
    }

    private fun launch(): ActivityScenario<DeviceDetailActivity> {
        val intent = Intent(context, DeviceDetailActivity::class.java).apply {
            putExtra(DeviceDetailActivity.EXTRA_PUBLIC_KEY_HEX, publicKeyHex)
        }
        val launched = ActivityScenario.launch<DeviceDetailActivity>(intent)
        scenario = launched
        awaitText(launched, deviceName)
        return launched
    }

    private fun closeScenario() {
        scenario?.close()
        scenario = null
    }

    /**
     * Asserts that the row labelled [label] is or is not on screen.
     *
     * `createInfoRow` builds `[label][value]` inside its own container and the
     * whole container is hidden when there is nothing to report, so the label's
     * parent is what carries the visibility.
     */
    private fun assertRowShown(
        scenario: ActivityScenario<DeviceDetailActivity>,
        label: Int,
        expected: Boolean
    ) {
        val text = context.getString(label)
        val shown = awaitActivity(scenario) { activity ->
            rowVisibility(activity, text) == (if (expected) View.VISIBLE else View.GONE)
        }
        assertTrue(
            "Expected the '$text' row to be ${if (expected) "shown" else "hidden"}",
            shown
        )
        if (!expected) {
            assertEquals(
                View.GONE,
                withActivity(scenario) { rowVisibility(it, text) }
            )
        }
    }

    private fun rowVisibility(activity: DeviceDetailActivity, label: String): Int? {
        val labelView = collectViews(activity.window.decorView) {
            it is TextView && it.text?.toString() == label
        }.firstOrNull() ?: return null
        return (labelView.parent as? ViewGroup)?.visibility
    }
}
