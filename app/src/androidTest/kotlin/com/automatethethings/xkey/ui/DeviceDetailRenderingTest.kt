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
import android.content.SharedPreferences
import android.view.MenuItem
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.TextView
import androidx.appcompat.widget.PopupMenu
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.automatethethings.xkey.settings.PairedDeviceData
import com.automatethethings.xkey.settings.PairedDeviceRepository
import org.json.JSONArray
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Value-formatting branches of [DeviceDetailActivity].
 *
 * `DeviceDetailFlowTest` seeds through [PairedDeviceRepository], whose write
 * methods always stamp `System.currentTimeMillis()` and always demand a
 * non-null certificate subject and expiry. That leaves four rendering branches
 * unreachable from the existing suites: the three non-"Just now" arms of the
 * relative-time formatter, the seconds-only arm of the grace-period countdown,
 * and the two `?:` fallbacks in the identity card. It also never touches
 * `onOptionsItemSelected`, which is 0% covered because both back-navigation
 * tests press the system back button.
 *
 * Those states are produced by rewriting this suite's own record in the
 * repository's `EncryptedSharedPreferences` file, built with the same master key
 * and schemes the production code uses. Only the row whose public key this run
 * generated is rewritten — every other paired device is round-tripped through
 * `PairedDeviceData.toJson()` untouched — and the record is removed in `@After`.
 */
@RunWith(AndroidJUnit4::class)
class DeviceDetailRenderingTest {

    private val runId = System.nanoTime()

    /** 32 bytes of hex, unique to this run. */
    private val publicKeyHex = "de".repeat(31) + String.format("%02x", (runId and 0xFF).toInt())

    private val deviceName = "UITestRender$runId"

    private lateinit var context: Context
    private lateinit var repository: PairedDeviceRepository

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        repository = PairedDeviceRepository(context)
        repository.removeDevice(publicKeyHex)
        repository.addDevice(publicKeyHex = publicKeyHex, deviceName = deviceName)
    }

    @After
    fun tearDown() {
        repository.removeDevice(publicKeyHex)
    }

    // ---------------------------------------------------------------
    // Relative time
    // ---------------------------------------------------------------

    /** A connection minutes old is reported in minutes. */
    @Test
    fun aConnectionMinutesOld_isReportedInMinutes() {
        mutateDevice { it.copy(lastConnectedAt = System.currentTimeMillis() - 5 * MINUTE_MS) }

        val scenario = launch()

        assertRowValue(
            scenario,
            context.getString(R.string.device_last_connected),
            context.getString(R.string.device_minutes_ago, 5)
        )
        scenario.close()
    }

    /** A connection hours old is reported in hours. */
    @Test
    fun aConnectionHoursOld_isReportedInHours() {
        mutateDevice { it.copy(lastConnectedAt = System.currentTimeMillis() - 3 * HOUR_MS) }

        val scenario = launch()

        assertRowValue(
            scenario,
            context.getString(R.string.device_last_connected),
            context.getString(R.string.device_hours_ago, 3)
        )
        scenario.close()
    }

    /**
     * Anything older than a day stops being relative and becomes a date.
     *
     * The expected string is computed with the same format and locale the
     * activity uses, so the assertion holds wherever the device is configured.
     */
    @Test
    fun aConnectionOlderThanADay_isReportedAsADate() {
        val timestamp = System.currentTimeMillis() - 5 * DAY_MS
        mutateDevice { it.copy(lastConnectedAt = timestamp) }

        val scenario = launch()

        assertRowValue(
            scenario,
            context.getString(R.string.device_last_connected),
            SimpleDateFormat("MMM d, yyyy", Locale.getDefault()).format(Date(timestamp))
        )
        scenario.close()
    }

    /** The attestation row runs through the same formatter. */
    @Test
    fun anAttestationHoursOld_isReportedInHours() {
        mutateDevice {
            it.copy(lastAttestationTime = System.currentTimeMillis() - 2 * HOUR_MS)
        }

        val scenario = launch()

        assertRowValue(
            scenario,
            context.getString(R.string.device_last_attested),
            context.getString(R.string.device_hours_ago, 2)
        )
        scenario.close()
    }

    // ---------------------------------------------------------------
    // Grace-period countdown
    // ---------------------------------------------------------------

    /**
     * A grace period under a minute renders seconds only.
     *
     * The hours-minutes-seconds and minutes-seconds arms are already driven by
     * `DeviceDetailFlowTest`; a one-minute window is the only way to leave both
     * the hour and the minute component at zero.
     */
    @Test
    fun aGracePeriodUnderAMinute_countsDownInSecondsOnly() {
        mutateDevice {
            it.copy(
                lastAttestationTime = System.currentTimeMillis(),
                attestationGracePeriodMinutes = 1
            )
        }

        val scenario = launch()

        assertTrue(
            "The countdown should render seconds only",
            awaitActivity(scenario) { activity ->
                valueForLabel(activity, activity.getString(R.string.device_time_remaining))
                    ?.matches(Regex("""\d+s""")) == true
            }
        )
        scenario.close()
    }

    // ---------------------------------------------------------------
    // Identity card fallbacks
    // ---------------------------------------------------------------

    /**
     * A verified IDevID with no recorded subject still renders its row, marked
     * unknown rather than blank.
     */
    @Test
    fun aVerifiedIdevIdWithNoSubject_rendersAsUnknown() {
        mutateDevice {
            it.copy(
                idevidCertificateDER = ByteArray(8) { byte -> byte.toByte() },
                idevidTrustLevel = TRUST_LEVEL,
                idevidSubjectDN = null,
                idevidNotAfter = System.currentTimeMillis() + 365L * DAY_MS
            )
        }

        val scenario = launch()

        assertRowValue(
            scenario,
            context.getString(R.string.device_idevid_subject),
            context.getString(R.string.device_unknown)
        )
        scenario.close()
    }

    /**
     * An IDevID with no expiry counts as expired — the conservative default —
     * so the badge appears and the expiry row reads N/A.
     */
    @Test
    fun anIdevIdWithNoExpiry_readsAsExpired() {
        mutateDevice {
            it.copy(
                idevidCertificateDER = ByteArray(8) { byte -> byte.toByte() },
                idevidTrustLevel = TRUST_LEVEL,
                idevidSubjectDN = "CN=xKey Render Test $runId",
                idevidNotAfter = null
            )
        }

        val scenario = launch()

        assertShownTextInTree(scenario, context.getString(R.string.device_idevid_expired))
        assertRowValue(
            scenario,
            context.getString(R.string.device_idevid_expires),
            context.getString(R.string.device_na)
        )
        scenario.close()
    }

    /**
     * Copying the fingerprint of a device that has no IDevID does nothing: there
     * is no certificate to hash, so the confirmation must not appear.
     */
    @Test
    fun copyingTheFingerprintWithNoIdevId_isANoOp() {
        val scenario = launch()

        clickFingerprintCopy(scenario)

        assertTextNotInTree(scenario, context.getString(R.string.device_fingerprint_copied))
        scenario.close()
    }

    // ---------------------------------------------------------------
    // Options menu
    // ---------------------------------------------------------------

    /** The `home` item routes through the back dispatcher and closes the screen. */
    @Test
    fun homeMenuItem_finishesTheActivity() {
        val scenario = launch()

        val handled = selectMenuItem(scenario, android.R.id.home)

        assertTrue("The home item should be handled by the activity", handled)
        assertActivityDestroyed(scenario)
    }

    /** Any other item falls through to the superclass and is left unhandled. */
    @Test
    fun anUnrecognisedMenuItem_isNotHandled() {
        val scenario = launch()

        val handled = selectMenuItem(scenario, UNRECOGNISED_ITEM_ID)

        assertFalse("An unknown menu item must not be claimed", handled)
        assertFalse(
            "An unhandled menu item must not close the screen",
            withActivity(scenario) { it.isFinishing }
        )
        scenario.close()
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    private fun launch(): ActivityScenario<DeviceDetailActivity> {
        val intent = Intent(context, DeviceDetailActivity::class.java).apply {
            putExtra(DeviceDetailActivity.EXTRA_PUBLIC_KEY_HEX, publicKeyHex)
        }
        val scenario = ActivityScenario.launch<DeviceDetailActivity>(intent)
        awaitText(scenario, deviceName)
        return scenario
    }

    /**
     * Clicks the copy affordance beside the IDevID fingerprint.
     *
     * The button carries no text of its own, so it is located as the row's only
     * [ImageView] — the fingerprint label is what identifies the row.
     */
    private fun clickFingerprintCopy(scenario: ActivityScenario<DeviceDetailActivity>) {
        scenario.onActivity { activity ->
            val label = activity.getString(R.string.device_idevid_fingerprint)
            val labelView = collectViews(activity.window.decorView) {
                it is TextView && it.text?.toString() == label
            }.firstOrNull() ?: throw AssertionError("No fingerprint row on the identity card")
            val row = labelView.parent as ViewGroup
            collectViews(row) { it is ImageView }.firstOrNull()?.performClick()
        }
        waitForIdle()
    }

    /** Passes a synthesised [MenuItem] with [itemId] to the activity's handler. */
    private fun selectMenuItem(
        scenario: ActivityScenario<DeviceDetailActivity>,
        itemId: Int
    ): Boolean {
        val handled = withActivity(scenario) { activity ->
            val item: MenuItem = PopupMenu(activity, activity.window.decorView)
                .menu
                .add(0, itemId, 0, "synthetic")
            activity.onOptionsItemSelected(item)
        }
        waitForIdle()
        return handled
    }

    /** Asserts that the info row labelled [label] settles on [value]. */
    private fun assertRowValue(
        scenario: ActivityScenario<DeviceDetailActivity>,
        label: String,
        value: String
    ) {
        assertTrue(
            "Expected the '$label' row to read '$value'",
            awaitActivity(scenario) { valueForLabel(it, label) == value }
        )
    }

    /**
     * The value rendered beside [label].
     *
     * `createInfoRow` builds `[label][value]` inside its own container, so the
     * value is the row's other text view rather than a child of the label.
     */
    private fun valueForLabel(activity: DeviceDetailActivity, label: String): String? {
        val labelView = collectViews(activity.window.decorView) {
            it is TextView && it.text?.toString() == label
        }.firstOrNull() ?: return null
        val row = labelView.parent as? ViewGroup ?: return null
        return collectViews(row) { it is TextView && it !== labelView }
            .map { (it as TextView).text?.toString().orEmpty() }
            .firstOrNull { it.isNotEmpty() }
    }

    // ---------------------------------------------------------------
    // Seeding beyond what the repository can express
    // ---------------------------------------------------------------

    /**
     * Rewrites this suite's own device record with [transform] applied.
     *
     * Every other record is round-tripped verbatim, so a suite running before or
     * after this one keeps its devices. The preferences file is opened with the
     * same master key and encryption schemes the repository uses, which is the
     * only way to write timestamps in the past or leave the certificate fields
     * partly null — the repository's writers always stamp "now" and always
     * demand a subject and an expiry.
     */
    private fun mutateDevice(transform: (PairedDeviceData) -> PairedDeviceData) {
        val prefs = devicePrefs()
        val stored = JSONArray(prefs.getString(KEY_DEVICES, "[]"))
        val rewritten = JSONArray()
        for (index in 0 until stored.length()) {
            val device = PairedDeviceData.fromJson(stored.getJSONObject(index))
            rewritten.put(
                if (device.publicKeyHex == publicKeyHex) transform(device).toJson() else device.toJson()
            )
        }
        prefs.edit().putString(KEY_DEVICES, rewritten.toString()).commit()
    }

    private fun devicePrefs(): SharedPreferences {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        return EncryptedSharedPreferences.create(
            context,
            PREFS_NAME,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    private companion object {

        /** Mirrors `PairedDeviceRepository.PREFS_NAME`, which is private. */
        const val PREFS_NAME = "xkey_paired_devices"

        /** Mirrors `PairedDeviceRepository.KEY_DEVICES`, which is private. */
        const val KEY_DEVICES = "paired_devices"

        const val TRUST_LEVEL = "android-ca"

        /** An id no resource in this app can collide with. */
        const val UNRECOGNISED_ITEM_ID = 0x7EEE0002

        const val MINUTE_MS = 60_000L
        const val HOUR_MS = 60 * MINUTE_MS
        const val DAY_MS = 24 * HOUR_MS
    }
}
