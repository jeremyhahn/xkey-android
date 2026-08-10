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
import android.widget.CompoundButton
import android.widget.Spinner
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.automatethethings.xkey.settings.PairedDeviceRepository
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented tests for two [DeviceDetailActivity] defects that only show up
 * with values the screen did not itself produce.
 *
 * **Off-preset grace periods.** `attestationGracePeriodMinutes` is a plain
 * `Int`; the six-entry spinner is a UI convenience, not a constraint, and the
 * pairing protocol and other screens can store anything. A value outside the
 * presets used to leave the spinner on its first entry, so the *next* change to
 * any device setting quietly wrote five minutes over it — the attestation
 * validity window silently shrank without the user touching it.
 *
 * **The connection-duration row.** The duration is only meaningful during a
 * session. Hiding the value alone left its label stranded beside an empty
 * column, which is the state whenever the device is disconnected — that is,
 * almost always.
 *
 * One device is paired per test and removed in @After, so devices the user
 * actually paired are untouched.
 */
@RunWith(AndroidJUnit4::class)
class DeviceDetailGracePeriodFlowTest {

    private lateinit var context: Context
    private lateinit var repository: PairedDeviceRepository

    private var scenario: ActivityScenario<DeviceDetailActivity>? = null

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        repository = PairedDeviceRepository(context)
        repository.removeDevice(DEVICE_KEY_HEX)
        repository.addDevice(publicKeyHex = DEVICE_KEY_HEX, deviceName = DEVICE_NAME)
    }

    @After
    fun tearDown() {
        scenario?.close()
        scenario = null
        repository.removeDevice(DEVICE_KEY_HEX)
    }

    // ---------------------------------------------------------------
    // Grace period presets
    // ---------------------------------------------------------------

    /** A preset value selects its own entry and adds nothing to the list. */
    @Test
    fun presetGracePeriod_selectsItsPresetWithoutAddingAnEntry() {
        storeGracePeriod(30)
        val scenario = launch()

        assertEquals(PRESET_COUNT, spinnerItemCount(scenario))
        assertEquals("30 minutes", selectedGracePeriod(scenario))
    }

    /** An off-preset value is named and selected rather than ignored. */
    @Test
    fun offPresetGracePeriod_isOfferedAsItsOwnEntry() {
        storeGracePeriod(OFF_PRESET_MINUTES)
        val scenario = launch()

        assertEquals(PRESET_COUNT + 1, spinnerItemCount(scenario))
        assertEquals(
            context.getString(R.string.device_grace_period_other, OFF_PRESET_MINUTES),
            selectedGracePeriod(scenario)
        )
    }

    /**
     * The regression itself: changing an unrelated setting must not rewrite the
     * grace period. Before the fix the spinner sat on its first entry, so this
     * toggle wrote five minutes over the stored value.
     */
    @Test
    fun offPresetGracePeriod_survivesAnUnrelatedSettingsChange() {
        storeGracePeriod(OFF_PRESET_MINUTES)
        val scenario = launch()

        toggleSwitch(scenario, R.string.device_require_attest_key_use)

        awaitCondition("Toggling a policy should have persisted") {
            repository.getDevice(DEVICE_KEY_HEX)?.requireAttestationForKeyUse == true
        }
        assertEquals(
            "The stored grace period must not be overwritten by an unrelated change",
            OFF_PRESET_MINUTES,
            repository.getDevice(DEVICE_KEY_HEX)?.attestationGracePeriodMinutes
        )
    }

    /** The user can still move an off-preset device onto a preset. */
    @Test
    fun offPresetGracePeriod_canBeReplacedByAPreset() {
        storeGracePeriod(OFF_PRESET_MINUTES)
        val scenario = launch()

        selectGracePeriod(scenario, ONE_HOUR_OPTION_INDEX)

        awaitCondition("The chosen preset should be persisted") {
            repository.getDevice(DEVICE_KEY_HEX)?.attestationGracePeriodMinutes == 60
        }
    }

    /** Reopening the screen on a preset value drops the "Other" entry again. */
    @Test
    fun theOtherEntry_disappearsOnceAPresetIsStored() {
        storeGracePeriod(OFF_PRESET_MINUTES)
        val scenario = launch()

        selectGracePeriod(scenario, ONE_HOUR_OPTION_INDEX)
        awaitCondition("Precondition: the preset was stored") {
            repository.getDevice(DEVICE_KEY_HEX)?.attestationGracePeriodMinutes == 60
        }

        scenario.recreate()
        awaitDeviceName(scenario)

        assertEquals(PRESET_COUNT, spinnerItemCount(scenario))
        assertEquals("1 hour", selectedGracePeriod(scenario))
    }

    // ---------------------------------------------------------------
    // Connection duration row
    // ---------------------------------------------------------------

    /**
     * With no session there is no duration, so the whole row goes — label
     * included. The rest of the connection card stays.
     */
    @Test
    fun connectionDurationRow_isHiddenWhileDisconnected() {
        val scenario = launch()

        assertShownTextInTree(scenario, context.getString(R.string.device_disconnected))
        assertShownTextInTree(scenario, context.getString(R.string.device_last_connected))
        assertNull(
            "The Connection Duration label must not be left behind on its own",
            withActivity(scenario) {
                findShownTextViewContaining(
                    it.window.decorView,
                    context.getString(R.string.device_connection_duration)
                )
            }
        )
    }

    /** The row is hidden, not deleted: it is still there to be shown again. */
    @Test
    fun connectionDurationRow_remainsInTheTreeWhileHidden() {
        val scenario = launch()

        assertNotNull(
            "The Connection Duration row should still exist, ready to be shown",
            withActivity(scenario) {
                findTextViewContaining(
                    it.window.decorView,
                    context.getString(R.string.device_connection_duration)
                )
            }
        )
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    private fun launch(): ActivityScenario<DeviceDetailActivity> {
        val intent = Intent(context, DeviceDetailActivity::class.java).apply {
            putExtra(DeviceDetailActivity.EXTRA_PUBLIC_KEY_HEX, DEVICE_KEY_HEX)
        }
        val launched = ActivityScenario.launch<DeviceDetailActivity>(intent)
        scenario = launched
        awaitDeviceName(launched)
        return launched
    }

    private fun awaitDeviceName(scenario: ActivityScenario<DeviceDetailActivity>) {
        assertShownTextInTree(scenario, DEVICE_NAME)
    }

    private fun storeGracePeriod(minutes: Int) {
        val device = repository.getDevice(DEVICE_KEY_HEX)!!
        repository.updateDeviceSettings(
            publicKeyHex = DEVICE_KEY_HEX,
            requireAttestationForKeyUse = device.requireAttestationForKeyUse,
            requireAttestationForKeyAttestation = device.requireAttestationForKeyAttestation,
            attestationGracePeriodMinutes = minutes
        )
    }

    /** The settings card holds the screen's only [Spinner]. */
    private fun gracePeriodSpinner(scenario: ActivityScenario<DeviceDetailActivity>): Spinner =
        withActivity(scenario) { activity ->
            collectViews(activity.window.decorView) { it is Spinner }.firstOrNull() as? Spinner
                ?: throw AssertionError("The settings card has no grace period spinner")
        }

    private fun spinnerItemCount(scenario: ActivityScenario<DeviceDetailActivity>): Int =
        gracePeriodSpinner(scenario).adapter.count

    private fun selectedGracePeriod(scenario: ActivityScenario<DeviceDetailActivity>): String =
        gracePeriodSpinner(scenario).selectedItem.toString()

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
            assertTrue(
                "The switch should start off so the toggle has an effect",
                !toggle.isChecked
            )
            toggle.isChecked = true
        }
        waitForIdle()
    }

    private companion object {
        /** A 32-byte Noise static public key, distinct from every other suite's. */
        const val DEVICE_KEY_HEX =
            "1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809"
        const val DEVICE_NAME = "xKey Grace Period Device"

        /** Entries in `DeviceDetailActivity.GRACE_PERIOD_OPTIONS`. */
        const val PRESET_COUNT = 6

        /** Index of "1 hour" among the presets. */
        const val ONE_HOUR_OPTION_INDEX = 3

        /**
         * A grace period no preset offers. Reachable through the repository,
         * which every non-UI writer uses.
         */
        const val OFF_PRESET_MINUTES = 7
    }
}
