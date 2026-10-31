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
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.R
import com.automatethethings.xkey.settings.PairedDeviceRepository
import org.junit.After
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented tests for the connected-device badge on [PairedDevicesActivity].
 *
 * The badge was driven by a hardcoded `connectedCount = 0`, so it could never
 * appear whatever the state of the GATT session — dead UI promising information
 * the screen never had. It now reads the live connection state of
 * [com.automatethethings.xkey.ble.XKeyGattService].
 *
 * No session exists under test, and the screen deliberately binds to the service
 * *without* `BIND_AUTO_CREATE` so that opening the device list never brings the
 * foreground service up. These tests therefore pin the honest observable
 * behaviour: with nothing connected the badge stays hidden — including for a
 * paired device, which is exactly the case a placeholder count could not tell
 * apart — and the service binding survives a full lifecycle round trip.
 *
 * One device is added per test and removed in @After.
 */
@RunWith(AndroidJUnit4::class)
class PairedDevicesConnectedBadgeTest {

    private lateinit var context: Context
    private lateinit var repository: PairedDeviceRepository

    private var scenario: ActivityScenario<PairedDevicesActivity>? = null

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

    /**
     * A paired device holding no session is not a connected device, so the badge
     * stays out of the way rather than claiming one.
     */
    @Test
    fun connectedBadge_isHiddenWhileNoSessionExists() {
        val scenario = launch()

        assertShownTextInList(scenario, DEVICE_NAME)
        assertBadgeHidden(scenario)
    }

    /**
     * The screen binds to the GATT service to read the connection state; a
     * lifecycle round trip must leave both the binding and the badge intact.
     */
    @Test
    fun connectedBadge_survivesARecreate() {
        val scenario = launch()
        assertShownTextInList(scenario, DEVICE_NAME)

        scenario.recreate()

        assertShownTextInList(scenario, DEVICE_NAME)
        assertBadgeHidden(scenario)
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    private fun launch(): ActivityScenario<PairedDevicesActivity> {
        val launched = ActivityScenario.launch(PairedDevicesActivity::class.java)
        scenario = launched
        return launched
    }

    /**
     * Asserts the badge is not on screen.
     *
     * Matched on the rendered text for a single connection: the badge is the
     * only view that can read "1 connected", and the neighbouring
     * last-connection line says "connection", never "connected".
     */
    private fun assertBadgeHidden(scenario: ActivityScenario<PairedDevicesActivity>) {
        val badgeText = context.getString(R.string.paired_devices_connected_count, 1)
        assertNull(
            "The connected badge must not be shown without a session",
            withActivity(scenario) {
                findShownTextViewContaining(it.window.decorView, badgeText)
            }
        )
    }

    private companion object {
        /** A 32-byte Noise static public key, distinct from every other suite's. */
        const val DEVICE_KEY_HEX =
            "2b3c4d5e6f708192a3b4c5d6e7f809102b3c4d5e6f708192a3b4c5d6e7f80910"
        const val DEVICE_NAME = "xKey Badge Suite Laptop"
    }
}
