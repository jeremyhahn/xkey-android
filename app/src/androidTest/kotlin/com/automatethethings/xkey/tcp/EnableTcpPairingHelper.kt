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
package com.automatethethings.xkey.tcp

import android.content.Context
import android.content.Intent
import com.automatethethings.xkey.ble.XKeyGattService
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.automatethethings.xkey.settings.BiometricSettingsRepository
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.usb.UsbHsmSettingsRepository
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Turns on the loopback TCP pairing server so the desktop end-to-end probe can
 * reach this app over `adb forward`.
 *
 * Not a test of anything: it is a fixture the host-side probe needs, kept here
 * because the setting lives in a DataStore only the app can write. It is
 * excluded from ordinary suites by name -- nothing runs it unless it is asked
 * for explicitly by class.
 */
@RunWith(AndroidJUnit4::class)
class EnableTcpPairingHelper {

    @Test
    fun enableTcpPairing() {
        val context: Context = ApplicationProvider.getApplicationContext()
        val repository = UsbHsmSettingsRepository(context)

        runBlocking {
            repository.setTcpHsmEnabled(true)
            val settings = repository.settingsFlow.first()
            assertTrue("TCP pairing must be enabled", settings.tcpHsmEnabled)
        }

        // Disable the biometric gate for an unattended run when asked (emulators have no fingerprint); off by default.
        if (InstrumentationRegistry.getArguments().getString("disableUv") == "true") {
            runBlocking { BiometricSettingsRepository(context).setBiometricEnabled(false) }
        }

        // Pre-trust the probe's Noise static key when supplied: the trust the user would grant by approving once.
        InstrumentationRegistry.getArguments()
            .getString("probePublicKeyHex")
            ?.trim()
            ?.takeIf { it.isNotEmpty() }
            ?.let { publicKeyHex ->
                PairedDeviceRepository(context).addDevice(publicKeyHex, "e2eprobe")
            }

        // Start the service from here: it is not exported, and a foreground service outlives instrumentation.
        val intent = Intent(context, XKeyGattService::class.java).apply {
            action = XKeyGattService.ACTION_START_ADVERTISING
        }
        context.startForegroundService(intent)

        // Keep the process alive for the probe run, for the holdSeconds instrumentation argument.
        val holdSeconds = InstrumentationRegistry.getArguments()
            .getString("holdSeconds")?.toLongOrNull() ?: DEFAULT_HOLD_SECONDS
        Thread.sleep(holdSeconds * 1000L)
    }

    private companion object {
        const val DEFAULT_HOLD_SECONDS = 3L
    }
}
