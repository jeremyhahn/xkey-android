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

        // Stand the biometric gate down for an unattended run, when asked.
        //
        // The gate itself has its own instrumented coverage; what the host
        // probe exercises is the enrollment protocol, and an emulator has no
        // fingerprint to answer a prompt with -- every gated method fails with
        // "No fingerprints enrolled" before reaching the code under test.
        //
        // Off by default, so an ordinary run still requires user presence.
        if (InstrumentationRegistry.getArguments().getString("disableUv") == "true") {
            runBlocking { BiometricSettingsRepository(context).setBiometricEnabled(false) }
        }

        // Pre-trust the probe's Noise static key, when one was supplied.
        //
        // Approving an unknown peer is a human decision by design -- the
        // service answers pairing.confirm with PAIRING_REJECTED when no
        // approval UI can be reached. Registering the key here is the same
        // trust the user would grant once by tapping approve, which is what
        // lets an unattended run proceed without weakening that gate.
        InstrumentationRegistry.getArguments()
            .getString("probePublicKeyHex")
            ?.trim()
            ?.takeIf { it.isNotEmpty() }
            ?.let { publicKeyHex ->
                PairedDeviceRepository(context).addDevice(publicKeyHex, "e2eprobe")
            }

        // The TCP listener lives inside XKeyGattService, so the setting alone
        // opens nothing. Started from here rather than over adb because the
        // service is not exported: `am start-foreground-service` is refused
        // with "not exported from uid", and instrumentation runs as the app.
        //
        // A foreground service outlives the instrumentation process, which is
        // what lets the host-side probe connect after this returns.
        val intent = Intent(context, XKeyGattService::class.java).apply {
            action = XKeyGattService.ACTION_START_ADVERTISING
        }
        context.startForegroundService(intent)

        // Hold the process open while the host-side probe runs.
        //
        // The service was started from the instrumentation process, and when
        // instrumentation returns that process is killed -- taking the
        // listener with it before anything can connect. Blocking here keeps it
        // alive for the length of one probe run. The duration is read from an
        // instrumentation argument so the caller sets it:
        //
        //   adb shell am instrument -w \
        //     -e class com.automatethethings.xkey.tcp.EnableTcpPairingHelper \
        //     -e holdSeconds 180 \
        //     com.automatethethings.xkey.debug.test/androidx.test.runner.AndroidJUnitRunner
        val holdSeconds = InstrumentationRegistry.getArguments()
            .getString("holdSeconds")?.toLongOrNull() ?: DEFAULT_HOLD_SECONDS
        Thread.sleep(holdSeconds * 1000L)
    }

    private companion object {
        const val DEFAULT_HOLD_SECONDS = 3L
    }
}
