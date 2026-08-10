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
package com.automatethethings.xkey.e2e

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.settings.AttestationBiometricPolicy
import com.automatethethings.xkey.settings.BiometricSettingsRepository
import com.automatethethings.xkey.settings.UserVerificationPolicy
import com.automatethethings.xkey.usb.UsbHsmSettingsRepository
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Live-E2E setup helper, not a functional test. Applies exactly the settings a
 * user would choose in the app before an unattended conformance run, so the
 * host can start XKeyGattService and drive it with
 * `go-xkms/xkey/cmd/e2eprobe`:
 *
 *  - TCP pairing (ADB) enabled, so the loopback :8444 server starts.
 *  - User verification DISABLED and attestation biometric policy NEVER,
 *    because an emulator has no enrolled biometrics and Keystore refuses to
 *    generate auth-bound keys without them.
 *
 * Run with:
 * ```
 * ./gradlew connectedDebugAndroidTest \
 *   -Pandroid.testInstrumentationRunnerArguments.class=com.automatethethings.xkey.e2e.TcpHsmSettingEnabler
 * ```
 */
@RunWith(AndroidJUnit4::class)
class TcpHsmSettingEnabler {

    @Test
    fun configureForHeadlessE2E() = runBlocking {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()

        val usbHsmSettings = UsbHsmSettingsRepository(context)
        usbHsmSettings.setTcpHsmEnabled(true)
        assertTrue(usbHsmSettings.settingsFlow.first().tcpHsmEnabled)

        val biometricSettings = BiometricSettingsRepository(context)
        biometricSettings.updateUserVerificationPolicy(UserVerificationPolicy.DISABLED)
        biometricSettings.updateAttestationBiometricPolicy(AttestationBiometricPolicy.NEVER)
    }
}
