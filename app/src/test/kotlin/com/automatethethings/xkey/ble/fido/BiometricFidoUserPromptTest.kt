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

package com.automatethethings.xkey.ble.fido

import android.content.Context
import android.hardware.biometrics.BiometricManager
import androidx.test.core.app.ApplicationProvider
import com.automatethethings.xkey.auth.BiometricActivityLauncher
import io.mockk.mockk
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.shadow.api.Shadow
import org.robolectric.shadows.ShadowBiometricManager

/**
 * getInfo's `uv` comes from [BiometricFidoUserPrompt.available], so it may
 * only claim the verification the prompt can perform. The prompt
 * (TransparentBiometricActivity) accepts a strong biometric only.
 */
@RunWith(RobolectricTestRunner::class)
class BiometricFidoUserPromptTest {

    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val launcher = mockk<BiometricActivityLauncher>(relaxed = true)

    private fun enrol(authenticators: Int) {
        val shadow = Shadow.extract<ShadowBiometricManager>(context.getSystemService(BiometricManager::class.java))
        shadow.setCanAuthenticate(true)
        shadow.setAuthenticatorType(authenticators)
    }

    @After
    fun tearDown() = ShadowBiometricManager.reset()

    @Test
    fun `a strong biometric makes user verification available`() {
        enrol(BiometricManager.Authenticators.BIOMETRIC_STRONG)

        assertTrue(BiometricFidoUserPrompt(context) { launcher }.available)
    }

    @Test
    fun `a device credential alone does not advertise user verification the prompt cannot accept`() {
        enrol(BiometricManager.Authenticators.DEVICE_CREDENTIAL)

        assertFalse(BiometricFidoUserPrompt(context) { launcher }.available)
    }

    @Test
    fun `no launcher means no user verification`() {
        enrol(BiometricManager.Authenticators.BIOMETRIC_STRONG)

        assertFalse(BiometricFidoUserPrompt(context) { null }.available)
    }
}
