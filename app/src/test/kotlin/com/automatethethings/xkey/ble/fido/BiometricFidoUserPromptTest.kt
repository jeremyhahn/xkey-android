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
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import com.automatethethings.xkey.auth.BiometricActivityLauncher
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * getInfo's `uv` comes from [BiometricFidoUserPrompt.available], so it may
 * only claim the verification the prompt can perform. The prompt
 * (TransparentBiometricActivity) accepts a strong biometric only.
 */
class BiometricFidoUserPromptTest {

    private val context = mockk<Context>(relaxed = true)
    private val launcher = mockk<BiometricActivityLauncher>(relaxed = true)

    /** A phone on which only [enrolled] authenticators can verify the user. */
    private fun enrol(enrolled: Int) {
        val manager = mockk<BiometricManager>()
        every { manager.canAuthenticate(any()) } answers {
            // As the framework answers: success when any requested
            // authenticator is enrolled.
            if (firstArg<Int>() and enrolled != 0) BiometricManager.BIOMETRIC_SUCCESS
            else BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED
        }
        mockkStatic(BiometricManager::class)
        every { BiometricManager.from(any()) } returns manager
    }

    @After
    fun tearDown() = unmockkAll()

    @Test
    fun `a strong biometric makes user verification available`() {
        enrol(BIOMETRIC_STRONG)

        assertTrue(BiometricFidoUserPrompt(context) { launcher }.available)
    }

    @Test
    fun `a device credential alone does not advertise user verification the prompt cannot accept`() {
        enrol(DEVICE_CREDENTIAL)

        assertFalse(BiometricFidoUserPrompt(context) { launcher }.available)
    }

    @Test
    fun `no launcher means no user verification`() {
        enrol(BIOMETRIC_STRONG)

        assertFalse(BiometricFidoUserPrompt(context) { null }.available)
    }
}
