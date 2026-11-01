/*
 * Copyright (c) 2025 Jeremy Hahn
 * Copyright (c) 2025 Automate The Things, LLC
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
package com.automatethethings.xkey.crypto

import androidx.biometric.BiometricManager
import androidx.test.core.app.ActivityScenario
import com.automatethethings.xkey.ui.MainActivity
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented tests for BiometricHelper.
 *
 * These tests verify the biometric availability checking functionality.
 * Actual biometric authentication cannot be tested automatically as it
 * requires real user interaction.
 *
 * Note: These tests launch MainActivity to provide the required
 * FragmentActivity context for BiometricHelper.
 */
@RunWith(AndroidJUnit4::class)
class BiometricHelperTest {

    @Test
    fun getBiometricStatus_matchesIsBiometricAvailable() {
        ActivityScenario.launch(MainActivity::class.java).onActivity { activity ->
            val helper = BiometricHelper(activity)

            val isAvailable = helper.isBiometricAvailable()
            val status = helper.getBiometricStatus()

            if (isAvailable) {
                assertEquals(
                    "When available, status should be AVAILABLE",
                    BiometricStatus.AVAILABLE,
                    status
                )
            } else {
                assertTrue(
                    "When not available, status should not be AVAILABLE",
                    status != BiometricStatus.AVAILABLE
                )
            }
        }
    }

    /**
     * Note: The following tests are intentionally NOT included because they
     * require actual user interaction with biometric hardware:
     *
     * - authenticate() success path
     * - authenticate() with CryptoObject
     * - authenticateWithoutCrypto() success path
     * - Actual biometric lockout behavior
     *
     * These scenarios should be tested manually during development and QA.
     * Integration tests that mock the BiometricPrompt callbacks can be
     * added if needed for CI/CD pipelines.
     */
}
