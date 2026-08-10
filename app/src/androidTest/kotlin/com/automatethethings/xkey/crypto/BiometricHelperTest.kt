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
import org.junit.Assert.assertNotNull
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
    fun isBiometricAvailable_returnsBoolean() {
        ActivityScenario.launch(MainActivity::class.java).onActivity { activity ->
            val helper = BiometricHelper(activity)

            // Should return a valid boolean without throwing
            val result = helper.isBiometricAvailable()
            assertNotNull(result)
        }
    }

    @Test
    fun getBiometricStatus_returnsValidStatus() {
        ActivityScenario.launch(MainActivity::class.java).onActivity { activity ->
            val helper = BiometricHelper(activity)

            val status = helper.getBiometricStatus()

            assertNotNull("Status should not be null", status)
            assertTrue(
                "Status should be a valid BiometricStatus",
                status in BiometricStatus.values()
            )
        }
    }

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

    @Test
    fun biometricStatus_coversAllPossibleStates() {
        // Verify all expected status values exist
        val allStatuses = BiometricStatus.values()

        assertTrue(
            "Should have AVAILABLE status",
            allStatuses.contains(BiometricStatus.AVAILABLE)
        )
        assertTrue(
            "Should have NO_HARDWARE status",
            allStatuses.contains(BiometricStatus.NO_HARDWARE)
        )
        assertTrue(
            "Should have HARDWARE_UNAVAILABLE status",
            allStatuses.contains(BiometricStatus.HARDWARE_UNAVAILABLE)
        )
        assertTrue(
            "Should have NONE_ENROLLED status",
            allStatuses.contains(BiometricStatus.NONE_ENROLLED)
        )
        assertTrue(
            "Should have SECURITY_UPDATE_REQUIRED status",
            allStatuses.contains(BiometricStatus.SECURITY_UPDATE_REQUIRED)
        )
        assertTrue(
            "Should have UNKNOWN status",
            allStatuses.contains(BiometricStatus.UNKNOWN)
        )
    }

    @Test
    fun biometricHelper_canBeCreatedMultipleTimes() {
        ActivityScenario.launch(MainActivity::class.java).onActivity { activity ->
            // Creating multiple helpers should not cause issues
            val helper1 = BiometricHelper(activity)
            val helper2 = BiometricHelper(activity)

            // Both should work independently
            val status1 = helper1.getBiometricStatus()
            val status2 = helper2.getBiometricStatus()

            assertEquals(
                "Multiple helpers should report same status",
                status1,
                status2
            )
        }
    }

    @Test
    fun biometricHelper_statusIsConsistent() {
        ActivityScenario.launch(MainActivity::class.java).onActivity { activity ->
            val helper = BiometricHelper(activity)

            // Multiple calls should return consistent results
            val status1 = helper.getBiometricStatus()
            val status2 = helper.getBiometricStatus()
            val status3 = helper.getBiometricStatus()

            assertEquals("Status should be consistent", status1, status2)
            assertEquals("Status should be consistent", status2, status3)
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
