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

import android.text.TextUtils
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators
import androidx.biometric.BiometricPrompt
import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The two prompt shapes the app builds, and the codes it branches on, under
 * androidx.biometric 1.4.0-alpha07 (upgraded from 1.2.0-alpha05).
 *
 * `PromptInfo.Builder.build()` throws on an invalid prompt, and every call
 * site builds on the path that signs with a TEE key, so a combination the
 * new version rejects fails every signature. 1.4 dropped 1.2's negative-text
 * checks from `build()` and kept the title and authenticator-combination
 * checks (`AuthenticatorUtils.isSupportedCombination`, now in
 * `androidx.biometric.utils`). The JVM's `Build.VERSION.SDK_INT` is 0, so
 * the STRONG | DEVICE_CREDENTIAL arm, which depends on the API level, takes
 * its pre-P branch here; that branch, and the API 28-29 rejection, are the
 * same in both versions.
 */
class BiometricLibraryUpgradeTest {

    @Before
    fun setUp() {
        // build() checks the title with TextUtils.isEmpty, which the
        // unit-test android.jar does not implement.
        mockkStatic(TextUtils::class)
        every { TextUtils.isEmpty(any()) } answers { firstArg<CharSequence?>().isNullOrEmpty() }
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    /**
     * Turns red if 1.4 rejects, or drops a field of, the prompt that
     * BiometricHelper.kt:143-148 and :202-207, CryptoSigningActivity.kt:264-270
     * and TransparentBiometricActivity.kt:160-165 build for key signing.
     */
    @Test
    fun `strong-biometric signing prompt with a cancel button builds`() {
        val prompt = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Sign with xKey")
            .setSubtitle("Confirm with your fingerprint")
            .setNegativeButtonText("Cancel")
            .setAllowedAuthenticators(Authenticators.BIOMETRIC_STRONG)
            .setConfirmationRequired(true)
            .build()

        assertEquals("Sign with xKey", prompt.title)
        assertEquals("Confirm with your fingerprint", prompt.subtitle)
        assertEquals("Cancel", prompt.negativeButtonText)
        assertEquals(Authenticators.BIOMETRIC_STRONG, prompt.allowedAuthenticators)
        assertTrue(prompt.isConfirmationRequired)
    }

    /**
     * Turns red if 1.4 rejects the passkey prompt CredentialSelectorActivity.kt:265-269
     * builds: STRONG | DEVICE_CREDENTIAL and, as device credential requires,
     * no negative button.
     */
    @Test
    fun `passkey prompt allowing device credential builds without a negative button`() {
        val authenticators = Authenticators.BIOMETRIC_STRONG or Authenticators.DEVICE_CREDENTIAL

        val prompt = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Use passkey")
            .setSubtitle("webauthn.io")
            .setAllowedAuthenticators(authenticators)
            .build()

        assertEquals(authenticators, prompt.allowedAuthenticators)
        assertEquals("", prompt.negativeButtonText.toString())
    }

    /**
     * Turns red if 1.4 renumbers an authenticator or status constant away
     * from the framework value: the app passes these to the framework
     * through the library (BiometricHelper.kt:65-66, :79-80,
     * CreateCredentialHandler.kt:71-73, CredentialSelectorActivity.kt:234-236)
     * and compares the returned status in BiometricHelper.kt:82-89. 1.4 moved
     * the status values onto the new `BiometricConstants`. Expected values
     * are the framework's (android.hardware.biometrics.BiometricManager).
     */
    @Test
    fun `authenticator and status constants keep the framework values`() {
        assertEquals(0x000F, Authenticators.BIOMETRIC_STRONG)
        assertEquals(0x8000, Authenticators.DEVICE_CREDENTIAL)
        assertEquals(0, BiometricManager.BIOMETRIC_SUCCESS)
        assertEquals(1, BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE)
        assertEquals(11, BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED)
        assertEquals(12, BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE)
        assertEquals(15, BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED)
        assertEquals(-1, BiometricManager.BIOMETRIC_STATUS_UNKNOWN)
    }

    /**
     * Turns red if 1.4 renumbers an error code away from the framework value
     * it forwards to `onAuthenticationError`: BiometricHelper.kt:227-271 maps
     * these to typed exceptions, so a shifted code would, for example, report
     * a lockout as a generic error. 1.4 moved these declarations off
     * BiometricPrompt onto the package-private `BiometricConstants` it
     * implements. Expected values are the framework's
     * (android.hardware.biometrics.BiometricConstants).
     */
    @Test
    fun `prompt error codes keep the framework values`() {
        assertEquals(1, BiometricPrompt.ERROR_HW_UNAVAILABLE)
        assertEquals(2, BiometricPrompt.ERROR_UNABLE_TO_PROCESS)
        assertEquals(3, BiometricPrompt.ERROR_TIMEOUT)
        assertEquals(4, BiometricPrompt.ERROR_NO_SPACE)
        assertEquals(5, BiometricPrompt.ERROR_CANCELED)
        assertEquals(7, BiometricPrompt.ERROR_LOCKOUT)
        assertEquals(8, BiometricPrompt.ERROR_VENDOR)
        assertEquals(9, BiometricPrompt.ERROR_LOCKOUT_PERMANENT)
        assertEquals(10, BiometricPrompt.ERROR_USER_CANCELED)
        assertEquals(11, BiometricPrompt.ERROR_NO_BIOMETRICS)
        assertEquals(12, BiometricPrompt.ERROR_HW_NOT_PRESENT)
        assertEquals(13, BiometricPrompt.ERROR_NEGATIVE_BUTTON)
        assertEquals(14, BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL)
        assertEquals(15, BiometricPrompt.ERROR_SECURITY_UPDATE_REQUIRED)
    }
}
