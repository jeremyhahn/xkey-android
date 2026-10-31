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
package com.automatethethings.xkey.settings

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for [BiometricSettingsData], [AuthTimeWindow] and the biometric
 * policy enums.
 *
 * These are the values that decide whether a user-verification prompt is shown,
 * so the defaults and the "unrecognised persisted value" fallbacks are security
 * relevant: an unknown enum name read back from DataStore must land on the
 * strict option, never the permissive one.
 *
 * [BiometricSettingsRepository] itself needs Jetpack DataStore and is covered
 * by instrumented tests.
 */
class BiometricSettingsDataTest {

    // -------------------------------------------------------------------------
    // Defaults
    // -------------------------------------------------------------------------

    @Test
    fun `defaults are the strict WebAuthn-compliant configuration`() {
        val settings = BiometricSettingsData()

        assertEquals(UserVerificationPolicy.REQUIRED, settings.uvPolicy)
        assertEquals(BiometricAuthMode.PER_OPERATION, settings.authMode)
        assertEquals(120, settings.timeWindowSeconds)
        assertEquals(AttestationBiometricPolicy.ALWAYS, settings.attestationBiometricPolicy)
        assertTrue("strict UV must default on", settings.strictUserVerification)
        assertTrue(settings.isBiometricEnabled)
    }

    @Test
    fun `isBiometricEnabled tracks the uv policy only`() {
        assertTrue(
            BiometricSettingsData(
                uvPolicy = UserVerificationPolicy.REQUIRED,
                authMode = BiometricAuthMode.PER_SESSION
            ).isBiometricEnabled
        )
        assertFalse(
            BiometricSettingsData(
                uvPolicy = UserVerificationPolicy.DISABLED,
                authMode = BiometricAuthMode.PER_OPERATION
            ).isBiometricEnabled
        )
    }

    // -------------------------------------------------------------------------
    // Presets
    // -------------------------------------------------------------------------

    @Test
    fun `DEFAULT preset equals a plain construction`() {
        assertEquals(BiometricSettingsData(), BiometricSettingsData.DEFAULT)
    }

    @Test
    fun `DISABLED preset turns off user verification but keeps other defaults`() {
        val disabled = BiometricSettingsData.DISABLED

        assertEquals(UserVerificationPolicy.DISABLED, disabled.uvPolicy)
        assertFalse(disabled.isBiometricEnabled)
        assertEquals(BiometricAuthMode.PER_OPERATION, disabled.authMode)
        assertTrue(disabled.strictUserVerification)
    }

    @Test
    fun `HIGH_SECURITY preset is per-operation with the shortest window`() {
        val high = BiometricSettingsData.HIGH_SECURITY

        assertEquals(UserVerificationPolicy.REQUIRED, high.uvPolicy)
        assertEquals(BiometricAuthMode.PER_OPERATION, high.authMode)
        assertEquals(AuthTimeWindow.SECONDS_30.seconds, high.timeWindowSeconds)
        assertEquals(AuthTimeWindow.SECONDS_30, high.getAuthTimeWindow())
    }

    @Test
    fun `CONVENIENCE preset is per-session with the longest window`() {
        val convenience = BiometricSettingsData.CONVENIENCE

        assertEquals(BiometricAuthMode.PER_SESSION, convenience.authMode)
        assertEquals(AuthTimeWindow.MINUTES_10.seconds, convenience.timeWindowSeconds)
        assertTrue(convenience.isBiometricEnabled)
    }

    // -------------------------------------------------------------------------
    // Time-window helpers
    // -------------------------------------------------------------------------

    @Test
    fun `getAuthTimeWindow resolves every predefined duration`() {
        for (window in AuthTimeWindow.entries) {
            val settings = BiometricSettingsData(timeWindowSeconds = window.seconds)
            assertEquals(window, settings.getAuthTimeWindow())
        }
    }

    @Test
    fun `getAuthTimeWindow returns null for a custom duration`() {
        assertNull(BiometricSettingsData(timeWindowSeconds = 45).getAuthTimeWindow())
        assertNull(BiometricSettingsData(timeWindowSeconds = 0).getAuthTimeWindow())
        assertNull(BiometricSettingsData(timeWindowSeconds = -1).getAuthTimeWindow())
    }

    @Test
    fun `withTimeWindow replaces only the duration`() {
        val original = BiometricSettingsData(
            uvPolicy = UserVerificationPolicy.REQUIRED,
            authMode = BiometricAuthMode.TIME_WINDOW,
            attestationBiometricPolicy = AttestationBiometricPolicy.NEVER,
            strictUserVerification = false
        )

        val updated = original.withTimeWindow(AuthTimeWindow.MINUTES_5)

        assertEquals(300, updated.timeWindowSeconds)
        assertEquals(original.uvPolicy, updated.uvPolicy)
        assertEquals(original.authMode, updated.authMode)
        assertEquals(original.attestationBiometricPolicy, updated.attestationBiometricPolicy)
        assertFalse(updated.strictUserVerification)
        assertEquals(120, original.timeWindowSeconds)
    }

    // -------------------------------------------------------------------------
    // AuthTimeWindow
    // -------------------------------------------------------------------------

    @Test
    fun `AuthTimeWindow exposes the documented durations`() {
        assertEquals(30, AuthTimeWindow.SECONDS_30.seconds)
        assertEquals(60, AuthTimeWindow.MINUTES_1.seconds)
        assertEquals(120, AuthTimeWindow.MINUTES_2.seconds)
        assertEquals(300, AuthTimeWindow.MINUTES_5.seconds)
        assertEquals(600, AuthTimeWindow.MINUTES_10.seconds)
        assertEquals(5, AuthTimeWindow.entries.size)
    }

    @Test
    fun `fromSeconds matches exact durations only`() {
        assertSame(AuthTimeWindow.MINUTES_2, AuthTimeWindow.fromSeconds(120))
        assertNull(AuthTimeWindow.fromSeconds(121))
        assertNull(AuthTimeWindow.fromSeconds(0))
        assertNull(AuthTimeWindow.fromSeconds(-120))
        assertNull(AuthTimeWindow.fromSeconds(Int.MAX_VALUE))
    }

    @Test
    fun `fromSecondsOrDefault falls back to two minutes for unknown values`() {
        assertEquals(AuthTimeWindow.MINUTES_2, AuthTimeWindow.fromSecondsOrDefault(9999))
        assertEquals(AuthTimeWindow.SECONDS_30, AuthTimeWindow.fromSecondsOrDefault(30))
    }

    @Test
    fun `fromSecondsOrDefault honours an explicit fallback`() {
        assertEquals(
            AuthTimeWindow.MINUTES_10,
            AuthTimeWindow.fromSecondsOrDefault(9999, AuthTimeWindow.MINUTES_10)
        )
        assertEquals(
            "a recognised value wins over the fallback",
            AuthTimeWindow.SECONDS_30,
            AuthTimeWindow.fromSecondsOrDefault(30, AuthTimeWindow.MINUTES_10)
        )
    }

    // -------------------------------------------------------------------------
    // Policy enums (persisted by name, so the names are the wire format)
    // -------------------------------------------------------------------------

    @Test
    fun `enum members cover the documented options`() {
        assertEquals(
            listOf("DISABLED", "REQUIRED"),
            UserVerificationPolicy.entries.map { it.name }
        )
        assertEquals(
            listOf("PER_OPERATION", "TIME_WINDOW", "PER_SESSION"),
            BiometricAuthMode.entries.map { it.name }
        )
        assertEquals(
            listOf("ALWAYS", "PAIRED_DEVICES_SKIP", "NEVER"),
            AttestationBiometricPolicy.entries.map { it.name }
        )
    }
}
