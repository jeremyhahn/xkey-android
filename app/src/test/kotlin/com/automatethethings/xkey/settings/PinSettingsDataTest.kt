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
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for [PinSettingsData].
 *
 * This is the persisted PKCS#11-style PIN state (SO PIN and User PIN hashes,
 * salts, attempt counters and lockout deadlines). The defaults are the security
 * posture of a freshly installed app, so they are pinned explicitly: no PIN
 * set, no material stored, no attempts burned, backoff on.
 *
 * [PinSettingsRepository] needs Jetpack DataStore; its read/write behaviour is
 * exercised through the mocked repository in `PinManagerTest` and by
 * instrumented tests.
 */
class PinSettingsDataTest {

    @Test
    fun `a fresh install has no PIN configured and no material stored`() {
        val settings = PinSettingsData()

        assertFalse(settings.soPinSet)
        assertFalse(settings.userPinSet)
        assertNull(settings.soPinHashBase64)
        assertNull(settings.userPinHashBase64)
        assertNull(settings.soPinSaltBase64)
        assertNull(settings.userPinSaltBase64)
    }

    @Test
    fun `a fresh install has no failed attempts and no lockout`() {
        val settings = PinSettingsData()

        assertEquals(0, settings.failedSoPinAttempts)
        assertEquals(0, settings.failedUserPinAttempts)
        assertEquals(0L, settings.soPinLockedUntil)
        assertEquals(0L, settings.userPinLockedUntil)
    }

    @Test
    fun `default lockout policy is five attempts, five minutes, backoff on`() {
        val settings = PinSettingsData()

        assertEquals(5, settings.maxPinAttempts)
        assertEquals(300, settings.lockoutDurationSeconds)
        assertTrue("exponential backoff must be on by default", settings.backoffEnabled)
    }

    @Test
    fun `SO and user PIN state are tracked independently`() {
        val settings = PinSettingsData(
            soPinSet = true,
            soPinHashBase64 = "c29IYXNo",
            soPinSaltBase64 = "c29TYWx0",
            failedSoPinAttempts = 2,
            soPinLockedUntil = 1_700_000_000_000L
        )

        assertTrue(settings.soPinSet)
        assertEquals(2, settings.failedSoPinAttempts)
        assertEquals(1_700_000_000_000L, settings.soPinLockedUntil)
        assertFalse("touching the SO PIN must not imply a user PIN", settings.userPinSet)
        assertNull(settings.userPinHashBase64)
        assertEquals(0, settings.failedUserPinAttempts)
        assertEquals(0L, settings.userPinLockedUntil)
    }

    @Test
    fun `copy produces an independent snapshot`() {
        val original = PinSettingsData(userPinSet = true, failedUserPinAttempts = 1)
        val afterFailure = original.copy(failedUserPinAttempts = 2)

        assertEquals(1, original.failedUserPinAttempts)
        assertEquals(2, afterFailure.failedUserPinAttempts)
        assertTrue(afterFailure.userPinSet)
        assertNotEquals(original, afterFailure)
    }

    @Test
    fun `clearing a PIN drops both the hash and the salt`() {
        val configured = PinSettingsData(
            userPinSet = true, userPinHashBase64 = "aGFzaA==", userPinSaltBase64 = "c2FsdA=="
        )

        val cleared = configured.copy(
            userPinSet = false, userPinHashBase64 = null, userPinSaltBase64 = null
        )

        assertEquals(PinSettingsData(), cleared)
    }

    @Test
    fun `equality is structural over every field`() {
        val a = PinSettingsData(soPinSet = true, maxPinAttempts = 3)
        val b = PinSettingsData(soPinSet = true, maxPinAttempts = 3)

        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
        assertNotEquals(a, b.copy(maxPinAttempts = 4))
        assertNotEquals(a, b.copy(backoffEnabled = false))
        assertNotEquals(a, b.copy(userPinLockedUntil = 1L))
    }

    @Test
    fun `a custom lockout policy is preserved verbatim`() {
        val settings = PinSettingsData(
            maxPinAttempts = 3, lockoutDurationSeconds = 60, backoffEnabled = false
        )

        assertEquals(3, settings.maxPinAttempts)
        assertEquals(60, settings.lockoutDurationSeconds)
        assertFalse(settings.backoffEnabled)
    }
}
