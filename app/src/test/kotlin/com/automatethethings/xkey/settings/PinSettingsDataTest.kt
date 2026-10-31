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
}
