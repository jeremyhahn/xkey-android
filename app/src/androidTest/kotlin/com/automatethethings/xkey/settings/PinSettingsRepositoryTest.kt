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
package com.automatethethings.xkey.settings

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented tests for [PinSettingsRepository].
 *
 * PIN state -- hashes, salts, attempt counters and lockout deadlines -- lives in
 * a DataStore, so the repository can only be exercised on a device.
 * `PinSettingsDataTest` already covers the data class; this covers persistence,
 * the per-field setters, and the empty-string-means-null convention the
 * repository uses because DataStore has no null string.
 *
 * The store belongs to the app, so the suite snapshots the device's real PIN
 * settings and puts them back in teardown -- clearing it outright would unset a
 * PIN the user or another suite configured.
 */
@RunWith(AndroidJUnit4::class)
class PinSettingsRepositoryTest {

    private lateinit var repository: PinSettingsRepository
    private lateinit var snapshot: PinSettingsData

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        repository = PinSettingsRepository(context)
        runBlocking {
            snapshot = repository.getSettings()
            repository.clearSettings()
        }
    }

    @After
    fun tearDown() {
        runBlocking {
            repository.clearSettings()
            repository.updateSettings(snapshot)
        }
    }

    @Test
    fun updateSettings_roundTripsEveryField() = runBlocking {
        val written = PinSettingsData(
            soPinSet = true,
            userPinSet = true,
            soPinHashBase64 = "c29QaW5IYXNo",
            userPinHashBase64 = "dXNlclBpbkhhc2g=",
            soPinSaltBase64 = "c29TYWx0",
            userPinSaltBase64 = "dXNlclNhbHQ=",
            failedSoPinAttempts = 2,
            failedUserPinAttempts = 3,
            maxPinAttempts = 8,
            lockoutDurationSeconds = 45,
            backoffEnabled = false,
            soPinLockedUntil = 1_700_000_000_000L,
            userPinLockedUntil = 1_700_000_999_000L
        )

        repository.updateSettings(written)

        assertEquals(written, repository.getSettings())
    }

    @Test
    fun updateSettings_isABlindOverwriteOfEveryKey() = runBlocking {
        repository.updateSettings(
            PinSettingsData(userPinSet = true, failedUserPinAttempts = 4, maxPinAttempts = 9)
        )

        // Writing a fresh snapshot resets the counters the earlier write raised;
        // the KDoc calls this out because callers must serialise read-modify-write.
        repository.updateSettings(PinSettingsData(userPinSet = true))

        val settings = repository.getSettings()
        assertEquals(0, settings.failedUserPinAttempts)
        assertEquals(5, settings.maxPinAttempts)
        assertTrue(settings.userPinSet)
    }

    @Test
    fun pinSetFlags_persistIndependently() = runBlocking {
        repository.updateSoPinSet(true)
        repository.updateUserPinSet(false)

        val settings = repository.getSettings()
        assertTrue(settings.soPinSet)
        assertFalse(settings.userPinSet)
    }

    @Test
    fun hashesAndSalts_roundTripThroughTheirOwnSetters() = runBlocking {
        repository.updateSoPinHashBase64("c29IYXNo")
        repository.updateUserPinHashBase64("dXNlckhhc2g=")
        repository.updateSoPinSaltBase64("c29TYWx0")
        repository.updateUserPinSaltBase64("dXNlclNhbHQ=")

        val settings = repository.getSettings()
        assertEquals("c29IYXNo", settings.soPinHashBase64)
        assertEquals("dXNlckhhc2g=", settings.userPinHashBase64)
        assertEquals("c29TYWx0", settings.soPinSaltBase64)
        assertEquals("dXNlclNhbHQ=", settings.userPinSaltBase64)
    }

    @Test
    fun nullHash_isStoredAsEmptyAndReadBackAsNull() = runBlocking {
        repository.updateSoPinHashBase64("c29IYXNo")

        repository.updateSoPinHashBase64(null)

        assertNull(repository.getSettings().soPinHashBase64)
    }

    @Test
    fun nullSalt_isStoredAsEmptyAndReadBackAsNull() = runBlocking {
        repository.updateUserPinSaltBase64("dXNlclNhbHQ=")

        repository.updateUserPinSaltBase64(null)

        assertNull(repository.getSettings().userPinSaltBase64)
    }

    @Test
    fun failedAttemptCounters_persist() = runBlocking {
        repository.updateFailedSoPinAttempts(3)
        repository.updateFailedUserPinAttempts(1)

        val settings = repository.getSettings()
        assertEquals(3, settings.failedSoPinAttempts)
        assertEquals(1, settings.failedUserPinAttempts)
    }

    @Test
    fun lockoutPolicy_persists() = runBlocking {
        repository.updateMaxPinAttempts(3)
        repository.updateLockoutDurationSeconds(60)
        repository.updateBackoffEnabled(false)

        val settings = repository.getSettings()
        assertEquals(3, settings.maxPinAttempts)
        assertEquals(60, settings.lockoutDurationSeconds)
        assertFalse(settings.backoffEnabled)
    }

    @Test(expected = IllegalArgumentException::class)
    fun updateMaxPinAttempts_rejectsNonPositive(): Unit = runBlocking {
        repository.updateMaxPinAttempts(0)
    }

    @Test(expected = IllegalArgumentException::class)
    fun updateLockoutDurationSeconds_rejectsNonPositive(): Unit = runBlocking {
        repository.updateLockoutDurationSeconds(-1)
    }

    @Test
    fun lockoutDeadlines_persist() = runBlocking {
        val soDeadline = System.currentTimeMillis() + 60_000L
        val userDeadline = System.currentTimeMillis() + 120_000L

        repository.updateSoPinLockedUntil(soDeadline)
        repository.updateUserPinLockedUntil(userDeadline)

        val settings = repository.getSettings()
        assertEquals(soDeadline, settings.soPinLockedUntil)
        assertEquals(userDeadline, settings.userPinLockedUntil)
    }

    @Test
    fun resetToDefaults_clearsCountersAndDeadlines() = runBlocking {
        repository.updateSettings(
            PinSettingsData(
                soPinSet = true,
                userPinSet = true,
                failedUserPinAttempts = 4,
                userPinLockedUntil = System.currentTimeMillis() + 60_000L
            )
        )

        repository.resetToDefaults()

        assertEquals(PinSettingsData(), repository.getSettings())
    }

    @Test
    fun clearSettings_fallsBackToDefaults() = runBlocking {
        repository.updateSettings(PinSettingsData(soPinSet = true, maxPinAttempts = 2))

        repository.clearSettings()

        assertEquals(PinSettingsData(), repository.getSettings())
    }
}
