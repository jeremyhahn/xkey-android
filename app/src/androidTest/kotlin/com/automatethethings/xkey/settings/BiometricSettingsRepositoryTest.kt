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
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented tests for [BiometricSettingsRepository].
 *
 * The repository is backed by Jetpack DataStore, which needs a real filesystem
 * and a real `Context`, so none of this is reachable from a JVM unit test --
 * `BiometricSettingsDataTest` covers the data class, this covers persistence.
 *
 * The store is process-wide and shared with the running app, so the suite
 * snapshots whatever settings the device already had, works from a cleared
 * store, and restores the snapshot in teardown. Every assertion reads the value
 * back through [BiometricSettingsRepository.getSettings] rather than trusting
 * the write.
 */
@RunWith(AndroidJUnit4::class)
class BiometricSettingsRepositoryTest {

    private lateinit var repository: BiometricSettingsRepository
    private lateinit var snapshot: BiometricSettingsData

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        repository = BiometricSettingsRepository(context)
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
        val written = BiometricSettingsData(
            uvPolicy = UserVerificationPolicy.DISABLED,
            authMode = BiometricAuthMode.TIME_WINDOW,
            timeWindowSeconds = AuthTimeWindow.MINUTES_10.seconds,
            attestationBiometricPolicy = AttestationBiometricPolicy.NEVER,
            strictUserVerification = false
        )

        repository.updateSettings(written)

        assertEquals(written, repository.getSettings())
    }

    @Test
    fun updateUserVerificationPolicy_persistsOnlyThatField() = runBlocking {
        repository.updateAuthMode(BiometricAuthMode.PER_SESSION)

        repository.updateUserVerificationPolicy(UserVerificationPolicy.DISABLED)

        val settings = repository.getSettings()
        assertEquals(UserVerificationPolicy.DISABLED, settings.uvPolicy)
        assertEquals(BiometricAuthMode.PER_SESSION, settings.authMode)
        assertFalse(settings.isBiometricEnabled)
    }

    @Test
    fun updateAuthMode_persists() = runBlocking {
        repository.updateAuthMode(BiometricAuthMode.TIME_WINDOW)

        assertEquals(BiometricAuthMode.TIME_WINDOW, repository.getSettings().authMode)
    }

    @Test
    fun updateTimeWindow_acceptsRawSeconds() = runBlocking {
        repository.updateTimeWindow(45)

        assertEquals(45, repository.getSettings().timeWindowSeconds)
    }

    @Test
    fun updateTimeWindow_acceptsTheEnumOverload() = runBlocking {
        repository.updateTimeWindow(AuthTimeWindow.MINUTES_5)

        val settings = repository.getSettings()
        assertEquals(AuthTimeWindow.MINUTES_5.seconds, settings.timeWindowSeconds)
        assertEquals(AuthTimeWindow.MINUTES_5, settings.getAuthTimeWindow())
    }

    @Test(expected = IllegalArgumentException::class)
    fun updateTimeWindow_rejectsNonPositiveSeconds(): Unit = runBlocking {
        repository.updateTimeWindow(0)
    }

    @Test
    fun updateAttestationBiometricPolicy_persists() = runBlocking {
        repository.updateAttestationBiometricPolicy(AttestationBiometricPolicy.PAIRED_DEVICES_SKIP)

        assertEquals(
            AttestationBiometricPolicy.PAIRED_DEVICES_SKIP,
            repository.getSettings().attestationBiometricPolicy
        )
    }

    @Test
    fun setBiometricEnabled_togglesTheVerificationPolicy() = runBlocking {
        repository.setBiometricEnabled(false)
        assertEquals(UserVerificationPolicy.DISABLED, repository.getSettings().uvPolicy)

        repository.setBiometricEnabled(true)
        val enabled = repository.getSettings()
        assertEquals(UserVerificationPolicy.REQUIRED, enabled.uvPolicy)
        assertTrue(enabled.isBiometricEnabled)
    }

    @Test
    fun resetToDefaults_overwritesEveryStoredField() = runBlocking {
        repository.updateSettings(BiometricSettingsData.HIGH_SECURITY.copy(
            uvPolicy = UserVerificationPolicy.DISABLED,
            strictUserVerification = false
        ))

        repository.resetToDefaults()

        assertEquals(BiometricSettingsData.DEFAULT, repository.getSettings())
    }

    @Test
    fun clearSettings_fallsBackToDefaults() = runBlocking {
        repository.updateSettings(BiometricSettingsData.DISABLED)

        repository.clearSettings()

        assertEquals(BiometricSettingsData.DEFAULT, repository.getSettings())
    }

    @Test
    fun unparsableUvPolicy_fallsBackToRequired() = runBlocking {
        PreferenceStoreProbe.writeRaw(repository) {
            it[stringPreferencesKey("uv_policy")] = "NOT_A_POLICY"
        }

        assertEquals(UserVerificationPolicy.REQUIRED, repository.getSettings().uvPolicy)
    }

    @Test
    fun unparsableAuthMode_fallsBackToPerOperation() = runBlocking {
        PreferenceStoreProbe.writeRaw(repository) {
            it[stringPreferencesKey("auth_mode")] = "EVERY_SECOND_TUESDAY"
        }

        assertEquals(BiometricAuthMode.PER_OPERATION, repository.getSettings().authMode)
    }

    @Test
    fun unparsableAttestationPolicy_fallsBackToAlways() = runBlocking {
        PreferenceStoreProbe.writeRaw(repository) {
            it[stringPreferencesKey("attestation_biometric_policy")] = "SOMETIMES"
        }

        assertEquals(
            AttestationBiometricPolicy.ALWAYS,
            repository.getSettings().attestationBiometricPolicy
        )
    }

    @Test
    fun corruptEnumsDoNotDiscardTheValidNeighbours() = runBlocking {
        PreferenceStoreProbe.writeRaw(repository) {
            it[stringPreferencesKey("uv_policy")] = "???"
            it[intPreferencesKey("time_window_seconds")] = 90
            it[booleanPreferencesKey("strict_user_verification")] = false
        }

        val settings = repository.getSettings()
        assertEquals(UserVerificationPolicy.REQUIRED, settings.uvPolicy)
        assertEquals(90, settings.timeWindowSeconds)
        assertFalse(settings.strictUserVerification)
    }

    @Test
    fun absentStrictUserVerification_defaultsToCompliant() = runBlocking {
        PreferenceStoreProbe.writeRaw(repository) {
            it[stringPreferencesKey("uv_policy")] = UserVerificationPolicy.DISABLED.name
        }

        assertTrue(repository.getSettings().strictUserVerification)
    }
}
