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
package com.automatethethings.xkey.credential

import android.content.Context
import android.os.Build
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented tests for [CredentialProviderSettingsRepository].
 *
 * The repository is DataStore-backed, so it needs a device. Its default is the
 * one that matters: the credential provider is **off** until the user turns it
 * on, because a passkey provider that opts itself in would start intercepting
 * WebAuthn ceremonies the user never asked xKey to handle.
 *
 * The store is shared with the running app, so the device's own value is
 * snapshotted in `@Before` and restored in `@After`.
 */
@RunWith(AndroidJUnit4::class)
class CredentialProviderSettingsRepositoryTest {

    private lateinit var repository: CredentialProviderSettingsRepository
    private var snapshot: Boolean = false

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        repository = CredentialProviderSettingsRepository(context)
        runBlocking {
            snapshot = repository.getSettings().isEnabled
            repository.clearSettings()
        }
    }

    @After
    fun tearDown() {
        runBlocking {
            repository.clearSettings()
            if (snapshot) repository.setEnabled(true)
        }
    }

    // -------------------------------------------------------------------------
    // Defaults
    // -------------------------------------------------------------------------

    @Test
    fun freshStore_leavesTheProviderDisabled() = runBlocking {
        assertFalse(repository.getSettings().isEnabled)
    }

    @Test
    fun freshStore_matchesTheDataClassDefault() = runBlocking {
        assertEquals(CredentialProviderSettingsData(), repository.getSettings())
    }

    // -------------------------------------------------------------------------
    // Round trip
    // -------------------------------------------------------------------------

    @Test
    fun setEnabled_persistsTheChoice() = runBlocking {
        repository.setEnabled(true)

        assertTrue(repository.getSettings().isEnabled)
    }

    @Test
    fun setEnabled_canTurnTheProviderBackOff() = runBlocking {
        repository.setEnabled(true)
        repository.setEnabled(false)

        assertFalse(repository.getSettings().isEnabled)
    }

    @Test
    fun setEnabled_isIdempotent() = runBlocking {
        repository.setEnabled(true)
        repository.setEnabled(true)

        assertTrue(repository.getSettings().isEnabled)
    }

    @Test
    fun settingsFlow_emitsTheStoredValue() = runBlocking {
        repository.setEnabled(true)

        assertTrue(repository.settingsFlow.first().isEnabled)
    }

    @Test
    fun settingsFlow_emitsTheDefaultForAnEmptyStore() = runBlocking {
        assertEquals(CredentialProviderSettingsData(false), repository.settingsFlow.first())
    }

    @Test
    fun clearSettings_returnsTheProviderToItsDisabledDefault() = runBlocking {
        repository.setEnabled(true)

        repository.clearSettings()

        assertFalse(repository.getSettings().isEnabled)
    }

    @Test
    fun clearSettings_isSafeOnAnAlreadyEmptyStore() = runBlocking {
        repository.clearSettings()
        repository.clearSettings()

        assertFalse(repository.getSettings().isEnabled)
    }

    @Test
    fun aSecondRepositoryInstanceSeesTheSameStoredValue() = runBlocking {
        val context = ApplicationProvider.getApplicationContext<Context>()
        repository.setEnabled(true)

        assertTrue(CredentialProviderSettingsRepository(context).getSettings().isEnabled)
    }

    // -------------------------------------------------------------------------
    // Feature availability
    // -------------------------------------------------------------------------

    @Test
    fun isFeatureAvailable_tracksTheAndroid14Requirement() {
        assertEquals(
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE,
            repository.isFeatureAvailable()
        )
    }

    @Test
    fun isFeatureAvailable_isIndependentOfTheStoredPreference() = runBlocking {
        val availability = repository.isFeatureAvailable()

        repository.setEnabled(true)

        // Enabling the preference cannot make an unsupported OS support the API.
        assertEquals(availability, repository.isFeatureAvailable())
    }

    // -------------------------------------------------------------------------
    // Settings data
    // -------------------------------------------------------------------------

    @Test
    fun settingsData_hasValueSemantics() {
        assertEquals(CredentialProviderSettingsData(true), CredentialProviderSettingsData(true))
        assertEquals(
            CredentialProviderSettingsData(true).hashCode(),
            CredentialProviderSettingsData(true).hashCode()
        )
        assertFalse(
            CredentialProviderSettingsData(true) == CredentialProviderSettingsData(false)
        )
        assertTrue(
            CredentialProviderSettingsData(false).copy(isEnabled = true).isEnabled
        )
    }
}
