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
import kotlinx.coroutines.flow.first
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
 * Instrumented tests for [MediaSigningSettingsRepository].
 *
 * `MediaSigningSettingsTest` covers the data class; the repository needs
 * DataStore. The repository has no `clearSettings`, so the suite empties the
 * backing store through [PreferenceStoreProbe] and restores the device's own
 * settings afterwards.
 *
 * The clearing branch matters: an unset signing key must come back as null, not
 * as the empty string, because [MediaSigningService] treats a non-null key id
 * as "sign with this" and would then look up a key that cannot exist.
 */
@RunWith(AndroidJUnit4::class)
class MediaSigningSettingsRepositoryTest {

    private lateinit var repository: MediaSigningSettingsRepository
    private lateinit var snapshot: MediaSigningSettingsData

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        repository = MediaSigningSettingsRepository(context)
        runBlocking {
            snapshot = repository.getSettings()
            PreferenceStoreProbe.clear(repository)
        }
    }

    @After
    fun tearDown() {
        runBlocking {
            PreferenceStoreProbe.clear(repository)
            repository.updateSettings(snapshot)
        }
    }

    @Test
    fun freshStore_yieldsDocumentedDefaults() = runBlocking {
        val settings = repository.getSettings()

        assertEquals(MediaSigningSettingsData(), settings)
        assertFalse(settings.autoSignEnabled)
        assertNull(settings.signingKeyId)
        assertTrue(settings.signPhotos)
        assertTrue(settings.signVideos)
    }

    @Test
    fun updateSettings_roundTripsEveryField() = runBlocking {
        val written = MediaSigningSettingsData(
            autoSignEnabled = true,
            signingKeyId = "media-key-${System.nanoTime()}",
            signPhotos = false,
            signVideos = true
        )

        repository.updateSettings(written)

        assertEquals(written, repository.getSettings())
    }

    @Test
    fun settingsFlow_emitsThePersistedValue() = runBlocking {
        repository.setAutoSignEnabled(true)

        assertTrue(repository.settingsFlow.first().autoSignEnabled)
    }

    @Test
    fun updateSettings_removesTheKeyIdWhenItIsNull() = runBlocking {
        repository.setSigningKeyId("media-key-${System.nanoTime()}")

        repository.updateSettings(MediaSigningSettingsData(autoSignEnabled = true))

        val settings = repository.getSettings()
        assertNull(settings.signingKeyId)
        assertTrue(settings.autoSignEnabled)
    }

    @Test
    fun setAutoSignEnabled_persistsBothWays() = runBlocking {
        repository.setAutoSignEnabled(true)
        assertTrue(repository.getSettings().autoSignEnabled)

        repository.setAutoSignEnabled(false)

        assertFalse(repository.getSettings().autoSignEnabled)
    }

    @Test
    fun setSigningKeyId_roundTripsAndClears() = runBlocking {
        val keyId = "media-key-${System.nanoTime()}"

        repository.setSigningKeyId(keyId)
        assertEquals(keyId, repository.getSettings().signingKeyId)

        repository.setSigningKeyId(null)

        assertNull(repository.getSettings().signingKeyId)
    }

    @Test
    fun mediaTypeToggles_persistIndependently() = runBlocking {
        repository.setSignPhotos(false)
        repository.setSignVideos(false)

        val bothOff = repository.getSettings()
        assertFalse(bothOff.signPhotos)
        assertFalse(bothOff.signVideos)

        repository.setSignPhotos(true)

        val photosOnly = repository.getSettings()
        assertTrue(photosOnly.signPhotos)
        assertFalse(photosOnly.signVideos)
    }
}
