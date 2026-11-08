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
 * Instrumented tests for [BootstrapSettingsRepository].
 *
 * `BootstrapSettingsDataTest` covers the data class in the JVM; everything here
 * needs DataStore. The interesting parts are the partial-update setters (each
 * takes nullable arguments and must leave the untouched fields alone), the
 * method-order round trip through a comma-separated string, and the decode
 * fallback when that string names a method this build no longer has.
 */
@RunWith(AndroidJUnit4::class)
class BootstrapSettingsRepositoryTest {

    private lateinit var repository: BootstrapSettingsRepository
    private lateinit var snapshot: BootstrapSettingsData

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        repository = BootstrapSettingsRepository(context)
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
        val written = BootstrapSettingsData(
            autoBootstrapEnabled = false,
            methodOrder = listOf(BootstrapMethod.DIRECT, BootstrapMethod.SPKI),
            perMethodTimeoutSeconds = 30,
            daneEnabled = false,
            daneServerUrl = "https://dane.example.test:8443",
            daneDnsServer = "1.1.1.1:53",
            daneDnsOverTls = true,
            daneRequireDnssec = false,
            noiseEnabled = true,
            noiseServerAddr = "noise.example.test:8445",
            noiseServerStaticKey = "ab".repeat(32),
            spkiEnabled = true,
            spkiServerUrl = "https://spki.example.test:8443",
            spkiPinSha256 = "cd".repeat(32),
            directEnabled = true,
            directServerUrl = "https://direct.example.test:8443"
        )

        repository.updateSettings(written)

        assertEquals(written, repository.getSettings())
    }

    @Test
    fun updateAutoBootstrapEnabled_persists() = runBlocking {
        repository.updateAutoBootstrapEnabled(false)

        assertFalse(repository.getSettings().autoBootstrapEnabled)
    }

    @Test
    fun updateMethodOrder_roundTripsThroughTheStoredString() = runBlocking {
        val order = listOf(BootstrapMethod.SPKI, BootstrapMethod.DANE, BootstrapMethod.DIRECT)

        repository.updateMethodOrder(order)

        assertEquals(order, repository.getSettings().methodOrder)
    }

    @Test
    fun emptyMethodOrder_readsBackAsTheDefaultOrder() = runBlocking {
        repository.updateMethodOrder(emptyList())

        assertEquals(BootstrapMethod.DEFAULT_ORDER, repository.getSettings().methodOrder)
    }

    @Test
    fun unknownMethodNames_areDroppedFromTheStoredOrder() = runBlocking {
        PreferenceStoreProbe.writeRaw(repository) {
            it[stringPreferencesKey("method_order")] = "DIRECT,QUANTUM_ENTANGLEMENT,SPKI"
        }

        assertEquals(
            listOf(BootstrapMethod.DIRECT, BootstrapMethod.SPKI),
            repository.getSettings().methodOrder
        )
    }

    @Test
    fun anEntirelyUnknownMethodOrder_fallsBackToTheDefaultOrder() = runBlocking {
        PreferenceStoreProbe.writeRaw(repository) {
            it[stringPreferencesKey("method_order")] = "SMOKE_SIGNAL,CARRIER_PIGEON"
        }

        assertEquals(BootstrapMethod.DEFAULT_ORDER, repository.getSettings().methodOrder)
    }

    @Test
    fun updatePerMethodTimeout_acceptsRawSeconds() = runBlocking {
        repository.updatePerMethodTimeout(42)

        val settings = repository.getSettings()
        assertEquals(42, settings.perMethodTimeoutSeconds)
        assertEquals(42, settings.timeoutSeconds)
    }

    @Test
    fun updatePerMethodTimeout_acceptsTheEnumOverload() = runBlocking {
        repository.updatePerMethodTimeout(BootstrapTimeout.SECONDS_60)

        val settings = repository.getSettings()
        assertEquals(BootstrapTimeout.SECONDS_60.seconds, settings.perMethodTimeoutSeconds)
        assertEquals(BootstrapTimeout.SECONDS_60, settings.getTimeoutEnum())
    }

    @Test(expected = IllegalArgumentException::class)
    fun updatePerMethodTimeout_rejectsNonPositive(): Unit = runBlocking {
        repository.updatePerMethodTimeout(0)
    }

    @Test
    fun updateDaneSettings_writesOnlyTheSuppliedFields() = runBlocking {
        repository.updateDaneSettings(
            enabled = true,
            serverUrl = "https://dane.example.test:8443",
            dnsServer = "9.9.9.9:53",
            dnsOverTls = true,
            requireDnssec = false
        )

        repository.updateDaneSettings(serverUrl = "https://other.example.test:8443")

        val settings = repository.getSettings()
        assertEquals("https://other.example.test:8443", settings.daneServerUrl)
        assertEquals("9.9.9.9:53", settings.daneDnsServer)
        assertTrue(settings.daneDnsOverTls)
        assertFalse(settings.daneRequireDnssec)
    }

    @Test
    fun updateNoiseSettings_writesOnlyTheSuppliedFields() = runBlocking {
        repository.updateNoiseSettings(
            enabled = true,
            serverAddr = "noise.example.test:8445",
            serverStaticKey = "ab".repeat(32)
        )

        repository.updateNoiseSettings(enabled = false)

        val settings = repository.getSettings()
        assertFalse(settings.noiseEnabled)
        assertEquals("noise.example.test:8445", settings.noiseServerAddr)
        assertEquals("ab".repeat(32), settings.noiseServerStaticKey)
        assertTrue(settings.isNoiseKeyValid())
    }

    @Test
    fun updateSpkiSettings_writesOnlyTheSuppliedFields() = runBlocking {
        repository.updateSpkiSettings(
            enabled = true,
            serverUrl = "https://spki.example.test:8443",
            pinSha256 = "cd".repeat(32)
        )

        repository.updateSpkiSettings(pinSha256 = "ef".repeat(32))

        val settings = repository.getSettings()
        assertTrue(settings.spkiEnabled)
        assertEquals("https://spki.example.test:8443", settings.spkiServerUrl)
        assertEquals("ef".repeat(32), settings.spkiPinSha256)
    }

    @Test
    fun updateDirectSettings_writesOnlyTheSuppliedFields() = runBlocking {
        repository.updateDirectSettings(
            enabled = true,
            serverUrl = "https://direct.example.test:8443"
        )

        repository.updateDirectSettings(enabled = false)

        val settings = repository.getSettings()
        assertFalse(settings.directEnabled)
        assertEquals("https://direct.example.test:8443", settings.directServerUrl)
    }

    @Test
    fun deriveSettingsFromUrl_populatesEveryTransportUrl() = runBlocking {
        repository.deriveSettingsFromUrl("https://kms.example.test:8443")

        val settings = repository.getSettings()
        assertEquals("https://kms.example.test:8443", settings.daneServerUrl)
        assertEquals("https://kms.example.test:8443", settings.spkiServerUrl)
        assertEquals("https://kms.example.test:8443", settings.directServerUrl)
        assertEquals("kms.example.test:8445", settings.noiseServerAddr)
    }

    @Test
    fun deriveSettingsFromUrl_ignoresABlankUrl() = runBlocking {
        repository.updateDirectSettings(serverUrl = "https://kept.example.test")

        repository.deriveSettingsFromUrl("")

        assertEquals("https://kept.example.test", repository.getSettings().directServerUrl)
    }

    @Test
    fun isMethodEnabled_readsThroughToTheStore() = runBlocking {
        repository.updateSettings(BootstrapSettingsData.HIGH_SECURITY)

        assertTrue(repository.isMethodEnabled(BootstrapMethod.DANE))
        assertTrue(repository.isMethodEnabled(BootstrapMethod.NOISE))
        assertFalse(repository.isMethodEnabled(BootstrapMethod.SPKI))
        assertFalse(repository.isMethodEnabled(BootstrapMethod.DIRECT))
    }

    @Test
    fun getEnabledMethods_preservesTheConfiguredPriority() = runBlocking {
        repository.updateSettings(
            BootstrapSettingsData(
                methodOrder = listOf(
                    BootstrapMethod.DIRECT,
                    BootstrapMethod.DANE,
                    BootstrapMethod.SPKI
                ),
                daneEnabled = true,
                directEnabled = true,
                spkiEnabled = false,
                noiseEnabled = false
            )
        )

        assertEquals(
            listOf(BootstrapMethod.DIRECT, BootstrapMethod.DANE),
            repository.getEnabledMethods()
        )
    }

    @Test
    fun resetToDefaults_overwritesEveryStoredField() = runBlocking {
        repository.updateSettings(BootstrapSettingsData.HIGH_SECURITY)

        repository.resetToDefaults()

        assertEquals(BootstrapSettingsData.DEFAULT, repository.getSettings())
    }

    @Test
    fun clearSettings_fallsBackToDefaults() = runBlocking {
        repository.updateSettings(BootstrapSettingsData.DEVELOPMENT)

        repository.clearSettings()

        assertEquals(BootstrapSettingsData.DEFAULT, repository.getSettings())
    }
}
