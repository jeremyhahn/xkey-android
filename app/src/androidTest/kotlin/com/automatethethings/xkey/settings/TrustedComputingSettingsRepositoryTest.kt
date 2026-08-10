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
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
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
 * Instrumented tests for [TrustedComputingSettingsRepository].
 *
 * Two branches are worth singling out.
 *
 * `xkmsEndpoint`: DataStore has no null string, so the repository removes the
 * key instead of writing one, and a later read must produce null rather than an
 * empty string -- `useXkmsCA` keys off `isNullOrBlank`, so getting this wrong
 * would silently route enrolment at an empty endpoint.
 *
 * Migration: installs written before the three-way choice existed stored an
 * `act_as_ca_server` boolean and a `ca_server_url`, and those users must land on
 * the authority they actually configured rather than on "nobody signs". The
 * legacy state has no setter, so those tests write the retired preference keys
 * straight into the store; the whole store is snapshotted raw in @Before and put
 * back verbatim in @After, because the legacy keys are outside what
 * [TrustedComputingSettingsData] can carry.
 */
@RunWith(AndroidJUnit4::class)
class TrustedComputingSettingsRepositoryTest {

    private lateinit var repository: TrustedComputingSettingsRepository

    /**
     * The very DataStore the repository writes, reached through its own field.
     *
     * DataStore refuses a second instance over the same file, so the legacy keys
     * cannot be written through a store the test builds for itself.
     */
    private lateinit var dataStore: DataStore<Preferences>

    private lateinit var snapshot: Preferences

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        repository = TrustedComputingSettingsRepository(context)
        dataStore = dataStoreOf(repository)
        runBlocking {
            snapshot = dataStore.data.first()
            repository.clearSettings()
        }
    }

    @After
    fun tearDown() {
        runBlocking {
            dataStore.edit { mutable ->
                mutable.clear()
                snapshot.asMap().forEach { (key, value) ->
                    @Suppress("UNCHECKED_CAST")
                    mutable[key as Preferences.Key<Any>] = value
                }
            }
        }
    }

    @Test
    fun freshStore_yieldsDocumentedDefaults() = runBlocking {
        val settings = repository.getSettings()

        assertEquals(TrustedComputingSettingsData.DEFAULT, settings)
        assertFalse(settings.enabled)
        assertEquals(CertificateAuthoritySource.NONE, settings.caSource)
        assertNull(settings.xkmsEndpoint)
        assertTrue(settings.trustNewDevices)
        assertEquals("xkey_intermediate_ca", settings.platformCAAlias)
        assertFalse(settings.useXkmsCA)
        assertFalse(settings.useLocalCA)
        assertFalse(settings.isDeviceVerificationActive)
    }

    @Test
    fun updateSettings_roundTripsEveryField() = runBlocking {
        val written = TrustedComputingSettingsData(
            enabled = true,
            caSource = CertificateAuthoritySource.XKMS,
            xkmsEndpoint = "https://xkms.example.test/bundle",
            requireTrustedIDevID = true,
            requireFullAttestation = true,
            trustNewDevices = false,
            importToSystemStore = true,
            caSubjectOrganization = "Automate The Things",
            caSubjectOU = "Engineering",
            caSubjectLocality = "Austin",
            caSubjectProvince = "Texas",
            caSubjectCountry = "US",
            caSubjectCommonName = "xKey Test CA",
            platformCAAlias = "xkey_root_ca"
        )

        repository.updateSettings(written)

        val read = repository.getSettings()
        assertEquals(written, read)
        assertTrue(read.useXkmsCA)
        assertFalse(read.useLocalCA)
        assertTrue(read.isDeviceVerificationActive)
    }

    @Test
    fun settingsFlow_emitsThePersistedValue() = runBlocking {
        repository.updateSettings(TrustedComputingSettingsData.STRICT)

        assertEquals(TrustedComputingSettingsData.STRICT, repository.settingsFlow.first())
    }

    @Test
    fun updateSettings_removesTheEndpointWhenItIsNull() = runBlocking {
        repository.updateXkmsEndpoint("https://xkms.example.test/bundle")

        repository.updateSettings(TrustedComputingSettingsData(enabled = true, xkmsEndpoint = null))

        assertNull(repository.getSettings().xkmsEndpoint)
    }

    @Test
    fun updateEnabled_persists() = runBlocking {
        repository.updateEnabled(true)

        assertTrue(repository.getSettings().enabled)
    }

    @Test
    fun updateCASource_persistsEveryAuthority() = runBlocking {
        for (source in CertificateAuthoritySource.entries) {
            repository.updateCASource(source)

            assertEquals(source, repository.getSettings().caSource)
        }
    }

    /** The choice is what drives the derived flags, with the feature on. */
    @Test
    fun updateCASource_drivesTheDerivedFlags() = runBlocking {
        repository.updateEnabled(true)
        repository.updateXkmsEndpoint("https://xkms.example.test/bundle")

        repository.updateCASource(CertificateAuthoritySource.THIS_DEVICE)
        repository.getSettings().let {
            assertTrue(it.useLocalCA)
            assertFalse("a stored endpoint must not act for another authority", it.useXkmsCA)
        }

        repository.updateCASource(CertificateAuthoritySource.XKMS)
        repository.getSettings().let {
            assertTrue(it.useXkmsCA)
            assertFalse(it.useLocalCA)
        }

        repository.updateCASource(CertificateAuthoritySource.NONE)
        repository.getSettings().let {
            assertFalse(it.useXkmsCA)
            assertFalse(it.useLocalCA)
        }
    }

    @Test
    fun updateXkmsEndpoint_roundTripsAndClears() = runBlocking {
        repository.updateXkmsEndpoint("https://xkms.example.test/bundle")
        assertEquals("https://xkms.example.test/bundle", repository.getSettings().xkmsEndpoint)

        repository.updateXkmsEndpoint(null)

        assertNull(repository.getSettings().xkmsEndpoint)
    }

    @Test
    fun attestationRequirements_persist() = runBlocking {
        repository.updateRequireTrustedIDevID(true)
        repository.updateRequireFullAttestation(true)

        val settings = repository.getSettings()
        assertTrue(settings.requireTrustedIDevID)
        assertTrue(settings.requireFullAttestation)
    }

    @Test
    fun updateTrustNewDevices_persists() = runBlocking {
        repository.updateTrustNewDevices(false)

        assertFalse(repository.getSettings().trustNewDevices)
    }

    @Test
    fun updateImportToSystemStore_persists() = runBlocking {
        repository.updateImportToSystemStore(true)

        assertTrue(repository.getSettings().importToSystemStore)
    }

    @Test
    fun updateCASubject_writesEverySubjectField() = runBlocking {
        repository.updateCASubject(
            org = "Automate The Things",
            ou = "Security",
            locality = "Austin",
            province = "Texas",
            country = "US",
            cn = "xKey Platform CA"
        )

        val settings = repository.getSettings()
        assertEquals("Automate The Things", settings.caSubjectOrganization)
        assertEquals("Security", settings.caSubjectOU)
        assertEquals("Austin", settings.caSubjectLocality)
        assertEquals("Texas", settings.caSubjectProvince)
        assertEquals("US", settings.caSubjectCountry)
        assertEquals("xKey Platform CA", settings.caSubjectCommonName)
    }

    @Test
    fun updatePlatformCAAlias_persists() = runBlocking {
        repository.updatePlatformCAAlias("xkey_root_ca")

        assertEquals("xkey_root_ca", repository.getSettings().platformCAAlias)
    }

    @Test
    fun resetToDefaults_overwritesEveryStoredField() = runBlocking {
        repository.updateSettings(TrustedComputingSettingsData.STRICT)

        repository.resetToDefaults()

        assertEquals(TrustedComputingSettingsData.DEFAULT, repository.getSettings())
    }

    @Test
    fun clearSettings_fallsBackToDefaults() = runBlocking {
        repository.updateSettings(TrustedComputingSettingsData.PERMISSIVE)

        repository.clearSettings()

        assertEquals(TrustedComputingSettingsData.DEFAULT, repository.getSettings())
    }

    // -------------------------------------------------------------------------
    // Migration off the act_as_ca_server boolean
    // -------------------------------------------------------------------------

    /**
     * The user who ticked "Act as CA Server" chose this phone, and must keep
     * signing after the upgrade. Reading them as NONE would silently stop
     * issuing certificates at the next pairing.
     */
    @Test
    fun migration_actAsCaServerReadsAsThisDevice() = runBlocking {
        writeLegacy(actAsCAServer = true)

        val settings = repository.getSettings()

        assertEquals(CertificateAuthoritySource.THIS_DEVICE, settings.caSource)
        assertTrue(settings.copy(enabled = true).useLocalCA)
    }

    /**
     * The old model could only express an external CA as a URL, and the only
     * external CA the app talks to is xkms. The endpoint has to come across with
     * the choice, or the migrated source would be selected but unusable.
     */
    @Test
    fun migration_aStoredCaServerUrlReadsAsXkms() = runBlocking {
        writeLegacy(caServerURL = LEGACY_URL)

        val settings = repository.getSettings()

        assertEquals(CertificateAuthoritySource.XKMS, settings.caSource)
        assertEquals(LEGACY_URL, settings.xkmsEndpoint)
        assertTrue(settings.copy(enabled = true).useXkmsCA)
    }

    /** An install that never configured a CA is not migrated into one. */
    @Test
    fun migration_anEmptyStoreReadsAsNone() = runBlocking {
        assertEquals(CertificateAuthoritySource.NONE, repository.getSettings().caSource)
    }

    /** "Act as CA Server" off with no URL is exactly the no-authority case. */
    @Test
    fun migration_actAsCaServerOffWithoutAUrlReadsAsNone() = runBlocking {
        writeLegacy(actAsCAServer = false, caServerURL = "   ")

        assertEquals(CertificateAuthoritySource.NONE, repository.getSettings().caSource)
    }

    /**
     * Acting as the CA outranks a URL left over from before that switch was
     * turned on: the old code ignored the URL in that state, so migrating to
     * xkms would change behaviour rather than preserve it.
     */
    @Test
    fun migration_actAsCaServerWinsOverALeftoverUrl() = runBlocking {
        writeLegacy(actAsCAServer = true, caServerURL = LEGACY_URL)

        assertEquals(CertificateAuthoritySource.THIS_DEVICE, repository.getSettings().caSource)
    }

    /** Once the new key is written, the legacy keys stop being consulted. */
    @Test
    fun migration_anExplicitChoiceOutranksTheLegacyKeys() = runBlocking {
        writeLegacy(actAsCAServer = true, caServerURL = LEGACY_URL)

        repository.updateCASource(CertificateAuthoritySource.NONE)

        assertEquals(CertificateAuthoritySource.NONE, repository.getSettings().caSource)
    }

    /**
     * A value this build does not know — a downgrade, or a hand-edited store —
     * must degrade to "nobody signs" rather than throw out of the settings flow
     * and take every screen that collects it with it.
     */
    @Test
    fun migration_anUnrecognisedCaSourceFallsBackToNone() = runBlocking {
        dataStore.edit { it[CA_SOURCE_KEY] = "SOME_FUTURE_AUTHORITY" }

        assertEquals(CertificateAuthoritySource.NONE, repository.getSettings().caSource)
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * Writes the retired preference keys an install from before the three-way
     * choice would hold. Nothing writes `ca_source`, which is what leaves the
     * migration branch reachable.
     */
    private suspend fun writeLegacy(actAsCAServer: Boolean? = null, caServerURL: String? = null) {
        dataStore.edit { preferences ->
            actAsCAServer?.let { preferences[ACT_AS_CA_SERVER_KEY] = it }
            caServerURL?.let { preferences[CA_SERVER_URL_KEY] = it }
        }
    }

    private fun dataStoreOf(
        repository: TrustedComputingSettingsRepository
    ): DataStore<Preferences> {
        val field = try {
            TrustedComputingSettingsRepository::class.java.getDeclaredField("dataStore")
        } catch (e: NoSuchFieldException) {
            throw AssertionError(
                "TrustedComputingSettingsRepository.dataStore is the only handle on the " +
                    "legacy preference keys these migration tests seed",
                e
            )
        }
        field.isAccessible = true
        @Suppress("UNCHECKED_CAST")
        return field.get(repository) as DataStore<Preferences>
    }

    private companion object {
        const val LEGACY_URL = "https://ca.legacy.example.test"

        val CA_SOURCE_KEY = stringPreferencesKey("ca_source")
        val ACT_AS_CA_SERVER_KEY = booleanPreferencesKey("act_as_ca_server")
        val CA_SERVER_URL_KEY = stringPreferencesKey("ca_server_url")
    }
}
