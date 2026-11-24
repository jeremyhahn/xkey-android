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

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import com.automatethethings.xkey.audit.AuditLogDao
import com.automatethethings.xkey.audit.AuditLogEntity
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.audit.AuditOperationType
import io.mockk.coEvery
import io.mockk.mockk
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.util.concurrent.atomic.AtomicReference

/**
 * [TrustedComputingSettingsRepository] on a real file-backed Preferences
 * DataStore: defaults of an empty store, every update read back through a
 * second repository on the same file, the migration of the legacy
 * `act_as_ca_server` and `ca_server_url` keys, and the audit entries of the
 * security-relevant setters.
 *
 * The [AuditLogger] singleton gets a mock DAO and an unconfined scope, as in
 * `UsbHsmSettingsAuditTest`, so entries are captured synchronously.
 */
class TrustedComputingSettingsRepositoryJvmTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val inserted = mutableListOf<AuditLogEntity>()
    private val jobs = mutableListOf<Job>()
    private lateinit var file: File
    private lateinit var store: DataStore<Preferences>
    private lateinit var repository: TrustedComputingSettingsRepository

    @Suppress("UNCHECKED_CAST")
    private fun <T> holder(name: String): AtomicReference<T?> =
        AuditLogger::class.java.getDeclaredField(name)
            .apply { isAccessible = true }
            .get(AuditLogger) as AtomicReference<T?>

    private fun open(): DataStore<Preferences> {
        val job = Job().also { jobs += it }
        return PreferenceDataStoreFactory.create(scope = CoroutineScope(Dispatchers.IO + job)) { file }
    }

    /** Closes the current store and reads the file through a new repository. */
    private suspend fun reopened(): TrustedComputingSettingsRepository {
        jobs.last().cancelAndJoin()
        store = open()
        repository = TrustedComputingSettingsRepository(store)
        return repository
    }

    @Before
    fun setUp() {
        val dao = mockk<AuditLogDao>(relaxed = true)
        coEvery { dao.insert(any()) } answers {
            inserted += firstArg<AuditLogEntity>()
            inserted.size.toLong()
        }
        holder<AuditLogDao>("daoRef").set(dao)
        holder<CoroutineScope>("scopeRef").set(CoroutineScope(Dispatchers.Unconfined))
        file = tmp.newFile("trusted_computing_settings.preferences_pb").apply { delete() }
        store = open()
        repository = TrustedComputingSettingsRepository(store)
    }

    @After
    fun tearDown() {
        runBlocking { jobs.forEach { it.cancelAndJoin() } }
        holder<AuditLogDao>("daoRef").set(null)
        holder<CoroutineScope>("scopeRef").set(null)
    }

    private fun assertChange(entry: AuditLogEntity, setting: String, old: String, new: String) {
        assertEquals(AuditOperationType.SETTINGS_CHANGED, entry.operationType)
        assertTrue(entry.success)
        val details = JSONObject(entry.details!!)
        assertEquals(setting, details.getString("setting"))
        assertEquals(old, details.getString("oldValue"))
        assertEquals(new, details.getString("newValue"))
    }

    private suspend fun writeLegacy(actAsCaServer: Boolean? = null, caServerUrl: String? = null) {
        store.edit { preferences ->
            actAsCaServer?.let { preferences[KEY_ACT_AS_CA_SERVER] = it }
            caServerUrl?.let { preferences[KEY_CA_SERVER_URL] = it }
        }
    }

    private suspend fun storedKeys(): Set<String> =
        store.data.first().asMap().keys.map { it.name }.toSet()

    // -------------------------------------------------------------------------
    // Defaults
    // -------------------------------------------------------------------------

    @Test
    fun `an empty store reads the defaults`() = runBlocking {
        val settings = repository.getSettings()

        assertFalse(settings.enabled)
        assertEquals(CertificateAuthoritySource.NONE, settings.caSource)
        assertNull(settings.xkmsEndpoint)
        assertFalse(settings.requireTrustedIDevID)
        assertFalse(settings.requireFullAttestation)
        assertTrue(settings.trustNewDevices)
        assertFalse(settings.importToSystemStore)
        assertEquals("xkey_intermediate_ca", settings.platformCAAlias)
        assertEquals(TrustedComputingSettingsData.DEFAULT, settings)
    }

    // -------------------------------------------------------------------------
    // Round-trips through a second repository on the same file
    // -------------------------------------------------------------------------

    @Test
    fun `updateSettings round-trips every field`() = runBlocking {
        val written = TrustedComputingSettingsData(
            enabled = true,
            caSource = CertificateAuthoritySource.XKMS,
            xkmsEndpoint = "https://xkms.example.com:8443",
            requireTrustedIDevID = true,
            requireFullAttestation = true,
            trustNewDevices = false,
            importToSystemStore = true,
            caSubjectOrganization = "Example Org",
            caSubjectOU = "Devices",
            caSubjectLocality = "Springfield",
            caSubjectProvince = "State",
            caSubjectCountry = "US",
            caSubjectCommonName = "Example Device CA",
            platformCAAlias = "xkey_root_ca"
        )
        repository.updateSettings(written)

        assertEquals(written, reopened().getSettings())
    }

    @Test
    fun `updateSettings with no endpoint round-trips as null`() = runBlocking {
        repository.updateSettings(TrustedComputingSettingsData.STRICT.copy(xkmsEndpoint = "https://xkms.example.com"))
        repository.updateSettings(TrustedComputingSettingsData.STRICT)

        assertEquals(TrustedComputingSettingsData.STRICT, reopened().getSettings())
    }

    @Test
    fun `each single-field update round-trips`() = runBlocking {
        repository.updateEnabled(true)
        repository.updateCASource(CertificateAuthoritySource.THIS_DEVICE)
        repository.updateXkmsEndpoint("https://xkms.example.com")
        repository.updateRequireTrustedIDevID(true)
        repository.updateRequireFullAttestation(true)
        repository.updateTrustNewDevices(false)
        repository.updateImportToSystemStore(true)
        repository.updateCASubject("Org", "OU", "City", "Province", "DE", "CN")
        repository.updatePlatformCAAlias("xkey_root_ca")

        assertEquals(
            TrustedComputingSettingsData(
                enabled = true,
                caSource = CertificateAuthoritySource.THIS_DEVICE,
                xkmsEndpoint = "https://xkms.example.com",
                requireTrustedIDevID = true,
                requireFullAttestation = true,
                trustNewDevices = false,
                importToSystemStore = true,
                caSubjectOrganization = "Org",
                caSubjectOU = "OU",
                caSubjectLocality = "City",
                caSubjectProvince = "Province",
                caSubjectCountry = "DE",
                caSubjectCommonName = "CN",
                platformCAAlias = "xkey_root_ca"
            ),
            reopened().getSettings()
        )
    }

    @Test
    fun `updateCASource round-trips each source`() = runBlocking {
        for (source in CertificateAuthoritySource.entries) {
            repository.updateCASource(source)
            assertEquals(source, reopened().getSettings().caSource)
        }
    }

    @Test
    fun `updateXkmsEndpoint null clears a stored endpoint`() = runBlocking {
        repository.updateXkmsEndpoint("https://xkms.example.com")
        repository.updateXkmsEndpoint(null)

        assertNull(reopened().getSettings().xkmsEndpoint)
    }

    @Test
    fun `clearSettings reads back the defaults and leaves no key`() = runBlocking {
        repository.updateSettings(TrustedComputingSettingsData.STRICT)
        writeLegacy(actAsCaServer = true, caServerUrl = "https://legacy.example.com")
        repository.clearSettings()

        assertEquals(emptySet<String>(), storedKeys())
        assertEquals(TrustedComputingSettingsData.DEFAULT, reopened().getSettings())
    }

    // -------------------------------------------------------------------------
    // readCASource and the legacy keys
    // -------------------------------------------------------------------------

    @Test
    fun `each stored source name is read`() = runBlocking {
        for (source in CertificateAuthoritySource.entries) {
            store.edit { it[KEY_CA_SOURCE] = source.name }
            assertEquals(source, repository.getSettings().caSource)
        }
    }

    @Test
    fun `an unknown stored source reads as NONE, even over a legacy key`() = runBlocking {
        writeLegacy(actAsCaServer = true, caServerUrl = "https://legacy.example.com")
        store.edit { it[KEY_CA_SOURCE] = "LEGACY_CA" }

        assertEquals(CertificateAuthoritySource.NONE, repository.getSettings().caSource)
    }

    @Test
    fun `a stored source wins over the legacy keys`() = runBlocking {
        writeLegacy(actAsCaServer = true)
        store.edit { it[KEY_CA_SOURCE] = CertificateAuthoritySource.XKMS.name }

        assertEquals(CertificateAuthoritySource.XKMS, repository.getSettings().caSource)
    }

    @Test
    fun `legacy act_as_ca_server true reads as THIS_DEVICE`() = runBlocking {
        writeLegacy(actAsCaServer = true, caServerUrl = "https://legacy.example.com")

        assertEquals(CertificateAuthoritySource.THIS_DEVICE, repository.getSettings().caSource)
    }

    @Test
    fun `legacy server URL without a source reads as XKMS at that URL`() = runBlocking {
        writeLegacy(actAsCaServer = false, caServerUrl = "https://legacy.example.com")

        val settings = repository.getSettings()
        assertEquals(CertificateAuthoritySource.XKMS, settings.caSource)
        assertEquals("https://legacy.example.com", settings.xkmsEndpoint)
    }

    @Test
    fun `legacy act_as_ca_server false and a blank URL read as NONE`() = runBlocking {
        writeLegacy(actAsCaServer = false, caServerUrl = "  ")

        assertEquals(CertificateAuthoritySource.NONE, repository.getSettings().caSource)
    }

    @Test
    fun `a stored endpoint wins over the legacy server URL`() = runBlocking {
        writeLegacy(caServerUrl = "https://legacy.example.com")
        repository.updateXkmsEndpoint("https://xkms.example.com")

        assertEquals("https://xkms.example.com", reopened().getSettings().xkmsEndpoint)
    }

    /**
     * Found: requireTrustedIDevID, requireFullAttestation and trustNewDevices
     * are stored and shown, but no enforcement code reads them; this test
     * only pins the stored value.
     */
    @Test
    fun `found - the trust flags are stored as written`() = runBlocking {
        repository.updateSettings(TrustedComputingSettingsData.STRICT)

        val settings = reopened().getSettings()
        assertTrue(settings.requireTrustedIDevID)
        assertTrue(settings.requireFullAttestation)
        assertFalse(settings.trustNewDevices)
    }

    // -------------------------------------------------------------------------
    // A cleared endpoint stays cleared
    // -------------------------------------------------------------------------

    @Test
    fun `updateXkmsEndpoint null with a legacy server URL stored reads back null`() = runBlocking {
        writeLegacy(caServerUrl = "https://legacy.example.com")
        repository.updateXkmsEndpoint("https://xkms.example.com")
        repository.updateXkmsEndpoint(null)

        assertNull(reopened().getSettings().xkmsEndpoint)
    }

    @Test
    fun `updateSettings with no endpoint and a legacy server URL stored reads back null`() = runBlocking {
        writeLegacy(caServerUrl = "https://legacy.example.com")
        repository.updateSettings(TrustedComputingSettingsData.STRICT)

        assertEquals(TrustedComputingSettingsData.STRICT, reopened().getSettings())
    }

    @Test
    fun `resetToDefaults leaves no legacy key`() = runBlocking {
        writeLegacy(actAsCaServer = true, caServerUrl = "https://legacy.example.com")
        repository.resetToDefaults()

        val keys = storedKeys()
        assertFalse(keys.contains(KEY_ACT_AS_CA_SERVER.name))
        assertFalse(keys.contains(KEY_CA_SERVER_URL.name))
        assertEquals(TrustedComputingSettingsData.DEFAULT, reopened().getSettings())
    }

    // -------------------------------------------------------------------------
    // Audit entries
    // -------------------------------------------------------------------------

    @Test
    fun `each security-relevant update records one entry with old and new value`() = runBlocking {
        repository.updateEnabled(true)
        repository.updateCASource(CertificateAuthoritySource.XKMS)
        repository.updateXkmsEndpoint("https://xkms.example.com")
        repository.updateRequireTrustedIDevID(true)
        repository.updateRequireFullAttestation(true)
        repository.updateTrustNewDevices(false)
        repository.updateImportToSystemStore(true)
        repository.updateXkmsEndpoint(null)
        repository.updateTrustNewDevices(true)

        assertEquals(9, inserted.size)
        assertChange(inserted[0], "trustedComputingEnabled", "false", "true")
        assertChange(inserted[1], "caSource", "NONE", "XKMS")
        assertChange(inserted[2], "xkmsEndpoint", "", "https://xkms.example.com")
        assertChange(inserted[3], "requireTrustedIDevID", "false", "true")
        assertChange(inserted[4], "requireFullAttestation", "false", "true")
        assertChange(inserted[5], "trustNewDevices", "true", "false")
        assertChange(inserted[6], "importToSystemStore", "false", "true")
        assertChange(inserted[7], "xkmsEndpoint", "https://xkms.example.com", "")
        assertChange(inserted[8], "trustNewDevices", "false", "true")
    }

    @Test
    fun `a legacy source is the old value of a CA source change`() = runBlocking {
        writeLegacy(actAsCaServer = true)
        repository.updateCASource(CertificateAuthoritySource.XKMS)

        assertEquals(1, inserted.size)
        assertChange(inserted[0], "caSource", "THIS_DEVICE", "XKMS")
    }

    @Test
    fun `writing the stored trusted computing values records nothing`() = runBlocking {
        repository.updateEnabled(false)
        repository.updateCASource(CertificateAuthoritySource.NONE)
        repository.updateXkmsEndpoint(null)
        repository.updateRequireTrustedIDevID(false)
        repository.updateRequireFullAttestation(false)
        repository.updateTrustNewDevices(true)
        repository.updateImportToSystemStore(false)

        assertEquals(emptyList<AuditLogEntity>(), inserted)
    }

    private companion object {
        val KEY_CA_SOURCE = stringPreferencesKey("ca_source")
        val KEY_ACT_AS_CA_SERVER = booleanPreferencesKey("act_as_ca_server")
        val KEY_CA_SERVER_URL = stringPreferencesKey("ca_server_url")
    }
}
