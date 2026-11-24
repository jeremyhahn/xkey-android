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
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
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
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.util.concurrent.atomic.AtomicReference

/**
 * [BootstrapSettingsRepository] on a real file-backed Preferences DataStore:
 * defaults of an empty store, every update read back through a second
 * repository on the same file, the mapping of raw stored values, URL
 * derivation, and the audit entries of the settings that decide how the
 * bootstrap connection is pinned.
 *
 * The [AuditLogger] singleton gets a mock DAO and an unconfined scope, as in
 * `UsbHsmSettingsAuditTest`, so entries are captured synchronously.
 */
class BootstrapSettingsRepositoryJvmTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val inserted = mutableListOf<AuditLogEntity>()
    private val jobs = mutableListOf<Job>()
    private lateinit var file: File
    private lateinit var store: DataStore<Preferences>
    private lateinit var repository: BootstrapSettingsRepository

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
    private suspend fun reopened(): BootstrapSettingsRepository {
        jobs.last().cancelAndJoin()
        store = open()
        repository = BootstrapSettingsRepository(store)
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
        file = tmp.newFile("bootstrap_settings.preferences_pb").apply { delete() }
        store = open()
        repository = BootstrapSettingsRepository(store)
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

    // -------------------------------------------------------------------------
    // Defaults
    // -------------------------------------------------------------------------

    @Test
    fun `an empty store reads the defaults`() = runBlocking {
        val settings = repository.getSettings()

        assertTrue(settings.autoBootstrapEnabled)
        assertEquals(BootstrapMethod.DEFAULT_ORDER, settings.methodOrder)
        assertEquals(BootstrapSettingsData.DEFAULT_PER_METHOD_TIMEOUT_SECONDS, settings.perMethodTimeoutSeconds)
        assertTrue(settings.daneEnabled)
        assertTrue(settings.daneRequireDnssec)
        assertEquals(BootstrapSettingsData.DEFAULT_DNS_SERVER, settings.daneDnsServer)
        assertEquals("", settings.noiseServerStaticKey)
        assertEquals("", settings.spkiPinSha256)
        assertEquals(BootstrapSettingsData.DEFAULT, settings)
    }

    // -------------------------------------------------------------------------
    // Round-trips through a second repository on the same file
    // -------------------------------------------------------------------------

    @Test
    fun `updateSettings round-trips every field`() = runBlocking {
        val written = BootstrapSettingsData(
            autoBootstrapEnabled = false,
            methodOrder = listOf(BootstrapMethod.SPKI, BootstrapMethod.DIRECT),
            perMethodTimeoutSeconds = 60,
            daneEnabled = false,
            daneServerUrl = "https://kms.example.com:8443",
            daneDnsServer = "192.0.2.53:53",
            daneDnsOverTls = true,
            daneRequireDnssec = false,
            noiseEnabled = true,
            noiseServerAddr = "kms.example.com:8445",
            noiseServerStaticKey = NOISE_KEY,
            spkiEnabled = true,
            spkiServerUrl = "https://kms.example.com:8443",
            spkiPinSha256 = PIN,
            directEnabled = true,
            directServerUrl = "https://kms.example.com"
        )
        repository.updateSettings(written)

        assertEquals(written, reopened().getSettings())
    }

    @Test
    fun `each single-group update round-trips`() = runBlocking {
        repository.updateAutoBootstrapEnabled(false)
        repository.updateMethodOrder(listOf(BootstrapMethod.NOISE, BootstrapMethod.DANE))
        repository.updatePerMethodTimeout(BootstrapTimeout.SECONDS_30)
        repository.updateDaneSettings(
            enabled = false,
            serverUrl = "https://dane.example.com",
            dnsServer = "192.0.2.1:853",
            dnsOverTls = true,
            requireDnssec = false
        )
        repository.updateNoiseSettings(enabled = true, serverAddr = "noise.example.com:8445", serverStaticKey = NOISE_KEY)
        repository.updateSpkiSettings(enabled = true, serverUrl = "https://spki.example.com", pinSha256 = PIN)
        repository.updateDirectSettings(enabled = true, serverUrl = "https://direct.example.com")

        assertEquals(
            BootstrapSettingsData(
                autoBootstrapEnabled = false,
                methodOrder = listOf(BootstrapMethod.NOISE, BootstrapMethod.DANE),
                perMethodTimeoutSeconds = 30,
                daneEnabled = false,
                daneServerUrl = "https://dane.example.com",
                daneDnsServer = "192.0.2.1:853",
                daneDnsOverTls = true,
                daneRequireDnssec = false,
                noiseEnabled = true,
                noiseServerAddr = "noise.example.com:8445",
                noiseServerStaticKey = NOISE_KEY,
                spkiEnabled = true,
                spkiServerUrl = "https://spki.example.com",
                spkiPinSha256 = PIN,
                directEnabled = true,
                directServerUrl = "https://direct.example.com"
            ),
            reopened().getSettings()
        )
    }

    @Test
    fun `partial group updates leave the other fields`() = runBlocking {
        repository.updateDaneSettings(serverUrl = "https://dane.example.com")
        repository.updateSpkiSettings(enabled = true)

        val settings = reopened().getSettings()
        assertEquals("https://dane.example.com", settings.daneServerUrl)
        assertTrue(settings.daneRequireDnssec)
        assertTrue(settings.spkiEnabled)
        assertEquals("", settings.spkiPinSha256)
    }

    @Test
    fun `updatePerMethodTimeout round-trips each predefined timeout`() = runBlocking {
        for (timeout in BootstrapTimeout.entries) {
            repository.updatePerMethodTimeout(timeout)
            assertEquals(timeout.seconds, reopened().getSettings().perMethodTimeoutSeconds)
        }
    }

    @Test(expected = IllegalArgumentException::class)
    fun `updatePerMethodTimeout of zero is refused`() = runBlocking {
        repository.updatePerMethodTimeout(0)
    }

    @Test
    fun `resetToDefaults and clearSettings read back the defaults`() = runBlocking {
        repository.updateSettings(BootstrapSettingsData.DEVELOPMENT.copy(daneRequireDnssec = false))
        repository.resetToDefaults()
        assertEquals(BootstrapSettingsData.DEFAULT, reopened().getSettings())

        repository.updateSettings(BootstrapSettingsData.HIGH_SECURITY)
        repository.clearSettings()
        assertEquals(BootstrapSettingsData.DEFAULT, reopened().getSettings())
    }

    @Test
    fun `enabled methods follow the stored order`() = runBlocking {
        repository.updateSettings(BootstrapSettingsData.HIGH_SECURITY)

        assertEquals(listOf(BootstrapMethod.DANE, BootstrapMethod.NOISE), repository.getEnabledMethods())
        assertTrue(repository.isMethodEnabled(BootstrapMethod.NOISE))
        assertEquals(false, repository.isMethodEnabled(BootstrapMethod.DIRECT))
    }

    // -------------------------------------------------------------------------
    // Raw stored values
    // -------------------------------------------------------------------------

    @Test
    fun `stored method order skips blanks and unknown names`() = runBlocking {
        store.edit { it[KEY_METHOD_ORDER] = " spki, ,tofu,DIRECT," }

        assertEquals(listOf(BootstrapMethod.SPKI, BootstrapMethod.DIRECT), repository.getSettings().methodOrder)
    }

    @Test
    fun `stored method order of only unknown names reads as the default order`() = runBlocking {
        store.edit { it[KEY_METHOD_ORDER] = "tofu,bogus" }

        assertEquals(BootstrapMethod.DEFAULT_ORDER, repository.getSettings().methodOrder)
    }

    @Test
    fun `stored method order drops duplicates and keeps the first occurrence`() = runBlocking {
        store.edit { it[KEY_METHOD_ORDER] = "direct,DANE,DIRECT,spki,dane" }

        val settings = repository.getSettings()
        assertEquals(
            listOf(BootstrapMethod.DIRECT, BootstrapMethod.DANE, BootstrapMethod.SPKI),
            settings.methodOrder
        )
        assertEquals(listOf(BootstrapMethod.DANE), settings.getEnabledMethods())
    }

    @Test
    fun `stored method order of one repeated method reads as that method once`() = runBlocking {
        store.edit { it[KEY_METHOD_ORDER] = "noise,NOISE,noise" }

        assertEquals(listOf(BootstrapMethod.NOISE), repository.getSettings().methodOrder)
    }

    // -------------------------------------------------------------------------
    // deriveSettingsFromUrl
    // -------------------------------------------------------------------------

    @Test
    fun `deriveSettingsFromUrl fills every server from an https URL`() = runBlocking {
        repository.deriveSettingsFromUrl("https://kms.example.com:8443")

        val settings = reopened().getSettings()
        assertEquals("https://kms.example.com:8443", settings.daneServerUrl)
        assertEquals("kms.example.com:8445", settings.noiseServerAddr)
        assertEquals("https://kms.example.com:8443", settings.spkiServerUrl)
        assertEquals("https://kms.example.com:8443", settings.directServerUrl)
    }

    @Test
    fun `deriveSettingsFromUrl upgrades an http URL to https`() = runBlocking {
        repository.deriveSettingsFromUrl("http://kms.example.com")

        val settings = reopened().getSettings()
        assertEquals("https://kms.example.com:443", settings.directServerUrl)
        assertEquals("kms.example.com:8445", settings.noiseServerAddr)
    }

    @Test
    fun `deriveSettingsFromUrl with no scheme changes nothing`() = runBlocking {
        repository.deriveSettingsFromUrl("kms.example.com")

        assertEquals(BootstrapSettingsData.DEFAULT, reopened().getSettings())
    }

    /**
     * Found: [BootstrapSettingsRepository.updateSettings] writes every field
     * without the audited path, so turning DNSSEC off or replacing a pin
     * through it leaves no entry. This test records what main does.
     */
    @Test
    fun `found - updateSettings writes no audit entry`() = runBlocking {
        repository.updateSettings(BootstrapSettingsData(daneRequireDnssec = false, spkiPinSha256 = PIN))

        assertEquals(emptyList<AuditLogEntity>(), inserted)
    }

    // -------------------------------------------------------------------------
    // Stored timeout, validation and scheme
    // -------------------------------------------------------------------------

    @Test
    fun `a stored per-method timeout of zero or below reads as the default`() = runBlocking {
        for (stored in listOf(0, -1, Int.MIN_VALUE)) {
            store.edit { it[KEY_PER_METHOD_TIMEOUT] = stored }
            assertEquals(
                BootstrapSettingsData.DEFAULT_PER_METHOD_TIMEOUT_SECONDS,
                repository.getSettings().perMethodTimeoutSeconds
            )
        }
    }

    @Test
    fun `updateSpkiSettings refuses a pin that is not 64 hex characters`() = runBlocking {
        repository.updateSpkiSettings(pinSha256 = PIN)
        for (bad in listOf(PIN.dropLast(1), PIN + "0", PIN.dropLast(1) + "g", "sha256/" + PIN.drop(7))) {
            assertFalse("pin $bad was accepted", repository.updateSpkiSettings(enabled = true, pinSha256 = bad))
        }

        val settings = reopened().getSettings()
        assertEquals(PIN, settings.spkiPinSha256)
        assertEquals(false, settings.spkiEnabled)
    }

    @Test
    fun `updateNoiseSettings refuses an invalid static key`() = runBlocking {
        repository.updateNoiseSettings(serverStaticKey = NOISE_KEY)
        for (bad in listOf(NOISE_KEY.take(32), NOISE_KEY + "AB", NOISE_KEY.dropLast(1) + "Z")) {
            assertFalse("key $bad was accepted", repository.updateNoiseSettings(enabled = true, serverStaticKey = bad))
        }

        val settings = reopened().getSettings()
        assertEquals(NOISE_KEY, settings.noiseServerStaticKey)
        assertEquals(false, settings.noiseEnabled)
    }

    @Test
    fun `an empty pin and key clear them`() = runBlocking {
        repository.updateSpkiSettings(pinSha256 = PIN)
        repository.updateNoiseSettings(serverStaticKey = NOISE_KEY)
        repository.updateSpkiSettings(pinSha256 = "")
        repository.updateNoiseSettings(serverStaticKey = "")

        val settings = reopened().getSettings()
        assertEquals("", settings.spkiPinSha256)
        assertEquals("", settings.noiseServerStaticKey)
    }

    @Test
    fun `deriveSettingsFromUrl ignores a URL that is not http or https`() = runBlocking {
        repository.deriveSettingsFromUrl("ftp://kms.example.com:2121")

        assertEquals(BootstrapSettingsData.DEFAULT, reopened().getSettings())
    }

    // -------------------------------------------------------------------------
    // Audit entries
    // -------------------------------------------------------------------------

    @Test
    fun `turning DNSSEC off and on records each change`() = runBlocking {
        repository.updateDaneSettings(requireDnssec = false)
        repository.updateDaneSettings(serverUrl = "https://dane.example.com", requireDnssec = true)

        assertEquals(2, inserted.size)
        assertChange(inserted[0], "daneRequireDnssec", "true", "false")
        assertChange(inserted[1], "daneRequireDnssec", "false", "true")
    }

    @Test
    fun `a new SPKI pin records one entry`() = runBlocking {
        repository.updateSpkiSettings(enabled = true, serverUrl = "https://spki.example.com", pinSha256 = PIN)

        assertEquals(1, inserted.size)
        assertChange(inserted[0], "spkiPinSha256", "", PIN)
    }

    @Test
    fun `a new Noise static key records one entry`() = runBlocking {
        repository.updateNoiseSettings(enabled = true, serverAddr = "noise.example.com:8445", serverStaticKey = NOISE_KEY)

        assertEquals(1, inserted.size)
        assertChange(inserted[0], "noiseServerStaticKey", "", NOISE_KEY)
    }

    @Test
    fun `unchanged DNSSEC, pin and key record nothing`() = runBlocking {
        repository.updateDaneSettings(requireDnssec = true, serverUrl = "https://dane.example.com")
        repository.updateSpkiSettings(pinSha256 = "", enabled = true)
        repository.updateNoiseSettings(serverStaticKey = "", enabled = true)
        repository.updateDaneSettings(dnsOverTls = true)

        assertEquals(emptyList<AuditLogEntity>(), inserted)
    }

    private companion object {
        const val PIN = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        const val NOISE_KEY = "FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210"
        val KEY_METHOD_ORDER = stringPreferencesKey("method_order")
        val KEY_PER_METHOD_TIMEOUT = intPreferencesKey("per_method_timeout_seconds")
    }
}
