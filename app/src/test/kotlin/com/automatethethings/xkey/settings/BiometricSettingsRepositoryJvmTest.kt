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
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.util.concurrent.atomic.AtomicReference

/**
 * [BiometricSettingsRepository] on a real file-backed Preferences DataStore:
 * defaults of an empty store, every update read back through a second
 * repository on the same file, the mapping of raw stored values, and the
 * `SETTINGS_CHANGED` audit entries of the policy setters.
 *
 * The [AuditLogger] singleton gets a mock DAO and an unconfined scope, as in
 * `UsbHsmSettingsAuditTest`, so entries are captured synchronously.
 */
class BiometricSettingsRepositoryJvmTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val inserted = mutableListOf<AuditLogEntity>()
    private val jobs = mutableListOf<Job>()
    private lateinit var file: File
    private lateinit var store: DataStore<Preferences>
    private lateinit var repository: BiometricSettingsRepository

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
    private suspend fun reopened(): BiometricSettingsRepository {
        jobs.last().cancelAndJoin()
        store = open()
        repository = BiometricSettingsRepository(store)
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
        file = tmp.newFile("biometric_settings.preferences_pb").apply { delete() }
        store = open()
        repository = BiometricSettingsRepository(store)
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

        assertEquals(UserVerificationPolicy.REQUIRED, settings.uvPolicy)
        assertEquals(BiometricAuthMode.PER_OPERATION, settings.authMode)
        assertEquals(AuthTimeWindow.MINUTES_2.seconds, settings.timeWindowSeconds)
        assertEquals(AttestationBiometricPolicy.ALWAYS, settings.attestationBiometricPolicy)
        assertTrue(settings.strictUserVerification)
        assertEquals(BiometricSettingsData.DEFAULT, settings)
    }

    // -------------------------------------------------------------------------
    // Round-trips through a second repository on the same file
    // -------------------------------------------------------------------------

    @Test
    fun `updateSettings round-trips every field`() = runBlocking {
        val written = BiometricSettingsData(
            uvPolicy = UserVerificationPolicy.DISABLED,
            authMode = BiometricAuthMode.TIME_WINDOW,
            timeWindowSeconds = AuthTimeWindow.MINUTES_10.seconds,
            attestationBiometricPolicy = AttestationBiometricPolicy.PAIRED_DEVICES_SKIP,
            strictUserVerification = false
        )
        repository.updateSettings(written)

        assertEquals(written, reopened().getSettings())
    }

    @Test
    fun `updateUserVerificationPolicy round-trips`() = runBlocking {
        repository.updateUserVerificationPolicy(UserVerificationPolicy.DISABLED)

        assertEquals(UserVerificationPolicy.DISABLED, reopened().getSettings().uvPolicy)
    }

    @Test
    fun `updateAuthMode round-trips each mode`() = runBlocking {
        for (mode in BiometricAuthMode.entries) {
            repository.updateAuthMode(mode)
            assertEquals(mode, reopened().getSettings().authMode)
        }
    }

    @Test
    fun `updateTimeWindow round-trips each predefined window and a custom value`() = runBlocking {
        for (window in AuthTimeWindow.entries) {
            repository.updateTimeWindow(window)
            assertEquals(window.seconds, reopened().getSettings().timeWindowSeconds)
        }
        repository.updateTimeWindow(45)
        assertEquals(45, reopened().getSettings().timeWindowSeconds)
    }

    @Test
    fun `updateAttestationBiometricPolicy round-trips each policy`() = runBlocking {
        for (policy in AttestationBiometricPolicy.entries) {
            repository.updateAttestationBiometricPolicy(policy)
            assertEquals(policy, reopened().getSettings().attestationBiometricPolicy)
        }
    }

    @Test
    fun `setBiometricEnabled round-trips as the user verification policy`() = runBlocking {
        repository.setBiometricEnabled(false)
        assertEquals(UserVerificationPolicy.DISABLED, reopened().getSettings().uvPolicy)

        repository.setBiometricEnabled(true)
        assertEquals(UserVerificationPolicy.REQUIRED, reopened().getSettings().uvPolicy)
    }

    @Test
    fun `resetToDefaults and clearSettings read back the defaults`() = runBlocking {
        repository.updateSettings(BiometricSettingsData.CONVENIENCE.copy(strictUserVerification = false))
        repository.resetToDefaults()
        assertEquals(BiometricSettingsData.DEFAULT, reopened().getSettings())

        repository.updateSettings(BiometricSettingsData.DISABLED)
        repository.clearSettings()
        assertEquals(BiometricSettingsData.DEFAULT, reopened().getSettings())
    }

    @Test(expected = IllegalArgumentException::class)
    fun `updateTimeWindow of zero is refused`() = runBlocking {
        repository.updateTimeWindow(0)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `updateTimeWindow of a negative value is refused`() = runBlocking {
        repository.updateTimeWindow(-1)
    }

    // -------------------------------------------------------------------------
    // Raw stored values
    // -------------------------------------------------------------------------

    @Test
    fun `unknown stored enum names read as the defaults`() = runBlocking {
        store.edit {
            it[stringPreferencesKey("uv_policy")] = "OPTIONAL"
            it[stringPreferencesKey("auth_mode")] = "per_operation"
            it[stringPreferencesKey("attestation_biometric_policy")] = ""
        }

        val settings = repository.getSettings()
        assertEquals(UserVerificationPolicy.REQUIRED, settings.uvPolicy)
        assertEquals(BiometricAuthMode.PER_OPERATION, settings.authMode)
        assertEquals(AttestationBiometricPolicy.ALWAYS, settings.attestationBiometricPolicy)
    }

    @Test
    fun `stored values of each key are read`() = runBlocking {
        store.edit {
            it[stringPreferencesKey("uv_policy")] = "DISABLED"
            it[stringPreferencesKey("auth_mode")] = "PER_SESSION"
            it[intPreferencesKey("time_window_seconds")] = 300
            it[stringPreferencesKey("attestation_biometric_policy")] = "NEVER"
            it[booleanPreferencesKey("strict_user_verification")] = false
        }

        assertEquals(
            BiometricSettingsData(
                uvPolicy = UserVerificationPolicy.DISABLED,
                authMode = BiometricAuthMode.PER_SESSION,
                timeWindowSeconds = 300,
                attestationBiometricPolicy = AttestationBiometricPolicy.NEVER,
                strictUserVerification = false
            ),
            repository.getSettings()
        )
    }

    /**
     * Found: the read path takes any stored time window, although
     * [BiometricSettingsRepository.updateTimeWindow] refuses one that is not
     * positive. A window of 0 or below makes every TIME_WINDOW operation
     * prompt; Int.MAX_VALUE is a window of about 68 years. This test records
     * what main reads; bounding the window is left to a follow-up.
     */
    @Test
    fun `found - stored time windows out of range are read as stored`() = runBlocking {
        for (stored in listOf(0, -1, Int.MAX_VALUE)) {
            store.edit { it[intPreferencesKey("time_window_seconds")] = stored }
            assertEquals(stored, repository.getSettings().timeWindowSeconds)
        }
    }

    // -------------------------------------------------------------------------
    // Audit entries
    // -------------------------------------------------------------------------

    @Test
    fun `updateUserVerificationPolicy records the old and new policy`() = runBlocking {
        repository.updateUserVerificationPolicy(UserVerificationPolicy.DISABLED)

        assertEquals(1, inserted.size)
        assertChange(inserted[0], "userVerificationPolicy", "REQUIRED", "DISABLED")
    }

    @Test
    fun `updateAuthMode records the old and new mode`() = runBlocking {
        repository.updateAuthMode(BiometricAuthMode.TIME_WINDOW)

        assertEquals(1, inserted.size)
        assertChange(inserted[0], "authMode", "PER_OPERATION", "TIME_WINDOW")
    }

    @Test
    fun `updateAttestationBiometricPolicy records the old and new policy`() = runBlocking {
        repository.updateAttestationBiometricPolicy(AttestationBiometricPolicy.NEVER)

        assertEquals(1, inserted.size)
        assertChange(inserted[0], "attestationBiometricPolicy", "ALWAYS", "NEVER")
    }

    @Test
    fun `setBiometricEnabled false records the policy change`() = runBlocking {
        repository.setBiometricEnabled(false)

        assertEquals(1, inserted.size)
        assertChange(inserted[0], "userVerificationPolicy", "REQUIRED", "DISABLED")
    }

    @Test
    fun `writing the stored policy records nothing`() = runBlocking {
        repository.updateUserVerificationPolicy(UserVerificationPolicy.REQUIRED)
        repository.updateAuthMode(BiometricAuthMode.PER_OPERATION)
        repository.updateAttestationBiometricPolicy(AttestationBiometricPolicy.ALWAYS)
        repository.setBiometricEnabled(true)

        assertEquals(emptyList<AuditLogEntity>(), inserted)
    }

    /**
     * Found: [BiometricSettingsRepository.updateTimeWindow],
     * [BiometricSettingsRepository.updateSettings] and
     * [BiometricSettingsRepository.resetToDefaults] write the policy without
     * the audited path, so turning user verification off through them leaves
     * no entry. This test records what main does.
     */
    @Test
    fun `found - updateTimeWindow, updateSettings and resetToDefaults write no audit entry`() = runBlocking {
        repository.updateTimeWindow(AuthTimeWindow.MINUTES_10)
        repository.updateSettings(BiometricSettingsData.DISABLED.copy(strictUserVerification = false))
        repository.resetToDefaults()

        assertEquals(emptyList<AuditLogEntity>(), inserted)
        assertEquals(BiometricSettingsData.DEFAULT, repository.getSettings())
    }
}
