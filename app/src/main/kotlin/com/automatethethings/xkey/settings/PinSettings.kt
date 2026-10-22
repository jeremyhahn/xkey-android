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

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map

/**
 * Data class containing PIN management settings.
 *
 * This immutable data class encapsulates all PIN-related configuration
 * for the xKey application, including SO PIN and User PIN state,
 * hashes, salts, lockout policy, and attempt tracking.
 *
 * The SO PIN (Security Officer PIN) is the administrative PIN used to
 * manage User PINs and recover from lockouts, following the PKCS#11
 * security model.
 *
 * @property soPinSet Whether the SO PIN has been configured.
 * @property userPinSet Whether the User PIN has been configured.
 * @property soPinHashBase64 Base64-encoded Argon2id hash of the SO PIN.
 * @property userPinHashBase64 Base64-encoded Argon2id hash of the User PIN.
 * @property soPinSaltBase64 Base64-encoded salt used for SO PIN hashing.
 * @property userPinSaltBase64 Base64-encoded salt used for User PIN hashing.
 * @property failedSoPinAttempts Number of consecutive failed SO PIN attempts.
 * @property failedUserPinAttempts Number of consecutive failed User PIN attempts.
 * @property maxPinAttempts Maximum allowed failed attempts before lockout.
 * @property lockoutDurationSeconds Duration of lockout in seconds after max attempts exceeded.
 * @property backoffEnabled Whether exponential backoff is enabled for failed attempts.
 * @property soPinLockedUntil Epoch milliseconds until which the SO PIN is locked (0 = not locked).
 * @property userPinLockedUntil Epoch milliseconds until which the User PIN is locked (0 = not locked).
 */
public data class PinSettingsData(
    val soPinSet: Boolean = false,
    val userPinSet: Boolean = false,
    val soPinHashBase64: String? = null,
    val userPinHashBase64: String? = null,
    val soPinSaltBase64: String? = null,
    val userPinSaltBase64: String? = null,
    val failedSoPinAttempts: Int = 0,
    val failedUserPinAttempts: Int = 0,
    val maxPinAttempts: Int = 5,
    val lockoutDurationSeconds: Int = 300,
    val backoffEnabled: Boolean = true,
    val soPinLockedUntil: Long = 0,
    val userPinLockedUntil: Long = 0
)

/**
 * The password vault's failed-unlock counter, persisted beside the PIN
 * counters and held to the same lockout rule
 * ([com.automatethethings.xkey.pin.PinLockout]).
 *
 * @property failedAttempts Number of consecutive failed vault unlocks.
 * @property lockedUntil Epoch milliseconds until which vault unlocks are refused (0 = not locked).
 */
public data class VaultUnlockAttempts(
    val failedAttempts: Int = 0,
    val lockedUntil: Long = 0
)

/**
 * Extension property to create a DataStore instance for PIN settings.
 */
private val Context.pinSettingsDataStore: DataStore<Preferences> by preferencesDataStore(
    name = "pin_settings"
)

/**
 * Repository for persisting and retrieving PIN management settings.
 *
 * This class provides a coroutine-based API for managing PIN settings
 * using Jetpack DataStore for persistence. Settings are stored as preferences
 * and automatically persisted to disk.
 *
 * Usage:
 * ```kotlin
 * val repository = PinSettingsRepository(context)
 *
 * // Observe settings changes
 * repository.settingsFlow.collect { settings ->
 *     updateUI(settings)
 * }
 *
 * // Update settings
 * repository.updateSettings(
 *     PinSettingsData(soPinSet = true, maxPinAttempts = 3)
 * )
 * ```
 *
 * @param dataStore The DataStore the settings are persisted in.
 */
public class PinSettingsRepository internal constructor(
    private val dataStore: DataStore<Preferences>
) {
    /**
     * @param context The Android context used to access DataStore.
     */
    public constructor(context: Context) : this(context.pinSettingsDataStore)

    /**
     * Flow of PIN settings that emits whenever settings change.
     *
     * Collectors will receive the current settings immediately upon subscription
     * and subsequent updates as they occur.
     */
    public val settingsFlow: Flow<PinSettingsData> = dataStore.data.map { preferences ->
        mapPreferencesToSettings(preferences)
    }

    /**
     * Get the current PIN settings synchronously.
     *
     * This is a suspend function that retrieves the current settings
     * without setting up a continuous flow.
     *
     * @return The current [PinSettingsData].
     */
    public suspend fun getSettings(): PinSettingsData {
        return settingsFlow.first()
    }

    /**
     * Update all PIN settings at once.
     *
     * The write is a blind overwrite of every key: whatever [settings] holds
     * replaces the stored state, including the lockout counters. Callers that
     * derive [settings] from a previously read snapshot must serialize the
     * whole read-modify-write, or a concurrent update is silently lost --
     * `PinManager` does this through its process-wide PIN state mutex.
     *
     * @param settings The new settings to persist.
     */
    public suspend fun updateSettings(settings: PinSettingsData) {
        dataStore.edit { preferences ->
            preferences[KEY_SO_PIN_SET] = settings.soPinSet
            preferences[KEY_USER_PIN_SET] = settings.userPinSet
            preferences[KEY_SO_PIN_HASH_BASE64] = settings.soPinHashBase64 ?: ""
            preferences[KEY_USER_PIN_HASH_BASE64] = settings.userPinHashBase64 ?: ""
            preferences[KEY_SO_PIN_SALT_BASE64] = settings.soPinSaltBase64 ?: ""
            preferences[KEY_USER_PIN_SALT_BASE64] = settings.userPinSaltBase64 ?: ""
            preferences[KEY_FAILED_SO_PIN_ATTEMPTS] = settings.failedSoPinAttempts
            preferences[KEY_FAILED_USER_PIN_ATTEMPTS] = settings.failedUserPinAttempts
            preferences[KEY_MAX_PIN_ATTEMPTS] = settings.maxPinAttempts
            preferences[KEY_LOCKOUT_DURATION_SECONDS] = settings.lockoutDurationSeconds
            preferences[KEY_BACKOFF_ENABLED] = settings.backoffEnabled
            preferences[KEY_SO_PIN_LOCKED_UNTIL] = settings.soPinLockedUntil
            preferences[KEY_USER_PIN_LOCKED_UNTIL] = settings.userPinLockedUntil
        }
    }

    /**
     * Update whether the SO PIN has been set.
     *
     * @param set True if the SO PIN is configured.
     */
    public suspend fun updateSoPinSet(set: Boolean) {
        dataStore.edit { preferences ->
            preferences[KEY_SO_PIN_SET] = set
        }
    }

    /**
     * Update whether the User PIN has been set.
     *
     * @param set True if the User PIN is configured.
     */
    public suspend fun updateUserPinSet(set: Boolean) {
        dataStore.edit { preferences ->
            preferences[KEY_USER_PIN_SET] = set
        }
    }

    /**
     * Update the SO PIN hash (Base64-encoded).
     *
     * @param hashBase64 The Base64-encoded Argon2id hash of the SO PIN.
     */
    public suspend fun updateSoPinHashBase64(hashBase64: String?) {
        dataStore.edit { preferences ->
            preferences[KEY_SO_PIN_HASH_BASE64] = hashBase64 ?: ""
        }
    }

    /**
     * Update the User PIN hash (Base64-encoded).
     *
     * @param hashBase64 The Base64-encoded Argon2id hash of the User PIN.
     */
    public suspend fun updateUserPinHashBase64(hashBase64: String?) {
        dataStore.edit { preferences ->
            preferences[KEY_USER_PIN_HASH_BASE64] = hashBase64 ?: ""
        }
    }

    /**
     * Update the SO PIN salt (Base64-encoded).
     *
     * @param saltBase64 The Base64-encoded salt for SO PIN hashing.
     */
    public suspend fun updateSoPinSaltBase64(saltBase64: String?) {
        dataStore.edit { preferences ->
            preferences[KEY_SO_PIN_SALT_BASE64] = saltBase64 ?: ""
        }
    }

    /**
     * Update the User PIN salt (Base64-encoded).
     *
     * @param saltBase64 The Base64-encoded salt for User PIN hashing.
     */
    public suspend fun updateUserPinSaltBase64(saltBase64: String?) {
        dataStore.edit { preferences ->
            preferences[KEY_USER_PIN_SALT_BASE64] = saltBase64 ?: ""
        }
    }

    /**
     * Update the number of consecutive failed SO PIN attempts.
     *
     * @param attempts The current failed attempt count.
     */
    public suspend fun updateFailedSoPinAttempts(attempts: Int) {
        dataStore.edit { preferences ->
            preferences[KEY_FAILED_SO_PIN_ATTEMPTS] = attempts
        }
    }

    /**
     * Update the number of consecutive failed User PIN attempts.
     *
     * @param attempts The current failed attempt count.
     */
    public suspend fun updateFailedUserPinAttempts(attempts: Int) {
        dataStore.edit { preferences ->
            preferences[KEY_FAILED_USER_PIN_ATTEMPTS] = attempts
        }
    }

    /**
     * Update the maximum allowed failed PIN attempts before lockout.
     *
     * @param maxAttempts The maximum number of failed attempts.
     */
    public suspend fun updateMaxPinAttempts(maxAttempts: Int) {
        require(maxAttempts > 0) { "Max PIN attempts must be positive" }
        dataStore.edit { preferences ->
            preferences[KEY_MAX_PIN_ATTEMPTS] = maxAttempts
        }
    }

    /**
     * Update the lockout duration in seconds.
     *
     * @param seconds The lockout duration in seconds.
     */
    public suspend fun updateLockoutDurationSeconds(seconds: Int) {
        require(seconds > 0) { "Lockout duration must be positive" }
        dataStore.edit { preferences ->
            preferences[KEY_LOCKOUT_DURATION_SECONDS] = seconds
        }
    }

    /**
     * Update whether exponential backoff is enabled for failed attempts.
     *
     * @param enabled True to enable backoff.
     */
    public suspend fun updateBackoffEnabled(enabled: Boolean) {
        dataStore.edit { preferences ->
            preferences[KEY_BACKOFF_ENABLED] = enabled
        }
    }

    /**
     * Update the epoch milliseconds until which the SO PIN is locked.
     *
     * @param lockedUntil Epoch milliseconds (0 = not locked).
     */
    public suspend fun updateSoPinLockedUntil(lockedUntil: Long) {
        dataStore.edit { preferences ->
            preferences[KEY_SO_PIN_LOCKED_UNTIL] = lockedUntil
        }
    }

    /**
     * Update the epoch milliseconds until which the User PIN is locked.
     *
     * @param lockedUntil Epoch milliseconds (0 = not locked).
     */
    public suspend fun updateUserPinLockedUntil(lockedUntil: Long) {
        dataStore.edit { preferences ->
            preferences[KEY_USER_PIN_LOCKED_UNTIL] = lockedUntil
        }
    }

    /**
     * Get the password vault's failed-unlock counter.
     *
     * Kept on keys of its own, outside [PinSettingsData], so the blind
     * overwrite in [updateSettings] can never roll it back.
     *
     * @return The current [VaultUnlockAttempts].
     */
    public suspend fun getVaultUnlockAttempts(): VaultUnlockAttempts {
        val preferences = dataStore.data.first()
        return VaultUnlockAttempts(
            failedAttempts = preferences[KEY_FAILED_VAULT_UNLOCK_ATTEMPTS] ?: 0,
            lockedUntil = preferences[KEY_VAULT_UNLOCK_LOCKED_UNTIL] ?: 0
        )
    }

    /**
     * Update the password vault's failed-unlock counter.
     *
     * @param attempts The counter to persist.
     */
    public suspend fun updateVaultUnlockAttempts(attempts: VaultUnlockAttempts) {
        dataStore.edit { preferences ->
            preferences[KEY_FAILED_VAULT_UNLOCK_ATTEMPTS] = attempts.failedAttempts
            preferences[KEY_VAULT_UNLOCK_LOCKED_UNTIL] = attempts.lockedUntil
        }
    }

    /**
     * Reset all settings to their default values.
     */
    public suspend fun resetToDefaults() {
        updateSettings(PinSettingsData())
    }

    /**
     * Clear all stored settings.
     *
     * After calling this method, [settingsFlow] will emit default values
     * until new settings are saved.
     */
    public suspend fun clearSettings() {
        dataStore.edit { preferences ->
            preferences.clear()
        }
    }

    /**
     * Map DataStore preferences to [PinSettingsData].
     */
    private fun mapPreferencesToSettings(preferences: Preferences): PinSettingsData {
        return PinSettingsData(
            soPinSet = preferences[KEY_SO_PIN_SET] ?: false,
            userPinSet = preferences[KEY_USER_PIN_SET] ?: false,
            soPinHashBase64 = preferences[KEY_SO_PIN_HASH_BASE64]?.ifEmpty { null },
            userPinHashBase64 = preferences[KEY_USER_PIN_HASH_BASE64]?.ifEmpty { null },
            soPinSaltBase64 = preferences[KEY_SO_PIN_SALT_BASE64]?.ifEmpty { null },
            userPinSaltBase64 = preferences[KEY_USER_PIN_SALT_BASE64]?.ifEmpty { null },
            failedSoPinAttempts = preferences[KEY_FAILED_SO_PIN_ATTEMPTS] ?: 0,
            failedUserPinAttempts = preferences[KEY_FAILED_USER_PIN_ATTEMPTS] ?: 0,
            maxPinAttempts = preferences[KEY_MAX_PIN_ATTEMPTS] ?: 5,
            lockoutDurationSeconds = preferences[KEY_LOCKOUT_DURATION_SECONDS] ?: 300,
            backoffEnabled = preferences[KEY_BACKOFF_ENABLED] ?: true,
            soPinLockedUntil = preferences[KEY_SO_PIN_LOCKED_UNTIL] ?: 0,
            userPinLockedUntil = preferences[KEY_USER_PIN_LOCKED_UNTIL] ?: 0
        )
    }

    private companion object {
        val KEY_SO_PIN_SET = booleanPreferencesKey("so_pin_set")
        val KEY_USER_PIN_SET = booleanPreferencesKey("user_pin_set")
        val KEY_SO_PIN_HASH_BASE64 = stringPreferencesKey("so_pin_hash_base64")
        val KEY_USER_PIN_HASH_BASE64 = stringPreferencesKey("user_pin_hash_base64")
        val KEY_SO_PIN_SALT_BASE64 = stringPreferencesKey("so_pin_salt_base64")
        val KEY_USER_PIN_SALT_BASE64 = stringPreferencesKey("user_pin_salt_base64")
        val KEY_FAILED_SO_PIN_ATTEMPTS = intPreferencesKey("failed_so_pin_attempts")
        val KEY_FAILED_USER_PIN_ATTEMPTS = intPreferencesKey("failed_user_pin_attempts")
        val KEY_MAX_PIN_ATTEMPTS = intPreferencesKey("max_pin_attempts")
        val KEY_LOCKOUT_DURATION_SECONDS = intPreferencesKey("lockout_duration_seconds")
        val KEY_BACKOFF_ENABLED = booleanPreferencesKey("backoff_enabled")
        val KEY_SO_PIN_LOCKED_UNTIL = longPreferencesKey("so_pin_locked_until")
        val KEY_USER_PIN_LOCKED_UNTIL = longPreferencesKey("user_pin_locked_until")
        val KEY_FAILED_VAULT_UNLOCK_ATTEMPTS = intPreferencesKey("failed_vault_unlock_attempts")
        val KEY_VAULT_UNLOCK_LOCKED_UNTIL = longPreferencesKey("vault_unlock_locked_until")
    }
}
