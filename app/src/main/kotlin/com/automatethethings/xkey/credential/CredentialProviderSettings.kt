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
package com.automatethethings.xkey.credential

import android.content.Context
import android.content.Intent
import android.os.Build
import android.provider.Settings
import androidx.annotation.RequiresApi
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map

/**
 * Extension property to create a DataStore instance for credential provider settings.
 */
private val Context.credentialProviderSettingsDataStore: DataStore<Preferences> by preferencesDataStore(
    name = "credential_provider_settings"
)

/**
 * Settings data for the credential provider feature.
 *
 * @property isEnabled Whether the credential provider is enabled by the user.
 */
data class CredentialProviderSettingsData(
    val isEnabled: Boolean = false
)

/**
 * Repository for managing credential provider settings.
 *
 * This class handles the persistence and retrieval of credential provider
 * settings using Jetpack DataStore. It also provides helper methods for
 * navigating to system credential provider settings.
 *
 * The credential provider feature requires Android 14 (API 34) or higher.
 * On older versions, the feature is not available and [isFeatureAvailable]
 * returns false.
 *
 * Usage:
 * ```kotlin
 * val repository = CredentialProviderSettingsRepository(context)
 *
 * // Check if feature is available
 * if (repository.isFeatureAvailable()) {
 *     // Observe settings
 *     repository.settingsFlow.collect { settings ->
 *         updateUI(settings.isEnabled)
 *     }
 *
 *     // Enable and open system settings
 *     repository.setEnabled(true)
 *     repository.openSystemCredentialSettings()
 * }
 * ```
 */
class CredentialProviderSettingsRepository(
    private val context: Context,
    private val dataStore: DataStore<Preferences> = context.credentialProviderSettingsDataStore
) {

    /**
     * Flow of credential provider settings that emits whenever settings change.
     */
    val settingsFlow: Flow<CredentialProviderSettingsData> = dataStore.data.map { preferences ->
        CredentialProviderSettingsData(
            isEnabled = preferences[KEY_ENABLED] ?: false
        )
    }

    /**
     * Check if the credential provider feature is available on this device.
     *
     * The feature requires Android 14 (API 34) or higher.
     *
     * @return True if the feature is available.
     */
    fun isFeatureAvailable(): Boolean {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE
    }

    /**
     * Get the current settings synchronously.
     *
     * @return The current settings.
     */
    suspend fun getSettings(): CredentialProviderSettingsData {
        return settingsFlow.first()
    }

    /**
     * Whether the user has turned the credential provider on.
     *
     * Off when nothing is stored. [XKeyCredentialService] reads this before
     * every begin request, through [CredentialProviderEnableGate].
     */
    suspend fun isEnabled(): Boolean = getSettings().isEnabled

    /**
     * Set whether the credential provider is enabled.
     *
     * Note: This only stores the user's preference. The user must also
     * enable the provider in system settings for it to actually work.
     * Use [openSystemCredentialSettings] to guide the user there.
     *
     * @param enabled Whether to enable the credential provider.
     */
    suspend fun setEnabled(enabled: Boolean) {
        dataStore.edit { preferences ->
            preferences[KEY_ENABLED] = enabled
        }
    }

    /**
     * Open the system credential provider settings.
     *
     * This opens the Android settings page where the user can enable
     * this app as a credential provider.
     *
     * @return True if the settings were opened successfully.
     */
    @RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
    fun openSystemCredentialSettings(): Boolean {
        return try {
            // ACTION_CREDENTIAL_PROVIDER = "android.settings.CREDENTIAL_PROVIDER"
            val intent = Intent("android.settings.CREDENTIAL_PROVIDER")
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            context.startActivity(intent)
            true
        } catch (e: Exception) {
            // Fallback to general security settings
            try {
                val fallbackIntent = Intent(Settings.ACTION_SECURITY_SETTINGS)
                fallbackIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                context.startActivity(fallbackIntent)
                true
            } catch (e2: Exception) {
                false
            }
        }
    }

    /**
     * Clear all credential provider settings.
     */
    suspend fun clearSettings() {
        dataStore.edit { preferences ->
            preferences.clear()
        }
    }

    private companion object {
        val KEY_ENABLED = booleanPreferencesKey("credential_provider_enabled")
    }
}

/**
 * Puts the user's enable switch in front of the passkey handlers.
 *
 * @param isEnabled Reads the switch; called once per begin request.
 */
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
class CredentialProviderEnableGate(
    private val isEnabled: suspend () -> Boolean
) {
    /** The create handler's answer while the switch is on; no create entries while it is off. */
    suspend fun beginCreate(
        request: BeginCreateCredentialRequest,
        handle: suspend (BeginCreateCredentialRequest) -> BeginCreateCredentialResponse
    ): BeginCreateCredentialResponse =
        if (isEnabled()) handle(request) else BeginCreateCredentialResponse()

    /** The get handler's answer while the switch is on; no credential entries while it is off. */
    suspend fun beginGet(
        request: BeginGetCredentialRequest,
        handle: suspend (BeginGetCredentialRequest) -> BeginGetCredentialResponse
    ): BeginGetCredentialResponse =
        if (isEnabled()) handle(request) else BeginGetCredentialResponse()
}
