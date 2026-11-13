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
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.automatethethings.xkey.audit.AuditLogger
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map

data class MediaSigningSettingsData(
    val autoSignEnabled: Boolean = false,
    val signingKeyId: String? = null,
    val signPhotos: Boolean = true,
    val signVideos: Boolean = true
)

private val Context.mediaSigningSettingsDataStore: DataStore<Preferences> by preferencesDataStore(
    name = "media_signing_settings"
)

class MediaSigningSettingsRepository(private val context: Context) {

    private val dataStore: DataStore<Preferences> = context.mediaSigningSettingsDataStore

    val settingsFlow: Flow<MediaSigningSettingsData> = dataStore.data.map { preferences ->
        mapPreferencesToSettings(preferences)
    }

    suspend fun getSettings(): MediaSigningSettingsData = settingsFlow.first()

    suspend fun updateSettings(settings: MediaSigningSettingsData) {
        dataStore.edit { preferences ->
            preferences[KEY_AUTO_SIGN_ENABLED] = settings.autoSignEnabled
            settings.signingKeyId?.let { preferences[KEY_SIGNING_KEY_ID] = it }
                ?: preferences.remove(KEY_SIGNING_KEY_ID)
            preferences[KEY_SIGN_PHOTOS] = settings.signPhotos
            preferences[KEY_SIGN_VIDEOS] = settings.signVideos
        }
    }

    suspend fun setAutoSignEnabled(enabled: Boolean) {
        AuditLogger.editAuditedSetting(dataStore, "mediaAutoSign") { preferences ->
            val oldValue = mapPreferencesToSettings(preferences).autoSignEnabled
            preferences[KEY_AUTO_SIGN_ENABLED] = enabled
            AuditLogger.SettingChange(oldValue.toString(), enabled.toString())
        }
    }

    suspend fun setSigningKeyId(keyId: String?) {
        dataStore.edit { preferences ->
            keyId?.let { preferences[KEY_SIGNING_KEY_ID] = it }
                ?: preferences.remove(KEY_SIGNING_KEY_ID)
        }
    }

    suspend fun setSignPhotos(enabled: Boolean) {
        dataStore.edit { preferences ->
            preferences[KEY_SIGN_PHOTOS] = enabled
        }
    }

    suspend fun setSignVideos(enabled: Boolean) {
        dataStore.edit { preferences ->
            preferences[KEY_SIGN_VIDEOS] = enabled
        }
    }

    private fun mapPreferencesToSettings(preferences: Preferences): MediaSigningSettingsData {
        return MediaSigningSettingsData(
            autoSignEnabled = preferences[KEY_AUTO_SIGN_ENABLED] ?: false,
            signingKeyId = preferences[KEY_SIGNING_KEY_ID],
            signPhotos = preferences[KEY_SIGN_PHOTOS] ?: true,
            signVideos = preferences[KEY_SIGN_VIDEOS] ?: true
        )
    }

    private companion object {
        val KEY_AUTO_SIGN_ENABLED = booleanPreferencesKey("auto_sign_enabled")
        val KEY_SIGNING_KEY_ID = stringPreferencesKey("signing_key_id")
        val KEY_SIGN_PHOTOS = booleanPreferencesKey("sign_photos")
        val KEY_SIGN_VIDEOS = booleanPreferencesKey("sign_videos")
    }
}
