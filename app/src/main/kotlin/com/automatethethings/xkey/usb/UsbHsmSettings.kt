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
package com.automatethethings.xkey.usb

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map

/**
 * Settings data for HSM connectivity transports.
 *
 * @property nativeUsbEnabled Whether native USB accessory mode is enabled (default: off).
 * @property tcpHsmEnabled Whether the TCP pairing server (loopback :8444, for
 *   ADB-forwarded / emulator connections) is enabled (default: off).
 */
data class UsbHsmSettingsData(
    val nativeUsbEnabled: Boolean = false,
    val tcpHsmEnabled: Boolean = false
)

/**
 * Extension property for the USB HSM settings DataStore.
 */
private val Context.usbHsmSettingsDataStore: DataStore<Preferences> by preferencesDataStore(
    name = "usb_hsm_settings"
)

/**
 * Repository for persisting and retrieving USB connectivity settings.
 *
 * Uses Jetpack DataStore for persistence, following the same pattern as
 * [com.automatethethings.xkey.settings.BiometricSettingsRepository].
 *
 * @param context The Android context used to access DataStore.
 */
class UsbHsmSettingsRepository(
    private val context: Context
) {
    private val dataStore: DataStore<Preferences> = context.usbHsmSettingsDataStore

    /**
     * Flow of USB settings that emits whenever settings change.
     *
     * Collectors receive the current value immediately upon subscription
     * and subsequent updates as they occur.
     */
    val settingsFlow: Flow<UsbHsmSettingsData> = dataStore.data.map { preferences ->
        UsbHsmSettingsData(
            nativeUsbEnabled = preferences[KEY_NATIVE_USB_ENABLED] ?: false,
            tcpHsmEnabled = preferences[KEY_TCP_HSM_ENABLED] ?: false
        )
    }

    /**
     * Get the current USB settings.
     *
     * @return The current [UsbHsmSettingsData].
     */
    suspend fun getSettings(): UsbHsmSettingsData {
        return settingsFlow.first()
    }

    /**
     * Enable or disable native USB accessory mode.
     *
     * @param enabled True to enable native USB, false to disable.
     */
    suspend fun setNativeUsbEnabled(enabled: Boolean) {
        dataStore.edit { preferences ->
            preferences[KEY_NATIVE_USB_ENABLED] = enabled
        }
    }

    /**
     * Enable or disable the TCP pairing server (loopback :8444).
     *
     * @param enabled True to enable the TCP server, false to disable.
     */
    suspend fun setTcpHsmEnabled(enabled: Boolean) {
        dataStore.edit { preferences ->
            preferences[KEY_TCP_HSM_ENABLED] = enabled
        }
    }

    private companion object {
        val KEY_NATIVE_USB_ENABLED = booleanPreferencesKey("native_usb_enabled")
        val KEY_TCP_HSM_ENABLED = booleanPreferencesKey("tcp_hsm_enabled")
    }
}
