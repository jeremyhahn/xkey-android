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
import androidx.datastore.preferences.preferencesDataStore
import com.automatethethings.xkey.audit.AuditLogger
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
 * @param dataStore The DataStore holding the settings.
 */
class UsbHsmSettingsRepository internal constructor(
    private val dataStore: DataStore<Preferences>
) {
    /**
     * @param context The Android context used to access DataStore.
     */
    constructor(context: Context) : this(context.usbHsmSettingsDataStore)

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
     * A change is audited as setting `nativeUsb`; writing the stored value is not.
     *
     * @param enabled True to enable native USB, false to disable.
     */
    suspend fun setNativeUsbEnabled(enabled: Boolean) {
        setAudited(KEY_NATIVE_USB_ENABLED, AUDIT_NATIVE_USB, enabled)
    }

    /**
     * Enable or disable the TCP pairing server (loopback :8444).
     *
     * A change is audited as setting `tcpPairing`; writing the stored value is not.
     *
     * @param enabled True to enable the TCP server, false to disable.
     */
    suspend fun setTcpHsmEnabled(enabled: Boolean) {
        setAudited(KEY_TCP_HSM_ENABLED, AUDIT_TCP_PAIRING, enabled)
    }

    /**
     * Stores [enabled] under [key] and, when it differs from the stored value,
     * records the change: either toggle opens a path to the pairing responder.
     * The write and its entry go through [AuditLogger.editAuditedSetting], so a
     * caller cancelled after the commit still leaves the entry.
     */
    private suspend fun setAudited(key: Preferences.Key<Boolean>, settingName: String, enabled: Boolean) {
        AuditLogger.editAuditedSetting(dataStore, settingName) { preferences ->
            val oldValue = preferences[key] ?: false
            preferences[key] = enabled
            if (oldValue == enabled) {
                null
            } else {
                AuditLogger.SettingChange(oldValue.toString(), enabled.toString())
            }
        }
    }

    private companion object {
        val KEY_NATIVE_USB_ENABLED = booleanPreferencesKey("native_usb_enabled")
        val KEY_TCP_HSM_ENABLED = booleanPreferencesKey("tcp_hsm_enabled")
        const val AUDIT_NATIVE_USB = "nativeUsb"
        const val AUDIT_TCP_PAIRING = "tcpPairing"
    }
}
