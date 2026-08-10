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
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map

private val Context.syncStateDataStore: DataStore<Preferences> by preferencesDataStore(name = "sync_state")

/**
 * Persists bidirectional-sync state — currently the timestamp of the last
 * successful sync, surfaced via `local.syncStatus` / `remote.syncStatus`.
 */
class SyncStateRepository(context: Context) {
    private val dataStore = context.syncStateDataStore

    /** Last successful sync time in Unix millis, or 0 if never synced. */
    suspend fun getLastSyncMillis(): Long =
        dataStore.data.map { it[KEY_LAST_SYNC] ?: 0L }.first()

    /** Record that a sync just completed at [millis] (defaults to now). */
    suspend fun setLastSyncMillis(millis: Long = System.currentTimeMillis()) {
        dataStore.edit { it[KEY_LAST_SYNC] = millis }
    }

    private companion object {
        val KEY_LAST_SYNC = longPreferencesKey("last_sync_millis")
    }
}
