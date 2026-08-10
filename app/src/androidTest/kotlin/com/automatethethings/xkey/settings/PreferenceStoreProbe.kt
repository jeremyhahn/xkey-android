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

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.MutablePreferences
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit

/**
 * Reaches the `DataStore` a settings repository owns, so a test can plant a
 * value the repository's own API cannot express.
 *
 * Every repository in this package funnels reads through a private
 * `mapPreferencesToSettings`, whose job is to survive a stored value that no
 * longer parses -- an enum constant that was renamed, a hand-edited file, a
 * downgrade. Those branches are unreachable through the setters, because the
 * setters only ever write well-formed values. Opening a second `DataStore` on
 * the same file is not an option either: DataStore refuses more than one active
 * instance per file in a process. So the test borrows the repository's own
 * instance by name.
 *
 * The field is `private val dataStore` in every repository here; a rename
 * breaks these tests loudly rather than silently skipping the fallback checks.
 */
internal object PreferenceStoreProbe {

    private const val FIELD_NAME = "dataStore"

    @Suppress("UNCHECKED_CAST")
    fun storeOf(repository: Any): DataStore<Preferences> {
        val field = repository.javaClass.getDeclaredField(FIELD_NAME)
        field.isAccessible = true
        return requireNotNull(field.get(repository)) {
            "${repository.javaClass.simpleName}.$FIELD_NAME was null"
        } as DataStore<Preferences>
    }

    /** Writes directly into the repository's backing store. */
    suspend fun writeRaw(repository: Any, block: (MutablePreferences) -> Unit) {
        storeOf(repository).edit { block(it) }
    }

    /** Empties the repository's backing store. */
    suspend fun clear(repository: Any) {
        storeOf(repository).edit { it.clear() }
    }
}
