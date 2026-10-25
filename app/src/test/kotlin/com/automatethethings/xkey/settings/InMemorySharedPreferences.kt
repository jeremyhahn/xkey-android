/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
 *
 * This file is part of xkey-android.
 *
 * xkey-android is dual-licensed:
 *
 * 1. GNU Affero General Public License v3.0 (AGPL-3.0)
 *    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
 *
 * 2. Commercial License
 *    Contact licensing@automatethethings.com for commercial licensing options.
 */

package com.automatethethings.xkey.settings

import android.content.SharedPreferences
import java.util.concurrent.ConcurrentHashMap

/**
 * A [SharedPreferences] held in memory, so a JVM test can build a
 * [PairedDeviceRepository] without `EncryptedSharedPreferences` or a device.
 * Edits apply at once; listeners are not supported.
 */
class InMemorySharedPreferences : SharedPreferences {

    private val values = ConcurrentHashMap<String, Any>()

    override fun getAll(): Map<String, *> = HashMap(values)

    override fun getString(key: String, defValue: String?): String? = values[key] as String? ?: defValue

    @Suppress("UNCHECKED_CAST")
    override fun getStringSet(key: String, defValues: Set<String>?): Set<String>? =
        values[key] as Set<String>? ?: defValues

    override fun getInt(key: String, defValue: Int): Int = values[key] as Int? ?: defValue

    override fun getLong(key: String, defValue: Long): Long = values[key] as Long? ?: defValue

    override fun getFloat(key: String, defValue: Float): Float = values[key] as Float? ?: defValue

    override fun getBoolean(key: String, defValue: Boolean): Boolean = values[key] as Boolean? ?: defValue

    override fun contains(key: String): Boolean = values.containsKey(key)

    override fun edit(): SharedPreferences.Editor = Editor()

    override fun registerOnSharedPreferenceChangeListener(
        listener: SharedPreferences.OnSharedPreferenceChangeListener
    ) = throw UnsupportedOperationException()

    override fun unregisterOnSharedPreferenceChangeListener(
        listener: SharedPreferences.OnSharedPreferenceChangeListener
    ) = throw UnsupportedOperationException()

    private inner class Editor : SharedPreferences.Editor {
        private val puts = HashMap<String, Any?>()
        private var clear = false

        override fun putString(key: String, value: String?): SharedPreferences.Editor = put(key, value)
        override fun putStringSet(key: String, values: Set<String>?): SharedPreferences.Editor =
            put(key, values?.toSet())
        override fun putInt(key: String, value: Int): SharedPreferences.Editor = put(key, value)
        override fun putLong(key: String, value: Long): SharedPreferences.Editor = put(key, value)
        override fun putFloat(key: String, value: Float): SharedPreferences.Editor = put(key, value)
        override fun putBoolean(key: String, value: Boolean): SharedPreferences.Editor = put(key, value)
        override fun remove(key: String): SharedPreferences.Editor = put(key, null)

        override fun clear(): SharedPreferences.Editor {
            clear = true
            return this
        }

        private fun put(key: String, value: Any?): SharedPreferences.Editor {
            puts[key] = value
            return this
        }

        override fun commit(): Boolean {
            synchronized(values) {
                if (clear) values.clear()
                for ((key, value) in puts) {
                    if (value == null) values.remove(key) else values[key] = value
                }
            }
            return true
        }

        override fun apply() {
            commit()
        }
    }
}
