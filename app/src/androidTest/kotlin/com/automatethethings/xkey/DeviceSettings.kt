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
package com.automatethethings.xkey

/** Runs one shell command on the device and returns its standard output. */
fun interface SettingsShell {
    fun run(command: String): String
}

/** A `settings` read or write over the shell that did not take effect. */
class SettingsAccessException(message: String) : IllegalStateException(message)

/** One device setting: its `settings` table (`global`, `secure`, `system`) and name. */
data class DeviceSetting(val table: String, val name: String)

/**
 * The one place the androidTest suite reads and writes device settings over
 * the shell (`settings get/put/delete`).
 */
class DeviceSettings(private val shell: SettingsShell) {

    /** The setting's value, or `null` when it has none. */
    fun read(table: String, name: String): String? {
        val output = shell.run("settings get $table $name").trim()
        return output.takeUnless { it.isEmpty() || it == NULL_OUTPUT }
    }

    /** Sets the setting to [value]. */
    fun write(table: String, name: String, value: String) {
        shell.run("settings put $table $name $value")
    }

    /** Removes the setting's value. */
    fun delete(table: String, name: String) {
        shell.run("settings delete $table $name")
    }

    private companion object {
        /** What `settings get` prints for a setting that has no value. */
        const val NULL_OUTPUT = "null"
    }
}

/**
 * Puts [testingValues] on the device for a test run and puts the owner's
 * values back afterwards.
 *
 * The owner's originals are parked in `Settings.Global` under [SAVED_PREFIX]
 * keys until they are restored, so a run killed before [restore] is repaired
 * by the next run instead of having its testing values taken as the owner's.
 */
class SettingsGuard(
    private val settings: DeviceSettings,
    private val testingValues: Map<DeviceSetting, String>,
    private val warn: (String, Throwable) -> Unit = { _, _ -> },
) {

    /** Saves each setting's original value, then sets its testing value. */
    fun prepare() {
        testingValues.forEach { (setting, value) ->
            val savedKey = savedKey(setting)
            if (settings.read(SAVED_TABLE, savedKey) == null) {
                // No earlier run left a value behind: the current one is the owner's.
                val current = settings.read(setting.table, setting.name)
                settings.write(SAVED_TABLE, savedKey, current ?: UNSET_MARKER)
            }
            settings.write(setting.table, setting.name, value)
        }
    }

    /** Writes each saved original back and drops its saved copy. */
    fun restore() {
        testingValues.keys.forEach { setting ->
            try {
                val savedKey = savedKey(setting)
                val original = settings.read(SAVED_TABLE, savedKey) ?: return@forEach
                if (original == UNSET_MARKER) {
                    settings.delete(setting.table, setting.name)
                } else {
                    settings.write(setting.table, setting.name, original)
                }
                settings.delete(SAVED_TABLE, savedKey)
            } catch (e: Exception) {
                warn("could not restore ${setting.name}", e)
            }
        }
    }

    companion object {
        /** Prefix of the `Settings.Global` keys holding the owner's values mid-run. */
        const val SAVED_PREFIX = "xkey_test_saved_"

        /** The table the saved originals live in. */
        const val SAVED_TABLE = "global"

        /** Stored for a setting that had no value, so restore deletes it again. */
        const val UNSET_MARKER = "__unset__"

        fun savedKey(setting: DeviceSetting): String = SAVED_PREFIX + setting.name
    }
}
