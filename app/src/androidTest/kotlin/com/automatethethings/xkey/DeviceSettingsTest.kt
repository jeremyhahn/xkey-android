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

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Drives [SettingsGuard] through a fake shell whose `settings` commands can be
 * made to fail, so the owner's saved values are proved to survive a failed
 * restore or read. No device API is touched.
 */
class DeviceSettingsTest {

    private val shell = FakeSettingsShell()
    private val guard = SettingsGuard(
        DeviceSettings(shell),
        linkedMapOf(TIMEOUT to TESTING_TIMEOUT, ANIMATION to TESTING_ANIMATION),
    )

    @Test
    fun restoreWhosePutIsIgnoredKeepsTheSavedValue() {
        shell.values[TIMEOUT_KEY] = TESTING_TIMEOUT
        shell.values[TIMEOUT_SAVED] = OWNER_TIMEOUT
        shell.values[ANIMATION_KEY] = TESTING_ANIMATION
        shell.values[ANIMATION_SAVED] = OWNER_ANIMATION
        shell.ignoredPuts += TIMEOUT_KEY

        guard.restore()

        assertEquals(OWNER_TIMEOUT, shell.values[TIMEOUT_SAVED])
        // The next setting is still restored.
        assertEquals(OWNER_ANIMATION, shell.values[ANIMATION_KEY])
        assertNull(shell.values[ANIMATION_SAVED])
    }

    @Test
    fun restoreWhoseDeleteIsIgnoredKeepsTheUnsetMarker() {
        shell.values[TIMEOUT_KEY] = TESTING_TIMEOUT
        shell.values[TIMEOUT_SAVED] = SettingsGuard.UNSET_MARKER
        shell.ignoredDeletes += TIMEOUT_KEY

        guard.restore()

        assertEquals(SettingsGuard.UNSET_MARKER, shell.values[TIMEOUT_SAVED])
    }

    @Test
    fun successfulRestorePutsTheOriginalBackAndDropsTheSavedValue() {
        shell.values[TIMEOUT_KEY] = TESTING_TIMEOUT
        shell.values[TIMEOUT_SAVED] = OWNER_TIMEOUT
        shell.values[ANIMATION_KEY] = TESTING_ANIMATION
        shell.values[ANIMATION_SAVED] = SettingsGuard.UNSET_MARKER

        guard.restore()

        assertEquals(OWNER_TIMEOUT, shell.values[TIMEOUT_KEY])
        assertNull(shell.values[TIMEOUT_SAVED])
        assertNull(shell.values[ANIMATION_KEY])
        assertNull(shell.values[ANIMATION_SAVED])
    }

    @Test
    fun prepareWithAFailedReadOfTheSavedValueChangesNothing() {
        shell.values[TIMEOUT_KEY] = OTHER_TIMEOUT
        shell.values[TIMEOUT_SAVED] = OWNER_TIMEOUT
        shell.failedGets += TIMEOUT_SAVED

        guard.prepare()

        assertEquals(OWNER_TIMEOUT, shell.values[TIMEOUT_SAVED])
        assertEquals(OTHER_TIMEOUT, shell.values[TIMEOUT_KEY])
    }

    @Test
    fun prepareWithAFailedReadOfTheCurrentValueChangesNothing() {
        shell.values[TIMEOUT_KEY] = OWNER_TIMEOUT
        shell.failedGets += TIMEOUT_KEY

        guard.prepare()

        assertNull(shell.values[TIMEOUT_SAVED])
        assertEquals(OWNER_TIMEOUT, shell.values[TIMEOUT_KEY])
    }

    @Test
    fun prepareWithAFailedBackupWriteLeavesTheSettingUnchanged() {
        shell.values[TIMEOUT_KEY] = OWNER_TIMEOUT
        shell.ignoredPuts += TIMEOUT_SAVED

        guard.prepare()

        assertNull(shell.values[TIMEOUT_SAVED])
        assertEquals(OWNER_TIMEOUT, shell.values[TIMEOUT_KEY])
    }

    /**
     * A `settings` command line over an in-memory table. A key in
     * [ignoredPuts] or [ignoredDeletes] keeps its value; a key in [failedGets]
     * reads as empty output, which is what a failed `settings get` prints.
     */
    private class FakeSettingsShell : SettingsShell {
        val values = mutableMapOf<String, String>()
        val ignoredPuts = mutableSetOf<String>()
        val ignoredDeletes = mutableSetOf<String>()
        val failedGets = mutableSetOf<String>()

        override fun run(command: String): String {
            val parts = command.split(" ", limit = 5)
            require(parts.size >= 4 && parts[0] == "settings") { "unexpected command: $command" }
            val key = "${parts[2]} ${parts[3]}"
            return when (parts[1]) {
                "get" -> if (key in failedGets) "" else "${values[key] ?: "null"}\n"
                "put" -> {
                    if (key !in ignoredPuts) values[key] = parts[4]
                    ""
                }
                "delete" -> {
                    val removed = key !in ignoredDeletes && values.remove(key) != null
                    if (removed) "Deleted 1 rows\n" else "Deleted 0 rows\n"
                }
                else -> throw IllegalArgumentException("unexpected command: $command")
            }
        }
    }

    private companion object {
        val TIMEOUT = DeviceSetting("system", "screen_off_timeout")
        val ANIMATION = DeviceSetting("global", "window_animation_scale")

        const val TIMEOUT_KEY = "system screen_off_timeout"
        const val ANIMATION_KEY = "global window_animation_scale"
        const val TIMEOUT_SAVED = "global ${SettingsGuard.SAVED_PREFIX}screen_off_timeout"
        const val ANIMATION_SAVED = "global ${SettingsGuard.SAVED_PREFIX}window_animation_scale"

        const val TESTING_TIMEOUT = "1800000"
        const val OWNER_TIMEOUT = "60000"
        const val OTHER_TIMEOUT = "30000"
        const val TESTING_ANIMATION = "0"
        const val OWNER_ANIMATION = "1.0"
    }
}
