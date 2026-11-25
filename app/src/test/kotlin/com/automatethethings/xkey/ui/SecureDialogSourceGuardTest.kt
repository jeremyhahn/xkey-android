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
package com.automatethethings.xkey.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Every dialog a secret screen opens goes through [SecureScreens.show].
 *
 * A dialog does not inherit its activity's FLAG_SECURE, so a screen that
 * takes a PIN, password, passphrase or OATH secret must protect each dialog
 * on its own. The guarded set is every UI source file with a password-type
 * input, plus the OATH secret entry dialog; in each, the number of dialog
 * builders equals the number of [SecureScreens.show] calls.
 */
class SecureDialogSourceGuardTest {

    private val passwordMarkers = listOf(
        "END_ICON_PASSWORD_TOGGLE",
        "TYPE_TEXT_VARIATION_PASSWORD",
        "TYPE_NUMBER_VARIATION_PASSWORD",
        "PasswordTransformationMethod",
    )

    @Test
    fun everyDialogOnASecretScreenIsShownSecure() {
        val guarded = guardedFiles()
        val names = guarded.map { it.name }.toSet()
        for (required in listOf(
            "PinManagementActivity.kt",
            "PasswordManagementActivity.kt",
            "DesktopBackupDialogs.kt",
            "AddOathDialog.kt",
        )) {
            assertTrue("$required not in the guarded set: $names", required in names)
        }

        for (file in guarded) {
            val source = file.readText()
            val builders = count(source, "MaterialAlertDialogBuilder(") + count(source, "AlertDialog.Builder(")
            val secured = count(source, "SecureScreens.show(")
            assertEquals(
                "${file.name}: $builders dialog builders, $secured SecureScreens.show calls",
                builders,
                secured
            )
        }
    }

    private fun guardedFiles(): List<File> {
        val rel = "src/main/kotlin/com/automatethethings/xkey/ui"
        val dir = listOf(File(rel), File("app/$rel")).first { it.isDirectory }
        val sources = dir.listFiles { f -> f.isFile && f.name.endsWith(".kt") }!!.toList()
        return sources.filter { file ->
            file.name == "AddOathDialog.kt" || passwordMarkers.any { file.readText().contains(it) }
        }.sortedBy { it.name }
    }

    private fun count(source: String, needle: String): Int {
        var n = 0
        var at = source.indexOf(needle)
        while (at >= 0) {
            n++
            at = source.indexOf(needle, at + needle.length)
        }
        return n
    }
}
