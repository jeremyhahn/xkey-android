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

package com.automatethethings.xkey.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * An xKey Keystore alias has one choke point: [KeystoreManager] holds the
 * `xkey_credential_` and `xkey_key_` prefixes, and every other file names an
 * alias through [KeystoreManager.credentialAlias],
 * [KeystoreManager.generalKeyAlias] or [KeystoreManager.keyRowAlias]. A
 * hand-built alias guesses a key row's namespace (a desktop-created FIDO2 key
 * is a general key, not a credential) and names the wrong key.
 *
 * A source scan, so a new hand-built alias fails here on the JVM.
 */
class KeystoreAliasNamingChokePointTest {

    private val sources: List<File> by lazy {
        val root = listOf(File("src/main/kotlin"), File("app/src/main/kotlin")).first { it.isDirectory }
        root.walkTopDown().filter { it.isFile && (it.extension == "kt" || it.extension == "java") }.toList()
    }

    @Test
    fun noFileButKeystoreManagerSpellsAnAliasPrefix() {
        val handBuilt = sources
            .filter { it.name != "KeystoreManager.kt" }
            .flatMap { file -> handBuiltAliasLines(file.readText()).map { "${file.name}: $it" } }
        assertTrue("Keystore aliases built by hand, outside KeystoreManager: $handBuilt", handBuilt.isEmpty())
    }

    @Test
    fun keystoreManagerSpellsEachPrefixOnlyInItsConstant() {
        val keystore = sources.single { it.name == "KeystoreManager.kt" }.readText()
        assertEquals(
            listOf(
                "internal const val KEY_ALIAS_PREFIX = \"xkey_credential_\"",
                "internal const val KEY_ALIAS_PREFIX_GENERAL = \"xkey_key_\""
            ),
            handBuiltAliasLines(keystore)
        )
    }

    @Test
    fun theScanCatchesAHandBuiltAlias() {
        val bypass = """
            // a comment naming "xkey_credential_" is not code
            val alias = "xkey_credential_" + keyId
            val other = "xkey_key_${'$'}keyId"
            val fine = KeystoreManager.generalKeyAlias(keyId)
        """.trimIndent()
        assertEquals(
            listOf("val alias = \"xkey_credential_\" + keyId", "val other = \"xkey_key_\$keyId\""),
            handBuiltAliasLines(bypass)
        )
    }

    /** Code lines (comments skipped) with a string literal starting with an alias prefix. */
    private fun handBuiltAliasLines(source: String): List<String> =
        source.lines()
            .map { it.trim() }
            .filterNot { it.startsWith("//") || it.startsWith("*") || it.startsWith("/*") }
            .filter { line -> PREFIX_LITERAL.containsMatchIn(line) }

    private companion object {
        val PREFIX_LITERAL = Regex("\"xkey_(credential|key)_")
    }
}
