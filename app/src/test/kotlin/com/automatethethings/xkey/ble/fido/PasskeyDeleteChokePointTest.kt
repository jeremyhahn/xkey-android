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

package com.automatethethings.xkey.ble.fido

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Every passkey the FIDO BLE authenticator deletes goes through
 * `KeyDao.deletePasskeyRows` (inside `KeyDao.completePasskeyRegistration`
 * for a registration's replacements), which deletes a row only while its sharing
 * policy is still the one the caller checked. No BLE code deletes a key row,
 * a metadata row or a Keystore key any other way, and nothing outside
 * `KeyDao` calls the raw deletes that path is built from.
 */
class PasskeyDeleteChokePointTest {

    private val root = listOf(File("src/main/kotlin"), File("app/src/main/kotlin")).first { it.isDirectory }
    private val sources = root.walkTopDown().filter { it.isFile && it.extension == "kt" }.toList()
    private val fido = sources.filter { it.path.replace('\\', '/').contains("/xkey/ble/fido/") }

    @Test
    fun `the BLE authenticator deletes key rows only through deletePasskeyRows`() {
        val deletes = Regex("""\b(keyDao|credentialDao)\s*\.\s*(delete\w*)\s*\(""")
        val offenders = fido.flatMap { file ->
            deletes.findAll(file.readText())
                .filter { it.groupValues[1] != "keyDao" || it.groupValues[2] != "deletePasskeyRows" }
                .map { "${file.name}: ${it.value}" }
                .toList()
        }
        assertEquals(emptyList<String>(), offenders)
        // A registration deletes the passkeys it replaces inside its commit,
        // KeyDao.completePasskeyRegistration, which uses the same guarded delete.
        assertTrue(fido.any { it.readText().contains("keyDao.completePasskeyRegistration(") })
    }

    @Test
    fun `only the backend's guarded delete removes a passkey's Keystore key`() {
        val offenders = fido.filter { it.name != "AndroidFidoCredentialBackend.kt" && it.readText().contains(".deleteKey(") }
        assertEquals(emptyList<File>(), offenders)
    }

    @Test
    fun `nothing outside KeyDao calls the raw passkey row deletes`() {
        val raw = Regex("""\b(deletePasskeyRowsInTransaction|deletePasskeyRowIfUnchanged|deleteMetadataRowByCredentialId)\s*\(""")
        val offenders = sources.filter { it.name != "KeyDao.kt" && raw.containsMatchIn(it.readText()) }
        assertEquals(emptyList<File>(), offenders)
    }
}
