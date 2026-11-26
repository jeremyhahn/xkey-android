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

package com.automatethethings.xkey.storage

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Every crypto use of a user key outside the protocol handlers runs inside
 * the key-use gate (#255): KeyPolicyStore.withUsableKey, withKeyUseOnTurn or
 * withKeyUseInOneTurn, which recheck the deletion tombstone under the key's
 * material lock before any crypto.
 *
 * The protocol package has its own sweep (SignAfterDeleteTest). This one
 * covers every other package: the screens, the credential provider, file
 * encryption, media signing and the BLE authenticator. A call counts as gated
 * when a gate opens on its line or up to [GATE_WINDOW] lines above it, or
 * when it sits in a private helper whose every call is gated that way.
 */
class KeyUseGateSweepTest {

    private val root = listOf(File("src/main/kotlin"), File("app/src/main/kotlin")).first { it.isDirectory }
    private val app = File(root, "com/automatethethings/xkey")

    /** KeystoreManager's crypto entry points on a user key. */
    private val crypto = Regex(
        """\.(sign|signWithoutBiometric|signWithAlgorithm|signApproved|signApprovedMlDsa|authenticateThenSign|""" +
            """rsaDecrypt|rsaDecryptWithAlgorithm|rsaOaepDecrypt|computeHMAC|computeHMACWithAlgorithm|""" +
            """symmetricEncrypt|symmetricDecrypt|performECDH)\("""
    )

    /** Receivers that are a KeystoreManager. */
    private val receiver = Regex("""\b(keystoreManager|keystore|KeystoreManager\([^)]*\))\s*$""")

    private val gates = listOf("withUsableKey(", "withKeyUseOnTurn(", "withKeyUseInOneTurn(")

    @Test
    fun `every user key crypto call outside the protocol handlers runs inside the use gate`() {
        val scanned = app.walkTopDown()
            .filter { it.isFile && it.extension == "kt" }
            .filterNot { it.parentFile.name == "protocol" && it.parentFile.parentFile == app }
            .filterNot { it.name == "KeystoreManager.kt" }
            .toList()
        val calls = scanned.flatMap { file -> cryptoCalls(file).map { file to it } }
        // The sweep must see the callers it is about, or it proves nothing.
        val seen = calls.map { it.first.name }.toSet()
        for (name in listOf("FileOperationActivity.kt", "CoSignActivity.kt", "MediaSigningService.kt", "FileEncryptor.kt", "GetCredentialHandler.kt")) {
            assertTrue("the sweep finds the key use in $name", name in seen)
        }
        val ungated = calls.filter { (file, line) -> !gated(file, line) && file.name !in ROW_CHECKED }
            .map { (file, line) -> "${file.relativeTo(app)}:${line + 1}" }
        assertEquals(emptyList<String>(), ungated)
    }

    /**
     * The BLE authenticator signs inside its stored-key lock, not the use
     * gate: it re-reads the passkey's row and public key before the data is
     * made and again after the signature, so a passkey whose delete committed
     * meanwhile is refused and its signature dropped. That rule is pinned
     * here, so the exception above cannot outlive it.
     */
    @Test
    fun `the BLE authenticator signs only between two row checks under the stored-key lock`() {
        val text = File(app, "ble/fido/AndroidFidoCredentialBackend.kt").readText()
        val signSelected = text.substringAfter("private suspend fun signSelected(").substringBefore("\n    }\n")
        assertTrue("signSelected holds the stored-key lock", "= withStoredKey(selected.row.keyId) {" in signSelected)
        assertEquals("signSelected checks the row before and after the signature", 2, Regex("""\bstillSelected\(selected\)""").findAll(signSelected).count())
        val check = text.substringAfter("private suspend fun stillSelected(").substringBefore("\n    }\n")
        assertTrue("the check re-reads the row", "keyDao.getByKeyId(selected.row.keyId)" in check)
        assertTrue("the check compares the key under the alias", "publicKeyDERAt(selected.alias)" in check)
        // Every crypto call in the file is inside signSelected's sign block.
        for (line in cryptoCalls(File(app, "ble/fido/AndroidFidoCredentialBackend.kt"))) {
            val lines = File(app, "ble/fido/AndroidFidoCredentialBackend.kt").readLines()
            assertTrue(
                "AndroidFidoCredentialBackend.kt:${line + 1} signs inside signSelected",
                (maxOf(0, line - GATE_WINDOW) until line).any { "signSelected(selected, signedData)" in lines[it] }
            )
        }
    }

    /** The 0-based lines of [file] that call a KeystoreManager crypto entry point. */
    private fun cryptoCalls(file: File): List<Int> {
        val lines = file.readLines()
        return lines.indices.filter { i ->
            val code = lines[i].substringBefore("//")
            if (code.trimStart().startsWith("*")) return@filter false
            crypto.findAll(code).any { m -> receiver.containsMatchIn(code.substring(0, m.range.first)) }
        }
    }

    private fun gated(file: File, line: Int): Boolean {
        val lines = file.readLines()
        if (opensGate(lines, line)) return true
        // A private helper whose every call opens the gate.
        val helper = (line downTo 0).firstNotNullOfOrNull { i ->
            Regex("""private (suspend )?fun (\w+)\(""").find(lines[i])?.groupValues?.get(2)
        } ?: return false
        val uses = lines.indices.filter { i ->
            Regex("""\b$helper\(""").containsMatchIn(lines[i].substringBefore("//")) && "fun $helper(" !in lines[i]
        }
        return uses.isNotEmpty() && uses.all { opensGate(lines, it) }
    }

    private fun opensGate(lines: List<String>, line: Int): Boolean =
        (maxOf(0, line - GATE_WINDOW)..line).any { i -> gates.any { it in lines[i].substringBefore("//") } }

    private companion object {
        const val GATE_WINDOW = 4

        /** Files that sign under a row check instead of the use gate, each pinned by its own test above. */
        val ROW_CHECKED = setOf("AndroidFidoCredentialBackend.kt")
    }
}
