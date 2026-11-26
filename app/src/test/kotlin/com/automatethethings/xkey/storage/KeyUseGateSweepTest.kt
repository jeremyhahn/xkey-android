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

package com.automatethethings.xkey.storage

import com.automatethethings.xkey.testing.GateScopeScanner
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
 * only inside the block of a gate on the key it names ([GateScopeScanner]),
 * or in a private helper whose every call is inside such a gate.
 */
class KeyUseGateSweepTest {

    private val root = listOf(File("src/main/kotlin"), File("app/src/main/kotlin")).first { it.isDirectory }
    private val app = File(root, "com/automatethethings/xkey")

    /** KeystoreManager's crypto entry points on a user key, called on a KeystoreManager. */
    private val crypto = Regex(
        """\b(keystoreManager|keystore|KeystoreManager\([^)]*\))\s*\.""" +
            """(sign|signWithoutBiometric|signWithAlgorithm|signApproved|signApprovedMlDsa|authenticateThenSign|""" +
            """rsaDecrypt|rsaDecryptWithAlgorithm|rsaOaepDecrypt|computeHMAC|computeHMACWithAlgorithm|""" +
            """symmetricEncrypt|symmetricDecrypt|performECDH)\("""
    )

    private val gates = listOf("withUsableKey", "withKeyUseOnTurn", "withKeyUseInOneTurn")

    @Test
    fun `every user key crypto call outside the protocol handlers runs inside the use gate`() {
        val scanned = app.walkTopDown()
            .filter { it.isFile && it.extension == "kt" }
            .filterNot { it.parentFile.name == "protocol" && it.parentFile.parentFile == app }
            .filterNot { it.name == "KeystoreManager.kt" }
            .toList()
        val calls = scanned.flatMap { file ->
            val scanner = GateScopeScanner(file.readText(), gates)
            scanner.calls(crypto).map { Triple(file, scanner, it) }
        }
        // The sweep must see the callers it is about, or it proves nothing.
        val seen = calls.map { it.first.name }.toSet()
        for (name in listOf("FileOperationActivity.kt", "CoSignActivity.kt", "MediaSigningService.kt", "FileEncryptor.kt", "GetCredentialHandler.kt")) {
            assertTrue("the sweep finds the key use in $name", name in seen)
        }
        val ungated = calls
            .filter { (file, scanner, call) ->
                file.name !in ROW_CHECKED && !scanner.isGated(call, ::sameKeyOrAlias) && !scanner.isGatedThroughHelper(call)
            }
            .map { (file, _, call) -> "${file.relativeTo(app)}:${call.line + 1}" }
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
        val file = File(app, "ble/fido/AndroidFidoCredentialBackend.kt")
        val text = file.readText()
        val signSelected = text.substringAfter("private suspend fun signSelected(").substringBefore("\n    }\n")
        assertTrue("signSelected holds the stored-key lock", "= withStoredKey(selected.row.keyId) {" in signSelected)
        assertEquals("signSelected checks the row before and after the signature", 2, Regex("""\bstillSelected\(selected\)""").findAll(signSelected).count())
        val check = text.substringAfter("private suspend fun stillSelected(").substringBefore("\n    }\n")
        assertTrue("the check re-reads the row", "keyDao.getByKeyId(selected.row.keyId)" in check)
        assertTrue("the check compares the key under the alias", "publicKeyDERAt(selected.alias)" in check)

        val scanner = GateScopeScanner(text, listOf("withStoredKey", "signSelected"))
        // Every crypto call in the file is in the sign block handed to signSelected for the selected passkey.
        val calls = scanner.calls(crypto)
        assertTrue("the sweep finds the BLE sign", calls.isNotEmpty())
        for (call in calls) {
            assertTrue(
                "AndroidFidoCredentialBackend.kt:${call.line + 1} signs in the block handed to signSelected(selected, ...)",
                scanner.gatesAround(call.offset).any { it.name == "signSelected" && it.keyId == "selected" }
            )
        }
        // signSelected runs that block only inside its withStoredKey(selected.row.keyId) block.
        val runs = scanner.calls(Regex("""\bsign\s*\{""")).filter { scanner.enclosingFunction(it.offset)?.name == "signSelected" }
        assertEquals("signSelected runs its sign block once", 1, runs.size)
        for (run in runs) {
            assertTrue(
                "AndroidFidoCredentialBackend.kt:${run.line + 1} runs the sign block inside withStoredKey(selected.row.keyId)",
                scanner.gatesAround(run.offset).any { it.name == "withStoredKey" && it.keyId == "selected.row.keyId" }
            )
        }
    }

    private companion object {
        /** Files that sign under a row check instead of the use gate, each pinned by its own test above. */
        val ROW_CHECKED = setOf("AndroidFidoCredentialBackend.kt")

        /**
         * A gate on a general key id covers a call on that id's Keystore
         * alias: CoSignActivity.kt:678 signs `KeystoreManager.generalKeyAlias(keyId)`
         * inside `withUsableKey(keyId, ...)`.
         */
        fun sameKeyOrAlias(gate: String, call: String): Boolean =
            GateScopeScanner.sameKey(gate, call) || GateScopeScanner.sameKey("KeystoreManager.generalKeyAlias($gate)", call)
    }
}
