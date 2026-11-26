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

package com.automatethethings.xkey.testing

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The key-use gate sweeps count a crypto call as gated only when it lies
 * inside a gate's block and names the key that gate opened: a call after a
 * closed gate block, or inside a gate on another key, is ungated however
 * close it sits to the gate.
 */
class GateScopeScannerTest {

    private val crypto = Regex("""keystoreManager\.(sign|signWithoutBiometric|performECDH)\(""")

    private fun gatedLines(source: String, keyMatches: (String, String) -> Boolean = GateScopeScanner::sameKey): Map<Int, Boolean> {
        val scanner = GateScopeScanner(source, GATES)
        return scanner.calls(crypto).associate { it.line + 1 to scanner.isGated(it, keyMatches) }
    }

    @Test
    fun `a call inside its gate is gated`() {
        val source = """
            fun use(id: String) {
                store.withUsableKey(id, kind) {
                    keystoreManager.sign(id, data)
                }
            }
        """.trimIndent()

        assertEquals(mapOf(3 to true), gatedLines(source))
    }

    @Test
    fun `a call after a closed gate block is ungated`() {
        val source = """
            fun use(id: String) {
                store.withUsableKey(id, kind) { Unit }
                keystoreManager.signWithoutBiometric(id, kind, data)
            }
        """.trimIndent()

        assertEquals(mapOf(3 to false), gatedLines(source))
    }

    @Test
    fun `a call inside a gate on another key is ungated`() {
        val source = """
            fun use(id: String, other: String) {
                store.withUsableKey(other, kind) {
                    keystoreManager.sign(id, data)
                }
            }
        """.trimIndent()

        assertEquals(mapOf(3 to false), gatedLines(source))
    }

    @Test
    fun `a call in a lambda nested inside the gate is gated`() {
        val source = """
            fun use(id: String) {
                val out = store.withUsableKey(id, kind) {
                    listOf(1, 2).map { n ->
                        runCatching { keystoreManager.sign(id, data) }.getOrNull()
                    }
                }
                keystoreManager.sign(id, data)
            }
        """.trimIndent()

        assertEquals(mapOf(4 to true, 7 to false), gatedLines(source))
    }

    @Test
    fun `a brace in a string, a char or a comment does not end the block`() {
        val source = """
            fun use(id: String) {
                store.withUsableKey(id, kind) {
                    log("}")
                    log(${"\"\"\""}} ${'$'}{ "}" } }${"\"\"\""})
                    val close = '}'
                    // }
                    /* } /* } */ } */
                    keystoreManager.sign(id, data)
                }
            }
        """.trimIndent()

        assertEquals(mapOf(8 to true), gatedLines(source))
    }

    @Test
    fun `a gate whose lambda is its last argument scopes that lambda`() {
        val source = """
            fun use(id: String) {
                store.withKeyUseOnTurn(id, kind, { keystoreManager.sign(id, data) })
                keystoreManager.sign(id, data)
            }
        """.trimIndent()

        assertEquals(mapOf(2 to true, 3 to false), gatedLines(source))
    }

    @Test
    fun `a gate written as its name and a block scopes that block and names no key`() {
        val source = """
            fun interface CryptoObjectSigner {
                fun sign(alias: String, bytes: ByteArray): ByteArray
            }
            fun use(id: String) {
                val signer = CryptoObjectSigner { alias, bytes ->
                    keystoreManager.sign(alias, bytes)
                }
                keystoreManager.sign(id, data)
            }
        """.trimIndent()

        val scanner = GateScopeScanner(source, listOf("CryptoObjectSigner"))
        val gate = scanner.gates.single()
        assertEquals("", gate.keyId)
        assertEquals(4, gate.line)
        assertEquals(
            mapOf(6 to true, 8 to false),
            scanner.calls(crypto).associate { it.line + 1 to scanner.gatesAround(it.offset).isNotEmpty() }
        )
    }

    @Test
    fun `the gate's key id is its first argument, trimmed, named or not`() {
        val source = """
            fun use(row: Row) {
                store.withKeyUseInOneTurn(
                    keyId = row.keyId ,
                    kind,
                    "op"
                ) {
                    keystoreManager.sign(row.keyId, kind, data)
                    keystoreManager.sign(row.alias, kind, data)
                }
            }
        """.trimIndent()

        assertEquals(mapOf(7 to true, 8 to false), gatedLines(source))
        val gate = GateScopeScanner(source, GATES).gates.single()
        assertEquals("withKeyUseInOneTurn", gate.name)
        assertEquals("row.keyId", gate.keyId)
        assertEquals(1, gate.line)
    }

    @Test
    fun `a caller's key rule matches a key written differently`() {
        val source = """
            fun use(keyId: String) {
                store.withUsableKey(keyId, kind) {
                    keystoreManager.sign(KeystoreManager.generalKeyAlias(keyId), data)
                }
            }
        """.trimIndent()

        assertEquals(mapOf(3 to false), gatedLines(source))
        val alias = { gate: String, call: String -> call == "KeystoreManager.generalKeyAlias($gate)" }
        assertEquals(mapOf(3 to true), gatedLines(source) { gate, call -> GateScopeScanner.sameKey(gate, call) || alias(gate, call) })
    }

    @Test
    fun `a gate's own declaration opens no gate`() {
        val source = """
            suspend inline fun <T> withUsableKey(keyId: String, kind: Kind? = null, block: () -> T): T {
                keystoreManager.sign(keyId, data)
                return block()
            }
        """.trimIndent()

        val scanner = GateScopeScanner(source, GATES)
        assertTrue(scanner.gates.isEmpty())
        assertEquals(mapOf(2 to false), gatedLines(source))
    }

    @Test
    fun `a private helper is gated only when every call of it is in a gate on a key it is passed`() {
        val gated = """
            fun use(keyId: String) {
                store.withUsableKey(keyId, kind) { signHash(keyId, hash) }
            }
            private suspend fun signHash(keyId: String, hash: ByteArray): ByteArray {
                val alias = KeystoreManager.generalKeyAlias(keyId)
                return keystoreManager.sign(alias, hash)
            }
        """.trimIndent()
        val scanner = GateScopeScanner(gated, GATES)
        val call = scanner.calls(crypto).single()
        assertEquals("signHash", scanner.enclosingFunction(call.offset)?.name)
        assertTrue(scanner.isGatedThroughHelper(call))

        val oneUngated = gated.replace("fun use(keyId: String) {", "fun early(keyId: String) = signHash(keyId, hash)\nfun use(keyId: String) {")
        val unsafe = GateScopeScanner(oneUngated, GATES)
        assertFalse(unsafe.isGatedThroughHelper(unsafe.calls(crypto).single()))

        val otherKey = gated.replace("{ signHash(keyId, hash) }", "{ signHash(otherId, hash) }")
        val wrong = GateScopeScanner(otherKey, GATES)
        assertFalse(wrong.isGatedThroughHelper(wrong.calls(crypto).single()))

        val public = gated.replace("private suspend fun signHash", "suspend fun signHash")
        val open = GateScopeScanner(public, GATES)
        assertFalse(open.isGatedThroughHelper(open.calls(crypto).single()))
    }

    @Test
    fun `a call's arguments are read past nested calls and strings`() {
        val source = """
            fun use(id: String) {
                keystoreManager.sign(
                    pick(id, "a,b"),
                    listOf(1, 2), data
                )
            }
        """.trimIndent()

        val call = GateScopeScanner(source, GATES).calls(crypto).single()
        assertEquals(listOf("pick(id, \"a,b\")", "listOf(1, 2)", "data"), call.arguments)
        assertEquals("pick(id, \"a,b\")", call.keyId)
        assertEquals(1, call.line)
    }

    private companion object {
        val GATES = listOf("withUsableKey", "withKeyUseOnTurn", "withKeyUseInOneTurn")
    }
}
