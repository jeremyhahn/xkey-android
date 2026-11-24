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

package com.automatethethings.xkey.crypto

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * A Signature for a Keystore key is initialised in [KeystoreManager] only in
 * `freshSignature`, which refuses a per-operation key, and in the
 * CryptoObject prompt path (`signWithPrompt`). A new `initSign` anywhere else
 * in the key manager, or any in the protocol handler, fails this scan.
 */
class PerOperationSignScanTest {

    private val sourceRoot = listOf(File("src/main/kotlin"), File("app/src/main/kotlin")).first { it.isDirectory }

    private fun source(path: String) = File(sourceRoot, path).readText()

    /** The name of the function each `initSign(` call sits in, in order. */
    private fun initSignFunctions(text: String): List<String> {
        val fn = Regex("""\bfun\s+(?:<[^>]*>\s*)?(?:[A-Za-z0-9_.]+\.)?([A-Za-z0-9_]+)\s*\(""")
        return Regex("""\.initSign\(|\binitSign\(""").findAll(text).map { call ->
            fn.findAll(text.substring(0, call.range.first)).lastOrNull()?.groupValues?.get(1) ?: "<top>"
        }.toList()
    }

    @Test
    fun `KeystoreManager initialises a Signature only in freshSignature and the CryptoObject prompt`() {
        val text = source("com/automatethethings/xkey/crypto/KeystoreManager.kt")

        assertEquals(
            setOf("freshSignature", "signWithPrompt"),
            initSignFunctions(text).toSet()
        )
    }

    @Test
    fun `freshSignature refuses a per-operation key before it initialises`() {
        val text = source("com/automatethethings/xkey/crypto/KeystoreManager.kt")
        val start = text.indexOf("fun freshSignature(")
        assertTrue("freshSignature is the one fresh-Signature choke point", start >= 0)
        val body = text.substring(start, text.indexOf("\n    }\n", start))

        val guard = body.indexOf("isPerOperationKey(")
        assertTrue("freshSignature checks isPerOperationKey", guard >= 0)
        assertTrue("the check comes before initSign", guard < body.indexOf("initSign("))
    }

    @Test
    fun `the protocol handler never initialises a Signature itself`() {
        val text = source("com/automatethethings/xkey/protocol/Handler.kt")

        assertEquals(emptyList<String>(), initSignFunctions(text))
    }
}
