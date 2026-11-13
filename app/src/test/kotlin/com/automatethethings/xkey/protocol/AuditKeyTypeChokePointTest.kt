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
package com.automatethethings.xkey.protocol

import java.io.File
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Every key-use audit entry in Handler.kt names the key's stored type, which
 * the audit screen filters on. The type comes from one place,
 * `RequestHandler.auditKeyType`; a literal such as `keyType = "agreement"`
 * mislabels the key (an ECDH on a signing key vanished from the Signing
 * filter). This scan fails on any key-use AuditLogger call that does not take
 * its keyType from that helper.
 */
class AuditKeyTypeChokePointTest {

    private val keyUseCall = Regex(
        """AuditLogger\.log(Signing|Decryption|Encryption|Hmac|KeyDerivation)Request\("""
    )

    @Test
    fun `key-use audit calls take keyType from auditKeyType`() {
        val source = handlerSource()
        val calls = keyUseCall.findAll(source).toList()
        assertTrue("no key-use audit calls found; is the scan stale?", calls.size >= 6)

        val offenders = calls.mapNotNull { match ->
            val args = argumentList(source, match.range.last)
            val keyTypeArg = Regex("""keyType\s*=\s*([^,\n)]+)""").find(args)
                ?.groupValues?.get(1)?.trim()
            if (keyTypeArg == null || !keyTypeArg.startsWith("auditKeyType(")) {
                "line ${lineOf(source, match.range.first)}: ${match.value} keyType = $keyTypeArg"
            } else {
                null
            }
        }
        if (offenders.isNotEmpty()) {
            fail("key-use audit calls bypass auditKeyType:\n" + offenders.joinToString("\n"))
        }
    }

    /** The text between the call's opening parenthesis at [open] and its match. */
    private fun argumentList(source: String, open: Int): String {
        var depth = 0
        for (i in open until source.length) {
            when (source[i]) {
                '(' -> depth++
                ')' -> if (--depth == 0) return source.substring(open + 1, i)
            }
        }
        fail("unbalanced call at offset $open")
        return ""
    }

    private fun lineOf(source: String, offset: Int): Int =
        source.substring(0, offset).count { it == '\n' } + 1

    private fun handlerSource(): String {
        val rel = "src/main/kotlin/com/automatethethings/xkey/protocol/Handler.kt"
        val file = listOf(File(rel), File("app/$rel")).firstOrNull { it.isFile }
            ?: error("Handler.kt not found from ${File(".").absolutePath}")
        return file.readText()
    }
}
