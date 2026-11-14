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
package com.automatethethings.xkey.protocol

import java.io.File
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * A completed key use in Handler.kt is recorded through one choke point,
 * `RequestHandler.logKeyUse`, which writes the usage and the audit entry
 * under `NonCancellable`, so a request cancelled after its key operation
 * (its desktop disconnected or was unpaired) still leaves both.
 *
 * This scan fails when the usage is written anywhere else, when logKeyUse
 * stops running under NonCancellable, when a handler runs more key
 * operations than it records, or when the OATH code entry is written where
 * a cancel can drop it.
 */
class KeyUseRecordChokePointTest {

    private val keyOperation = Regex(
        """keystoreManager\.(signWithAlgorithm|rsaDecryptWithAlgorithm|symmetricEncrypt|symmetricDecrypt|""" +
            """computeHMACWithAlgorithm|performECDH)\(|SoftwareKeyOps\.(aesGcmEncrypt|aesGcmDecrypt|hmac)\("""
    )

    @Test
    fun `usage is written only inside logKeyUse, under NonCancellable`() {
        val source = handlerSource()
        val helper = Regex("""private suspend fun logKeyUse\(""").find(source)
            ?: return fail("RequestHandler.logKeyUse is gone; is the scan stale?")
        val afterParams = helper.range.last + argumentList(source, helper.range.last).length + 2
        val signature = source.substring(afterParams, source.indexOf('{', afterParams) + 1)
        val offenders = mutableListOf<String>()
        if (!Regex("""^\s*:\s*Unit\s*=\s*withContext\(NonCancellable\)\s*\{$""").matches(signature)) {
            offenders += "logKeyUse does not run under withContext(NonCancellable): '${signature.trim()}'"
        }
        val body = bodyRange(source, helper.range.last)
        val helperText = source.substring(body.first, body.last)
        if (!helperText.contains("keyDao.recordUsage(keyId)")) offenders += "logKeyUse no longer records usage"

        val usages = Regex("""\.recordUsage\(""").findAll(source).toList()
        assertTrue("no usage writes found; is the scan stale?", usages.isNotEmpty())
        usages.filter { it.range.first !in body }.forEach {
            offenders += "line ${lineOf(source, it.range.first)}: recordUsage outside logKeyUse"
        }
        if (offenders.isNotEmpty()) fail("key use recorded outside the choke point:\n" + offenders.joinToString("\n"))
    }

    @Test
    fun `every handler records each key operation it runs`() {
        val source = handlerSource()
        val functions = Regex("""\n    private suspend fun (\w+)\(""").findAll(source).toList()
        val offenders = mutableListOf<String>()
        var operations = 0
        functions.forEach { fn ->
            val body = bodyRange(source, fn.range.last)
            val text = source.substring(body.first, body.last)
            val ops = keyOperation.findAll(text).count()
            val records = Regex("""(?<!fun )\blogKeyUse\(""").findAll(text).count()
            operations += ops
            if (ops > records) {
                offenders += "${fn.groupValues[1]} (line ${lineOf(source, fn.range.first)}): " +
                    "$ops key operation(s), $records logKeyUse call(s)"
            }
        }
        assertTrue("expected the sign, decrypt, encrypt, HMAC and ECDH operations; is the scan stale?", operations >= 9)
        if (offenders.isNotEmpty()) {
            fail("a key operation is not recorded through logKeyUse:\n" + offenders.joinToString("\n"))
        }
    }

    @Test
    fun `the OATH code entry is written under NonCancellable`() {
        val source = handlerSource()
        val calls = Regex("""AuditLogger\.logOathCodeGenerated\(""").findAll(source).toList()
        assertTrue("no OATH code entry found; is the scan stale?", calls.isNotEmpty())
        val blocks = Regex("""withContext\(NonCancellable\) \{""").findAll(source).map { match ->
            val open = match.range.last
            var depth = 0
            var end = open
            for (i in open until source.length) {
                when (source[i]) {
                    '{' -> depth++
                    '}' -> if (--depth == 0) { end = i; break }
                }
            }
            open..end
        }.toList()
        val offenders = calls.filter { call -> blocks.none { call.range.first in it } }
            .map { "line ${lineOf(source, it.range.first)}: logOathCodeGenerated outside NonCancellable" }
        if (offenders.isNotEmpty()) fail(offenders.joinToString("\n"))
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

    /** Offsets of the function body whose parameter list opens at [open]. */
    private fun bodyRange(source: String, open: Int): IntRange {
        val afterParams = open + argumentList(source, open).length + 1
        val brace = source.indexOf('{', afterParams)
        var depth = 0
        for (i in brace until source.length) {
            when (source[i]) {
                '{' -> depth++
                '}' -> if (--depth == 0) return brace..i
            }
        }
        fail("unbalanced body at offset $brace")
        return IntRange.EMPTY
    }

    private fun lineOf(source: String, offset: Int): Int =
        source.substring(0, offset).count { it == '\n' } + 1

    private fun handlerSource(): String {
        val rel = "src/main/kotlin/com/automatethethings/xkey/protocol/Handler.kt"
        val file = listOf(File(rel), File("app/$rel")).firstOrNull { it.isFile }
            ?: error("$rel not found from ${File(".").absolutePath}")
        return file.readText()
    }
}
