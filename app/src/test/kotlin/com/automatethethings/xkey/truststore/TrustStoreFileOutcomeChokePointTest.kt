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
package com.automatethethings.xkey.truststore

import java.io.File
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Every trust-store file removal or restore in TrustStoreRepository reports
 * a [FileOutcome] through `removeFile` or `restoreFile`, and only
 * [FileOutcome.REMOVED] counts as a removal. A raw Boolean from a delete
 * (`File.delete()`, the injected `fileDeleter`) or a helper that returns one
 * can report a CA file that is still on disk as gone, and the caller would
 * then record its deletion and drop its row. This scan fails on such a
 * bypass.
 */
class TrustStoreFileOutcomeChokePointTest {

    @Test
    fun `the removal and restore helpers report a FileOutcome`() {
        val source = repositorySource()
        val offenders = mutableListOf<String>()
        for (helper in listOf(
            """private fun removeFile\(file: File\): FileOutcome \{""",
            """private fun restoreFile\(file: File, bytes: ByteArray\): FileOutcome = try \{"""
        )) {
            if (!Regex(helper).containsMatchIn(source)) offenders += "missing or not a FileOutcome: $helper"
        }
        // No other file helper may hand its callers a Boolean.
        Regex("""fun \w+\([^)]*\bFile\b[^)]*\)\s*:\s*Boolean""").findAll(source).forEach {
            offenders += "line ${lineOf(source, it.range.first)}: a file helper returns a raw Boolean"
        }
        if (offenders.isNotEmpty()) fail(offenders.joinToString("\n"))
    }

    @Test
    fun `no delete result is read outside removeFile`() {
        val source = repositorySource()
        val removeFile = Regex("""private fun removeFile\(""").find(source)
            ?: return fail("removeFile is gone; is the scan stale?")
        val body = bodyRange(source, removeFile.range.last)
        val offenders = mutableListOf<String>()

        val deleterCalls = Regex("""\bfileDeleter\(""").findAll(source).toList()
        assertTrue("no fileDeleter call found; is the scan stale?", deleterCalls.isNotEmpty())
        deleterCalls.filter { it.range.first !in body }.forEach {
            offenders += "line ${lineOf(source, it.range.first)}: fileDeleter called outside removeFile"
        }
        // Inside removeFile the deleter's Boolean is not read: the file's
        // absence afterwards is the proof.
        deleterCalls.filter { it.range.first in body }.forEach { call ->
            val lineStart = source.lastIndexOf('\n', call.range.first) + 1
            if (source.substring(lineStart, call.range.first).isNotBlank()) {
                offenders += "line ${lineOf(source, call.range.first)}: removeFile reads the deleter's Boolean"
            }
        }

        // The default deleter and the metadata writer's own temp file are the
        // only direct deletes.
        Regex("""(\w+)\.delete\(\)""").findAll(source).forEach { match ->
            val receiver = match.groupValues[1]
            val defaultDeleter = receiver == "it" && source.substring(0, match.range.first).endsWith("{ ")
            if (!defaultDeleter && receiver != "tempFile") {
                offenders += "line ${lineOf(source, match.range.first)}: '${match.value}' deletes outside removeFile"
            }
        }
        if (offenders.isNotEmpty()) fail("a file removal bypasses FileOutcome:\n" + offenders.joinToString("\n"))
    }

    @Test
    fun `every removal or restore result is read as a FileOutcome`() {
        val source = repositorySource()
        val restore = Regex("""private fun restoreFile\(""").find(source)
            ?: return fail("restoreFile is gone; is the scan stale?")
        val restoreBody = restore.range.last..source.indexOf("\n    }\n", restore.range.last)
        val calls = Regex("""(?<!fun )\b(removeFile|restoreFile)\(""").findAll(source).toList()
        assertTrue("expected the delete, clear and restore call sites; is the scan stale?", calls.size >= 5)
        val offenders = calls.filter { call ->
            // restoreFile's cleanup returns removeFile's outcome as its own.
            if (call.range.first in restoreBody) return@filter false
            // The statement the call is in (its line and the two after) must
            // read the result against a FileOutcome value.
            val lineStart = source.lastIndexOf('\n', call.range.first) + 1
            var end = call.range.first
            repeat(3) { end = source.indexOf('\n', end + 1).takeIf { it >= 0 } ?: source.length }
            val statement = source.substring(lineStart, end)
            !statement.contains("FileOutcome.") || Regex("""!\s*(removeFile|restoreFile)\(""").containsMatchIn(statement)
        }.map { "line ${lineOf(source, it.range.first)}: ${it.groupValues[1]} result not read as a FileOutcome" }
        if (offenders.isNotEmpty()) fail(offenders.joinToString("\n"))
    }

    /** Offsets of the function body whose parameter list opens at [open]. */
    private fun bodyRange(source: String, open: Int): IntRange {
        var depth = 0
        var close = open
        for (i in open until source.length) {
            when (source[i]) {
                '(' -> depth++
                ')' -> if (--depth == 0) { close = i; break }
            }
        }
        val brace = source.indexOf('{', close)
        depth = 0
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

    private fun repositorySource(): String {
        val rel = "src/main/kotlin/com/automatethethings/xkey/truststore/TrustStoreRepository.kt"
        val file = listOf(File(rel), File("app/$rel")).firstOrNull { it.isFile }
            ?: error("$rel not found from ${File(".").absolutePath}")
        return file.readText()
    }
}
