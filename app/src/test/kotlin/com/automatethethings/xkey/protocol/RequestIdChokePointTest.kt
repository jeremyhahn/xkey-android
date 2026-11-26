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

package com.automatethethings.xkey.protocol

import java.io.File
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * A JSON-RPC answer carries its request's `id` exactly as sent, and the one
 * place that reads it from a message is Messages.kt. This scan of the main
 * sources fails when:
 *
 * - any source reads an `id` member as a number (`optLong("id"`, `getInt("id"`
 *   and the like), which turns a string id into -1 and rounds a wide one;
 * - a transport or protocol source outside Messages.kt and ble/fido (whose
 *   `id` members are WebAuthn credential and relying-party ids) reads an `id`
 *   member at all;
 * - an answer is built with a number literal or a `Long.` constant for its id,
 *   rather than the id the request carried.
 */
class RequestIdChokePointTest {

    private val numericIdRead = Regex("""(opt|get)(Long|Int|Double|Number)\("id"""")
    private val anyIdRead = Regex("""(opt|get)(String)?\("id"""")
    private val literalIdAnswer = Regex(
        """(Response\.(success|error)|createErrorResponse)\(\s*(id\s*=\s*)?(-?\d|Long\.)"""
    )

    private val messageDirs = listOf("protocol", "transport", "tcp", "usb", "remote", "ble")

    @Test
    fun `no main source reads a message id as a number`() {
        val offenders = mainSources().flatMap { (path, text) ->
            numericIdRead.findAll(text).map { "$path line ${lineOf(text, it.range.first)}: ${it.value}" }.toList()
        }
        if (offenders.isNotEmpty()) fail("message ids read as numbers:\n" + offenders.joinToString("\n"))
    }

    @Test
    fun `message ids are read only in Messages kt`() {
        val offenders = mainSources()
            .filter { (path, _) -> messageDirs.any { path.startsWith("$it/") } }
            .filterNot { (path, _) -> path.startsWith("ble/fido/") || path == "protocol/Messages.kt" }
            .flatMap { (path, text) ->
                anyIdRead.findAll(text).map { "$path line ${lineOf(text, it.range.first)}: ${it.value}" }.toList()
            }
        if (offenders.isNotEmpty()) fail("message ids read outside Messages.kt:\n" + offenders.joinToString("\n"))
    }

    @Test
    fun `no answer is built with a literal id`() {
        val offenders = mainSources().flatMap { (path, text) ->
            literalIdAnswer.findAll(text).map { "$path line ${lineOf(text, it.range.first)}: ${it.value}" }.toList()
        }
        if (offenders.isNotEmpty()) fail("answers built with an id the request did not carry:\n" + offenders.joinToString("\n"))
    }

    /** Each main Kotlin source as (path under the xkey package, text). */
    private fun mainSources(): List<Pair<String, String>> {
        val rel = "src/main/kotlin/com/automatethethings/xkey"
        val root = listOf(File(rel), File("app/$rel")).firstOrNull { it.isDirectory }
            ?: error("$rel not found from ${File(".").absolutePath}")
        val sources = root.walkTopDown()
            .filter { it.isFile && it.extension == "kt" }
            .map { it.relativeTo(root).invariantSeparatorsPath to it.readText() }
            .toList()
        assertTrue("no main sources found; is the scan stale?", sources.size > 50)
        assertTrue(
            "Messages.kt is gone; is the scan stale?",
            sources.any { (path, _) -> path == "protocol/Messages.kt" }
        )
        return sources
    }

    private fun lineOf(source: String, offset: Int): Int =
        source.substring(0, offset).count { it == '\n' } + 1
}
