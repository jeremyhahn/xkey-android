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
package com.automatethethings.xkey.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.lang.reflect.Modifier
import kotlin.coroutines.Continuation

/**
 * Pins the three OATH and clipboard choke points by scanning the main
 * sources: the clipboard is cleared only by [SensitiveClipboard]'s ownership
 * check, a shown code is computed only by `OathCurrentCode` (and a copied one
 * by `OathRepository.generateCode`), and [OathCodeClipboard.copy] takes only
 * the credential id, so no caller can copy a code it captured earlier.
 */
class OathChokePointsTest {

    private val sourceRoot: File =
        listOf("src/main/kotlin", "app/src/main/kotlin").map(::File).first { it.isDirectory }
            .resolve("com/automatethethings/xkey")

    /** Matches of [pattern] in code lines (comments skipped), by file relative to the package root. */
    private fun occurrences(pattern: Regex): Map<String, Int> =
        sourceRoot.walkTopDown().filter { it.isFile && it.extension == "kt" }.mapNotNull { file ->
            val count = file.readLines().filterNot { line ->
                line.trimStart().let { it.startsWith("*") || it.startsWith("//") || it.startsWith("/*") }
            }.sumOf { pattern.findAll(it).count() }
            if (count == 0) null else file.relativeTo(sourceRoot).invariantSeparatorsPath to count
        }.toMap()

    @Test
    fun theClipboardIsClearedOnlyByTheOwnershipCheck() {
        assertEquals(
            "clearPrimaryClip outside SensitiveClipboard's ownership check",
            mapOf("ui/SensitiveClipboard.kt" to 1),
            occurrences(Regex("""clearPrimaryClip\("""))
        )
    }

    @Test
    fun deadlinesUseTheSleepInclusiveClock() {
        val found = occurrences(Regex("""uptimeMillis\(|System\.nanoTime\(""")).filterKeys { it.startsWith("ui/") }
        assertTrue("a ui deadline reads a clock that stops in deep sleep: $found", found.isEmpty())
    }

    @Test
    fun codesAreComputedOnlyAtTheirChokePoints() {
        val found = occurrences(Regex("""OathEngine\.generate"""))
        val allowed = setOf("oath/OathEngine.kt", "oath/OathCurrentCode.kt", "oath/OathRepository.kt")
        val outside = found.keys - allowed
        assertTrue("OathEngine.generate* outside OathCurrentCode and generateCode: $outside", outside.isEmpty())
        // generateCode's TOTP and HOTP branches; the list goes through OathCurrentCode.
        assertEquals(2, found["oath/OathRepository.kt"])
    }

    @Test
    fun copyTakesOnlyTheCredentialId() {
        val copies = OathCodeClipboard::class.java.declaredMethods
            .filter { it.name == "copy" && Modifier.isPublic(it.modifiers) }
        assertEquals("OathCodeClipboard has one public copy", 1, copies.size)
        // A suspend fun compiles to (String, Continuation).
        assertEquals(listOf(String::class.java, Continuation::class.java), copies.single().parameterTypes.toList())
    }

    @Test
    fun noCallerPassesACapturedCode() {
        val mentions = sourceRoot.walkTopDown()
            .filter { it.isFile && it.extension == "kt" && "shownCode" in it.readText() }
            .map { it.relativeTo(sourceRoot).invariantSeparatorsPath }
            .toList()
        assertTrue("shownCode is back in the main sources: $mentions", mentions.isEmpty())
    }
}
