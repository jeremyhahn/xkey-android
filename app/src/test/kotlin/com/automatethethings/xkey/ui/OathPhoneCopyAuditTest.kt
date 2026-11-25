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

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * A code the user copies on the phone is a generation and is audited:
 * the copy goes through OathRepository.generateCode by oathId, which writes
 * the OATH_CODE_GENERATED row, and never takes the list's cached code,
 * which observeAll computes without an audit row.
 */
class OathPhoneCopyAuditTest {

    private val uiDir = "src/main/kotlin/com/automatethethings/xkey/ui"

    private fun dir(): File = listOf(File(uiDir), File("app/$uiDir")).first { it.isDirectory }

    private fun codeLines(file: File): List<String> = file.readLines().map { line ->
        val trimmed = line.trimStart()
        if (trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")) "" else line
    }

    private val activityLines: List<String> by lazy { codeLines(File(dir(), "OathActivity.kt")) }

    @Test
    fun `the phone copy takes an oathId`() {
        assertTrue(
            "OathActivity must declare private fun copyCodeToClipboard(oathId: String)",
            activityLines.any { it.contains("private fun copyCodeToClipboard(oathId: String)") }
        )
    }

    @Test
    fun `no cached list code reaches a clip`() {
        val clipOfCachedCode = Regex("""newPlainText\([^)]*\.code\b""")
        val hits = dir().walkTopDown()
            .filter { it.isFile && it.extension == "kt" }
            .flatMap { file ->
                codeLines(file).mapIndexedNotNull { index, line ->
                    if (clipOfCachedCode.containsMatchIn(line)) "${file.name}:${index + 1}: ${line.trim()}" else null
                }
            }
            .toList()
        assertTrue("a cached OATH code is copied without an audit row: $hits", hits.isEmpty())
    }

    @Test
    fun `the phone copy generates its code through the audited path`() {
        val start = activityLines.indexOfFirst { it.contains("fun copyCodeToClipboard(") }
        assertTrue("copyCodeToClipboard not found", start >= 0)
        val body = StringBuilder()
        var depth = 0
        var opened = false
        for (line in activityLines.drop(start)) {
            body.append(line).append('\n')
            depth += line.count { it == '{' } - line.count { it == '}' }
            if (line.contains('{')) opened = true
            if (opened && depth <= 0) break
        }
        val text = body.toString()
        assertTrue(
            "copyCodeToClipboard must get its code from repository.generateCode or codeClipboard.copy",
            text.contains("repository.generateCode(") || text.contains("codeClipboard.copy(")
        )
    }
}
