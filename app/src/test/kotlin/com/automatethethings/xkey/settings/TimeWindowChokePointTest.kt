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
package com.automatethethings.xkey.settings

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The biometric time window is clamped to the offered 30-600 s range in one
 * place, BiometricSettings.kt. A raw `.timeWindowSeconds` read anywhere else
 * would let a stored 0 or a huge value through unclamped; this scan fails on one.
 */
class TimeWindowChokePointTest {

    private val mainSources: File = listOf("src/main/kotlin", "app/src/main/kotlin")
        .map(::File)
        .first { it.isDirectory }

    @Test
    fun `the raw time window is read only in BiometricSettings`() {
        val sources = mainSources.walkTopDown().filter { it.isFile && it.extension == "kt" }.toList()
        assertTrue("no main sources found under $mainSources", sources.size > 10)

        val offenders = sources
            .filter { it.name != "BiometricSettings.kt" }
            .filter { file ->
                file.readLines().any { line ->
                    val code = line.trimStart()
                    !code.startsWith("*") && !code.startsWith("//") && code.contains(".timeWindowSeconds")
                }
            }
            .map { it.relativeTo(mainSources).path }
        assertEquals(emptyList<String>(), offenders)
    }
}
