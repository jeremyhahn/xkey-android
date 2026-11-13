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
 * Every audited settings write goes through
 * `AuditLogger.editAuditedSetting`, which runs the DataStore edit and the
 * audit dispatch together under `NonCancellable`, so a committed write is
 * always audited. A direct `logSettingsChanged` call after a separate
 * `dataStore.edit` reopens the gap where a caller cancelled after the
 * commit persists the change with no audit entry; this scan fails on one.
 */
class AuditedSettingsChokePointTest {

    private val mainSources: File = listOf("src/main/kotlin", "app/src/main/kotlin")
        .map(::File)
        .first { it.isDirectory }

    private fun kotlinSources(): List<File> =
        mainSources.walkTopDown().filter { it.isFile && it.extension == "kt" }.toList()

    private fun occurrences(text: String, needle: String): Int =
        text.windowed(needle.length).count { it == needle }

    @Test
    fun `logSettingsChanged is called only from the choke point`() {
        val sources = kotlinSources()
        assertTrue("no main sources found under $mainSources", sources.size > 10)

        val offenders = sources
            .filter { it.name != "AuditLogger.kt" }
            .filter { it.readText().contains("logSettingsChanged(") }
            .map { it.relativeTo(mainSources).path }
        assertEquals(emptyList<String>(), offenders)

        val logger = sources.single { it.name == "AuditLogger.kt" }.readText()
        // The declaration and the single call inside editAuditedSetting.
        assertEquals(2, occurrences(logger, "logSettingsChanged("))
        assertTrue(logger.contains("suspend fun editAuditedSetting("))
    }

    @Test
    fun `audited settings repositories route their writes through the choke point`() {
        val sources = kotlinSources()
        for (name in listOf("UsbHsmSettings.kt", "BiometricSettings.kt", "MediaSigningSettings.kt")) {
            val text = sources.single { it.name == name }.readText()
            assertTrue("$name does not use editAuditedSetting", text.contains("editAuditedSetting("))
        }
    }
}
