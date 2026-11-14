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
package com.automatethethings.xkey.storage

import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File

/**
 * The instrumented migration fixture ([LegacySchemas] in androidTest) tracks
 * the database version the app ships: its `CURRENT` is `XKeyDatabase`'s
 * version, and it has a schema for every version a user can migrate from
 * (#193 r10). Checked here, on the sources, because the instrumented suite
 * does not run with the unit tests.
 */
class LegacySchemasVersionTest {

    private fun source(path: String): String =
        listOf(File(path), File("app/$path")).first { it.isFile }.readText()

    @Test
    fun theMigrationFixtureIsAtTheShippedDatabaseVersion() {
        val database = source("src/main/kotlin/com/automatethethings/xkey/storage/XKeyDatabase.kt")
        val fixture = source("src/androidTest/kotlin/com/automatethethings/xkey/storage/LegacySchemas.kt")
        val shipped = Regex("""^\s*version = (\d+),""", RegexOption.MULTILINE).find(database)!!.groupValues[1].toInt()
        val current = Regex("""const val CURRENT = (\d+)""").find(fixture)!!.groupValues[1].toInt()
        val oldest = Regex("""const val OLDEST = (\d+)""").find(fixture)!!.groupValues[1].toInt()
        val schemas = Regex("""^\s{8}(\d+) to listOf\(|\((\d+) to it\.getValue\(""", RegexOption.MULTILINE).findAll(fixture)
            .map { (it.groups[1] ?: it.groups[2])!!.value.toInt() }.toList().sorted()

        assertEquals(shipped, current)
        assertEquals((oldest until current).toList(), schemas)
    }
}
