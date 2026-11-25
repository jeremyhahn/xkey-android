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

package com.automatethethings.xkey.sync

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * A sync merge and a local write to the same row never undo each other: a
 * password delete and its deletion record are one transaction, as are a
 * synced add and its deletion check (`PasswordDao.deleteAndRecordDeletion`,
 * `PasswordDao.insertIfAbsentUnlessDeleted`), and nothing outside
 * `PasswordDao` calls the raw statements those are built from. A HOTP
 * counter is advanced only by compare-and-set
 * (`OathCredentialDao.claimCounter`, only inside the DAO's
 * `claimAndRecordUsage` transaction, from `OathRepository.generateCode`),
 * so a counter a sync raised is never rewound, and nothing calls the
 * unconditional `OathCredentialDao.updateCounter`.
 */
class SyncChokePointTest {

    private val root = listOf(File("src/main/kotlin"), File("app/src/main/kotlin")).first { it.isDirectory }
    private val sources = root.walkTopDown().filter { it.isFile && it.extension == "kt" }.toList()

    /** The OATH store's own deletion record, written before its delete: not the password one. */
    private val oathDeletionFiles = setOf("OathCredentialDao.kt", "OathRepository.kt", "Handler.kt")

    @Test
    fun `nothing outside PasswordDao calls the raw password delete and deletion record statements`() {
        val raw = Regex("""\b(deleteByPasswordId|deleteByPasswordIdInTenant|recordDeletion|getDeletedAt)\s*\(""")
        val offenders = sources.filter { it.name != "PasswordDao.kt" }.flatMap { file ->
            raw.findAll(file.readText())
                .filter { it.groupValues[1] != "recordDeletion" || file.name !in oathDeletionFiles }
                .map { "${file.name}: ${it.value}" }
                .toList()
        }
        assertEquals(emptyList<String>(), offenders)
    }

    @Test
    fun `the password delete and the synced add are each one transaction`() {
        val dao = sources.single { it.name == "PasswordDao.kt" }.readText()
        for (method in listOf("deleteAndRecordDeletion", "insertIfAbsentUnlessDeleted")) {
            assertTrue(method, Regex("""@Transaction\s+suspend fun $method\(""").containsMatchIn(dao))
        }
    }

    @Test
    fun `a HOTP counter moves only by compare-and-set, from generateCode`() {
        val unconditional = sources.filter { Regex("""\.\s*updateCounter\s*\(""").containsMatchIn(it.readText()) }
        assertEquals(emptyList<File>(), unconditional)
        val claim = Regex("""\bclaimCounter\s*\(""")
        val outside = sources.filter { it.name != "OathCredentialDao.kt" && claim.containsMatchIn(it.readText()) }
        assertEquals(emptyList<File>(), outside)

        val dao = sources.single { it.name == "OathCredentialDao.kt" }.readText()
        assertTrue(Regex("""@Transaction\s+suspend fun claimAndRecordUsage\(""").containsMatchIn(dao))
        val transaction = dao.substringAfter("suspend fun claimAndRecordUsage(").substringBefore("\n    }")
        val daoCalls = Regex("""(?<!fun )\bclaimCounter\s*\(""").findAll(dao).count()
        assertEquals("claimCounter is called only from claimAndRecordUsage", 1, daoCalls)
        assertTrue(claim.containsMatchIn(transaction))

        val callers = sources.filter { Regex("""\.\s*claimAndRecordUsage\s*\(""").containsMatchIn(it.readText()) }
        assertEquals(listOf("OathRepository.kt"), callers.map { it.name })
        val repository = callers.single().readText()
        val functions = Regex("""\n    (?:private |internal |override )?(?:suspend )?fun (\w+)""").findAll(repository).toList()
        val enclosing = Regex("""\.\s*claimAndRecordUsage\s*\(""").findAll(repository).map { call ->
            functions.last { it.range.first < call.range.first }.groupValues[1]
        }.toSet()
        assertEquals(setOf("generateCode"), enclosing)
    }
}
