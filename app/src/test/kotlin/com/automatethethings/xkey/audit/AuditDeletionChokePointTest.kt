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
package com.automatethethings.xkey.audit

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * A user-initiated audit deletion exists only as one transaction with its
 * record: outside the audit package no code calls the audit DAO's deletes
 * directly, and the audit screen clears and prunes through
 * [AuditLogger.clearAuditLog] and [AuditLogger.pruneAuditLog].
 */
class AuditDeletionChokePointTest {

    private val directDeletes = listOf(
        "auditLogDao.deleteAll(",
        "auditLogDao.deleteOlderThan(",
        "auditLogDao().deleteAll(",
        "auditLogDao().deleteOlderThan(",
    )

    @Test
    fun noCodeOutsideTheAuditPackageDeletesAuditRowsDirectly() {
        val root = sourceRoot()
        val audit = File(root, "com/automatethethings/xkey/audit").canonicalFile
        val offenders = root.walkTopDown()
            .filter { it.isFile && it.name.endsWith(".kt") }
            .filterNot { it.canonicalPath.startsWith(audit.path + File.separator) }
            .flatMap { file ->
                val source = file.readText()
                directDeletes.filter { source.contains(it) }.map { "${file.name}: $it" }
            }
            .toList()
        assertTrue("direct audit deletes outside audit/: $offenders", offenders.isEmpty())
    }

    @Test
    fun theAuditScreenDeletesThroughTheTransactionEntryPoints() {
        val source = File(sourceRoot(), "com/automatethethings/xkey/ui/AuditLogActivity.kt").readText()
        assertTrue("AuditLogActivity clears through AuditLogger.clearAuditLog", source.contains("AuditLogger.clearAuditLog("))
        assertTrue("AuditLogActivity prunes through AuditLogger.pruneAuditLog", source.contains("AuditLogger.pruneAuditLog("))
    }

    private fun sourceRoot(): File {
        val rel = "src/main/kotlin"
        return listOf(File(rel), File("app/$rel")).first { it.isDirectory }
    }
}
