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
package com.automatethethings.xkey.password

import com.automatethethings.xkey.audit.AuditLogger

/**
 * Password adds and deletes made on the phone, each written to the audit log
 * with only the entry id and its display name.
 *
 * The audit lives here and not in [PasswordRepository] because the desktop
 * sync path writes through the repository too and is audited on its own.
 */
class PasswordEdits(private val repository: PasswordRepository) {

    /**
     * Stores [record] and audits the add. A refused add (for example
     * [PasswordEntryTooLargeException]) throws to the caller and is not
     * audited. Returns the stable password ID.
     */
    suspend fun add(record: PasswordRecord): String {
        val passwordId = repository.upsert(record)
        AuditLogger.logPasswordCreated(passwordId, displayName(record))
        return passwordId
    }

    /** Deletes [record]; audits the delete only if an entry was removed. */
    suspend fun delete(record: PasswordRecord): Boolean {
        val deleted = repository.delete(record.passwordId)
        if (deleted) AuditLogger.logPasswordDeleted(record.passwordId, displayName(record))
        return deleted
    }

    private fun displayName(record: PasswordRecord): String =
        record.title?.takeIf { it.isNotBlank() } ?: record.name
}
