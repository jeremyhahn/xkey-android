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

/**
 * The audit log's CSV encoder, the only place a CSV field is built.
 *
 * Every field is quoted (RFC 4180) with embedded quotes doubled, so commas
 * and line breaks stay inside their field. A value a spreadsheet would run
 * as a formula — one starting with `=`, `+`, `-`, `@`, a tab or a carriage
 * return — is prefixed with `'` so it opens as text. Null is an empty quoted
 * field.
 */
object AuditCsv {

    /** The leading characters a spreadsheet reads as the start of a formula. */
    private val FORMULA_LEADS = charArrayOf('=', '+', '-', '@', '\t', '\r')

    /** The export's column names, in [entryRow] order. */
    val HEADER: List<String> = listOf(
        "ID", "Timestamp", "Operation", "Key ID", "Key Label", "Key Type",
        "Device ID", "Device Name", "Success", "Error", "Details", "Duration (ms)"
    )

    /** One encoded field: [value]'s text, formula-neutralised, quoted. */
    fun field(value: Any?): String {
        val text = value?.toString() ?: ""
        val safe = if (text.isNotEmpty() && text[0] in FORMULA_LEADS) "'$text" else text
        return "\"" + safe.replace("\"", "\"\"") + "\""
    }

    /** One line of encoded [values] joined by commas, without a line break. */
    fun row(vararg values: Any?): String = values.joinToString(",") { field(it) }

    /** The encoded [HEADER] line. */
    fun headerRow(): String = row(*HEADER.toTypedArray())

    /** [entry] as one encoded line, its timestamp rendered as [formattedTimestamp]. */
    fun entryRow(entry: AuditLogEntity, formattedTimestamp: String): String = row(
        entry.id,
        formattedTimestamp,
        entry.operationType.name,
        entry.keyId,
        entry.keyLabel,
        entry.keyType,
        entry.deviceId,
        entry.deviceName,
        entry.success,
        entry.errorMessage,
        entry.details,
        entry.durationMs
    )
}
