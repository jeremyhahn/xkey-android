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

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Unit tests for [AuditCsv]: every field quoted, quotes doubled, separators
 * kept inside the quotes and spreadsheet formulas neutralised.
 */
class AuditCsvTest {

    @Test
    fun `a plain value is quoted`() {
        assertEquals("\"abc\"", AuditCsv.field("abc"))
    }

    @Test
    fun `null is an empty quoted field`() {
        assertEquals("\"\"", AuditCsv.field(null))
    }

    @Test
    fun `numbers and booleans are quoted too`() {
        assertEquals("\"42\"", AuditCsv.field(42L))
        assertEquals("\"true\"", AuditCsv.field(true))
    }

    @Test
    fun `quotes are doubled`() {
        assertEquals("\"say \"\"hi\"\"\"", AuditCsv.field("say \"hi\""))
    }

    @Test
    fun `commas and newlines stay inside the quotes`() {
        assertEquals("\"a,b\"", AuditCsv.field("a,b"))
        assertEquals("\"line1\nline2\"", AuditCsv.field("line1\nline2"))
        assertEquals("\"a\r\nb\"", AuditCsv.field("a\r\nb"))
    }

    @Test
    fun `a value a spreadsheet would run as a formula is prefixed`() {
        assertEquals("\"'=HYPERLINK(\"\"x\"\")\"", AuditCsv.field("=HYPERLINK(\"x\")"))
        assertEquals("\"'+1+1\"", AuditCsv.field("+1+1"))
        assertEquals("\"'-1+1\"", AuditCsv.field("-1+1"))
        assertEquals("\"'@SUM(A1)\"", AuditCsv.field("@SUM(A1)"))
        assertEquals("\"'\tcmd\"", AuditCsv.field("\tcmd"))
        assertEquals("\"'\rcmd\"", AuditCsv.field("\rcmd"))
    }

    @Test
    fun `a formula character after the first is left alone`() {
        assertEquals("\"a=b\"", AuditCsv.field("a=b"))
        assertEquals("\" =1\"", AuditCsv.field(" =1"))
    }

    @Test
    fun `an empty string is an empty quoted field`() {
        assertEquals("\"\"", AuditCsv.field(""))
    }

    @Test
    fun `a row joins encoded fields with commas`() {
        assertEquals(
            "\"1\",\"\",\"a,b\",\"'=x\"",
            AuditCsv.row(1L, null, "a,b", "=x")
        )
    }

    @Test
    fun `the header row is encoded like any other`() {
        assertEquals(AuditCsv.row(*AuditCsv.HEADER.toTypedArray()), AuditCsv.headerRow())
        assertEquals(12, AuditCsv.HEADER.size)
    }

    @Test
    fun `an entry row encodes every column, ids and numbers included`() {
        val entry = AuditLogEntity(
            id = 7L,
            timestamp = 0L,
            operationType = AuditOperationType.KEY_DELETED,
            keyId = "=key",
            keyLabel = "My \"key\", one",
            keyType = "+type",
            deviceId = "@dev",
            deviceName = "Phone\nTwo",
            success = false,
            errorMessage = "-err",
            details = "{\"a\":1}",
            durationMs = 12L
        )

        assertEquals(
            listOf(
                "\"7\"",
                "\"2025-01-01\"",
                "\"KEY_DELETED\"",
                "\"'=key\"",
                "\"My \"\"key\"\", one\"",
                "\"'+type\"",
                "\"'@dev\"",
                "\"Phone\nTwo\"",
                "\"false\"",
                "\"'-err\"",
                "\"{\"\"a\"\":1}\"",
                "\"12\""
            ).joinToString(","),
            AuditCsv.entryRow(entry, "2025-01-01")
        )
    }

    @Test
    fun `an entry row renders absent values as empty quoted fields`() {
        val entry = AuditLogEntity(id = 1L, timestamp = 0L, operationType = AuditOperationType.KEY_DELETED)

        assertEquals(
            "\"1\",\"t\",\"KEY_DELETED\",\"\",\"\",\"\",\"\",\"\",\"true\",\"\",\"\",\"\"",
            AuditCsv.entryRow(entry, "t")
        )
    }
}
