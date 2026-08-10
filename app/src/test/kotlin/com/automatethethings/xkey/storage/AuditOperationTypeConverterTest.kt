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

import com.automatethethings.xkey.audit.AuditOperationType
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * Unit tests for [AuditOperationTypeConverter].
 *
 * This converter is the only thing standing between the audit enum and the
 * `audit_logs.operation_type` column, so two properties matter. First, the
 * stored form must be the enum's own `name` — the column holds years of history
 * and renaming a constant would orphan every past row. Second, null has to
 * survive in both directions, because `AuditLogDao.getFiltered` binds a null
 * operation type to mean "no filter"; a converter that rejected null would make
 * the unfiltered audit-log view throw before its query ran.
 */
class AuditOperationTypeConverterTest {

    private val converter = AuditOperationTypeConverter()

    @Test
    fun `every operation type round-trips through its stored name`() {
        for (type in AuditOperationType.entries) {
            val stored = converter.fromAuditOperationType(type)

            assertEquals(type.name, stored)
            assertEquals(type, converter.toAuditOperationType(stored))
        }
    }

    @Test
    fun `a null type is stored as null so an unfiltered query still binds`() {
        assertNull(converter.fromAuditOperationType(null))
    }

    @Test
    fun `a null column reads back as a null type`() {
        assertNull(converter.toAuditOperationType(null))
    }

    @Test
    fun `the stored form is the enum name and not its ordinal`() {
        assertEquals(
            "KEY_CREATED",
            converter.fromAuditOperationType(AuditOperationType.KEY_CREATED)
        )
        assertEquals(
            "FIDO2_REGISTRATION",
            converter.fromAuditOperationType(AuditOperationType.FIDO2_REGISTRATION)
        )
    }

    @Test
    fun `an unrecognised column value fails loudly rather than silently dropping the row`() {
        assertThrows(IllegalArgumentException::class.java) {
            converter.toAuditOperationType("NOT_A_REAL_OPERATION")
        }
    }

    @Test
    fun `the stored name is case sensitive`() {
        assertThrows(IllegalArgumentException::class.java) {
            converter.toAuditOperationType("key_created")
        }
    }

    @Test
    fun `an empty column value is rejected rather than mapped to a default`() {
        assertThrows(IllegalArgumentException::class.java) {
            converter.toAuditOperationType("")
        }
    }
}
