/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
 *
 * This file is part of xkey-android.
 *
 * xkey-android is dual-licensed:
 *
 * 1. GNU Affero General Public License v3.0 (AGPL-3.0)
 *    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
 *
 * 2. Commercial License
 *    Contact licensing@automatethethings.com for commercial licensing options.
 */

package com.automatethethings.xkey.ui

import com.automatethethings.xkey.audit.AuditLogEntity
import com.automatethethings.xkey.audit.AuditOperationType
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The audit screen's operation chips and the filter behind them: a policy
 * refusal has a chip, and the chip shows only refusals.
 */
class AuditOperationLabelsTest {

    @Test
    fun `policy refusals have a filter chip`() {
        assertTrue(AuditOperationType.POLICY_DENIED in AuditOperationLabels.filterTypes)
    }

    @Test
    fun `the policy refusal filter keeps only policy refusals`() {
        val entries = listOf(
            entry(AuditOperationType.KEY_CREATED),
            entry(AuditOperationType.POLICY_DENIED),
            entry(AuditOperationType.SIGNING_REQUEST),
            entry(AuditOperationType.OATH_CODE_GENERATED),
            entry(AuditOperationType.POLICY_DENIED)
        )

        val filtered = AuditOperationLabels.filterByOperation(entries, AuditOperationType.POLICY_DENIED)

        assertEquals(2, filtered.size)
        assertTrue(filtered.all { it.operationType == AuditOperationType.POLICY_DENIED })
    }

    @Test
    fun `no operation filter keeps every entry`() {
        val entries = AuditOperationType.entries.map { entry(it) }

        assertEquals(entries, AuditOperationLabels.filterByOperation(entries, null))
    }

    @Test
    fun `every operation type has a chip or is listed as having none, never both`() {
        val chips = AuditOperationLabels.filterTypes.toSet()
        val none = AuditOperationLabels.typesWithoutChip

        assertEquals("a chip type is listed twice", AuditOperationLabels.filterTypes.size, chips.size)
        assertEquals("types with a chip and without one", emptySet<AuditOperationType>(), chips intersect none)
        assertEquals("types with neither", emptySet<AuditOperationType>(), AuditOperationType.entries.toSet() - chips - none)
    }

    @Test
    fun `every refusal the screen colors as a warning has a chip`() {
        assertEquals(
            setOf(AuditOperationType.PAIRING_DENIED, AuditOperationType.POLICY_DENIED, AuditOperationType.BIOMETRIC_FAILURE),
            AuditOperationLabels.refusalTypes
        )
        assertEquals(
            emptySet<AuditOperationType>(),
            AuditOperationLabels.refusalTypes - AuditOperationLabels.filterTypes.toSet()
        )
    }

    private fun entry(type: AuditOperationType) = AuditLogEntity(operationType = type, keyLabel = type.name)
}
