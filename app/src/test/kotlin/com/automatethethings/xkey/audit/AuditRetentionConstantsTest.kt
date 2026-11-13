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
package com.automatethethings.xkey.audit

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Pins the retention limits [AuditLogger] applies on startup.
 *
 * `docs/audit-log/architecture.md` names these two values; a change here
 * must change the page too.
 */
class AuditRetentionConstantsTest {

    @Test
    fun retentionPeriodIsNinetyDays() {
        assertEquals(90L * 24 * 60 * 60 * 1000, AuditLogger.DEFAULT_RETENTION_MS)
        assertEquals(7_776_000_000L, AuditLogger.DEFAULT_RETENTION_MS)
    }

    @Test
    fun maximumEntryCountIsTenThousand() {
        assertEquals(10_000, AuditLogger.MAX_ENTRIES)
    }
}
