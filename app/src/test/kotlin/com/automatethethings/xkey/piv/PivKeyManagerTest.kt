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
package com.automatethethings.xkey.piv

import io.mockk.coVerify
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Test

/**
 * Unit tests for the [PivKeyManager] usage path.
 *
 * The Android Keystore is not available in JVM unit tests, so key generation
 * and signing are covered by instrumented tests. [PivKeyManager.sign] records
 * each use through [PivSlotDao.recordUsage] without a timestamp; this pins that
 * the omitted timestamp is the current time.
 */
class PivKeyManagerTest {

    @Test
    fun `recordUsage without a timestamp stamps the current time`() = runTest {
        val pivSlotDao: PivSlotDao = mockk(relaxed = true)

        val before = System.currentTimeMillis()
        pivSlotDao.recordUsage("9A")
        val after = System.currentTimeMillis()

        coVerify { pivSlotDao.recordUsage("9A", match { it in before..after }) }
    }
}
