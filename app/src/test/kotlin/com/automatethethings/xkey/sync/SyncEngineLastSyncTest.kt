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
package com.automatethethings.xkey.sync

import android.content.Context
import com.automatethethings.xkey.settings.SyncStateRepository
import io.mockk.coEvery
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.unmockkAll
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.IOException

/**
 * [SyncEngine.lastSyncRfc3339], the last sync time `local.syncStatus`
 * reports: RFC 3339 in UTC with milliseconds only when there are any, and ""
 * for a phone that has never synced. The stored time is mocked; the real
 * DataStore read never runs.
 */
class SyncEngineLastSyncTest {

    private val engine = SyncEngine(mockk<Context>(relaxed = true))

    @Before
    fun setUp() {
        mockkConstructor(SyncStateRepository::class)
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    private fun stored(millis: Long) {
        coEvery { anyConstructed<SyncStateRepository>().getLastSyncMillis() } returns millis
    }

    @Test
    fun `a phone that never synced reports an empty time`() = runTest {
        stored(0L)

        assertEquals("", engine.lastSyncRfc3339())
    }

    @Test
    fun `a negative stored time reports an empty time`() = runTest {
        stored(-1L)
        assertEquals("", engine.lastSyncRfc3339())

        stored(Long.MIN_VALUE)
        assertEquals("", engine.lastSyncRfc3339())
    }

    @Test
    fun `a time with milliseconds keeps them`() = runTest {
        stored(1_700_000_000_123L)

        assertEquals("2023-11-14T22:13:20.123Z", engine.lastSyncRfc3339())
    }

    @Test
    fun `a whole second has no fraction`() = runTest {
        stored(1_700_000_000_000L)

        assertEquals("2023-11-14T22:13:20Z", engine.lastSyncRfc3339())
    }

    @Test
    fun `a failing read of the stored time propagates`() = runTest {
        // Recorded as is: the caller (local.syncStatus) sees the failure.
        coEvery { anyConstructed<SyncStateRepository>().getLastSyncMillis() } throws IOException("unreadable")

        val error = runCatching { engine.lastSyncRfc3339() }.exceptionOrNull()

        assertTrue("expected the read failure, got $error", error is IOException)
        assertEquals("unreadable", error?.message)
    }
}
