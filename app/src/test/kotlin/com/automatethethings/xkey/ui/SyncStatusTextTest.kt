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
package com.automatethethings.xkey.ui

import com.automatethethings.xkey.R
import com.automatethethings.xkey.remote.RemoteSyncClient
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Test
import java.io.IOException
import java.time.LocalDateTime
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle
import java.util.Locale

/**
 * JVM tests for [SyncStatusText], the line the Sync with Desktop result shows
 * about the desktop's own sync status (`remote.syncStatus`).
 */
class SyncStatusTextTest {

    private fun status(lastSync: String?) =
        RemoteSyncClient.DesktopSyncStatus(lastSync = lastSync, deviceId = "desk-1", storeChecksums = emptyMap())

    @Test
    fun `a desktop that has synced shows its last sync time in the phone's zone`() {
        val line = SyncStatusText.desktopLine(status("2026-11-12T08:30:00Z"), ZoneOffset.ofHours(2), Locale.US)

        assertEquals(R.string.sync_desktop_last_sync, line.message)
        assertEquals("Nov 12, 2026, 10:30:00 AM", line.arg)
    }

    @Test
    fun `a time the phone cannot parse is shown as the desktop sent it`() {
        val line = SyncStatusText.desktopLine(status("yesterday"), ZoneOffset.UTC, Locale.US)

        assertEquals(R.string.sync_desktop_last_sync, line.message)
        assertEquals("yesterday", line.arg)
    }

    @Test
    fun `a desktop that has never synced says so`() {
        val line = SyncStatusText.desktopLine(status(null), ZoneOffset.UTC, Locale.US)

        assertEquals(R.string.sync_desktop_never, line.message)
        assertNull(line.arg)
    }

    @Test
    fun `no status says the desktop's status is unavailable`() {
        val line = SyncStatusText.desktopLine(null, ZoneOffset.UTC, Locale.US)

        assertEquals(R.string.sync_desktop_status_unavailable, line.message)
        assertNull(line.arg)
    }

    @Test
    fun `a failed status request yields no status instead of throwing`() = runTest {
        assertNull(SyncStatusText.fetch { throw IOException("link down") })
        assertEquals(status(null), SyncStatusText.fetch { status(null) })
    }

    @Test
    fun `a cancelled status request still propagates the cancellation`() = runTest {
        val cancelled = CancellationException("activity destroyed")
        val thrown = runCatching { SyncStatusText.fetch { throw cancelled } }.exceptionOrNull()
        assertSame(cancelled, thrown)
    }
}
