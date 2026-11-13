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

import androidx.annotation.StringRes
import com.automatethethings.xkey.R
import com.automatethethings.xkey.remote.RemoteSyncClient
import kotlinx.coroutines.CancellationException
import java.time.OffsetDateTime
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.format.DateTimeParseException
import java.time.format.FormatStyle
import java.util.Locale

/**
 * The line the Sync with Desktop result shows about the desktop's own sync
 * status (`remote.syncStatus`), kept free of views so it runs on the JVM.
 */
object SyncStatusText {

    /** [message] takes [arg] when it is not null, and no argument otherwise. */
    data class DesktopLine(@StringRes val message: Int, val arg: String? = null)

    /**
     * Runs [request] for the desktop's status and turns any failure into
     * null: the stores already synced, so a status failure does not fail the
     * sync. Cancellation still propagates.
     */
    suspend fun fetch(request: suspend () -> RemoteSyncClient.DesktopSyncStatus): RemoteSyncClient.DesktopSyncStatus? =
        try {
            request()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            null
        }

    /**
     * The line for [status]: the desktop's last sync time in [zone], or that
     * it has never synced, or that its status is unavailable when [status] is
     * null. A time the phone cannot parse as RFC 3339 is shown as sent.
     */
    fun desktopLine(status: RemoteSyncClient.DesktopSyncStatus?, zone: ZoneId, locale: Locale): DesktopLine {
        if (status == null) return DesktopLine(R.string.sync_desktop_status_unavailable)
        val lastSync = status.lastSync ?: return DesktopLine(R.string.sync_desktop_never)
        val shown = try {
            OffsetDateTime.parse(lastSync)
                .atZoneSameInstant(zone)
                .format(DateTimeFormatter.ofLocalizedDateTime(FormatStyle.MEDIUM).withLocale(locale))
        } catch (e: DateTimeParseException) {
            lastSync
        }
        return DesktopLine(R.string.sync_desktop_last_sync, shown)
    }
}
