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
import com.automatethethings.xkey.audit.AuditLogDao
import com.automatethethings.xkey.audit.AuditLogEntity
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.onStart
import java.time.Clock

/** One row of the home screen's Recent Activity section. */
sealed interface RecentActivityRow {

    /**
     * An audit entry: its operation label, the key's label (never its id),
     * the outcome and how long ago it happened ([timeRes] formatted with
     * [timeCount]).
     */
    data class Entry(
        @StringRes val labelRes: Int,
        val keyLabel: String?,
        val success: Boolean,
        @StringRes val outcomeRes: Int,
        @StringRes val timeRes: Int,
        val timeCount: Long
    ) : RecentActivityRow

    /** The single row shown when there is no audit entry. */
    data object Empty : RecentActivityRow {
        @StringRes
        val messageRes: Int = R.string.recent_activity_empty
    }
}

/** Maps audit entries to the home screen's Recent Activity rows. */
object RecentActivityRows {

    /** How many entries the home screen shows. */
    const val DEFAULT_LIMIT = 5

    /** How often the shown relative times are recomputed. */
    const val REFRESH_MILLIS = 60_000L

    fun build(
        entries: List<AuditLogEntity>,
        clock: Clock,
        limit: Int = DEFAULT_LIMIT,
        keyLabels: Map<String, String> = emptyMap()
    ): List<RecentActivityRow> {
        if (entries.isEmpty() || limit <= 0) return listOf(RecentActivityRow.Empty)
        val nowMillis = clock.millis()
        return entries
            .sortedByDescending { it.timestamp }
            .take(limit)
            .map { entry ->
                val (timeRes, timeCount) = age(nowMillis - entry.timestamp)
                RecentActivityRow.Entry(
                    labelRes = AuditOperationLabels.labelRes(entry.operationType),
                    keyLabel = keyText(entry, keyLabels),
                    success = entry.success,
                    outcomeRes = if (entry.success) {
                        R.string.recent_activity_succeeded
                    } else {
                        R.string.recent_activity_failed
                    },
                    timeRes = timeRes,
                    timeCount = timeCount
                )
            }
    }

    /**
     * The rows the home screen binds: built from [AuditLogDao.observeRecent]
     * and rebuilt on every [ticks] emission so the relative times keep aging,
     * and whenever [keyLabels] (stored key id to label) changes.
     */
    fun observe(
        dao: AuditLogDao,
        clock: Clock,
        ticks: Flow<Unit> = ticker(REFRESH_MILLIS),
        limit: Int = DEFAULT_LIMIT,
        keyLabels: Flow<Map<String, String>> = flowOf(emptyMap())
    ): Flow<List<RecentActivityRow>> =
        combine(dao.observeRecent(limit), keyLabels, ticks.onStart { emit(Unit) }) { entries, labels, _ ->
            build(entries, clock, limit, labels)
        }.distinctUntilChanged()

    /** Emits every [periodMillis], forever. */
    fun ticker(periodMillis: Long): Flow<Unit> = flow {
        while (true) {
            delay(periodMillis)
            emit(Unit)
        }
    }

    /**
     * The key text of [entry]: the stored key's label for its key id, else the
     * logged label unless it is a key id (some call sites log the id as the
     * label), else none.
     */
    private fun keyText(entry: AuditLogEntity, keyLabels: Map<String, String>): String? {
        entry.keyId?.let { keyLabels[it] }?.let { return it }
        return entry.keyLabel?.takeUnless { it == entry.keyId || it in keyLabels }
    }

    /** How long ago [elapsedMillis] is; a time ahead of the clock reads "just now". */
    private fun age(elapsedMillis: Long): Pair<Int, Long> {
        val minutes = elapsedMillis / MINUTE_MILLIS
        return when {
            minutes < 1 -> R.string.recent_activity_just_now to 0L
            minutes < 60 -> R.string.recent_activity_minutes_ago to minutes
            minutes < 24 * 60 -> R.string.recent_activity_hours_ago to minutes / 60
            else -> R.string.recent_activity_days_ago to minutes / (24 * 60)
        }
    }

    private const val MINUTE_MILLIS = 60_000L
}
