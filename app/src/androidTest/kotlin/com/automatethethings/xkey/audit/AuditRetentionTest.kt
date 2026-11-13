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

import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.storage.XKeyDatabase
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Retention tests for [AuditLogDao] on an in-memory [XKeyDatabase].
 *
 * Each test is written so that it fails when its query is inverted:
 * `timestamp < :olderThan` turned into `>=`, or the keep-newest subquery's
 * `ORDER BY timestamp DESC` turned into `ASC`.
 *
 * The policy test applies the two DAO calls in the order
 * `AuditLogger.applyRetentionPolicy` runs them, with the same constants
 * ([AuditLogger.DEFAULT_RETENTION_MS], [AuditLogger.MAX_ENTRIES]).
 */
@RunWith(AndroidJUnit4::class)
class AuditRetentionTest {

    private lateinit var database: XKeyDatabase
    private lateinit var dao: AuditLogDao

    /** Fixed clock anchor so boundary assertions never race the wall clock. */
    private val t0 = 1_700_000_000_000L

    @Before
    fun setUp() {
        database = Room.inMemoryDatabaseBuilder(
            ApplicationProvider.getApplicationContext(),
            XKeyDatabase::class.java
        ).build()
        dao = database.auditLogDao()
    }

    @After
    fun tearDown() {
        database.close()
    }

    private fun entry(timestamp: Long, keyId: String) = AuditLogEntity(
        timestamp = timestamp,
        operationType = AuditOperationType.KEY_CREATED,
        keyId = keyId,
        keyLabel = null,
        keyType = null,
        deviceId = null,
        success = true,
        errorMessage = null,
        details = null,
        durationMs = null
    )

    // -------------------------------------------------------------------------
    // deleteOlderThan
    // -------------------------------------------------------------------------

    @Test
    fun deleteOlderThanDeletesOnlyRowsStrictlyBeforeTheCutoffAndCountsThem() = runBlocking {
        val cutoff = t0
        dao.insert(entry(cutoff - 10_000, "expired-1"))
        dao.insert(entry(cutoff - 5_000, "expired-2"))
        dao.insert(entry(cutoff - 1, "expired-3"))
        dao.insert(entry(cutoff, "boundary"))
        dao.insert(entry(cutoff + 1, "fresh"))

        assertEquals(3, dao.deleteOlderThan(cutoff))
        assertEquals(listOf("fresh", "boundary"), dao.getAll().map { it.keyId })
    }

    @Test
    fun deleteOlderThanReturnsZeroWhenNothingIsOlder() = runBlocking {
        dao.insert(entry(t0, "boundary"))
        dao.insert(entry(t0 + 1_000, "fresh"))

        assertEquals(0, dao.deleteOlderThan(t0))
        assertEquals(2L, dao.getCount())
    }

    // -------------------------------------------------------------------------
    // deleteExceedingCount
    // -------------------------------------------------------------------------

    @Test
    fun deleteExceedingCountKeepsTheNewestRowsAndCountsTheRest() = runBlocking {
        repeat(7) { i -> dao.insert(entry(t0 + i * 1_000L, "k$i")) }

        assertEquals(4, dao.deleteExceedingCount(3))
        assertEquals(listOf("k6", "k5", "k4"), dao.getAll().map { it.keyId })
    }

    @Test
    fun deleteExceedingCountKeepsExactlyNWhenTimestampsTieAtTheBoundary() = runBlocking {
        dao.insert(entry(t0, "old-1"))
        dao.insert(entry(t0, "old-2"))
        repeat(4) { i -> dao.insert(entry(t0 + 1_000, "tie-$i")) }
        dao.insert(entry(t0 + 2_000, "new"))

        // The limit falls inside the tied group: the newest row and two of the
        // four tied rows stay, every older row goes.
        assertEquals(4, dao.deleteExceedingCount(3))
        val kept = dao.getAll().map { it.keyId }
        assertEquals(3, kept.size)
        assertEquals("new", kept.first())
        assertEquals(2, kept.count { it!!.startsWith("tie-") })
        assertTrue(kept.none { it!!.startsWith("old-") })
    }

    @Test
    fun deleteExceedingCountKeepsAWholeTiedGroupThatFitsTheLimit() = runBlocking {
        dao.insert(entry(t0, "old-1"))
        dao.insert(entry(t0, "old-2"))
        repeat(4) { i -> dao.insert(entry(t0 + 1_000, "tie-$i")) }
        dao.insert(entry(t0 + 2_000, "new"))

        assertEquals(2, dao.deleteExceedingCount(5))
        val kept = dao.getAll().map { it.keyId }
        assertEquals("new", kept.first())
        assertEquals(setOf("tie-0", "tie-1", "tie-2", "tie-3"), kept.drop(1).toSet())
    }

    // -------------------------------------------------------------------------
    // The retention policy, as AuditLogger.applyRetentionPolicy runs it
    // -------------------------------------------------------------------------

    /** The policy's two calls, in its order, with its constants. */
    private suspend fun applyRetentionPolicy(now: Long): Pair<Int, Int> {
        val byAge = dao.deleteOlderThan(now - AuditLogger.DEFAULT_RETENTION_MS)
        val byCount = dao.deleteExceedingCount(AuditLogger.MAX_ENTRIES)
        return byAge to byCount
    }

    @Test
    fun retentionPolicyAppliesTheAgeLimitThenTheCountLimit() = runBlocking {
        val now = System.currentTimeMillis()
        val cutoff = now - AuditLogger.DEFAULT_RETENTION_MS
        val extra = 4

        dao.insert(entry(cutoff - 60_000, "expired-1"))
        dao.insert(entry(cutoff - 1, "expired-2"))
        dao.insert(entry(cutoff + 60_000, "aged-but-in-window"))
        // MAX_ENTRIES + extra recent rows, one millisecond apart, newest last.
        dao.insertAll(
            (AuditLogger.MAX_ENTRIES + extra - 1 downTo 0).map { i -> entry(now - i, "recent-$i") }
        )

        val (byAge, byCount) = applyRetentionPolicy(now)

        assertEquals(2, byAge)
        // The one in-window aged row and the `extra` oldest recent rows.
        assertEquals(1 + extra, byCount)
        assertEquals(AuditLogger.MAX_ENTRIES.toLong(), dao.getCount())

        val newest = dao.getRecent(1).single()
        assertEquals("recent-0", newest.keyId)
        assertTrue(dao.getByKeyId("aged-but-in-window").isEmpty())
        assertTrue(dao.getByKeyId("recent-${AuditLogger.MAX_ENTRIES + extra - 1}").isEmpty())
        assertEquals(1, dao.getByKeyId("recent-${AuditLogger.MAX_ENTRIES - 1}").size)
    }

    @Test
    fun retentionPolicyLeavesAnInLimitLogAlone() = runBlocking {
        val now = System.currentTimeMillis()
        dao.insert(entry(now - AuditLogger.DEFAULT_RETENTION_MS + 60_000, "in-window"))
        dao.insert(entry(now, "now"))

        assertEquals(0 to 0, applyRetentionPolicy(now))
        assertEquals(2L, dao.getCount())
    }
}
