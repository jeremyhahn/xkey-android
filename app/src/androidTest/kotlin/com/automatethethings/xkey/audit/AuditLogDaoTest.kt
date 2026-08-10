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
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented tests for [AuditLogDao] — the Room queries behind the audit log
 * screen and the retention policy.
 *
 * Every test runs against its own **in-memory** [XKeyDatabase], so nothing here
 * touches the shared on-device `xkey_credentials.db` and no other suite can see
 * these rows. That isolation is also why the counts asserted below are literal:
 * the only rows in the database are the ones the test itself seeded.
 *
 * The retention tests pin the exact policy [AuditLogger] applies on startup —
 * `deleteOlderThan(now - 90 days)` and `deleteExceedingCount(10_000)` — with an
 * emphasis on the boundary semantics (`timestamp < cutoff` is strict, and
 * "exceeding count" keeps the *newest* rows).
 */
@RunWith(AndroidJUnit4::class)
class AuditLogDaoTest {

    private lateinit var database: XKeyDatabase
    private lateinit var dao: AuditLogDao

    /** Fixed clock anchor so date-range assertions never race the wall clock. */
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

    private fun entry(
        timestamp: Long = t0,
        operationType: AuditOperationType = AuditOperationType.KEY_CREATED,
        keyId: String? = null,
        keyLabel: String? = null,
        keyType: String? = null,
        deviceId: String? = null,
        success: Boolean = true,
        errorMessage: String? = null,
        details: String? = null,
        durationMs: Long? = null
    ) = AuditLogEntity(
        timestamp = timestamp,
        operationType = operationType,
        keyId = keyId,
        keyLabel = keyLabel,
        keyType = keyType,
        deviceId = deviceId,
        success = success,
        errorMessage = errorMessage,
        details = details,
        durationMs = durationMs
    )

    // -------------------------------------------------------------------------
    // Insert / read back
    // -------------------------------------------------------------------------

    @Test
    fun insertReturnsRowIdAndEveryColumnSurvivesTheRoundTrip() = runBlocking {
        val id = dao.insert(
            entry(
                timestamp = t0,
                operationType = AuditOperationType.FIDO2_REGISTRATION,
                keyId = "key-1",
                keyLabel = "Work laptop",
                keyType = "fido2",
                deviceId = "device-1",
                success = false,
                errorMessage = "user cancelled",
                details = """{"rpId":"example.com"}""",
                durationMs = 42L
            )
        )
        assertTrue("row id must be assigned", id > 0)

        val loaded = dao.getById(id)!!
        assertEquals(id, loaded.id)
        assertEquals(t0, loaded.timestamp)
        assertEquals(AuditOperationType.FIDO2_REGISTRATION, loaded.operationType)
        assertEquals("key-1", loaded.keyId)
        assertEquals("Work laptop", loaded.keyLabel)
        assertEquals("fido2", loaded.keyType)
        assertEquals("device-1", loaded.deviceId)
        assertFalse(loaded.success)
        assertEquals("user cancelled", loaded.errorMessage)
        assertEquals("""{"rpId":"example.com"}""", loaded.details)
        assertEquals(42L, loaded.durationMs)
    }

    @Test
    fun getByIdReturnsNullForAnUnknownId() = runBlocking {
        val id = dao.insert(entry())
        assertNull(dao.getById(id + 1_000))
    }

    @Test
    fun insertAllReturnsOneIdPerEntry() = runBlocking {
        val ids = dao.insertAll(listOf(entry(), entry(), entry()))
        assertEquals(3, ids.size)
        assertEquals(3, ids.distinct().size)
        assertEquals(3L, dao.getCount())
    }

    @Test
    fun getAllOrdersNewestFirst() = runBlocking {
        dao.insert(entry(timestamp = t0, keyId = "oldest"))
        dao.insert(entry(timestamp = t0 + 2_000, keyId = "newest"))
        dao.insert(entry(timestamp = t0 + 1_000, keyId = "middle"))

        assertEquals(
            listOf("newest", "middle", "oldest"),
            dao.getAll().map { it.keyId }
        )
    }

    @Test
    fun getPaginatedWalksTheOrderedResultSet() = runBlocking {
        repeat(5) { i -> dao.insert(entry(timestamp = t0 + i * 1_000L, keyId = "k$i")) }

        assertEquals(listOf("k4", "k3"), dao.getPaginated(limit = 2, offset = 0).map { it.keyId })
        assertEquals(listOf("k2", "k1"), dao.getPaginated(limit = 2, offset = 2).map { it.keyId })
        assertEquals(listOf("k0"), dao.getPaginated(limit = 2, offset = 4).map { it.keyId })
        assertTrue(dao.getPaginated(limit = 2, offset = 5).isEmpty())
    }

    // -------------------------------------------------------------------------
    // Filtering
    // -------------------------------------------------------------------------

    @Test
    fun getByKeyIdSelectsOnlyThatKey() = runBlocking {
        dao.insert(entry(keyId = "wanted"))
        dao.insert(entry(keyId = "wanted"))
        dao.insert(entry(keyId = "other"))

        assertEquals(2, dao.getByKeyId("wanted").size)
        assertTrue(dao.getByKeyId("absent").isEmpty())
    }

    @Test
    fun getByKeyTypeAndOperationTypeSelectIndependently() = runBlocking {
        dao.insert(entry(keyType = "fido2", operationType = AuditOperationType.KEY_CREATED))
        dao.insert(entry(keyType = "signing", operationType = AuditOperationType.KEY_CREATED))
        dao.insert(entry(keyType = "signing", operationType = AuditOperationType.SIGNING_REQUEST))

        assertEquals(2, dao.getByKeyType("signing").size)
        assertEquals(2, dao.getByOperationType(AuditOperationType.KEY_CREATED).size)
        assertEquals(1, dao.getByOperationType(AuditOperationType.SIGNING_REQUEST).size)
        assertTrue(dao.getByOperationType(AuditOperationType.CRL_GENERATED).isEmpty())
    }

    @Test
    fun getByDateRangeIsInclusiveOnBothBounds() = runBlocking {
        dao.insert(entry(timestamp = t0 - 1, keyId = "before"))
        dao.insert(entry(timestamp = t0, keyId = "lower-bound"))
        dao.insert(entry(timestamp = t0 + 500, keyId = "inside"))
        dao.insert(entry(timestamp = t0 + 1_000, keyId = "upper-bound"))
        dao.insert(entry(timestamp = t0 + 1_001, keyId = "after"))

        val ids = dao.getByDateRange(t0, t0 + 1_000).map { it.keyId }
        assertEquals(listOf("upper-bound", "inside", "lower-bound"), ids)
    }

    @Test
    fun getByDeviceIdAndBySuccessPartitionTheTable() = runBlocking {
        dao.insert(entry(deviceId = "laptop", success = true))
        dao.insert(entry(deviceId = "laptop", success = false))
        dao.insert(entry(deviceId = "desktop", success = true))

        assertEquals(2, dao.getByDeviceId("laptop").size)
        assertEquals(2, dao.getBySuccess(true).size)
        assertEquals(1, dao.getBySuccess(false).size)
    }

    @Test
    fun searchByKeyLabelIsPartialAndCaseInsensitive() = runBlocking {
        dao.insert(entry(keyLabel = "Work Laptop"))
        dao.insert(entry(keyLabel = "home laptop"))
        dao.insert(entry(keyLabel = "Yubikey"))

        assertEquals(2, dao.searchByKeyLabel("LAPTOP").size)
        assertEquals(2, dao.searchByKeyLabel("lap").size)
        assertEquals(1, dao.searchByKeyLabel("yubi").size)
        assertTrue(dao.searchByKeyLabel("nothing-matches").isEmpty())
    }

    @Test
    fun getFilteredWithAllNullsReturnsEverything() = runBlocking {
        dao.insert(entry(keyType = "fido2"))
        dao.insert(entry(keyType = "signing", success = false))

        val all = dao.getFiltered(null, null, null, null, null)
        assertEquals(2, all.size)
    }

    @Test
    fun getFilteredCombinesOperationTypeKeyTypeAndSuccess() = runBlocking {
        dao.insert(
            entry(
                operationType = AuditOperationType.SIGNING_REQUEST,
                keyType = "signing",
                success = true,
                keyId = "match"
            )
        )
        dao.insert(
            entry(
                operationType = AuditOperationType.SIGNING_REQUEST,
                keyType = "signing",
                success = false
            )
        )
        dao.insert(
            entry(
                operationType = AuditOperationType.SIGNING_REQUEST,
                keyType = "fido2",
                success = true
            )
        )
        dao.insert(
            entry(
                operationType = AuditOperationType.KEY_CREATED,
                keyType = "signing",
                success = true
            )
        )

        val filtered = dao.getFiltered(
            operationType = AuditOperationType.SIGNING_REQUEST,
            keyType = "signing",
            success = true,
            startTimestamp = null,
            endTimestamp = null
        )
        assertEquals(1, filtered.size)
        assertEquals("match", filtered.single().keyId)
    }

    @Test
    fun getFilteredHonoursAPartiallySpecifiedDateWindow() = runBlocking {
        dao.insert(entry(timestamp = t0 - 5_000, keyId = "old"))
        dao.insert(entry(timestamp = t0 + 5_000, keyId = "new"))

        assertEquals(
            listOf("new"),
            dao.getFiltered(null, null, null, t0, null).map { it.keyId }
        )
        assertEquals(
            listOf("old"),
            dao.getFiltered(null, null, null, null, t0).map { it.keyId }
        )
    }

    // -------------------------------------------------------------------------
    // Aggregates
    // -------------------------------------------------------------------------

    @Test
    fun countsAgreeWithTheSeededRows() = runBlocking {
        dao.insert(entry(operationType = AuditOperationType.KEY_CREATED, keyType = "fido2"))
        dao.insert(entry(operationType = AuditOperationType.KEY_CREATED, keyType = "signing"))
        dao.insert(
            entry(
                operationType = AuditOperationType.SIGNING_REQUEST,
                keyType = "signing",
                success = false
            )
        )

        assertEquals(3L, dao.getCount())
        assertEquals(2L, dao.countByOperationType(AuditOperationType.KEY_CREATED))
        assertEquals(0L, dao.countByOperationType(AuditOperationType.PIN_LOCKOUT_RESET))
        assertEquals(2L, dao.countByKeyType("signing"))
        assertEquals(2L, dao.countSuccessful())
        assertEquals(1L, dao.countFailed())
    }

    @Test
    fun getRecentTakesTheNewestEntriesOnly() = runBlocking {
        repeat(6) { i -> dao.insert(entry(timestamp = t0 + i * 1_000L, keyId = "k$i")) }

        assertEquals(listOf("k5", "k4", "k3"), dao.getRecent(3).map { it.keyId })
        assertEquals(6, dao.getRecent(100).size)
    }

    @Test
    fun distinctKeyTypesSkipsNullsAndSortsAscending() = runBlocking {
        dao.insert(entry(keyType = "signing"))
        dao.insert(entry(keyType = "fido2"))
        dao.insert(entry(keyType = "fido2"))
        dao.insert(entry(keyType = null))

        assertEquals(listOf("fido2", "signing"), dao.getDistinctKeyTypes())
    }

    @Test
    fun distinctOperationTypesDeduplicates() = runBlocking {
        dao.insert(entry(operationType = AuditOperationType.KEY_CREATED))
        dao.insert(entry(operationType = AuditOperationType.KEY_CREATED))
        dao.insert(entry(operationType = AuditOperationType.CRL_GENERATED))

        val types = dao.getDistinctOperationTypes()
        assertEquals(2, types.size)
        assertTrue(types.contains(AuditOperationType.KEY_CREATED))
        assertTrue(types.contains(AuditOperationType.CRL_GENERATED))
    }

    // -------------------------------------------------------------------------
    // Flows
    // -------------------------------------------------------------------------

    @Test
    fun observeRecentEmitsTheCurrentNewestEntries() = runBlocking {
        dao.insert(entry(timestamp = t0, keyId = "older"))
        dao.insert(entry(timestamp = t0 + 1_000, keyId = "newer"))

        assertEquals(listOf("newer", "older"), dao.observeRecent(5).first().map { it.keyId })
        assertEquals(listOf("newer"), dao.observeRecent(1).first().map { it.keyId })
    }

    @Test
    fun observeCountAndObserveByKeyIdEmitTheCurrentState() = runBlocking {
        dao.insert(entry(keyId = "watched"))
        dao.insert(entry(keyId = "ignored"))

        assertEquals(2L, dao.observeCount().first())
        assertEquals(1, dao.observeByKeyId("watched").first().size)
        assertEquals(2, dao.observeAll().first().size)
    }

    @Test
    fun observeByOperationTypeKeyTypeAndDateRangeFilterTheEmission() = runBlocking {
        dao.insert(
            entry(
                timestamp = t0,
                operationType = AuditOperationType.KEY_CREATED,
                keyType = "fido2"
            )
        )
        dao.insert(
            entry(
                timestamp = t0 + 10_000,
                operationType = AuditOperationType.KEY_DELETED,
                keyType = "signing"
            )
        )

        assertEquals(1, dao.observeByOperationType(AuditOperationType.KEY_DELETED).first().size)
        assertEquals(1, dao.observeByDateRange(t0 + 1, t0 + 20_000).first().size)
        assertEquals(1, dao.observeByKeyType("fido2").first().size)
        assertTrue(dao.observeByKeyType("unknown").first().isEmpty())
    }

    @Test
    fun observeSearchByKeyLabelMatchesPartially() = runBlocking {
        dao.insert(entry(keyLabel = "Backup Key"))
        dao.insert(entry(keyLabel = "Primary"))

        assertEquals(1, dao.observeSearchByKeyLabel("backup").first().size)
    }

    // -------------------------------------------------------------------------
    // Retention policy (mirrors AuditLogger.applyRetentionPolicy)
    // -------------------------------------------------------------------------

    @Test
    fun deleteOlderThanIsStrictlyLessThanTheCutoff() = runBlocking {
        val cutoff = t0
        dao.insert(entry(timestamp = cutoff - 1, keyId = "expired"))
        dao.insert(entry(timestamp = cutoff, keyId = "on-the-boundary"))
        dao.insert(entry(timestamp = cutoff + 1, keyId = "fresh"))

        assertEquals(1, dao.deleteOlderThan(cutoff))
        assertEquals(
            listOf("fresh", "on-the-boundary"),
            dao.getAll().map { it.keyId }
        )
    }

    @Test
    fun deleteOlderThanEnforcesTheNinetyDayWindowUsedOnStartup() = runBlocking {
        val ninetyDaysMs = 90L * 24 * 60 * 60 * 1000
        val now = System.currentTimeMillis()
        dao.insert(entry(timestamp = now - ninetyDaysMs - 60_000, keyId = "91-days-old"))
        dao.insert(entry(timestamp = now - ninetyDaysMs + 60_000, keyId = "89-days-old"))
        dao.insert(entry(timestamp = now, keyId = "now"))

        val deleted = dao.deleteOlderThan(now - ninetyDaysMs)

        assertEquals(1, deleted)
        assertEquals(setOf("89-days-old", "now"), dao.getAll().map { it.keyId }.toSet())
    }

    @Test
    fun deleteExceedingCountKeepsTheNewestRows() = runBlocking {
        repeat(10) { i -> dao.insert(entry(timestamp = t0 + i * 1_000L, keyId = "k$i")) }

        val deleted = dao.deleteExceedingCount(4)

        assertEquals(6, deleted)
        assertEquals(listOf("k9", "k8", "k7", "k6"), dao.getAll().map { it.keyId })
    }

    @Test
    fun deleteExceedingCountIsANoOpBelowTheLimit() = runBlocking {
        repeat(3) { i -> dao.insert(entry(timestamp = t0 + i * 1_000L)) }

        assertEquals(0, dao.deleteExceedingCount(10_000))
        assertEquals(3L, dao.getCount())
    }

    @Test
    fun deleteByKeyIdRemovesOnlyThatKeysHistory() = runBlocking {
        dao.insert(entry(keyId = "doomed"))
        dao.insert(entry(keyId = "doomed"))
        dao.insert(entry(keyId = "kept"))

        assertEquals(2, dao.deleteByKeyId("doomed"))
        assertEquals(listOf("kept"), dao.getAll().map { it.keyId })
        assertEquals(0, dao.deleteByKeyId("doomed"))
    }

    @Test
    fun deleteAllEmptiesTheTable() = runBlocking {
        dao.insertAll(listOf(entry(), entry(), entry()))

        assertEquals(3, dao.deleteAll())
        assertEquals(0L, dao.getCount())
        assertTrue(dao.getAll().isEmpty())
    }
}
