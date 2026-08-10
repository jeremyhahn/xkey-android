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

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.storage.XKeyDatabase
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented tests for the [AuditLogger] singleton against the *real*
 * on-device database.
 *
 * [AuditLogger.log] dispatches onto a `SupervisorJob + Dispatchers.IO` scope, so
 * every assertion polls the DAO until the row lands rather than assuming the
 * write has completed. Each test tags its rows with a per-run key id and deletes
 * exactly those rows in `@After` — the shared `audit_logs` table is left with the
 * same contents it had before, and no test asserts a table-wide count.
 *
 * The retention policy itself (`deleteOlderThan(now - 90d)` +
 * `deleteExceedingCount(10_000)`) is private and only runs inside
 * [AuditLogger.initialize] on a cold process, so it cannot be invoked from a
 * test that shares the process with an already-initialised logger; its query
 * semantics are pinned in `AuditLogDaoTest` instead.
 */
@RunWith(AndroidJUnit4::class)
class AuditLoggerInstrumentedTest {

    private lateinit var dao: AuditLogDao
    private val keyId = "audit-logger-test-${System.nanoTime()}"

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        AuditLogger.initialize(context)
        dao = XKeyDatabase.getInstance(context).auditLogDao()
    }

    @After
    fun tearDown() = runBlocking<Unit> {
        dao.deleteByKeyId(keyId)
        Unit
    }

    /** Polls until [keyId] has at least [expected] rows, or fails after ~5s. */
    private fun awaitEntries(expected: Int): List<AuditLogEntity> = runBlocking {
        repeat(50) {
            val rows = dao.getByKeyId(keyId)
            if (rows.size >= expected) return@runBlocking rows
            Thread.sleep(100)
        }
        val rows = dao.getByKeyId(keyId)
        throw AssertionError("expected $expected audit rows for $keyId, saw ${rows.size}")
    }

    @Test
    fun initializeIsIdempotentAndReportsReady() {
        AuditLogger.initialize(ApplicationProvider.getApplicationContext())
        AuditLogger.initialize(ApplicationProvider.getApplicationContext())

        assertTrue("logger must report itself initialised", AuditLogger.isInitialized())
    }

    @Test
    fun logKeyCreatedPersistsTheEventWithItsAlgorithmDetails() {
        AuditLogger.logKeyCreated(
            keyId = keyId,
            keyLabel = "Instrumented key",
            keyType = "signing",
            algorithm = "ES256",
            strongBox = true
        )

        val entry = awaitEntries(1).single()
        assertEquals(AuditOperationType.KEY_CREATED, entry.operationType)
        assertEquals("Instrumented key", entry.keyLabel)
        assertEquals("signing", entry.keyType)
        assertTrue(entry.success)
        assertTrue("timestamp must be stamped", entry.timestamp > 0)

        val details = JSONObject(entry.details!!)
        assertEquals("ES256", details.getString("algorithm"))
        assertTrue(details.getBoolean("strongBox"))
    }

    @Test
    fun aFailedSigningRequestRecordsTheErrorAndDuration() {
        AuditLogger.logSigningRequest(
            keyId = keyId,
            keyLabel = "Instrumented key",
            keyType = "signing",
            algorithm = "ES256",
            deviceId = "desktop-1",
            deviceName = "Desktop",
            success = false,
            errorMessage = "user not authenticated",
            durationMs = 17L
        )

        val entry = awaitEntries(1).single()
        assertEquals(AuditOperationType.SIGNING_REQUEST, entry.operationType)
        assertFalse(entry.success)
        assertEquals("user not authenticated", entry.errorMessage)
        assertEquals(17L, entry.durationMs)
        assertEquals("desktop-1", entry.deviceId)
        assertEquals("Desktop", entry.deviceName)
        assertNotNull(entry.details)
    }

    @Test
    fun multipleEventsForOneKeyAreAllRetainedNewestFirst() {
        AuditLogger.logKeyCreated(keyId, "Instrumented key", "signing", "ES256")
        AuditLogger.logKeyExported(keyId, "Instrumented key", "signing", "pem")
        AuditLogger.logKeyDeleted(keyId, "Instrumented key", "signing")

        val entries = awaitEntries(3)
        assertEquals(3, entries.size)
        assertEquals(
            setOf(
                AuditOperationType.KEY_CREATED,
                AuditOperationType.KEY_EXPORTED,
                AuditOperationType.KEY_DELETED
            ),
            entries.map { it.operationType }.toSet()
        )
        // getByKeyId orders by timestamp DESC.
        val timestamps = entries.map { it.timestamp }
        assertEquals(timestamps.sortedDescending(), timestamps)
    }

    @Test
    fun deletingAKeysHistoryRemovesEveryRowForThatKey() = runBlocking {
        AuditLogger.logKeyCreated(keyId, "Instrumented key", "signing", "ES256")
        AuditLogger.logKeyDeleted(keyId, "Instrumented key", "signing")
        awaitEntries(2)

        val deleted = dao.deleteByKeyId(keyId)

        assertEquals(2, deleted)
        assertTrue(dao.getByKeyId(keyId).isEmpty())
    }
}
