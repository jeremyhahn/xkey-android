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
import com.automatethethings.xkey.audit.AuditLogDao
import com.automatethethings.xkey.audit.AuditLogEntity
import com.automatethethings.xkey.audit.AuditOperationType
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.take
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestCoroutineScheduler
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Parameterized
import java.time.Clock
import java.time.Instant
import java.time.ZoneId
import java.time.ZoneOffset

/**
 * JVM tests for [RecentActivityRows], the home screen's Recent Activity rows,
 * and [AuditOperationLabels], the labels it shares with the audit screen.
 */
class RecentActivityRowsTest {

    private val now = Instant.parse("2026-11-12T12:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    private fun entry(
        type: AuditOperationType = AuditOperationType.KEY_CREATED,
        agoMillis: Long = 0,
        success: Boolean = true,
        keyId: String? = null,
        keyLabel: String? = null,
        details: String? = null
    ) = AuditLogEntity(
        timestamp = now.toEpochMilli() - agoMillis,
        operationType = type,
        keyId = keyId,
        keyLabel = keyLabel,
        success = success,
        details = details
    )

    private fun entries(vararg e: AuditLogEntity) =
        RecentActivityRows.build(e.toList(), clock).map { it as RecentActivityRow.Entry }

    @Test
    fun `the audit screen's labels name each operation`() {
        assertEquals(R.string.audit_log_op_key_created, AuditOperationLabels.labelRes(AuditOperationType.KEY_CREATED))
        assertEquals(R.string.audit_log_op_signing, AuditOperationLabels.labelRes(AuditOperationType.SIGNING_REQUEST))
        assertEquals(R.string.audit_log_op_fido2, AuditOperationLabels.labelRes(AuditOperationType.FIDO2_AUTHENTICATION))
        assertEquals(R.string.audit_log_op_piv_key_deleted, AuditOperationLabels.labelRes(AuditOperationType.PIV_KEY_DELETED))
    }

    @Test
    fun `every operation type has a label`() {
        AuditOperationType.entries.forEach {
            assertNotEquals("no label for $it", 0, AuditOperationLabels.labelRes(it))
        }
    }

    @Test
    fun `a row uses the audit screen's label for its operation`() {
        AuditOperationType.entries.forEach { type ->
            val row = entries(entry(type = type)).single()
            assertEquals(AuditOperationLabels.labelRes(type), row.labelRes)
        }
    }

    @Test
    fun `success and failure render differently`() {
        val (ok, failed) = entries(entry(success = true, agoMillis = 1), entry(success = false, agoMillis = 2))

        assertEquals(true, ok.success)
        assertEquals(R.string.recent_activity_succeeded, ok.outcomeRes)
        assertEquals(false, failed.success)
        assertEquals(R.string.recent_activity_failed, failed.outcomeRes)
    }

    @Test
    fun `relative time is computed from the injected clock`() {
        val rows = entries(
            entry(agoMillis = 30_000),
            entry(agoMillis = 5 * MINUTE),
            entry(agoMillis = 3 * HOUR + 10 * MINUTE),
            entry(agoMillis = 2 * DAY + HOUR)
        )

        assertEquals(R.string.recent_activity_just_now, rows[0].timeRes)
        assertEquals(R.string.recent_activity_minutes_ago, rows[1].timeRes)
        assertEquals(5L, rows[1].timeCount)
        assertEquals(R.string.recent_activity_hours_ago, rows[2].timeRes)
        assertEquals(3L, rows[2].timeCount)
        assertEquals(R.string.recent_activity_days_ago, rows[3].timeRes)
        assertEquals(2L, rows[3].timeCount)
    }

    @Test
    fun `a timestamp ahead of the clock reads just now`() {
        val row = entries(entry(agoMillis = -10 * MINUTE)).single()

        assertEquals(R.string.recent_activity_just_now, row.timeRes)
    }

    @Test
    fun `at most N rows, newest first`() {
        val input = (1..8).map { entry(agoMillis = it * MINUTE, keyLabel = "k$it") }.shuffled()

        val rows = RecentActivityRows.build(input, clock, limit = 3).map { it as RecentActivityRow.Entry }

        assertEquals(listOf("k1", "k2", "k3"), rows.map { it.keyLabel })
    }

    @Test
    fun `an empty list gives the empty-state row`() {
        assertEquals(listOf(RecentActivityRow.Empty), RecentActivityRows.build(emptyList(), clock))
        assertEquals(R.string.recent_activity_empty, RecentActivityRow.Empty.messageRes)
    }

    @Test
    fun `no row carries the details JSON or a raw key id`() {
        val details = """{"rpId":"example.com","algorithm":"ES256"}"""
        val rows = entries(
            entry(keyId = "key-0123456789abcdef", keyLabel = "Work key", details = details),
            entry(keyId = "key-fedcba9876543210", keyLabel = null, details = details, agoMillis = 1)
        )

        assertEquals("Work key", rows[0].keyLabel)
        assertNull(rows[1].keyLabel)
        rows.forEach { row ->
            assertFalse(row.toString().contains("key-0123456789abcdef"))
            assertFalse(row.toString().contains("key-fedcba9876543210"))
            assertFalse(row.toString().contains("rpId"))
        }
        assertEquals(
            setOf("labelRes", "keyLabel", "success", "outcomeRes", "timeRes", "timeCount"),
            RecentActivityRow.Entry::class.java.declaredFields.map { it.name }.filterNot { it.startsWith("$") }.toSet()
        )
    }

    @Test
    fun `a key label that is the raw key id shows the stored key's label or nothing`() {
        // Signing, decryption and FIDO2 creation entries log the key id as the label.
        val rows = RecentActivityRows.build(
            listOf(
                entry(keyId = "key-0123456789abcdef", keyLabel = "key-0123456789abcdef"),
                entry(keyId = "key-fedcba9876543210", keyLabel = "key-fedcba9876543210", agoMillis = 1),
                entry(keyId = null, keyLabel = "key-0123456789abcdef", agoMillis = 2),
                entry(keyId = "key-0123456789abcdef", keyLabel = "example.com", agoMillis = 3)
            ),
            clock,
            keyLabels = mapOf("key-0123456789abcdef" to "Work key")
        ).map { it as RecentActivityRow.Entry }

        assertEquals("Work key", rows[0].keyLabel)
        assertNull(rows[1].keyLabel)
        assertNull(rows[2].keyLabel)
        assertEquals("Work key", rows[3].keyLabel)
        rows.forEach { row ->
            assertFalse(row.toString().contains("key-0123456789abcdef"))
            assertFalse(row.toString().contains("key-fedcba9876543210"))
        }
    }

    @Test
    fun `the bound rows follow the stored keys' labels`() = runTest {
        val dao = daoOf(flowOf(listOf(entry(keyId = "key-01", keyLabel = "key-01"))))
        val labels = MutableStateFlow(mapOf("key-01" to "Work key"))
        val bound = mutableListOf<List<RecentActivityRow>>()
        val job = launch(UnconfinedTestDispatcher(testScheduler)) {
            RecentActivityRows.observe(dao, clock, ticks = emptyFlow(), keyLabels = labels).toList(bound)
        }

        labels.value = mapOf("key-01" to "Renamed key")
        job.cancel()

        assertEquals(
            listOf("Work key", "Renamed key"),
            bound.map { (it.single() as RecentActivityRow.Entry).keyLabel }
        )
    }

    private fun daoOf(table: Flow<List<AuditLogEntity>>) = mockk<AuditLogDao> {
        every { observeRecent(RecentActivityRows.DEFAULT_LIMIT) } returns table
    }

    /** A clock that reads the test scheduler's virtual time, starting at [now]. */
    private class SchedulerClock(private val scheduler: TestCoroutineScheduler, private val start: Instant) : Clock() {
        override fun getZone(): ZoneId = ZoneOffset.UTC
        override fun withZone(zone: ZoneId?): Clock = this
        override fun instant(): Instant = start.plusMillis(scheduler.currentTime)
    }

    @Test
    fun `the home screen binds the rows of the audit DAO's observeRecent`() = runTest {
        val table = MutableStateFlow(listOf(entry(keyLabel = "first")))
        val dao = daoOf(table)
        val bound = mutableListOf<List<RecentActivityRow>>()
        backgroundScope.launch(UnconfinedTestDispatcher(testScheduler)) {
            RecentActivityRows.observe(dao, clock, ticks = emptyFlow()).toList(bound)
        }

        assertEquals(listOf(RecentActivityRows.build(table.value, clock)), bound)

        table.value = listOf(entry(keyLabel = "first", agoMillis = MINUTE), entry(keyLabel = "second"))

        assertEquals(listOf("second", "first"), bound.last().map { (it as RecentActivityRow.Entry).keyLabel })
        verify { dao.observeRecent(RecentActivityRows.DEFAULT_LIMIT) }
    }

    @Test
    fun `an empty audit table binds the empty-state row`() = runTest {
        val rows = RecentActivityRows.observe(daoOf(flowOf(emptyList())), clock, ticks = emptyFlow()).first()

        assertEquals(listOf(RecentActivityRow.Empty), rows)
    }

    @Test
    fun `the bound labels age as the clock advances without an audit change`() = runTest {
        val clock = SchedulerClock(testScheduler, now)
        val dao = daoOf(MutableStateFlow(listOf(entry(agoMillis = 30_000))))
        val bound = mutableListOf<List<RecentActivityRow>>()
        backgroundScope.launch(UnconfinedTestDispatcher(testScheduler)) {
            RecentActivityRows.observe(dao, clock).toList(bound)
        }
        fun shown() = bound.last().single() as RecentActivityRow.Entry

        assertEquals(R.string.recent_activity_just_now, shown().timeRes)

        advanceTimeBy(RecentActivityRows.REFRESH_MILLIS)
        runCurrent()
        assertEquals(R.string.recent_activity_minutes_ago, shown().timeRes)
        assertEquals(1L, shown().timeCount)

        advanceTimeBy(RecentActivityRows.REFRESH_MILLIS)
        runCurrent()
        assertEquals(2L, shown().timeCount)

        advanceTimeBy(58 * RecentActivityRows.REFRESH_MILLIS)
        runCurrent()
        assertEquals(R.string.recent_activity_hours_ago, shown().timeRes)
        assertEquals(1L, shown().timeCount)
    }

    @Test
    fun `the ticker emits once per period`() = runTest {
        val ticks = RecentActivityRows.ticker(MINUTE).take(3).toList()

        assertEquals(3, ticks.size)
        assertEquals(3 * MINUTE, testScheduler.currentTime)
    }

    private companion object {
        const val MINUTE = 60_000L
        const val HOUR = 60 * MINUTE
        const val DAY = 24 * HOUR
    }
}

/**
 * Every source of a row's key text passes the one raw key id filter in
 * [RecentActivityRows.build]: one case per source, each failing if that
 * source reaches [RecentActivityRow.Entry.keyLabel] around the filter.
 */
@RunWith(Parameterized::class)
class RecentActivityRowsKeyTextSourceTest(
    private val source: String,
    private val keyId: String?,
    private val loggedLabel: String?,
    private val keyLabels: Map<String, String>,
    private val expected: String?
) {

    @Test
    fun `no raw key id reaches a row's key text`() {
        val entry = AuditLogEntity(
            timestamp = 0L,
            operationType = AuditOperationType.KEY_CREATED,
            keyId = keyId,
            keyLabel = loggedLabel,
            success = true
        )
        val row = RecentActivityRows.build(listOf(entry), Clock.fixed(Instant.EPOCH, ZoneOffset.UTC), keyLabels = keyLabels)
            .single() as RecentActivityRow.Entry

        assertEquals(source, expected, row.keyLabel)
        (keyLabels.keys + listOfNotNull(keyId)).forEach { id ->
            assertFalse("$source shows raw key id $id", row.toString().contains(id))
        }
    }

    companion object {
        private const val KEY = "key-0123456789abcdef"
        private const val OTHER = "key-fedcba9876543210"

        @JvmStatic
        @Parameterized.Parameters(name = "{0}")
        fun cases(): List<Array<Any?>> = listOf(
            arrayOf("key-table label equal to its keyId", KEY, KEY, mapOf(KEY to KEY), null),
            arrayOf("key created without a label (label defaults to keyId)", KEY, null, mapOf(KEY to KEY), null),
            arrayOf("discovered general key labelled by keyId", KEY, "example.com", mapOf(KEY to KEY), "example.com"),
            arrayOf("key-table label equal to another key's keyId", KEY, null, mapOf(KEY to OTHER, OTHER to "Work key"), null),
            arrayOf("audit keyLabel equal to its keyId", KEY, KEY, emptyMap<String, String>(), null),
            arrayOf("audit keyLabel equal to another key's keyId", KEY, OTHER, mapOf(OTHER to "Work key"), null),
            arrayOf("audit entry with no key table row", null, KEY, mapOf(KEY to "Work key"), null),
            arrayOf("a real stored label still shows", KEY, KEY, mapOf(KEY to "Work key"), "Work key"),
            arrayOf("a real logged label still shows", KEY, "example.com", emptyMap<String, String>(), "example.com")
        )
    }
}
