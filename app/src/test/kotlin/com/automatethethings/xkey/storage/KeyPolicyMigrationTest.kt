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
package com.automatethethings.xkey.storage

import android.util.Log
import androidx.sqlite.db.SupportSQLiteDatabase
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.IOException

/**
 * The 12 -> 13 migration over the statements it runs: the denial records it
 * moves come from outside the database, and one it cannot read must never be
 * dropped silently (#193).
 */
class KeyPolicyMigrationTest {

    private val statements = mutableListOf<String>()
    private val bound = mutableListOf<Pair<String, List<Any?>>>()
    private val db = mockk<SupportSQLiteDatabase>(relaxed = true)

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.e(any(), any<String>(), any()) } returns 0
        every { Log.e(any(), any<String>()) } returns 0
        every { db.execSQL(any()) } answers { statements += firstArg<String>() }
        every { db.execSQL(any(), any()) } answers {
            statements += firstArg<String>()
            bound += firstArg<String>() to secondArg<Array<Any?>>().toList()
        }
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    /** The one key-wide update of the fallback: its SQL with any bound arguments substituted in order. */
    private fun keyWideUpdates(): List<String> =
        statements.filter { it.startsWith("UPDATE `key_policies` SET") && !it.contains("WHERE") }.map { sql ->
            val args = bound.firstOrNull { it.first == sql }?.second.orEmpty().iterator()
            sql.replace(Regex("""\?""")) { if (args.hasNext()) "'${args.next()}'" else "?" }
        }

    @Test
    fun unreadableDenialRecordsDenyEveryKeyInsteadOfBeingDropped() {
        XKeyDatabase.migration13To14 { throw IOException("unreadable") }.migrate(db)

        assertTrue("the key policy rows were not created", statements.any { it.startsWith("INSERT INTO `key_policies`") })
        assertTrue(
            "unreadable denial records were dropped: no deny-all marker",
            keyWideUpdates().any { it.contains("`denial` = 'PRIVATE'") }
        )
    }

    /**
     * Finding (3): an unreadable record may be a Private that owes its grant
     * clear, so the fallback owes every key's clear too, not only a denial.
     */
    @Test
    fun unreadableDenialRecordsKeepTheGrantClearsTheyMayOwe() {
        XKeyDatabase.migration13To14 { throw IOException("unreadable") }.migrate(db)

        assertTrue(
            "the fallback dropped the grant-clear obligations: ${keyWideUpdates()}",
            keyWideUpdates().any { it.contains("`denial` = 'PRIVATE'") && Regex("""`clear_grants` = '?(1|true)'?""").containsMatchIn(it) }
        )
    }

    @Test
    fun readableRecordsAddNoDenyAllMarker() {
        XKeyDatabase.migration13To14 { emptyMap() }.migrate(db)

        assertTrue(statements.none { it.startsWith("UPDATE `key_policies` SET") })
    }

    /** Round 9 (2): 13 -> 14 creates the deletion tombstone table, keyed by key id. */
    @Test
    fun migration13To14CreatesTheDeletionTombstoneTable() {
        XKeyDatabase.MIGRATION_14_15.migrate(db)

        assertTrue(
            "no key_deletions table: $statements",
            statements.any {
                it.startsWith("CREATE TABLE IF NOT EXISTS `key_deletions`") && "`key_instance` INTEGER NOT NULL" in it &&
                    "PRIMARY KEY(`key_id`)" in it
            }
        )
    }
}
