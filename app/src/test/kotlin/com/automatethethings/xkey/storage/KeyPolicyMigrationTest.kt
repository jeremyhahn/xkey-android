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
    private val db = mockk<SupportSQLiteDatabase>(relaxed = true)

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.e(any(), any<String>(), any()) } returns 0
        every { Log.e(any(), any<String>()) } returns 0
        every { db.execSQL(any()) } answers { statements += firstArg<String>() }
        every { db.execSQL(any(), any()) } answers { statements += firstArg<String>() }
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun unreadableDenialRecordsDenyEveryKeyInsteadOfBeingDropped() {
        XKeyDatabase.migration12To13 { throw IOException("unreadable") }.migrate(db)

        assertTrue("the key policy rows were not created", statements.any { it.startsWith("INSERT INTO `key_policies`") })
        assertTrue(
            "unreadable denial records were dropped: no deny-all marker",
            statements.any {
                it.startsWith("UPDATE `key_policies` SET") && it.contains("`denial` = 'PRIVATE'") && !it.contains("WHERE")
            }
        )
    }

    @Test
    fun readableRecordsAddNoDenyAllMarker() {
        XKeyDatabase.migration12To13 { emptyMap() }.migrate(db)

        assertTrue(statements.none { it.startsWith("UPDATE `key_policies` SET") })
    }
}
