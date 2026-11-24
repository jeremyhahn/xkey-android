// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under AGPL-3.0 (see LICENSE) or a commercial license.

package com.automatethethings.xkey.sync

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.password.PasswordRepository
import com.automatethethings.xkey.storage.XKeyDatabase
import kotlinx.coroutines.runBlocking
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented tests for [SyncEngine] gather/merge round-trips against the real
 * Room database. Exercises the password path (no external material needed);
 * trust-store and OATH share the same engine plumbing.
 */
@RunWith(AndroidJUnit4::class)
class SyncEngineTest {

    private val pwId = "sync-test-${System.nanoTime()}"
    private val oathId = "sync-test-oath-${System.nanoTime()}"
    private lateinit var engine: SyncEngine
    private lateinit var passwordRepo: PasswordRepository

    @Before
    fun setUp() {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        engine = SyncEngine(ctx)
        passwordRepo = PasswordRepository(XKeyDatabase.getInstance(ctx).passwordDao())
    }

    @After
    fun tearDown() = runBlocking<Unit> {
        passwordRepo.delete(pwId)
        XKeyDatabase.getInstance(ApplicationProvider.getApplicationContext<Context>())
            .oathCredentialDao().deleteByOathId(oathId)
    }

    @Test
    fun passwordMergeThenGatherRoundTrip() = runBlocking {
        val incoming = JSONArray().put(
            JSONObject().apply {
                put("id", pwId)
                put("name", "Sync Test")
                put("username", "user@example.com")
                put("password", "s3cr3t-pw")
                put("updated_at", "2026-01-01T00:00:00Z")
            }
        )

        val counts = engine.mergePasswords(incoming)
        assertEquals(1, counts.added)

        val gathered = engine.gatherPasswords()
        var found = false
        for (i in 0 until gathered.length()) {
            val obj = gathered.getJSONObject(i)
            if (obj.getString("id") == pwId) {
                found = true
                assertEquals("s3cr3t-pw", obj.getString("password"))
                assertEquals("user@example.com", obj.getString("username"))
            }
        }
        assertTrue("gathered passwords should include the merged entry", found)
    }

    @Test
    fun reMergeUpdatesInsteadOfDuplicating() = runBlocking {
        fun entry(pw: String, at: String) = JSONArray().put(
            JSONObject().apply {
                put("id", pwId)
                put("name", "Sync Test")
                put("password", pw)
                put("updated_at", at)
            }
        )
        assertEquals(1, engine.mergePasswords(entry("first", "2026-01-01T00:00:00Z")).added)
        val second = engine.mergePasswords(entry("second", "2026-01-02T00:00:00Z"))
        assertEquals(0, second.added)
        assertEquals(1, second.updated)
        assertEquals("second", passwordRepo.get(pwId)?.password)
    }

    @Test
    fun reMergeOfAnOlderPasswordKeepsTheLocalEntry() = runBlocking {
        fun entry(pw: String, at: String) = JSONArray().put(
            JSONObject().apply {
                put("id", pwId)
                put("name", "Sync Test")
                put("password", pw)
                put("updated_at", at)
            }
        )
        assertEquals(1, engine.mergePasswords(entry("newer", "2026-01-02T00:00:00Z")).added)
        val second = engine.mergePasswords(entry("older", "2026-01-01T00:00:00Z"))
        assertEquals(SyncEngine.ItemCounts(added = 0, updated = 0, skipped = 1), second)
        assertEquals("newer", passwordRepo.get(pwId)?.password)
    }

    @Test
    fun reMergeOfTheSameOathPayloadUpdatesInPlace() = runBlocking {
        val dao = XKeyDatabase.getInstance(ApplicationProvider.getApplicationContext<Context>()).oathCredentialDao()
        fun payload(counter: Long) = JSONArray().put(
            JSONObject().apply {
                put("id", oathId)
                put("name", oathId)
                put("issuer", "Sync Test")
                put("account_name", "user@example.com")
                put("secret", "JBSWY3DPEHPK3PXP")
                put("type", "hotp")
                put("counter", counter)
            }
        )
        val rowsBefore = dao.count()

        assertEquals(SyncEngine.ItemCounts(added = 1, updated = 0, skipped = 0), engine.mergeOath(payload(5)))
        val first = dao.getByOathId(oathId)!!
        assertEquals(SyncEngine.ItemCounts(added = 0, updated = 1, skipped = 0), engine.mergeOath(payload(5)))
        assertEquals(SyncEngine.ItemCounts(added = 0, updated = 1, skipped = 0), engine.mergeOath(payload(9)))

        assertEquals(rowsBefore + 1, dao.count())
        val row = dao.getByOathId(oathId)!!
        assertEquals(oathId, row.oathId)
        assertEquals(first.id, row.id)
        assertEquals(first.createdAt, row.createdAt)
        assertEquals(9L, row.counter)

        // A peer behind this one never rewinds the counter.
        engine.mergeOath(payload(2))
        assertEquals(9L, dao.getByOathId(oathId)!!.counter)
    }
}
