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
package com.automatethethings.xkey.backup

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * Instrumented tests for [BackupStore].
 *
 * The store writes into the app's private `filesDir`, so it needs a real
 * `Context`. This suite covers the round trip, generated ids and metadata;
 * how hostile or colliding ids are named on disk is in
 * [BackupStoreIdentityTest].
 *
 * Every file this suite creates is removed in `@After`, and ids are suffixed
 * with a per-run nonce so a leftover file can never satisfy a later assertion.
 */
@RunWith(AndroidJUnit4::class)
class BackupStoreTest {

    private lateinit var context: Context
    private lateinit var store: BackupStore
    private lateinit var backupsDir: File
    private lateinit var filesDir: File

    /** Unique per run so ids never collide with a previous run's leftovers. */
    private val runId = System.nanoTime().toString()

    private val writtenNames = mutableSetOf<String>()

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        store = BackupStore(context)
        filesDir = context.filesDir
        backupsDir = File(filesDir, "backups")
    }

    @After
    fun tearDown() {
        // Remove only what this run created, so a concurrently stored backup
        // belonging to the app is never destroyed.
        for (name in writtenNames) {
            File(backupsDir, name).delete()
            File(filesDir, name).delete()
        }
        writtenNames.clear()
    }

    /** Stores [data] under [backupId] and remembers the sanitised name for cleanup. */
    private fun store(backupId: String, data: ByteArray): String {
        val id = store.store(backupId, data)
        writtenNames += sanitised(id)
        return id
    }

    /**
     * The on-disk name for [id]: a SHA-256 digest, not a mangled id. The old
     * `[^A-Za-z0-9._-] -> _` scheme collapsed `a/b` and `a\b` onto one file,
     * so two distinct ids silently overwrote each other while `store()` handed
     * back two distinct ids.
     */
    private fun sanitised(id: String): String =
        java.security.MessageDigest.getInstance("SHA-256")
            .digest(id.toByteArray())
            .joinToString("") { "%02x".format(it) } + ".backup"

    // -------------------------------------------------------------------------
    // Round trip
    // -------------------------------------------------------------------------

    @Test
    fun store_thenLoad_returnsTheSameBytes() {
        val blob = byteArrayOf(1, 2, 3, 4, 5)
        val id = store("backup-$runId", blob)

        assertEquals("backup-$runId", id)
        assertTrue(store.load(id)!!.contentEquals(blob))
    }

    @Test
    fun store_treatsTheBlobAsOpaqueAndKeepsItByteForByte() {
        // Every byte value must survive; the phone never parses the blob.
        val blob = ByteArray(256) { it.toByte() }
        val id = store("opaque-$runId", blob)

        assertTrue(store.load(id)!!.contentEquals(blob))
    }

    @Test
    fun store_overwritesAPreviousBlobWithTheSameId() {
        val id = store("overwrite-$runId", byteArrayOf(1, 1, 1, 1))
        store(id, byteArrayOf(2, 2))

        val loaded = store.load(id)!!
        assertEquals(2, loaded.size)
        assertTrue(loaded.contentEquals(byteArrayOf(2, 2)))
    }

    @Test
    fun load_returnsNullForAnUnknownId() {
        assertNull(store.load("never-stored-$runId"))
    }

    @Test
    fun aSecondStoreInstanceSeesTheSameBlobs() {
        val id = store("shared-$runId", byteArrayOf(7, 7, 7))

        assertTrue(BackupStore(context).load(id)!!.contentEquals(byteArrayOf(7, 7, 7)))
    }

    // -------------------------------------------------------------------------
    // Generated ids
    // -------------------------------------------------------------------------

    @Test
    fun store_generatesATimestampIdForABlankBackupId() {
        val id = store.store("", byteArrayOf(1))
        writtenNames += sanitised(id)

        assertTrue(id.startsWith("backup-"))
        assertNotNull(store.load(id))
    }

    @Test
    fun store_generatesAnIdForAWhitespaceOnlyBackupId() {
        val id = store.store("   ", byteArrayOf(1))
        writtenNames += sanitised(id)

        assertTrue(id.startsWith("backup-"))
    }

    // -------------------------------------------------------------------------
    // Metadata
    // -------------------------------------------------------------------------

    @Test
    fun createdAtMillis_reportsAPlausibleTimeForAStoredBlob() {
        val before = System.currentTimeMillis()
        val id = store("timed-$runId", byteArrayOf(1))
        val after = System.currentTimeMillis()

        val created = store.createdAtMillis(id)
        assertTrue(created > 0L)
        // Filesystem timestamps can be coarse, so allow a second of slack.
        assertTrue(created in (before - 1000)..(after + 1000))
    }

    @Test
    fun createdAtMillis_isZeroForAnUnknownId() {
        assertEquals(0L, store.createdAtMillis("never-stored-$runId"))
    }

    @Test
    fun latestId_prefersTheMostRecentlyModifiedFile() {
        val older = store("older-$runId", byteArrayOf(1))
        val newer = store("newer-$runId", byteArrayOf(2))

        // Force an unambiguous ordering rather than depending on clock
        // granularity between two writes in the same millisecond.
        File(backupsDir, sanitised(older)).setLastModified(1_600_000_000_000L)
        File(backupsDir, sanitised(newer)).setLastModified(System.currentTimeMillis())

        assertEquals(newer, store.latestId())
    }
}
