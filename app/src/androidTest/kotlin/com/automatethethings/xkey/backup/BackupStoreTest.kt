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
 * `Context`. Its one piece of real logic is [BackupStore.store]'s filename
 * sanitiser: the backup id arrives over the pairing channel from the desktop,
 * so anything it can put in a path — separators, `..`, a leading dot — must be
 * neutralised before it reaches the filesystem. That is asserted directly by
 * writing hostile ids and checking that nothing lands outside the backups
 * directory.
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
    fun store_acceptsAnEmptyBlob() {
        val id = store("empty-$runId", ByteArray(0))

        assertEquals(0, store.load(id)!!.size)
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
    // Filename sanitising
    // -------------------------------------------------------------------------

    @Test
    fun store_neutralisesPathSeparatorsInTheBackupId() {
        val hostile = "..%2Fescape/$runId".replace("%2F", "/")
        val id = store(hostile, byteArrayOf(9))

        // The id is returned verbatim, but the file lands inside the backups
        // directory under a flattened name.
        assertEquals(hostile, id)
        assertTrue(File(backupsDir, sanitised(hostile)).exists())
        assertTrue(store.load(hostile)!!.contentEquals(byteArrayOf(9)))
    }

    @Test
    fun store_doesNotEscapeTheBackupsDirectory() {
        val hostile = "../escaped-$runId"
        store(hostile, byteArrayOf(9))

        assertTrue(
            "a traversal id must not write next to the backups directory",
            File(filesDir, "escaped-$runId").exists().not()
        )
    }

    /**
     * Two ids that differ only in punctuation are two backups. They used to
     * collapse onto one file and overwrite each other, while `store()` returned
     * distinct ids for what was now the same blob.
     */
    @Test
    fun store_keepsTwoIdsThatDifferOnlyInPunctuationApart() {
        val first = "collide/a-$runId"
        val second = "collide\\a-$runId"

        store(first, byteArrayOf(1))
        store(second, byteArrayOf(2))

        assertTrue(store.load(first)!!.contentEquals(byteArrayOf(1)))
        assertTrue(store.load(second)!!.contentEquals(byteArrayOf(2)))
    }

    /** A lookup answers for the id that was stored, and only that id. */
    @Test
    fun load_answersForTheExactIdThatWasStored() {
        val id = "space id $runId"
        store(id, byteArrayOf(4))

        assertTrue(store.load(id)!!.contentEquals(byteArrayOf(4)))
        assertNull(
            "a mangled spelling is a different id and must not resolve",
            store.load("space_id_$runId")
        )
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

    /** `latestId` returns the id the peer actually sent, so it round-trips. */
    @Test
    fun latestId_returnsTheIdThePeerSent() {
        val id = store("latest-$runId", byteArrayOf(1))

        assertEquals(id, store.latestId())
        assertTrue(File(backupsDir, sanitised(id)).exists())
        assertTrue(store.load(store.latestId()!!)!!.contentEquals(byteArrayOf(1)))
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
