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
import com.automatethethings.xkey.crypto.SyncCodec
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * Instrumented tests for how [BackupStore] names what it stores.
 *
 * The backup id arrives over the pairing channel from the desktop, and the
 * store used to derive a filename from it by replacing every character outside
 * `[A-Za-z0-9._-]` with `_`. Two problems followed from that, and they are what
 * this suite pins down:
 *
 * - The mapping is not injective. `a/b` and `a\b` — and any pair differing only
 *   in punctuation — collapsed onto one file, so storing the second destroyed
 *   the first while both calls reported distinct ids back to the peer.
 * - The mapping is not reversible, yet [BackupStore.latestId] returned a
 *   filename. The desktop was handed a mangled id it had never sent, and passing
 *   it back could name a different backup than the one just described.
 *
 * A digest filename fixes both: it is injective, and because it cannot be
 * inverted the id itself is written into the record.
 *
 * Files are created under the app's real `filesDir`, so every test cleans up the
 * exact records it wrote and ids carry a per-run nonce.
 */
@RunWith(AndroidJUnit4::class)
class BackupStoreIdentityTest {

    private lateinit var context: Context
    private lateinit var store: BackupStore
    private lateinit var backupsDir: File

    /** Unique per run so a leftover file can never satisfy an assertion. */
    private val runId = System.nanoTime().toString()

    private val storedIds = mutableSetOf<String>()

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        store = BackupStore(context)
        backupsDir = File(context.filesDir, "backups")
    }

    @After
    fun tearDown() {
        for (id in storedIds) {
            recordFor(id).delete()
            // A test that failed before migration ran can leave the old-style
            // file behind.
            File(backupsDir, id).delete()
        }
        storedIds.clear()
    }

    private fun store(backupId: String, data: ByteArray): String {
        storedIds += backupId
        val id = store.store(backupId, data)
        storedIds += id
        return id
    }

    /** The file [BackupStore] writes for [id]. */
    private fun recordFor(id: String): File =
        File(backupsDir, "${SyncCodec.sha256Hex(id.toByteArray(Charsets.UTF_8))}.backup")

    // -------------------------------------------------------------------------
    // Distinct ids stay distinct
    // -------------------------------------------------------------------------

    @Test
    fun store_keepsApartTwoIdsThatDifferOnlyInPunctuation() {
        val slash = "collide/a-$runId"
        val backslash = "collide\\a-$runId"

        store(slash, byteArrayOf(1))
        store(backslash, byteArrayOf(2))

        assertTrue("the first blob must survive the second", store.load(slash)!!.contentEquals(byteArrayOf(1)))
        assertTrue(store.load(backslash)!!.contentEquals(byteArrayOf(2)))
    }

    @Test
    fun store_keepsApartIdsSeparatedByAnyPunctuation() {
        // Colons, spaces, and dots are all flattened to '_' by a character
        // sanitiser; none of them may merge two backups.
        val ids = listOf("dup:a-$runId", "dup a-$runId", "dup;a-$runId", "dup=a-$runId")

        ids.forEachIndexed { index, id -> store(id, byteArrayOf(index.toByte())) }

        ids.forEachIndexed { index, id ->
            assertTrue(
                "'$id' must keep its own blob",
                store.load(id)!!.contentEquals(byteArrayOf(index.toByte()))
            )
        }
    }

    @Test
    fun load_doesNotAnswerToAMangledSpellingOfTheId() {
        val id = "space id $runId"
        store(id, byteArrayOf(4))

        assertTrue(store.load(id)!!.contentEquals(byteArrayOf(4)))
        assertNull("only the id the peer sent may resolve", store.load("space_id_$runId"))
    }

    @Test
    fun store_writesNothingOutsideTheBackupsDirectory() {
        val hostile = "../escaped-$runId"
        store(hostile, byteArrayOf(9))

        assertFalse(
            "a traversal id must not write next to the backups directory",
            File(context.filesDir, "escaped-$runId").exists()
        )
        assertTrue(recordFor(hostile).exists())
        assertTrue(store.load(hostile)!!.contentEquals(byteArrayOf(9)))
    }

    // -------------------------------------------------------------------------
    // The id the peer sent comes back
    // -------------------------------------------------------------------------

    @Test
    fun latestId_returnsTheIdThePeerSentRatherThanAFileName() {
        val id = "desktop backup/2026 $runId"
        store(id, byteArrayOf(1, 2, 3))

        assertEquals(id, store.latestId())
    }

    @Test
    fun anEmptyBlobIsStillARecord() {
        val id = "empty-$runId"
        store(id, ByteArray(0))

        assertEquals(0, store.load(id)!!.size)
        assertEquals(id, store.latestId())
    }

    // -------------------------------------------------------------------------
    // Blobs written by an older build
    // -------------------------------------------------------------------------

    @Test
    fun aBlobFromAnOlderBuildIsStillReadableUnderItsId() {
        val id = "legacy-backup-$runId"
        storedIds += id
        backupsDir.mkdirs()
        File(backupsDir, id).writeBytes(byteArrayOf(7, 7, 7))

        val loaded = BackupStore(context).load(id)

        assertTrue("an existing blob must not become unreachable", loaded!!.contentEquals(byteArrayOf(7, 7, 7)))
    }

    @Test
    fun aBlobFromAnOlderBuildIsRewrittenAsARecord() {
        val id = "legacy-record-$runId"
        storedIds += id
        backupsDir.mkdirs()
        File(backupsDir, id).writeBytes(byteArrayOf(8))

        val migrating = BackupStore(context)
        assertEquals("the file name is the only id an old blob carries", id, migrating.latestId())
        assertFalse("the old file is replaced, not duplicated", File(backupsDir, id).exists())
        assertTrue(recordFor(id).exists())
    }
}
