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
package com.automatethethings.xkey.password

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.storage.XKeyDatabase
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented tests for [PasswordDao].
 *
 * The DAO's behaviour is SQL, not Kotlin, so it can only be proved against a
 * real SQLite instance. Two properties carry real weight here: `password_id` is
 * a unique index paired with `OnConflictStrategy.REPLACE`, which is what makes a
 * repeated sync from the desktop an *update* rather than a growing pile of
 * duplicates; and the ordering clause is `name, username`, which is what the
 * password list renders in.
 *
 * The database is always **in-memory**, so nothing touches the shared on-device
 * `passwords` table and there is no state to clean up beyond closing it.
 */
@RunWith(AndroidJUnit4::class)
class PasswordDaoTest {

    private lateinit var database: XKeyDatabase
    private lateinit var dao: PasswordDao

    private val now = System.currentTimeMillis()

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        database = Room.inMemoryDatabaseBuilder(context, XKeyDatabase::class.java).build()
        dao = database.passwordDao()
    }

    @After
    fun tearDown() {
        database.close()
    }

    private fun password(
        passwordId: String,
        name: String = "Example",
        username: String? = "user@example.com",
        source: String = "local",
        ciphertext: ByteArray = byteArrayOf(1, 2, 3),
        id: Long = 0
    ) = PasswordEntity(
        id = id,
        passwordId = passwordId,
        name = name,
        title = "$name Login",
        username = username,
        passwordEncrypted = ciphertext,
        url = "https://example.com",
        notes = null,
        folderPath = "/work",
        source = source,
        createdAt = now,
        updatedAt = now
    )

    // -------------------------------------------------------------------------
    // Insert and read back
    // -------------------------------------------------------------------------

    @Test
    fun insert_returnsTheAssignedRowId() = runBlocking {
        val rowId = dao.insert(password("pw-1"))

        assertTrue(rowId > 0)
    }

    @Test
    fun insert_roundTripsEveryColumn() = runBlocking {
        dao.insert(password("pw-1", ciphertext = byteArrayOf(9, 8, 7)))

        val stored = dao.getByPasswordId("pw-1")!!
        assertEquals("pw-1", stored.passwordId)
        assertEquals("Example", stored.name)
        assertEquals("Example Login", stored.title)
        assertEquals("user@example.com", stored.username)
        assertEquals("https://example.com", stored.url)
        assertNull(stored.notes)
        assertEquals("/work", stored.folderPath)
        assertEquals("local", stored.source)
        assertEquals(now, stored.createdAt)
        assertEquals(now, stored.updatedAt)
        assertTrue(stored.passwordEncrypted.contentEquals(byteArrayOf(9, 8, 7)))
    }

    @Test
    fun insert_acceptsARowWhoseOptionalFieldsAreAllNull() = runBlocking {
        dao.insert(
            PasswordEntity(
                passwordId = "pw-sparse",
                name = "Sparse",
                passwordEncrypted = byteArrayOf(0),
                createdAt = now,
                updatedAt = now
            )
        )

        val stored = dao.getByPasswordId("pw-sparse")!!
        assertNull(stored.title)
        assertNull(stored.username)
        assertNull(stored.url)
        assertNull(stored.notes)
        assertNull(stored.folderPath)
    }

    @Test
    fun getByPasswordId_returnsNullForAnUnknownId() = runBlocking {
        dao.insert(password("pw-1"))

        assertNull(dao.getByPasswordId("pw-missing"))
    }

    // -------------------------------------------------------------------------
    // Conflict handling
    // -------------------------------------------------------------------------

    @Test
    fun insert_replacesAnExistingEntryWithTheSamePasswordId() = runBlocking {
        val first = dao.insert(password("pw-1", name = "Original"))
        dao.insert(password("pw-1", name = "Updated", id = first))

        assertEquals(1, dao.count())
        assertEquals("Updated", dao.getByPasswordId("pw-1")!!.name)
    }

    @Test
    fun insert_replacingWithRowIdZeroStillLeavesASingleRow() = runBlocking {
        // A repository that does not look up the existing row first passes id=0;
        // the unique index on password_id must still collapse the two.
        dao.insert(password("pw-1", name = "Original"))
        dao.insert(password("pw-1", name = "Updated"))

        assertEquals(1, dao.count())
        assertEquals("Updated", dao.getByPasswordId("pw-1")!!.name)
    }

    @Test
    fun insert_keepsEntriesWithDistinctPasswordIdsApart() = runBlocking {
        dao.insert(password("pw-1"))
        dao.insert(password("pw-2"))

        assertEquals(2, dao.count())
    }

    // -------------------------------------------------------------------------
    // Listing and ordering
    // -------------------------------------------------------------------------

    @Test
    fun getAll_isEmptyForAFreshStore() = runBlocking {
        assertTrue(dao.getAll().isEmpty())
    }

    @Test
    fun getAll_ordersByNameThenUsername() = runBlocking {
        dao.insert(password("pw-3", name = "Zulu", username = "a@example.com"))
        dao.insert(password("pw-2", name = "Alpha", username = "b@example.com"))
        dao.insert(password("pw-1", name = "Alpha", username = "a@example.com"))

        assertEquals(listOf("pw-1", "pw-2", "pw-3"), dao.getAll().map { it.passwordId })
    }

    @Test
    fun getAll_sortsARowWithNoUsernameFirstWithinItsName() = runBlocking {
        dao.insert(password("pw-named", name = "Alpha", username = "a@example.com"))
        dao.insert(password("pw-anon", name = "Alpha", username = null))

        assertEquals(listOf("pw-anon", "pw-named"), dao.getAll().map { it.passwordId })
    }

    @Test
    fun observeAll_emitsTheCurrentContentsAndTheSameOrdering() = runBlocking {
        dao.insert(password("pw-2", name = "Bravo"))
        dao.insert(password("pw-1", name = "Alpha"))

        assertEquals(listOf("pw-1", "pw-2"), dao.observeAll().first().map { it.passwordId })
    }

    @Test
    fun observeAll_emitsAnEmptyListForAFreshStore() = runBlocking {
        assertTrue(dao.observeAll().first().isEmpty())
    }

    // -------------------------------------------------------------------------
    // Source filtering
    // -------------------------------------------------------------------------

    @Test
    fun getBySource_returnsOnlyTheMatchingOrigin() = runBlocking {
        dao.insert(password("pw-local", source = "local"))
        dao.insert(password("pw-remote", source = "remote"))

        assertEquals(listOf("pw-local"), dao.getBySource("local").map { it.passwordId })
        assertEquals(listOf("pw-remote"), dao.getBySource("remote").map { it.passwordId })
    }

    @Test
    fun getBySource_isEmptyForAnUnusedOrigin() = runBlocking {
        dao.insert(password("pw-local", source = "local"))

        assertTrue(dao.getBySource("imported").isEmpty())
    }

    @Test
    fun getBySource_matchesTheTokenExactly() = runBlocking {
        dao.insert(password("pw-local", source = "local"))

        assertTrue(dao.getBySource("LOCAL").isEmpty())
    }

    // -------------------------------------------------------------------------
    // Delete
    // -------------------------------------------------------------------------

    @Test
    fun deleteByPasswordId_removesOnlyTheNamedEntry() = runBlocking {
        dao.insert(password("pw-1"))
        dao.insert(password("pw-2"))

        dao.deleteByPasswordId("pw-1")

        assertNull(dao.getByPasswordId("pw-1"))
        assertEquals(1, dao.count())
    }

    @Test
    fun deleteByPasswordId_isSilentForAnUnknownId() = runBlocking {
        dao.insert(password("pw-1"))

        dao.deleteByPasswordId("pw-missing")

        assertEquals(1, dao.count())
    }

    // -------------------------------------------------------------------------
    // Counts
    // -------------------------------------------------------------------------

    @Test
    fun count_isZeroForAFreshStore() = runBlocking {
        assertEquals(0, dao.count())
    }

    @Test
    fun count_tracksInsertsAndDeletes() = runBlocking {
        dao.insert(password("pw-1"))
        dao.insert(password("pw-2"))
        assertEquals(2, dao.count())

        dao.deleteByPasswordId("pw-1")
        assertEquals(1, dao.count())
    }

    @Test
    fun observeCount_emitsTheCurrentTotal() = runBlocking {
        assertEquals(0, dao.observeCount().first())

        dao.insert(password("pw-1"))

        assertEquals(1, dao.observeCount().first())
    }
}
