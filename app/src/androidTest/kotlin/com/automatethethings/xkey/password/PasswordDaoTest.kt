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
import org.junit.Assert.assertFalse
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
        id: Long = 0,
        folderPath: String? = "/work",
        expiresAt: String? = null,
        shared: Boolean = false,
        tenantId: String = PasswordEntity.DEFAULT_TENANT
    ) = PasswordEntity(
        id = id,
        passwordId = passwordId,
        name = name,
        title = "$name Login",
        username = username,
        passwordEncrypted = ciphertext,
        url = "https://example.com",
        notes = null,
        folderPath = folderPath,
        source = source,
        createdAt = now,
        updatedAt = now,
        expiresAt = expiresAt,
        shared = shared,
        tenantId = tenantId
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
    fun insertIfAbsent_addsANewEntry() = runBlocking {
        val rowId = dao.insertIfAbsent(password("pw-1"))

        assertTrue(rowId > 0)
        assertEquals(rowId, dao.getByPasswordId("pw-1")!!.id)
    }

    @Test
    fun insertIfAbsent_leavesAnExistingEntryWithTheSamePasswordIdAlone() = runBlocking {
        dao.insert(password("pw-1", name = "Original", expiresAt = "2030-01-01T00:00:00Z"))
        val before = dao.getByPasswordId("pw-1")!!

        assertEquals(-1L, dao.insertIfAbsent(password("pw-1", name = "Synced")))

        assertEquals(1, dao.count())
        val after = dao.getByPasswordId("pw-1")!!
        assertEquals(before.id, after.id)
        assertEquals("Original", after.name)
        assertEquals("2030-01-01T00:00:00Z", after.expiresAt)
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
    fun update_changesTheRowInPlaceAndCountsIt() = runBlocking {
        val id = dao.insert(password("pw-1", name = "Original"))

        val changed = dao.update(password("pw-1", name = "Updated", id = id))

        assertEquals(1, changed)
        assertEquals(1, dao.count())
        assertEquals("Updated", dao.getByPasswordId("pw-1")!!.name)
    }

    @Test
    fun update_ofADeletedRowChangesNothingAndNeverRecreatesIt() = runBlocking {
        dao.insert(password("pw-1"))
        val read = dao.getByPasswordId("pw-1")!!
        dao.deleteByPasswordId("pw-1")

        val changed = dao.update(read.copy(name = "Updated"))

        assertEquals(0, changed)
        assertNull(dao.getByPasswordId("pw-1"))
        assertEquals(0, dao.count())
    }

    private suspend fun updateFieldsIfUnchanged(read: PasswordEntity, notes: String) =
        dao.updateFieldsIfUnchanged(
            id = read.id,
            expectedPasswordEncrypted = read.passwordEncrypted,
            expectedName = read.name,
            expectedTitle = read.title,
            expectedUsername = read.username,
            expectedUrl = read.url,
            expectedNotes = read.notes,
            expectedFolderPath = read.folderPath,
            expectedSource = read.source,
            expectedCreatedAt = read.createdAt,
            expectedUpdatedAt = read.updatedAt,
            expectedExpiresAt = read.expiresAt,
            expectedShared = read.shared,
            expectedTenantId = read.tenantId,
            name = read.name,
            title = read.title,
            username = read.username,
            passwordEncrypted = read.passwordEncrypted,
            url = read.url,
            notes = notes,
            folderPath = read.folderPath,
            source = read.source,
            expiresAt = read.expiresAt,
            updatedAt = read.updatedAt + 1
        )

    @Test
    fun updateFieldsIfUnchanged_writesTheRowWhileEveryColumnIsTheOneRead() = runBlocking {
        // Null notes: the guard must match a NULL column it read.
        dao.insert(password("pw-1", ciphertext = byteArrayOf(1, 2, 3)))
        val read = dao.getByPasswordId("pw-1")!!

        val changed = updateFieldsIfUnchanged(read, notes = "rotated")

        assertEquals(1, changed)
        val written = dao.getByPasswordId("pw-1")!!
        assertEquals("rotated", written.notes)
        assertEquals(read.updatedAt + 1, written.updatedAt)
        assertEquals(read.createdAt, written.createdAt)
        assertEquals(1, dao.count())
    }

    @Test
    fun updateFieldsIfUnchanged_ofAReplacedRowChangesNothing() = runBlocking {
        dao.insert(password("pw-1", ciphertext = byteArrayOf(1, 2, 3)))
        val read = dao.getByPasswordId("pw-1")!!
        // A sync replaces the password, keeping the row id, after the read.
        dao.insert(password("pw-1", ciphertext = byteArrayOf(4, 5, 6), id = read.id))

        val changed = updateFieldsIfUnchanged(read, notes = "rotated")

        assertEquals(0, changed)
        val stored = dao.getByPasswordId("pw-1")!!
        assertTrue(stored.passwordEncrypted.contentEquals(byteArrayOf(4, 5, 6)))
        assertNull(stored.notes)
    }

    @Test
    fun updateFieldsIfUnchanged_ofARowWhoseOtherFieldChangedChangesNothing() = runBlocking {
        dao.insert(password("pw-1", ciphertext = byteArrayOf(1, 2, 3)))
        val read = dao.getByPasswordId("pw-1")!!
        // Another update changes the URL alone, keeping the ciphertext, after the read.
        dao.update(read.copy(url = "https://other.example"))

        val changed = updateFieldsIfUnchanged(read, notes = "rotated")

        assertEquals(0, changed)
        val stored = dao.getByPasswordId("pw-1")!!
        assertEquals("https://other.example", stored.url)
        assertNull(stored.notes)
    }

    @Test
    fun updateFieldsIfUnchanged_ofADeletedRowChangesNothingAndNeverRecreatesIt() = runBlocking {
        dao.insert(password("pw-1"))
        val read = dao.getByPasswordId("pw-1")!!
        dao.deleteByPasswordId("pw-1")

        val changed = updateFieldsIfUnchanged(read, notes = "rotated")

        assertEquals(0, changed)
        assertEquals(0, dao.count())
    }

    @Test
    fun updateFieldsIfUnchanged_ofARowWhosePolicyChangedChangesNothing() = runBlocking {
        dao.insert(password("pw-1"))
        val read = dao.getByPasswordId("pw-1")!!

        dao.update(read.copy(expiresAt = "2027-01-02T03:04:05Z"))
        assertEquals(0, updateFieldsIfUnchanged(read, notes = "rotated"))
        dao.update(read.copy(shared = true))
        assertEquals(0, updateFieldsIfUnchanged(read, notes = "rotated"))
        dao.update(read.copy(tenantId = "acme"))
        assertEquals(0, updateFieldsIfUnchanged(read, notes = "rotated"))

        assertNull(dao.getByPasswordId("pw-1")!!.notes)
    }

    @Test
    fun updateFieldsIfUnchanged_setsTheExpiryAndSourceAndKeepsTenantAndSharing() = runBlocking {
        dao.insert(password("pw-1", shared = true, tenantId = "acme"))
        val read = dao.getByPasswordId("pw-1")!!

        val changed = dao.updateFieldsIfUnchanged(
            id = read.id,
            expectedPasswordEncrypted = read.passwordEncrypted,
            expectedName = read.name,
            expectedTitle = read.title,
            expectedUsername = read.username,
            expectedUrl = read.url,
            expectedNotes = read.notes,
            expectedFolderPath = read.folderPath,
            expectedSource = read.source,
            expectedCreatedAt = read.createdAt,
            expectedUpdatedAt = read.updatedAt,
            expectedExpiresAt = read.expiresAt,
            expectedShared = read.shared,
            expectedTenantId = read.tenantId,
            name = read.name,
            title = read.title,
            username = read.username,
            passwordEncrypted = read.passwordEncrypted,
            url = read.url,
            notes = read.notes,
            folderPath = read.folderPath,
            source = "remote",
            expiresAt = "2027-01-02T03:04:05Z",
            updatedAt = read.updatedAt + 1
        )

        assertEquals(1, changed)
        val written = dao.getByPasswordId("pw-1")!!
        assertEquals("2027-01-02T03:04:05Z", written.expiresAt)
        assertEquals("remote", written.source)
        assertTrue(written.shared)
        assertEquals("acme", written.tenantId)
    }

    // -------------------------------------------------------------------------
    // Tenant and scope
    // -------------------------------------------------------------------------

    @Test
    fun insert_roundTripsThePolicyColumns() = runBlocking {
        dao.insert(password("pw-1", expiresAt = "2027-01-02T03:04:05Z", shared = true, tenantId = "acme"))

        val stored = dao.getByPasswordId("pw-1")!!
        assertEquals("2027-01-02T03:04:05Z", stored.expiresAt)
        assertTrue(stored.shared)
        assertEquals("acme", stored.tenantId)
    }

    @Test
    fun insert_defaultsThePolicyColumns() = runBlocking {
        dao.insert(password("pw-1"))

        val stored = dao.getByPasswordId("pw-1")!!
        assertNull(stored.expiresAt)
        assertFalse(stored.shared)
        assertEquals(PasswordEntity.DEFAULT_TENANT, stored.tenantId)
    }

    @Test
    fun getByPasswordIdInTenant_findsOnlyTheNamedTenantsEntry() = runBlocking {
        dao.insert(password("pw-1", tenantId = "acme"))

        assertEquals("pw-1", dao.getByPasswordIdInTenant("pw-1", "acme")!!.passwordId)
        assertNull(dao.getByPasswordIdInTenant("pw-1", "globex"))
        assertNull(dao.getByPasswordIdInTenant("pw-1", PasswordEntity.DEFAULT_TENANT))
        assertNull(dao.getByPasswordIdInTenant("pw-missing", "acme"))
    }

    @Test
    fun deleteByPasswordIdInTenant_leavesAnotherTenantsEntry() = runBlocking {
        dao.insert(password("pw-1", tenantId = "acme"))

        assertEquals(0, dao.deleteByPasswordIdInTenant("pw-1", "globex"))
        assertEquals(1, dao.count())
        assertEquals(1, dao.deleteByPasswordIdInTenant("pw-1", "acme"))
        assertEquals(0, dao.count())
    }

    @Test
    fun deleteByPasswordId_countsTheRowsItDeletes() = runBlocking {
        dao.insert(password("pw-1", tenantId = "acme"))

        assertEquals(0, dao.deleteByPasswordId("pw-missing"))
        assertEquals(1, dao.deleteByPasswordId("pw-1"))
    }

    private suspend fun listed(tenantId: String, shared: Boolean?, folderPath: String? = null) =
        dao.getForListing(tenantId, shared, folderPath).map { it.passwordId }

    private suspend fun insertMixedEntries() {
        dao.insert(password("a-personal", name = "A"))
        dao.insert(password("b-shared", name = "B", shared = true))
        dao.insert(password("c-personal", name = "C", folderPath = "/home"))
        dao.insert(password("d-shared", name = "D", shared = true, folderPath = "/home"))
        dao.insert(password("e-acme", name = "E", shared = true, tenantId = "acme"))
    }

    @Test
    fun getForListing_filtersByScopeWithinTheTenant() = runBlocking {
        insertMixedEntries()

        assertEquals(listOf("a-personal", "c-personal"), listed("", shared = false))
        assertEquals(listOf("b-shared", "d-shared"), listed("", shared = true))
        assertEquals(listOf("a-personal", "b-shared", "c-personal", "d-shared"), listed("", shared = null))
    }

    @Test
    fun getForListing_neverListsAnotherTenantsEntry() = runBlocking {
        insertMixedEntries()

        assertEquals(listOf("e-acme"), listed("acme", shared = null))
        assertEquals(emptyList<String>(), listed("acme", shared = false))
        assertEquals(emptyList<String>(), listed("globex", shared = null))
    }

    @Test
    fun getForListing_filtersByFolderTogetherWithScope() = runBlocking {
        insertMixedEntries()

        assertEquals(listOf("c-personal", "d-shared"), listed("", shared = null, folderPath = "/home"))
        assertEquals(listOf("d-shared"), listed("", shared = true, folderPath = "/home"))
        assertEquals(listOf("a-personal"), listed("", shared = false, folderPath = "/work"))
    }

    @Test
    fun getForListing_ordersByNameThenUsername() = runBlocking {
        dao.insert(password("pw-1", name = "Same", username = "zed"))
        dao.insert(password("pw-2", name = "Same", username = "amy"))
        dao.insert(password("pw-3", name = "Alpha"))

        assertEquals(listOf("pw-3", "pw-2", "pw-1"), listed("", shared = null))
    }

    // -------------------------------------------------------------------------
    // Counts
    // -------------------------------------------------------------------------

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
