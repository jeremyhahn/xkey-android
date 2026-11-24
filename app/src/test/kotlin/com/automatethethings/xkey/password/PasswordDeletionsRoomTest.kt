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
package com.automatethethings.xkey.password

import android.app.Application
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.automatethethings.xkey.crypto.KeystoreAeadCipher
import com.automatethethings.xkey.storage.XKeyDatabase
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * The `password_deletions` queries against Room's real SQL on an in-memory
 * [XKeyDatabase]: which deletion records a prune drops, how a record moves
 * forward, and how a record holds back a synced copy until it is pruned.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34], application = Application::class)
class PasswordDeletionsRoomTest {

    private lateinit var database: XKeyDatabase
    private lateinit var dao: PasswordDao

    private val marker: Byte = 0x7f

    @Before
    fun setUp() {
        database = Room.inMemoryDatabaseBuilder(ApplicationProvider.getApplicationContext(), XKeyDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        dao = database.passwordDao()
    }

    @After
    fun tearDown() = database.close()

    /** A cipher that prepends [marker], so no plaintext reaches the database. */
    private fun markerCipher(): KeystoreAeadCipher = mockk<KeystoreAeadCipher>().also { cipher ->
        every { cipher.encrypt(any()) } answers { byteArrayOf(marker) + firstArg<ByteArray>() }
        every { cipher.decrypt(any()) } answers {
            firstArg<ByteArray>().copyOfRange(1, firstArg<ByteArray>().size)
        }
    }

    private fun entity(passwordId: String, tenantId: String = PasswordEntity.DEFAULT_TENANT) = PasswordEntity(
        passwordId = passwordId,
        name = "Example $passwordId",
        passwordEncrypted = byteArrayOf(marker, 1, 2, 3),
        createdAt = 1_000L,
        updatedAt = 1_000L,
        tenantId = tenantId
    )

    private fun record(passwordId: String, deletedAt: Long) = runBlocking {
        dao.recordDeletion(PasswordDeletionEntity(passwordId, deletedAt))
    }

    private fun deletedAt(passwordId: String): Long? = runBlocking { dao.getDeletedAt(passwordId) }

    @Test
    fun `a prune drops only the records strictly before the cutoff`() {
        val cutoff = 10_000L
        record("before", cutoff - 1)
        record("at", cutoff)
        record("after", cutoff + 1)

        val dropped = runBlocking { dao.pruneDeletionsBefore(cutoff) }

        assertEquals(1, dropped)
        assertNull(deletedAt("before"))
        assertEquals(cutoff, deletedAt("at"))
        assertEquals(cutoff + 1, deletedAt("after"))
    }

    @Test
    fun `a prune returns how many records it dropped`() {
        record("a", 1L)
        record("b", 2L)
        record("c", 3L)
        record("d", 30L)

        assertEquals(3, runBlocking { dao.pruneDeletionsBefore(10L) })
        assertEquals(0, runBlocking { dao.pruneDeletionsBefore(10L) })
        assertEquals(30L, deletedAt("d"))
    }

    @Test
    fun `a prune of an empty table drops nothing`() {
        assertEquals(0, runBlocking { dao.pruneDeletionsBefore(Long.MAX_VALUE) })
    }

    @Test
    fun `recording a deletion again moves it forward past a prune`() {
        record("pw", 100L)
        record("pw", 500L)

        assertEquals(500L, deletedAt("pw"))
        // A prune that would drop the first time keeps the later one.
        assertEquals(0, runBlocking { dao.pruneDeletionsBefore(200L) })
        assertEquals(500L, deletedAt("pw"))
    }

    @Test
    fun `a deletion is recorded only when a row went`() = runBlocking {
        assertFalse(dao.deleteAndRecordDeletion("unknown", tenantId = null, deletedAt = 5_000L))
        assertNull(dao.getDeletedAt("unknown"))

        dao.insert(entity("pw"))
        assertTrue(dao.deleteAndRecordDeletion("pw", tenantId = null, deletedAt = 5_000L))
        assertNull(dao.getByPasswordId("pw"))
        assertEquals(5_000L, dao.getDeletedAt("pw"))
    }

    @Test
    fun `a delete with a tenant removes and records only that tenant's entry`() = runBlocking {
        dao.insert(entity("pw", tenantId = "team-a"))

        assertFalse(dao.deleteAndRecordDeletion("pw", tenantId = "team-b", deletedAt = 5_000L))
        assertNotNull(dao.getByPasswordId("pw"))
        assertNull(dao.getDeletedAt("pw"))

        assertTrue(dao.deleteAndRecordDeletion("pw", tenantId = "team-a", deletedAt = 6_000L))
        assertNull(dao.getByPasswordId("pw"))
        assertEquals(6_000L, dao.getDeletedAt("pw"))
    }

    @Test
    fun `a deleted entry stays deleted until its record is pruned`() = runBlocking {
        dao.recordDeletion(PasswordDeletionEntity("pw", 5_000L))

        assertEquals(KEPT_DELETED, dao.insertIfAbsentUnlessDeleted(entity("pw"), sentUpdatedAt = 4_000L))
        assertEquals(KEPT_DELETED, dao.insertIfAbsentUnlessDeleted(entity("pw"), sentUpdatedAt = 5_000L))
        assertEquals(KEPT_DELETED, dao.insertIfAbsentUnlessDeleted(entity("pw"), sentUpdatedAt = null))
        assertNull(dao.getByPasswordId("pw"))

        assertEquals(1, dao.pruneDeletionsBefore(5_001L))
        assertNull(dao.getDeletedAt("pw"))

        val rowId = dao.insertIfAbsentUnlessDeleted(entity("pw"), sentUpdatedAt = 4_000L)
        assertTrue("the copy was not added after the prune: $rowId", rowId > 0)
        assertNotNull(dao.getByPasswordId("pw"))
    }

    @Test
    fun `the repository keeps a record at the retention boundary and drops an older one`() = runBlocking {
        val now = PasswordRepository.DELETION_RETENTION_MS + 1_000_000L
        val repository = PasswordRepository(dao, cipher = markerCipher(), clock = { now })
        dao.recordDeletion(PasswordDeletionEntity("boundary", now - PasswordRepository.DELETION_RETENTION_MS))
        dao.recordDeletion(PasswordDeletionEntity("older", now - PasswordRepository.DELETION_RETENTION_MS - 1))
        dao.recordDeletion(PasswordDeletionEntity("recent", now - 1))

        assertEquals(1, repository.pruneDeletions())

        assertEquals(now - PasswordRepository.DELETION_RETENTION_MS, dao.getDeletedAt("boundary"))
        assertNull(dao.getDeletedAt("older"))
        assertEquals(now - 1, dao.getDeletedAt("recent"))
    }

    @Test
    fun `a clock earlier than the retention prunes nothing`() = runBlocking {
        val now = 1_000L
        val repository = PasswordRepository(dao, cipher = markerCipher(), clock = { now })
        dao.recordDeletion(PasswordDeletionEntity("zero", 0L))
        dao.recordDeletion(PasswordDeletionEntity("early", 500L))

        assertEquals(0, repository.pruneDeletions())
        assertEquals(0L, dao.getDeletedAt("zero"))
        assertEquals(500L, dao.getDeletedAt("early"))
    }
}
