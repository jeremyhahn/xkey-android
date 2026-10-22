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

import com.automatethethings.xkey.crypto.KeystoreAeadCipher
import io.mockk.every
import io.mockk.mockk
import io.mockk.unmockkAll
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Unit tests for [PasswordRepository.updateFields] against writers that race it.
 *
 * USB PasswordUpdate, BLE/TCP password sync and the phone UI write the same
 * rows. The property pinned here is that an update applies its patch to the
 * row as it stands at the write: it never writes back a password or a field
 * another writer changed after the update read the row, and never recreates
 * an entry deleted in between, while the size check holds for the row
 * actually written. [FakePasswordDao] gives the statements Room's semantics
 * and a hook at the point a racing write lands.
 */
class PasswordRepositoryUpdateTest {

    private val dao = FakePasswordDao()
    private val cipher: KeystoreAeadCipher = mockk()
    private lateinit var repository: PasswordRepository

    /** Stands in for AES-GCM's IV: every encryption of a password differs. */
    private var nonce: Byte = 0

    @Before
    fun setUp() {
        every { cipher.encrypt(any()) } answers { byteArrayOf(++nonce) + firstArg<ByteArray>() }
        every { cipher.decrypt(any()) } answers {
            firstArg<ByteArray>().copyOfRange(1, firstArg<ByteArray>().size)
        }
        repository = PasswordRepository(dao, cipher)
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    private fun record(
        password: String = "original",
        notes: String? = "notes",
        source: String = "local",
        updatedAt: Long = 2_000L
    ) = PasswordRecord(
        passwordId = "pw-1",
        name = "Example",
        title = "Example Login",
        username = "user@example.com",
        password = password,
        url = "https://example.com",
        notes = notes,
        folderPath = "/work",
        source = source,
        createdAt = 1_000L,
        updatedAt = updatedAt
    )

    private fun stored(): PasswordEntity = dao.rows.getValue("pw-1")

    private fun storedPassword(): String = String(cipher.decrypt(stored().passwordEncrypted), Charsets.UTF_8)

    /**
     * Another writer replacing the whole row through [PasswordRepository.upsert],
     * as a remote copy was merged before PasswordSync patched existing entries.
     */
    private suspend fun syncReplaces(password: String, notes: String) {
        repository.upsert(record(password = password, notes = notes, source = "remote", updatedAt = 2_500L))
    }

    @Test
    fun `a metadata-only update writes the row it read in place and never inserts`() = runTest {
        repository.upsert(record())
        val before = stored()

        assertTrue(repository.updateFields("pw-1", PasswordPatch(notes = "rotated", updatedAt = 3_000L)))

        assertEquals(before.id, stored().id)
        assertEquals("rotated", stored().notes)
        assertEquals(1_000L, stored().createdAt)
        assertEquals(3_000L, stored().updatedAt)
        assertArrayEquals(before.passwordEncrypted, stored().passwordEncrypted)
        assertEquals("only the setup inserts", 1, dao.inserts)
    }

    @Test
    fun `a field the patch leaves unset is kept and an empty one is cleared`() = runTest {
        repository.upsert(record())

        assertTrue(repository.updateFields("pw-1", PasswordPatch(name = "Renamed", url = "")))

        assertEquals("Renamed", stored().name)
        assertNull(stored().url)
        assertEquals("Example Login", stored().title)
        assertEquals("user@example.com", stored().username)
        assertEquals("notes", stored().notes)
        assertEquals("/work", stored().folderPath)
        assertEquals("original", storedPassword())
    }

    @Test
    fun `a new password replaces the stored one`() = runTest {
        repository.upsert(record())

        assertTrue(repository.updateFields("pw-1", PasswordPatch(password = "rotated")))

        assertEquals("rotated", storedPassword())
    }

    @Test
    fun `a password sync replaces between the update's read and its write survives with the update on top`() =
        runTest {
            repository.upsert(record())
            // The sync lands as soon as the update has read the row.
            dao.afterRead = {
                dao.afterRead = null
                syncReplaces("replaced", notes = "sync notes")
            }

            val updated = repository.updateFields("pw-1", PasswordPatch(notes = "usb notes", updatedAt = 3_000L))

            assertTrue(updated)
            assertEquals("the replaced password must not be restored", "replaced", storedPassword())
            assertEquals("usb notes", stored().notes)
            assertEquals(3_000L, stored().updatedAt)
            assertEquals("remote", stored().source)
        }

    @Test
    fun `a field a sync changes that the patch does not set survives the update`() = runTest {
        repository.upsert(record())
        // The USB request sets only the username; the sync changes the notes after the update read the row.
        dao.afterRead = {
            dao.afterRead = null
            syncReplaces("replaced", notes = "sync notes")
        }

        val updated = repository.updateFields("pw-1", PasswordPatch(username = "usb-user", updatedAt = 3_000L))

        assertTrue(updated)
        assertEquals("the sync's notes must not be overwritten", "sync notes", stored().notes)
        assertEquals("usb-user", stored().username)
        assertEquals("replaced", storedPassword())
    }

    @Test
    fun `two racing updates of different fields both land`() = runTest {
        repository.upsert(record())
        val before = stored()
        // A second update, patching only the URL and keeping the ciphertext, lands after the first one's read.
        dao.afterRead = {
            dao.afterRead = null
            assertTrue(repository.updateFields("pw-1", PasswordPatch(url = "https://other.example", updatedAt = 2_800L)))
        }

        val updated = repository.updateFields("pw-1", PasswordPatch(notes = "usb notes", updatedAt = 3_000L))

        assertTrue(updated)
        assertEquals("the other update's URL must not be reverted", "https://other.example", stored().url)
        assertEquals("usb notes", stored().notes)
        assertEquals(3_000L, stored().updatedAt)
        assertArrayEquals(before.passwordEncrypted, stored().passwordEncrypted)
        assertEquals("only the setup inserts", 1, dao.inserts)
    }

    @Test
    fun `an update a sync keeps replacing is refused and writes nothing`() = runTest {
        repository.upsert(record())
        var replacements = 0
        dao.afterRead = {
            replacements++
            syncReplaces("replaced-$replacements", notes = "sync notes")
        }

        try {
            repository.updateFields("pw-1", PasswordPatch(notes = "usb notes"))
            throw AssertionError("an update that never holds its row must be refused")
        } catch (e: PasswordUpdateConflictException) {
            // expected
        }

        assertEquals("one read, then one retry", 2, replacements)
        assertEquals("replaced-2", storedPassword())
        assertEquals("sync notes", stored().notes)
    }

    @Test
    fun `an entry deleted between the update's read and its write reports not found and stays deleted`() =
        runTest {
            repository.upsert(record())
            // The phone UI deletes the entry as soon as the update has read it.
            dao.afterRead = {
                dao.afterRead = null
                repository.delete("pw-1")
            }

            val updated = repository.updateFields("pw-1", PasswordPatch(password = "rotated"))

            assertFalse(updated)
            assertTrue("the deleted entry must not be recreated", dao.rows.isEmpty())
            assertEquals("only the setup inserts", 1, dao.inserts)
        }

    @Test
    fun `an update of an unknown entry reports not found and writes nothing`() = runTest {
        assertFalse(repository.updateFields("pw-1", PasswordPatch(notes = "rotated")))

        assertTrue(dao.rows.isEmpty())
        assertEquals(0, dao.inserts)
    }

    @Test
    fun `an oversized update is refused before any write`() = runTest {
        repository.upsert(record())
        val before = stored()

        try {
            repository.updateFields("pw-1", PasswordPatch(notes = "n".repeat(PasswordEntryLimit.MAX_ENTRY_SIZE)))
            throw AssertionError("an oversized update must be refused")
        } catch (e: PasswordEntryTooLargeException) {
            // expected
        }

        assertEquals(before, stored())
    }

    @Test
    fun `the size check is made again against the password a sync put there`() = runTest {
        repository.upsert(record(password = "a"))
        // Notes that fit beside "a" with 100 bytes to spare, not beside the sync's longer password.
        val base = PasswordEntryLimit.serializedSize(
            PasswordEntryLimit.getResponse(record(password = "a", notes = null, updatedAt = 3_000L))
        )
        val notes = "n".repeat(PasswordEntryLimit.MAX_ENTRY_SIZE - base - ",\"notes\":\"\"".length - 100)
        dao.afterRead = {
            dao.afterRead = null
            syncReplaces("p".repeat(1_000), notes = "sync notes")
        }

        try {
            repository.updateFields("pw-1", PasswordPatch(notes = notes, updatedAt = 3_000L))
            throw AssertionError("an update too large beside the replaced password must be refused")
        } catch (e: PasswordEntryTooLargeException) {
            // expected
        }

        assertEquals("p".repeat(1_000), storedPassword())
        assertEquals("sync notes", stored().notes)
    }
}

/**
 * [PasswordDao] over a map, with Room's semantics for the statements the
 * repository makes: INSERT OR REPLACE and INSERT OR IGNORE on `password_id`, `@Update` by primary
 * key, the guarded UPDATE that matches primary key and every stored column,
 * and the tenant, sharing and folder filters of the scoped reads and delete.
 * [afterRead] runs once a read by id has its row and before the caller sees
 * it, where a racing writer's statements land; the writer's own reads do not
 * run it again.
 */
internal class FakePasswordDao : PasswordDao {

    val rows = linkedMapOf<String, PasswordEntity>()
    var inserts = 0
        private set
    var afterRead: (suspend () -> Unit)? = null

    private var nextId = 1L
    private var racing = false

    override suspend fun insert(password: PasswordEntity): Long {
        inserts++
        val id = if (password.id == 0L) nextId++ else password.id
        rows.values.removeAll { it.id == id || it.passwordId == password.passwordId }
        rows[password.passwordId] = password.copy(id = id)
        return id
    }

    override suspend fun insertIfAbsent(password: PasswordEntity): Long {
        if (rows.containsKey(password.passwordId)) return -1
        val id = nextId++
        rows[password.passwordId] = password.copy(id = id)
        return id
    }

    override suspend fun update(password: PasswordEntity): Int {
        val current = rows.values.firstOrNull { it.id == password.id } ?: return 0
        rows.remove(current.passwordId)
        rows[password.passwordId] = password
        return 1
    }

    override suspend fun updateFieldsIfUnchanged(
        id: Long,
        expectedPasswordEncrypted: ByteArray,
        expectedName: String,
        expectedTitle: String?,
        expectedUsername: String?,
        expectedUrl: String?,
        expectedNotes: String?,
        expectedFolderPath: String?,
        expectedSource: String,
        expectedCreatedAt: Long,
        expectedUpdatedAt: Long,
        expectedExpiresAt: String?,
        expectedShared: Boolean,
        expectedTenantId: String,
        name: String,
        title: String?,
        username: String?,
        passwordEncrypted: ByteArray,
        url: String?,
        notes: String?,
        folderPath: String?,
        source: String,
        expiresAt: String?,
        updatedAt: Long
    ): Int {
        val current = rows.values.firstOrNull {
            it.id == id && it.passwordEncrypted.contentEquals(expectedPasswordEncrypted) &&
                it.name == expectedName && it.title == expectedTitle && it.username == expectedUsername &&
                it.url == expectedUrl && it.notes == expectedNotes && it.folderPath == expectedFolderPath &&
                it.source == expectedSource && it.createdAt == expectedCreatedAt &&
                it.updatedAt == expectedUpdatedAt && it.expiresAt == expectedExpiresAt &&
                it.shared == expectedShared && it.tenantId == expectedTenantId
        } ?: return 0
        rows[current.passwordId] = current.copy(
            name = name,
            title = title,
            username = username,
            passwordEncrypted = passwordEncrypted,
            url = url,
            notes = notes,
            folderPath = folderPath,
            source = source,
            expiresAt = expiresAt,
            updatedAt = updatedAt
        )
        return 1
    }

    override fun observeAll(): Flow<List<PasswordEntity>> = flowOf(sorted())

    override suspend fun getAll(): List<PasswordEntity> = sorted()

    override suspend fun getByPasswordId(passwordId: String): PasswordEntity? = read(rows[passwordId])

    override suspend fun getByPasswordIdInTenant(passwordId: String, tenantId: String): PasswordEntity? =
        read(rows[passwordId]?.takeIf { it.tenantId == tenantId })

    override suspend fun getForListing(tenantId: String, shared: Boolean?, folderPath: String?): List<PasswordEntity> =
        sorted().filter {
            it.tenantId == tenantId && (shared == null || it.shared == shared) &&
                (folderPath == null || it.folderPath == folderPath)
        }

    override suspend fun getBySource(source: String): List<PasswordEntity> =
        rows.values.filter { it.source == source }

    override suspend fun deleteByPasswordId(passwordId: String): Int =
        if (rows.remove(passwordId) != null) 1 else 0

    override suspend fun deleteByPasswordIdInTenant(passwordId: String, tenantId: String): Int =
        if (rows[passwordId]?.tenantId == tenantId) deleteByPasswordId(passwordId) else 0

    override suspend fun count(): Int = rows.size

    override fun observeCount(): Flow<Int> = flowOf(rows.size)

    private suspend fun read(row: PasswordEntity?): PasswordEntity? {
        val hook = afterRead
        if (hook != null && !racing) {
            racing = true
            try {
                hook()
            } finally {
                racing = false
            }
        }
        return row
    }

    private fun sorted(): List<PasswordEntity> =
        rows.values.sortedWith(compareBy<PasswordEntity>({ it.name }, { it.username }))
}
