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
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import io.mockk.unmockkAll
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Unit tests for [PasswordRepository].
 *
 * The repository is the only place that turns a plaintext [PasswordRecord] into
 * the encrypted [PasswordEntity] that Room persists, so the properties worth
 * pinning are the ones a caller cannot see: that the plaintext is handed to the
 * cipher and never to the DAO, that an update keeps the original creation time
 * and the original row id instead of inserting a duplicate, and that supplied
 * timestamps beat the clock only when they are actually set.
 *
 * The Keystore is stubbed here with a reversible byte transform so the tests
 * stay on the JVM; [com.automatethethings.xkey.crypto.KeystoreAeadCipher]'s own
 * behaviour is covered by its instrumented suite.
 */
class PasswordRepositoryTest {

    private lateinit var dao: PasswordDao
    private lateinit var cipher: KeystoreAeadCipher
    private lateinit var repository: PasswordRepository

    /** Marker prepended by the stub cipher so ciphertext is never plaintext. */
    private val marker: Byte = 0x7f

    @Before
    fun setUp() {
        dao = mockk(relaxed = true)
        cipher = mockk()

        every { cipher.encrypt(any()) } answers {
            byteArrayOf(marker) + firstArg<ByteArray>()
        }
        every { cipher.decrypt(any()) } answers {
            firstArg<ByteArray>().copyOfRange(1, firstArg<ByteArray>().size)
        }

        repository = PasswordRepository(dao, cipher)
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    private fun entity(
        id: Long = 1L,
        passwordId: String = "pw-1",
        plaintext: String = "hunter2",
        createdAt: Long = 1_000L,
        updatedAt: Long = 2_000L,
        source: String = "local"
    ) = PasswordEntity(
        id = id,
        passwordId = passwordId,
        name = "Example",
        title = "Example Login",
        username = "user@example.com",
        passwordEncrypted = byteArrayOf(marker) + plaintext.toByteArray(Charsets.UTF_8),
        url = "https://example.com",
        notes = "notes",
        folderPath = "/work",
        source = source,
        createdAt = createdAt,
        updatedAt = updatedAt
    )

    // -------------------------------------------------------------------------
    // Reads
    // -------------------------------------------------------------------------

    @Test
    fun `list decrypts every stored entry`() = runTest {
        coEvery { dao.getAll() } returns listOf(
            entity(id = 1L, passwordId = "pw-1", plaintext = "first"),
            entity(id = 2L, passwordId = "pw-2", plaintext = "second")
        )

        val records = repository.list()

        assertEquals(listOf("first", "second"), records.map { it.password })
        assertEquals(listOf("pw-1", "pw-2"), records.map { it.passwordId })
    }

    @Test
    fun `list carries every metadata field onto the record`() = runTest {
        coEvery { dao.getAll() } returns listOf(entity())

        val record = repository.list().single()

        assertEquals("pw-1", record.passwordId)
        assertEquals("Example", record.name)
        assertEquals("Example Login", record.title)
        assertEquals("user@example.com", record.username)
        assertEquals("https://example.com", record.url)
        assertEquals("notes", record.notes)
        assertEquals("/work", record.folderPath)
        assertEquals("local", record.source)
        assertEquals(1_000L, record.createdAt)
        assertEquals(2_000L, record.updatedAt)
    }

    @Test
    fun `listBySource filters through the DAO rather than in memory`() = runTest {
        coEvery { dao.getBySource("remote") } returns listOf(
            entity(passwordId = "pw-remote", source = "remote")
        )

        val records = repository.listBySource("remote")

        assertEquals(listOf("pw-remote"), records.map { it.passwordId })
        coVerify(exactly = 1) { dao.getBySource("remote") }
        coVerify(exactly = 0) { dao.getAll() }
    }

    @Test
    fun `get returns null for an unknown id`() = runTest {
        coEvery { dao.getByPasswordId("missing") } returns null

        assertNull(repository.get("missing"))
    }

    @Test
    fun `count delegates to the DAO`() = runTest {
        coEvery { dao.count() } returns 12

        assertEquals(12, repository.count())
    }

    @Test
    fun `observeAll exposes the DAO flow of encrypted entities`() = runTest {
        val rows = listOf(entity())
        every { dao.observeAll() } returns flowOf(rows)

        assertEquals(rows, repository.observeAll().first())
    }

    // -------------------------------------------------------------------------
    // Writes
    // -------------------------------------------------------------------------

    private fun record(
        passwordId: String = "pw-1",
        password: String = "hunter2",
        createdAt: Long = 0L,
        updatedAt: Long = 0L
    ) = PasswordRecord(
        passwordId = passwordId,
        name = "Example",
        title = "Example Login",
        username = "user@example.com",
        password = password,
        url = "https://example.com",
        notes = "notes",
        folderPath = "/work",
        source = "local",
        createdAt = createdAt,
        updatedAt = updatedAt
    )

    @Test
    fun `upsert encrypts the password and never persists the plaintext`() = runTest {
        coEvery { dao.getByPasswordId("pw-1") } returns null
        val stored = slot<PasswordEntity>()
        coEvery { dao.insert(capture(stored)) } returns 1L

        repository.upsert(record(password = "hunter2"))

        val persisted = stored.captured.passwordEncrypted
        assertEquals(marker.toInt(), persisted.first().toInt())
        assertEquals("hunter2", String(persisted.drop(1).toByteArray(), Charsets.UTF_8))
        assertFalse(persisted.contentEquals("hunter2".toByteArray(Charsets.UTF_8)))
    }

    @Test
    fun `upsert returns the stable password id`() = runTest {
        coEvery { dao.getByPasswordId(any()) } returns null
        coEvery { dao.insert(any()) } returns 1L

        assertEquals("pw-1", repository.upsert(record()))
    }

    @Test
    fun `a new entry gets row id zero so Room assigns one`() = runTest {
        coEvery { dao.getByPasswordId("pw-1") } returns null
        val stored = slot<PasswordEntity>()
        coEvery { dao.insert(capture(stored)) } returns 1L

        repository.upsert(record())

        assertEquals(0L, stored.captured.id)
    }

    @Test
    fun `an update reuses the existing row id instead of inserting a duplicate`() = runTest {
        coEvery { dao.getByPasswordId("pw-1") } returns entity(id = 42L)
        val stored = slot<PasswordEntity>()
        coEvery { dao.insert(capture(stored)) } returns 42L

        repository.upsert(record())

        assertEquals(42L, stored.captured.id)
    }

    @Test
    fun `an update preserves the original creation time`() = runTest {
        coEvery { dao.getByPasswordId("pw-1") } returns entity(createdAt = 1_234L)
        val stored = slot<PasswordEntity>()
        coEvery { dao.insert(capture(stored)) } returns 1L

        repository.upsert(record(createdAt = 9_999L))

        assertEquals(1_234L, stored.captured.createdAt)
    }

    @Test
    fun `a new entry honours an explicitly supplied creation time`() = runTest {
        coEvery { dao.getByPasswordId("pw-1") } returns null
        val stored = slot<PasswordEntity>()
        coEvery { dao.insert(capture(stored)) } returns 1L

        repository.upsert(record(createdAt = 9_999L))

        assertEquals(9_999L, stored.captured.createdAt)
    }

    @Test
    fun `a new entry with no timestamps is stamped with the current time`() = runTest {
        coEvery { dao.getByPasswordId("pw-1") } returns null
        val stored = slot<PasswordEntity>()
        coEvery { dao.insert(capture(stored)) } returns 1L

        val before = System.currentTimeMillis()
        repository.upsert(record(createdAt = 0L, updatedAt = 0L))
        val after = System.currentTimeMillis()

        assertTrue(stored.captured.createdAt in before..after)
        assertTrue(stored.captured.updatedAt in before..after)
    }

    @Test
    fun `an explicitly supplied update time wins over the clock`() = runTest {
        coEvery { dao.getByPasswordId("pw-1") } returns null
        val stored = slot<PasswordEntity>()
        coEvery { dao.insert(capture(stored)) } returns 1L

        repository.upsert(record(updatedAt = 8_888L))

        assertEquals(8_888L, stored.captured.updatedAt)
    }

    @Test
    fun `upsert round-trips through the cipher`() = runTest {
        coEvery { dao.getByPasswordId("pw-1") } returns null
        val stored = slot<PasswordEntity>()
        coEvery { dao.insert(capture(stored)) } returns 1L

        repository.upsert(record(password = "påsswörd ✓"))
        coEvery { dao.getByPasswordId("pw-1") } returns stored.captured

        assertEquals("påsswörd ✓", repository.get("pw-1")?.password)
    }

    @Test
    fun `an empty password is still encrypted rather than skipped`() = runTest {
        coEvery { dao.getByPasswordId("pw-1") } returns null
        val stored = slot<PasswordEntity>()
        coEvery { dao.insert(capture(stored)) } returns 1L

        repository.upsert(record(password = ""))

        assertEquals(1, stored.captured.passwordEncrypted.size)
    }

    @Test
    fun `delete removes by the stable password id`() = runTest {
        repository.delete("pw-1")

        coVerify(exactly = 1) { dao.deleteByPasswordId("pw-1") }
    }
}
