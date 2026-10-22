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
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Unit tests for the go-xkms policy fields of a password entry: its expiry,
 * its sharing and its tenant.
 *
 * Pinned here: [PasswordRepository] stores all three on add; a read, update or
 * delete scoped to a tenant does not see another tenant's entry, exactly as if
 * the id were unknown; a listing applies tenant, scope and folder before
 * anything is cut from it; an update keeps or clears the expiry and never
 * moves an entry between tenants or scopes, even when it races another write.
 */
class PasswordRepositoryPolicyTest {

    private val dao = FakePasswordDao()
    private val cipher: KeystoreAeadCipher = mockk()
    private lateinit var repository: PasswordRepository

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
        passwordId: String = "pw-1",
        name: String = "Example",
        folderPath: String? = "/work",
        expiresAt: String? = null,
        shared: Boolean = false,
        tenantId: String = PasswordEntity.DEFAULT_TENANT
    ) = PasswordRecord(
        passwordId = passwordId,
        name = name,
        password = "secret",
        folderPath = folderPath,
        createdAt = 1_000L,
        updatedAt = 2_000L,
        expiresAt = expiresAt,
        shared = shared,
        tenantId = tenantId
    )

    private fun stored(passwordId: String = "pw-1"): PasswordEntity = dao.rows.getValue(passwordId)

    // -------------------------------------------------------------------------
    // Add and get
    // -------------------------------------------------------------------------

    @Test
    fun `an entry added without policy fields gets the defaults`() = runTest {
        repository.upsert(record())

        val read = repository.get("pw-1", PasswordEntity.DEFAULT_TENANT)!!
        assertNull(read.expiresAt)
        assertFalse(read.shared)
        assertEquals("", read.tenantId)
    }

    @Test
    fun `an entry added with an expiry reads it back`() = runTest {
        repository.upsert(record(expiresAt = "2027-01-02T03:04:05Z"))

        assertEquals("2027-01-02T03:04:05Z", stored().expiresAt)
        assertEquals("2027-01-02T03:04:05Z", repository.get("pw-1", "")!!.expiresAt)
    }

    @Test
    fun `an entry added as shared reads back shared`() = runTest {
        repository.upsert(record(shared = true))

        assertTrue(stored().shared)
        assertTrue(repository.get("pw-1", "")!!.shared)
    }

    @Test
    fun `an entry added in a tenant reads back in that tenant`() = runTest {
        repository.upsert(record(tenantId = "acme"))

        assertEquals("acme", stored().tenantId)
        assertEquals("acme", repository.get("pw-1", "acme")!!.tenantId)
        assertEquals("acme", repository.getWithoutSecret("pw-1", "acme")!!.tenantId)
    }

    // -------------------------------------------------------------------------
    // Tenant isolation
    // -------------------------------------------------------------------------

    @Test
    fun `another tenant's entry is not found, as an unknown id is not`() = runTest {
        repository.upsert(record(tenantId = "acme"))

        assertNull(repository.get("pw-1", "globex"))
        assertNull(repository.get("pw-1", PasswordEntity.DEFAULT_TENANT))
        assertNull(repository.getWithoutSecret("pw-1", "globex"))
        assertNull(repository.get("pw-missing", "acme"))
    }

    @Test
    fun `an unscoped read finds an entry in any tenant`() = runTest {
        repository.upsert(record(tenantId = "acme"))

        assertEquals("acme", repository.get("pw-1")!!.tenantId)
    }

    @Test
    fun `an update scoped to another tenant changes nothing`() = runTest {
        repository.upsert(record(tenantId = "acme"))
        val before = stored()

        assertFalse(repository.updateFields("pw-1", PasswordPatch(name = "Hijacked"), "globex"))

        assertEquals(before, stored())
    }

    @Test
    fun `an update scoped to the entry's tenant applies`() = runTest {
        repository.upsert(record(tenantId = "acme"))

        assertTrue(repository.updateFields("pw-1", PasswordPatch(name = "Renamed"), "acme"))

        assertEquals("Renamed", stored().name)
        assertEquals("acme", stored().tenantId)
    }

    @Test
    fun `a delete scoped to another tenant leaves the entry`() = runTest {
        repository.upsert(record(tenantId = "acme"))

        assertFalse(repository.delete("pw-1", "globex"))
        assertFalse(repository.delete("pw-1", PasswordEntity.DEFAULT_TENANT))

        assertEquals("acme", stored().tenantId)
    }

    @Test
    fun `a delete scoped to the entry's tenant removes it`() = runTest {
        repository.upsert(record(tenantId = "acme"))

        assertTrue(repository.delete("pw-1", "acme"))

        assertTrue(dao.rows.isEmpty())
    }

    @Test
    fun `an unscoped delete removes an entry in any tenant`() = runTest {
        repository.upsert(record(tenantId = "acme"))

        assertTrue(repository.delete("pw-1"))
        assertFalse(repository.delete("pw-1"))
    }

    // -------------------------------------------------------------------------
    // Listing
    // -------------------------------------------------------------------------

    private suspend fun storeMixedEntries() {
        repository.upsert(record(passwordId = "a-personal", name = "A", shared = false))
        repository.upsert(record(passwordId = "b-shared", name = "B", shared = true))
        repository.upsert(record(passwordId = "c-personal", name = "C", shared = false, folderPath = "/home"))
        repository.upsert(record(passwordId = "d-shared", name = "D", shared = true, folderPath = "/home"))
        repository.upsert(record(passwordId = "e-other-tenant", name = "E", shared = true, tenantId = "acme"))
    }

    private suspend fun listedIds(scope: PasswordScope, folderPath: String? = null, tenantId: String = "") =
        repository.listInTenant(tenantId, scope, folderPath).map { it.passwordId }

    @Test
    fun `the personal scope lists only the tenant's unshared entries`() = runTest {
        storeMixedEntries()

        assertEquals(listOf("a-personal", "c-personal"), listedIds(PasswordScope.PERSONAL))
    }

    @Test
    fun `the shared scope lists only the tenant's shared entries`() = runTest {
        storeMixedEntries()

        assertEquals(listOf("b-shared", "d-shared"), listedIds(PasswordScope.SHARED))
    }

    @Test
    fun `the all scope lists every entry of the tenant and no other`() = runTest {
        storeMixedEntries()

        assertEquals(listOf("a-personal", "b-shared", "c-personal", "d-shared"), listedIds(PasswordScope.ALL))
        assertEquals(listOf("e-other-tenant"), listedIds(PasswordScope.ALL, tenantId = "acme"))
        assertEquals(emptyList<String>(), listedIds(PasswordScope.ALL, tenantId = "globex"))
    }

    @Test
    fun `scope and folder filter together`() = runTest {
        storeMixedEntries()

        assertEquals(listOf("d-shared"), listedIds(PasswordScope.SHARED, folderPath = "/home"))
        assertEquals(listOf("c-personal"), listedIds(PasswordScope.PERSONAL, folderPath = "/home"))
    }

    @Test
    fun `a listing carries the policy fields and no secret`() = runTest {
        repository.upsert(record(expiresAt = "2027-01-02T03:04:05Z", shared = true))

        val listed = repository.listInTenant("", PasswordScope.ALL).single()
        assertEquals("2027-01-02T03:04:05Z", listed.expiresAt)
        assertTrue(listed.shared)
        assertEquals("", listed.password)
    }

    @Test
    fun `a listing filtered down holds only matches, so its pages are full`() = runTest {
        // Interleave so that cutting pages first and filtering after would
        // leave every page half empty.
        repeat(6) { i ->
            repository.upsert(record(passwordId = "pw-$i", name = "Entry $i", shared = i % 2 == 0))
        }

        val shared = repository.listInTenant("", PasswordScope.SHARED)

        assertEquals(listOf("pw-0", "pw-2", "pw-4"), shared.map { it.passwordId })
        assertEquals(listOf("pw-0", "pw-2"), shared.take(2).map { it.passwordId })
    }

    @Test
    fun `scope names map as on the wire and an unknown one maps to nothing`() {
        assertEquals(PasswordScope.PERSONAL, PasswordScope.fromWire("personal"))
        assertEquals(PasswordScope.SHARED, PasswordScope.fromWire("shared"))
        assertEquals(PasswordScope.ALL, PasswordScope.fromWire("all"))
        assertNull(PasswordScope.fromWire("team"))
        assertNull(PasswordScope.fromWire("Shared"))
        assertNull(PasswordScope.fromWire(""))
    }

    // -------------------------------------------------------------------------
    // Update
    // -------------------------------------------------------------------------

    @Test
    fun `an update without an expiry keeps the stored one`() = runTest {
        repository.upsert(record(expiresAt = "2027-01-02T03:04:05Z"))

        assertTrue(repository.updateFields("pw-1", PasswordPatch(notes = "rotated")))

        assertEquals("2027-01-02T03:04:05Z", stored().expiresAt)
    }

    @Test
    fun `an update with an empty expiry clears it`() = runTest {
        repository.upsert(record(expiresAt = "2027-01-02T03:04:05Z"))

        assertTrue(repository.updateFields("pw-1", PasswordPatch(expiresAt = "")))

        assertNull(stored().expiresAt)
    }

    @Test
    fun `an update with an expiry sets it`() = runTest {
        repository.upsert(record())

        assertTrue(repository.updateFields("pw-1", PasswordPatch(expiresAt = "2028-06-30T00:00:00Z")))

        assertEquals("2028-06-30T00:00:00Z", stored().expiresAt)
    }

    @Test
    fun `an update keeps the entry's tenant and sharing`() = runTest {
        repository.upsert(record(shared = true, tenantId = "acme"))

        assertTrue(repository.updateFields("pw-1", PasswordPatch(name = "Renamed", password = "rotated")))

        assertTrue(stored().shared)
        assertEquals("acme", stored().tenantId)
    }

    @Test
    fun `an update that races another update keeps the policy fields of both`() = runTest {
        repository.upsert(record(expiresAt = "2027-01-02T03:04:05Z", shared = true, tenantId = "acme"))
        dao.afterRead = {
            dao.afterRead = null
            repository.updateFields("pw-1", PasswordPatch(notes = "from sync", source = "remote"))
        }

        assertTrue(repository.updateFields("pw-1", PasswordPatch(name = "Renamed"), "acme"))

        assertEquals("Renamed", stored().name)
        assertEquals("from sync", stored().notes)
        assertEquals("remote", stored().source)
        assertEquals("2027-01-02T03:04:05Z", stored().expiresAt)
        assertTrue(stored().shared)
        assertEquals("acme", stored().tenantId)
    }

    @Test
    fun `an update that races an expiry change applies its patch on top of it`() = runTest {
        repository.upsert(record(expiresAt = "2027-01-02T03:04:05Z"))
        dao.afterRead = {
            dao.afterRead = null
            repository.updateFields("pw-1", PasswordPatch(expiresAt = ""))
        }

        // The racing write cleared the expiry after this update read the row:
        // keeping the expiry means keeping the cleared one, not the one read.
        assertTrue(repository.updateFields("pw-1", PasswordPatch(name = "Renamed")))

        assertEquals("Renamed", stored().name)
        assertNull(stored().expiresAt)
    }

    @Test
    fun `a patch re-labels the source only when it names one`() = runTest {
        repository.upsert(record())

        assertTrue(repository.updateFields("pw-1", PasswordPatch(name = "Renamed")))
        assertEquals("local", stored().source)

        assertTrue(repository.updateFields("pw-1", PasswordPatch(source = "remote")))
        assertEquals("remote", stored().source)
    }
}
