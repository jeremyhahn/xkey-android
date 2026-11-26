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
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import javax.crypto.AEADBadTagException

/**
 * The small helpers of the password store that sync and listings rely on:
 * which entries sync carries ([hasSyncablePolicy]), how an update patch
 * applies to an entry ([PasswordPatch.applyTo]) and the listing that reads
 * no secret ([PasswordRepository.listWithoutSecrets]).
 */
class PasswordRepositoryHelpersTest {

    private val marker: Byte = 0x7f
    private val default = PasswordEntity.DEFAULT_TENANT

    // hasSyncablePolicy

    @Test
    fun `sync carries a personal default-tenant entry with no expiry`() {
        assertTrue(hasSyncablePolicy(default, shared = false, expiresAt = null))
        assertTrue(hasSyncablePolicy(default, shared = false, expiresAt = ""))
    }

    @Test
    fun `sync carries no entry of another tenant, shared or with an expiry`() {
        assertFalse(hasSyncablePolicy("team-a", shared = false, expiresAt = null))
        assertFalse(hasSyncablePolicy(default, shared = true, expiresAt = null))
        assertFalse(hasSyncablePolicy(default, shared = false, expiresAt = "2026-12-01T00:00:00Z"))
        assertFalse(hasSyncablePolicy("team-a", shared = true, expiresAt = "2026-12-01T00:00:00Z"))
    }

    @Test
    fun `a blank expiry or a blank tenant id is not the default policy`() {
        // Recorded as is: only an empty expiry means none. The USB and BLE
        // methods store an expiry only after it parses, so a blank one is
        // never written by them.
        assertFalse(hasSyncablePolicy(default, shared = false, expiresAt = " "))
        // The default tenant is the empty id; no other spelling names it.
        assertFalse(hasSyncablePolicy(" ", shared = false, expiresAt = null))
    }

    // PasswordPatch.applyTo

    private val record = PasswordRecord(
        passwordId = "pw-1",
        name = "Example",
        title = "Title",
        username = "alice",
        password = "secret",
        url = "https://example.com",
        notes = "notes",
        folderPath = "work",
        source = "local",
        createdAt = 1_000L,
        updatedAt = 2_000L,
        expiresAt = "2026-12-01T00:00:00Z",
        shared = true,
        tenantId = "team-a"
    )

    @Test
    fun `an empty patch keeps every field`() {
        assertEquals(record, PasswordPatch().applyTo(record))
    }

    @Test
    fun `an empty clearable field clears it to null`() {
        val patched = PasswordPatch(
            title = "",
            username = "",
            url = "",
            notes = "",
            folderPath = "",
            expiresAt = ""
        ).applyTo(record)

        assertEquals(
            record.copy(title = null, username = null, url = null, notes = null, folderPath = null, expiresAt = null),
            patched
        )
    }

    @Test
    fun `a value replaces each field`() {
        val patched = PasswordPatch(
            name = "Renamed",
            title = "T2",
            username = "bob",
            url = "https://example.org",
            notes = "n2",
            folderPath = "home",
            expiresAt = "2027-01-01T00:00:00Z",
            source = "remote"
        ).applyTo(record)

        assertEquals(
            record.copy(
                name = "Renamed",
                title = "T2",
                username = "bob",
                url = "https://example.org",
                notes = "n2",
                folderPath = "home",
                expiresAt = "2027-01-01T00:00:00Z",
                source = "remote"
            ),
            patched
        )
    }

    @Test
    fun `an empty name or source is set as given, never cleared to null`() {
        // Recorded as is: name and source are not clearable, so "" is stored
        // as "". The USB update refuses an empty name before it builds a patch.
        val patched = PasswordPatch(name = "", source = "").applyTo(record)

        assertEquals(record.copy(name = "", source = ""), patched)
    }

    @Test
    fun `a patch leaves the password and the times alone`() {
        val patched = PasswordPatch(password = "changed", updatedAt = 9_999L).applyTo(record)

        assertEquals("secret", patched.password)
        assertEquals(2_000L, patched.updatedAt)
        assertEquals(1_000L, patched.createdAt)
        assertEquals(record, patched)
    }

    // listWithoutSecrets

    @Test
    fun `a listing without secrets decrypts nothing and keeps every other field`() = runTest {
        val readable = PasswordEntity(
            id = 1,
            passwordId = "pw-a",
            name = "Alpha",
            title = "A",
            username = "alice",
            passwordEncrypted = byteArrayOf(marker) + "secret-a".toByteArray(Charsets.UTF_8),
            url = "https://example.com",
            notes = "n",
            folderPath = "work",
            source = "remote",
            createdAt = 10L,
            updatedAt = 20L,
            expiresAt = "2026-12-01T00:00:00Z",
            shared = true,
            tenantId = "team-a"
        )
        // Ciphertext under a lost key: it cannot be decrypted.
        val unreadable = PasswordEntity(
            id = 2,
            passwordId = "pw-b",
            name = "Beta",
            passwordEncrypted = byteArrayOf(1, 2, 3),
            createdAt = 30L,
            updatedAt = 40L
        )
        val dao = mockk<PasswordDao>()
        coEvery { dao.getAll() } returns listOf(readable, unreadable)
        val cipher = mockk<KeystoreAeadCipher>()
        every { cipher.decrypt(any()) } throws AEADBadTagException("tag mismatch")

        val listed = PasswordRepository(dao, cipher).listWithoutSecrets()

        assertEquals(
            listOf(
                PasswordRecord(
                    passwordId = "pw-a",
                    name = "Alpha",
                    title = "A",
                    username = "alice",
                    password = "",
                    url = "https://example.com",
                    notes = "n",
                    folderPath = "work",
                    source = "remote",
                    createdAt = 10L,
                    updatedAt = 20L,
                    expiresAt = "2026-12-01T00:00:00Z",
                    shared = true,
                    tenantId = "team-a"
                ),
                PasswordRecord(
                    passwordId = "pw-b",
                    name = "Beta",
                    password = "",
                    createdAt = 30L,
                    updatedAt = 40L
                )
            ),
            listed
        )
        verify(exactly = 0) { cipher.decrypt(any()) }
    }

    @Test
    fun `a listing without secrets of an empty store is empty`() = runTest {
        val dao = mockk<PasswordDao>()
        coEvery { dao.getAll() } returns emptyList()

        assertEquals(emptyList<PasswordRecord>(), PasswordRepository(dao, mockk()).listWithoutSecrets())
    }
}
