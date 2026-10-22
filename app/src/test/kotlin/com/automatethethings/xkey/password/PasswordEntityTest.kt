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

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for [PasswordEntity]'s hand-written value semantics.
 *
 * The persisted form of a password is a [ByteArray] of ciphertext, so the
 * entity overrides `equals`/`hashCode`. Two facts are pinned beyond the usual
 * field-by-field comparison: the plaintext never appears on the entity at all,
 * and every optional field really is optional, because the go-xkms `SyncPassword`
 * wire type it mirrors leaves them all omittable.
 */
class PasswordEntityTest {

    private val ciphertext = byteArrayOf(0x01, 0x02, 0x03, 0x04)

    private fun password(passwordEncrypted: ByteArray = ciphertext) = PasswordEntity(
        id = 5L,
        passwordId = "pw-1",
        name = "Example",
        title = "Example Login",
        username = "user@example.com",
        passwordEncrypted = passwordEncrypted,
        url = "https://example.com",
        notes = "recovery codes in the safe",
        folderPath = "/work",
        source = "local",
        createdAt = 1_700_000_000_000L,
        updatedAt = 1_700_000_500_000L
    )

    // -------------------------------------------------------------------------
    // Shape
    // -------------------------------------------------------------------------

    @Test
    fun `every descriptive field is optional`() {
        val entity = PasswordEntity(
            passwordId = "pw",
            name = "Minimal",
            passwordEncrypted = ciphertext,
            createdAt = 1L,
            updatedAt = 2L
        )

        assertEquals(0L, entity.id)
        assertNull(entity.title)
        assertNull(entity.username)
        assertNull(entity.url)
        assertNull(entity.notes)
        assertNull(entity.folderPath)
        assertEquals("local", entity.source)
        assertNull(entity.expiresAt)
        assertFalse(entity.shared)
        assertEquals(PasswordEntity.DEFAULT_TENANT, entity.tenantId)
    }

    @Test
    fun `a remote entry records its source`() {
        val entity = password().copy(source = "remote")

        assertEquals("remote", entity.source)
    }

    @Test
    fun `the entity carries no plaintext property at all`() {
        val rendered = password().toString()

        assertTrue(rendered.contains("passwordId=pw-1"))
        assertTrue(rendered.contains("name=Example"))

        // The stronger guarantee, and the one that matters: there is nowhere on
        // the entity for a plaintext password to live. Asserting on how a
        // ByteArray happens to render in toString pins a detail of the Kotlin
        // runtime, not a property of this class.
        val properties = PasswordEntity::class.java.declaredFields.map { it.name }
        assertFalse(properties.any { it.equals("password", ignoreCase = true) })
        assertTrue(properties.contains("passwordEncrypted"))
    }

    // -------------------------------------------------------------------------
    // equals / hashCode
    // -------------------------------------------------------------------------

    @Test
    fun `two entries with the same fields are equal and hash alike`() {
        assertEquals(password(), password())
        assertEquals(password().hashCode(), password().hashCode())
    }

    @Test
    fun `equal ciphertext held in distinct arrays still compares equal`() {
        val a = password(byteArrayOf(7, 7, 7))
        val b = password(byteArrayOf(7, 7, 7))

        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
    }

    @Test
    fun `an entry equals itself`() {
        val a = password()

        assertEquals(a, a)
    }

    @Test
    fun `an entry is never equal to null or an unrelated value`() {
        assertNotEquals(password(), null)
        assertFalse(password().equals("pw-1"))
    }

    @Test
    fun `entries differing in any single field are not equal`() {
        val base = password()

        assertNotEquals(base, base.copy(id = 6L))
        assertNotEquals(base, base.copy(passwordId = "pw-2"))
        assertNotEquals(base, base.copy(name = "Other"))
        assertNotEquals(base, base.copy(title = "Other Login"))
        assertNotEquals(base, base.copy(title = null))
        assertNotEquals(base, base.copy(username = "other@example.com"))
        assertNotEquals(base, base.copy(username = null))
        assertNotEquals(base, base.copy(url = "https://other.test"))
        assertNotEquals(base, base.copy(url = null))
        assertNotEquals(base, base.copy(notes = "different"))
        assertNotEquals(base, base.copy(notes = null))
        assertNotEquals(base, base.copy(folderPath = "/personal"))
        assertNotEquals(base, base.copy(folderPath = null))
        assertNotEquals(base, base.copy(source = "remote"))
        assertNotEquals(base, base.copy(createdAt = 1L))
        assertNotEquals(base, base.copy(updatedAt = 2L))
        assertNotEquals(base, base.copy(expiresAt = "2027-01-02T03:04:05Z"))
        assertNotEquals(base, base.copy(shared = true))
        assertNotEquals(base, base.copy(tenantId = "acme"))
    }

    @Test
    fun `entries whose ciphertext differs are not equal even with identical metadata`() {
        // Re-encrypting the same password produces different bytes because of the
        // fresh nonce, so two rows carrying the same secret are still distinct
        // rows; the entity must not pretend otherwise.
        assertNotEquals(password(byteArrayOf(1, 2, 3)), password(byteArrayOf(1, 2, 4)))
        assertNotEquals(password(byteArrayOf(1, 2, 3)), password(byteArrayOf(1, 2, 3, 0)))
    }

    @Test
    fun `hashCode absorbs the null optional fields`() {
        val sparse = password().copy(
            title = null,
            username = null,
            url = null,
            notes = null,
            folderPath = null
        )

        assertEquals(sparse.hashCode(), sparse.copy().hashCode())
        assertNotEquals(sparse.hashCode(), password().hashCode())
    }

    @Test
    fun `hashCode is stable across repeated calls`() {
        val a = password()

        assertEquals(a.hashCode(), a.hashCode())
    }

    // -------------------------------------------------------------------------
    // copy / destructuring
    // -------------------------------------------------------------------------

    @Test
    fun `copy re-stamps the update time while keeping the creation time`() {
        val base = password()
        val edited = base.copy(name = "Renamed", updatedAt = 1_700_009_999_000L)

        assertEquals("Renamed", edited.name)
        assertEquals(base.createdAt, edited.createdAt)
        assertEquals(1_700_009_999_000L, edited.updatedAt)
    }

    @Test
    fun `an entry destructures in declaration order`() {
        val (id, passwordId, name, title, username) = password()

        assertEquals(5L, id)
        assertEquals("pw-1", passwordId)
        assertEquals("Example", name)
        assertEquals("Example Login", title)
        assertEquals("user@example.com", username)
    }
}
