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
package com.automatethethings.xkey.storage.dao

import com.automatethethings.xkey.storage.entity.ContactEntity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for [ContactEntity] data class behavior.
 *
 * Since Room DAOs require an Android environment (or Robolectric with an
 * in-memory database), these tests focus on the entity's data class
 * semantics, custom equals/hashCode (ByteArray handling), and field
 * validation concepts.
 */
class ContactDaoTest {

    @Test
    fun `ContactEntity creation with default values`() {
        val entity = ContactEntity(
            name = "Bob",
            publicKeyDer = byteArrayOf(0x01),
            publicKeyFingerprint = "SHA256:def456",
            algorithm = "ES256",
            source = "qr"
        )

        assertEquals(0L, entity.id)
        assertNull(entity.notes)
        assertTrue(entity.importedAt > 0)
    }

    @Test
    fun `equals handles ByteArray content correctly`() {
        val key1 = byteArrayOf(0x30, 0x59, 0x30, 0x13)
        val key2 = byteArrayOf(0x30, 0x59, 0x30, 0x13)
        val key3 = byteArrayOf(0x30, 0x59, 0x30, 0x14)

        val entity1 = ContactEntity(
            id = 1L,
            name = "Alice",
            publicKeyDer = key1,
            publicKeyFingerprint = "SHA256:abc",
            algorithm = "ES256",
            importedAt = 1000L,
            source = "file"
        )
        val entity2 = ContactEntity(
            id = 1L,
            name = "Alice",
            publicKeyDer = key2,
            publicKeyFingerprint = "SHA256:abc",
            algorithm = "ES256",
            importedAt = 1000L,
            source = "file"
        )
        val entity3 = ContactEntity(
            id = 1L,
            name = "Alice",
            publicKeyDer = key3,
            publicKeyFingerprint = "SHA256:abc",
            algorithm = "ES256",
            importedAt = 1000L,
            source = "file"
        )

        assertEquals(entity1, entity2)
        assertNotEquals(entity1, entity3)
    }

    @Test
    fun `hashCode is consistent for equal entities with ByteArray`() {
        val key1 = byteArrayOf(0x04, 0x01, 0x02)
        val key2 = byteArrayOf(0x04, 0x01, 0x02)

        val entity1 = ContactEntity(
            id = 5L,
            name = "Charlie",
            publicKeyDer = key1,
            publicKeyFingerprint = "SHA256:xyz",
            algorithm = "ES384",
            importedAt = 2000L,
            source = "ble"
        )
        val entity2 = ContactEntity(
            id = 5L,
            name = "Charlie",
            publicKeyDer = key2,
            publicKeyFingerprint = "SHA256:xyz",
            algorithm = "ES384",
            importedAt = 2000L,
            source = "ble"
        )

        assertEquals(entity1.hashCode(), entity2.hashCode())
    }

    @Test
    fun `equals returns false for different types`() {
        val entity = ContactEntity(
            id = 1L,
            name = "Alice",
            publicKeyDer = byteArrayOf(0x01),
            publicKeyFingerprint = "SHA256:abc",
            algorithm = "ES256",
            importedAt = 1000L,
            source = "file"
        )

        assertFalse(entity.equals("not a contact entity"))
        assertFalse(entity.equals(null))
    }

    @Test
    fun `equals returns true for same reference`() {
        val entity = ContactEntity(
            id = 1L,
            name = "Alice",
            publicKeyDer = byteArrayOf(0x01),
            publicKeyFingerprint = "SHA256:abc",
            algorithm = "ES256",
            importedAt = 1000L,
            source = "file"
        )

        assertTrue(entity.equals(entity))
    }
}
