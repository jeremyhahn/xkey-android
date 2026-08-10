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
package com.automatethethings.xkey.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for [SoftwareKey]'s value semantics.
 *
 * The type carries raw key material in a `ByteArray`, so the generated
 * `equals`/`hashCode` would compare by identity and two reads of the same stored
 * key would look different. Both are hand-written; every field that
 * distinguishes one key from another is asserted here, and the material is
 * asserted to compare by content.
 */
class SoftwareKeyTest {

    private fun key(
        keyId: String = "sw-key",
        algorithm: String = "AES-256",
        keyType: String = "symmetric",
        keySize: Int = 256,
        exportable: Boolean = true,
        shareable: Boolean = true,
        material: ByteArray = ByteArray(32) { it.toByte() }
    ) = SoftwareKey(keyId, algorithm, keyType, keySize, exportable, shareable, material)

    @Test
    fun equalKeysCompareTheirMaterialByContent() {
        val original = key()
        val reread = key(material = ByteArray(32) { it.toByte() })

        assertEquals(original, original)
        assertEquals(original, reread)
        assertEquals(original.hashCode(), reread.hashCode())
    }

    @Test
    fun differentMaterialMakesADifferentKey() {
        assertNotEquals(key(), key(material = ByteArray(32)))
        assertNotEquals(key(), key(material = ByteArray(16) { it.toByte() }))
    }

    @Test
    fun everyMetadataFieldDiscriminates() {
        assertNotEquals(key(), key(keyId = "other"))
        assertNotEquals(key(), key(algorithm = "HMAC-SHA256"))
        assertNotEquals(key(), key(keyType = "private"))
        assertNotEquals(key(), key(keySize = 128))
        assertNotEquals(key(), key(exportable = false))
        assertNotEquals(key(), key(shareable = false))
    }

    @Test
    fun anUnrelatedValueIsNeverEqual() {
        val other: Any = "not a software key"
        assertFalse(key().equals(other))
    }

    @Test
    fun theHashCodeFoldsInEveryField() {
        val hashes = setOf(
            key().hashCode(),
            key(keyId = "other").hashCode(),
            key(algorithm = "HMAC-SHA256").hashCode(),
            key(keyType = "private").hashCode(),
            key(keySize = 128).hashCode(),
            key(exportable = false).hashCode(),
            key(shareable = false).hashCode(),
            key(material = ByteArray(32)).hashCode()
        )

        assertTrue("distinct keys should not all collide", hashes.size > 6)
    }
}
