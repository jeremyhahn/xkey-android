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
package com.automatethethings.xkey.storage.entity

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for [CredentialMetadataEntity]'s hand-written value semantics.
 *
 * The COSE public key is a [ByteArray], so the entity overrides
 * `equals`/`hashCode`; without that, two reads of the same passkey row would
 * compare unequal and the credential picker would show duplicates. Each field
 * is pinned individually so a future column cannot be added to the constructor
 * and silently left out of the comparison.
 */
class CredentialMetadataEntityTest {

    private val cose = byteArrayOf(0xA5.toByte(), 0x01, 0x02, 0x03, 0x26)

    private fun credential(publicKeyCose: ByteArray = cose) = CredentialMetadataEntity(
        id = 3L,
        credentialId = "Y3JlZC0x",
        rpId = "example.com",
        rpName = "Example Inc",
        userId = "dXNlci0x",
        userName = "user@example.com",
        userDisplayName = "A User",
        publicKeyCose = publicKeyCose,
        signCount = 5L,
        createdAt = 1_700_000_000_000L,
        lastUsedAt = 1_700_000_500_000L,
        isDiscoverable = true
    )

    // -------------------------------------------------------------------------
    // Defaults
    // -------------------------------------------------------------------------

    @Test
    fun `a freshly created credential starts discoverable with a zero counter`() {
        val entity = CredentialMetadataEntity(
            credentialId = "c",
            rpId = "example.com",
            rpName = "Example",
            userId = "u",
            userName = "user",
            userDisplayName = "User",
            publicKeyCose = cose
        )

        assertEquals(0L, entity.id)
        assertEquals(0L, entity.signCount)
        assertTrue(entity.isDiscoverable)
    }

    @Test
    fun `a freshly created credential stamps both timestamps`() {
        val before = System.currentTimeMillis()
        val entity = CredentialMetadataEntity(
            credentialId = "c",
            rpId = "example.com",
            rpName = "Example",
            userId = "u",
            userName = "user",
            userDisplayName = "User",
            publicKeyCose = cose
        )
        val after = System.currentTimeMillis()

        assertTrue(entity.createdAt in before..after)
        assertTrue(entity.lastUsedAt in before..after)
    }

    // -------------------------------------------------------------------------
    // equals / hashCode
    // -------------------------------------------------------------------------

    @Test
    fun `equal COSE content held in distinct arrays still compares equal`() {
        val a = credential(byteArrayOf(1, 2, 3))
        val b = credential(byteArrayOf(1, 2, 3))

        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
    }

    @Test
    fun `a credential equals itself`() {
        val a = credential()

        assertEquals(a, a)
    }

    @Test
    fun `a credential is never equal to null or an unrelated value`() {
        val a = credential()

        assertNotEquals(a, null)
        assertFalse(a.equals("Y3JlZC0x"))
    }

    @Test
    fun `credentials differing in any single field are not equal`() {
        val base = credential()

        assertNotEquals(base, base.copy(id = 4L))
        assertNotEquals(base, base.copy(credentialId = "other"))
        assertNotEquals(base, base.copy(rpId = "other.test"))
        assertNotEquals(base, base.copy(rpName = "Other"))
        assertNotEquals(base, base.copy(userId = "other"))
        assertNotEquals(base, base.copy(userName = "other@example.com"))
        assertNotEquals(base, base.copy(userDisplayName = "Other User"))
        assertNotEquals(base, base.copy(signCount = 6L))
        assertNotEquals(base, base.copy(createdAt = 1L))
        assertNotEquals(base, base.copy(lastUsedAt = 2L))
        assertNotEquals(base, base.copy(isDiscoverable = false))
    }

    @Test
    fun `credentials differing only in COSE key content are not equal`() {
        assertNotEquals(credential(byteArrayOf(1, 2, 3)), credential(byteArrayOf(1, 2, 4)))
        assertNotEquals(credential(byteArrayOf(1, 2, 3)), credential(byteArrayOf(1, 2, 3, 4)))
        assertNotEquals(credential(byteArrayOf()), credential(byteArrayOf(0)))
    }
}
