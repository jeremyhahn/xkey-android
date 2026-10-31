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
package com.automatethethings.xkey.oath

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for [OathCredentialEntity]'s hand-written value semantics.
 *
 * The encrypted secret is a [ByteArray], so the entity overrides
 * `equals`/`hashCode`. Every field is pinned individually, and the defaults are
 * asserted because they are the RFC 6238 defaults a scanned `otpauth://` URI
 * relies on when its optional parameters are absent.
 */
class OathCredentialEntityTest {

    private val secret = byteArrayOf(0x0c, 0x0d, 0x0e, 0x0f)

    private fun credential(secretEncrypted: ByteArray = secret) = OathCredentialEntity(
        id = 2L,
        oathId = "oath-1",
        oathType = "TOTP",
        algorithm = "SHA1",
        digits = 6,
        periodSeconds = 30,
        counter = 0L,
        issuer = "GitHub",
        accountName = "user@example.com",
        secretEncrypted = secretEncrypted,
        source = "local",
        remoteDeviceId = null,
        createdAt = 1_700_000_000_000L,
        lastUsedAt = 1_700_000_100_000L,
        useCount = 4
    )

    // -------------------------------------------------------------------------
    // Defaults
    // -------------------------------------------------------------------------

    @Test
    fun `an unspecified credential takes the RFC defaults`() {
        val entity = OathCredentialEntity(
            oathId = "o",
            oathType = "TOTP",
            algorithm = "SHA1",
            issuer = null,
            accountName = "user",
            secretEncrypted = secret,
            createdAt = 0L
        )

        assertEquals(0L, entity.id)
        assertEquals(6, entity.digits)
        assertEquals(30, entity.periodSeconds)
        assertEquals(0L, entity.counter)
        assertEquals("local", entity.source)
        assertNull(entity.remoteDeviceId)
        assertNull(entity.lastUsedAt)
        assertEquals(0, entity.useCount)
    }

    @Test
    fun `a credential may carry a null issuer`() {
        val entity = credential().copy(issuer = null)

        assertNull(entity.issuer)
        assertEquals("user@example.com", entity.accountName)
    }

    @Test
    fun `copy advances an HOTP counter without disturbing anything else`() {
        val base = credential().copy(oathType = "HOTP", counter = 7L)
        val advanced = base.copy(counter = base.counter + 1)

        assertEquals(8L, advanced.counter)
        assertEquals(base.oathId, advanced.oathId)
        assertTrue(base.secretEncrypted.contentEquals(advanced.secretEncrypted))
    }

    // -------------------------------------------------------------------------
    // equals / hashCode
    // -------------------------------------------------------------------------

    @Test
    fun `two credentials with the same fields are equal and hash alike`() {
        assertEquals(credential(), credential())
        assertEquals(credential().hashCode(), credential().hashCode())
    }

    @Test
    fun `equal secret content held in distinct arrays still compares equal`() {
        val a = credential(byteArrayOf(9, 8, 7))
        val b = credential(byteArrayOf(9, 8, 7))

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
        assertNotEquals(credential(), null)
        assertFalse(credential().equals("oath-1"))
    }

    @Test
    fun `credentials differing in any single field are not equal`() {
        val base = credential()

        assertNotEquals(base, base.copy(id = 3L))
        assertNotEquals(base, base.copy(oathId = "other"))
        assertNotEquals(base, base.copy(oathType = "HOTP"))
        assertNotEquals(base, base.copy(algorithm = "SHA256"))
        assertNotEquals(base, base.copy(digits = 8))
        assertNotEquals(base, base.copy(periodSeconds = 60))
        assertNotEquals(base, base.copy(counter = 1L))
        assertNotEquals(base, base.copy(issuer = "Google"))
        assertNotEquals(base, base.copy(issuer = null))
        assertNotEquals(base, base.copy(accountName = "other@example.com"))
        assertNotEquals(base, base.copy(source = "remote"))
        assertNotEquals(base, base.copy(remoteDeviceId = "desktop-1"))
        assertNotEquals(base, base.copy(createdAt = 1L))
        assertNotEquals(base, base.copy(lastUsedAt = 2L))
        assertNotEquals(base, base.copy(lastUsedAt = null))
        assertNotEquals(base, base.copy(useCount = 5))
    }

    @Test
    fun `credentials differing only in the encrypted secret are not equal`() {
        assertNotEquals(credential(byteArrayOf(1, 2)), credential(byteArrayOf(1, 3)))
        assertNotEquals(credential(byteArrayOf(1, 2)), credential(byteArrayOf(1, 2, 3)))
    }

    @Test
    fun `hashCode absorbs a null issuer, device id and last-used time`() {
        val sparse = credential().copy(issuer = null, remoteDeviceId = null, lastUsedAt = null)

        assertEquals(sparse.hashCode(), sparse.copy().hashCode())
        assertNotEquals(sparse.hashCode(), credential().hashCode())
    }

    // -------------------------------------------------------------------------
    // copy / destructuring / toString
    // -------------------------------------------------------------------------

    @Test
    fun `toString renders the identifying fields`() {
        val rendered = credential().toString()

        assertTrue(rendered.contains("oathId=oath-1"))
        assertTrue(rendered.contains("oathType=TOTP"))
        assertTrue(rendered.contains("issuer=GitHub"))
    }
}
