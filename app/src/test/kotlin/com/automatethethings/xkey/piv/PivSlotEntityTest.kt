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
package com.automatethethings.xkey.piv

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for the value semantics of [PivSlotEntity] and [PivSlotInfo].
 *
 * Both types carry *nullable* [ByteArray] fields, which is the interesting
 * case: an empty slot legitimately has no public key and no certificate, so
 * `equals` has to treat null-versus-null as equal, null-versus-present as
 * unequal in both directions, and identical-content-in-different-arrays as
 * equal. `PivKeyManagerTest` spot-checks two of those; this suite pins all of
 * them plus the field-by-field comparison.
 */
class PivSlotEntityTest {

    private val publicKey = byteArrayOf(0x30, 0x59, 0x30, 0x13)
    private val certificate = byteArrayOf(0x30, 0x82.toByte(), 0x01, 0x22)

    private fun entity(
        publicKeyDer: ByteArray? = publicKey,
        certificateDer: ByteArray? = certificate
    ) = PivSlotEntity(
        id = 1L,
        slotId = "9A",
        algorithm = "ES256",
        publicKeyDer = publicKeyDer,
        certificateDer = certificateDer,
        hasKey = true,
        createdAt = 1_700_000_000_000L,
        lastUsedAt = 1_700_000_100_000L,
        useCount = 3
    )

    // -------------------------------------------------------------------------
    // PivSlotEntity: defaults
    // -------------------------------------------------------------------------

    @Test
    fun `an empty slot row carries no key material`() {
        val empty = PivSlotEntity(slotId = "9C")

        assertEquals(0L, empty.id)
        assertNull(empty.algorithm)
        assertNull(empty.publicKeyDer)
        assertNull(empty.certificateDer)
        assertFalse(empty.hasKey)
        assertNull(empty.lastUsedAt)
        assertEquals(0, empty.useCount)
    }

    @Test
    fun `an empty slot row stamps its own creation time`() {
        val before = System.currentTimeMillis()
        val empty = PivSlotEntity(slotId = "9C")
        val after = System.currentTimeMillis()

        assertTrue(empty.createdAt in before..after)
    }

    // -------------------------------------------------------------------------
    // PivSlotEntity: equals / hashCode
    // -------------------------------------------------------------------------

    @Test
    fun `two slot rows with the same fields are equal and hash alike`() {
        assertEquals(entity(), entity())
        assertEquals(entity().hashCode(), entity().hashCode())
    }

    @Test
    fun `a slot row equals itself`() {
        val a = entity()

        assertEquals(a, a)
    }

    @Test
    fun `a slot row is never equal to null or an unrelated value`() {
        assertNotEquals(entity(), null)
        assertFalse(entity().equals("9A"))
    }

    @Test
    fun `two empty slot rows compare equal despite both arrays being absent`() {
        val a = entity(publicKeyDer = null, certificateDer = null)
        val b = entity(publicKeyDer = null, certificateDer = null)

        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
    }

    @Test
    fun `an absent public key never equals a present one in either direction`() {
        val present = entity(publicKeyDer = publicKey)
        val absent = entity(publicKeyDer = null)

        assertNotEquals(present, absent)
        assertNotEquals(absent, present)
    }

    @Test
    fun `an absent certificate never equals a present one in either direction`() {
        val present = entity(certificateDer = certificate)
        val absent = entity(certificateDer = null)

        assertNotEquals(present, absent)
        assertNotEquals(absent, present)
    }

    @Test
    fun `slot rows differing only in key or certificate content are not equal`() {
        assertNotEquals(entity(publicKeyDer = byteArrayOf(1)), entity(publicKeyDer = byteArrayOf(2)))
        assertNotEquals(
            entity(certificateDer = byteArrayOf(1)),
            entity(certificateDer = byteArrayOf(1, 2))
        )
    }

    @Test
    fun `slot rows differing in any single scalar field are not equal`() {
        val base = entity()

        assertNotEquals(base, base.copy(id = 2L))
        assertNotEquals(base, base.copy(slotId = "9C"))
        assertNotEquals(base, base.copy(algorithm = "RS2048"))
        assertNotEquals(base, base.copy(algorithm = null))
        assertNotEquals(base, base.copy(hasKey = false))
        assertNotEquals(base, base.copy(createdAt = 1L))
        assertNotEquals(base, base.copy(lastUsedAt = 2L))
        assertNotEquals(base, base.copy(lastUsedAt = null))
        assertNotEquals(base, base.copy(useCount = 4))
    }

    @Test
    fun `hashCode is stable across repeated calls`() {
        val a = entity()

        assertEquals(a.hashCode(), a.hashCode())
    }

    @Test
    fun `copy replaces only the named field`() {
        val base = entity()
        val used = base.copy(useCount = base.useCount + 1, lastUsedAt = 42L)

        assertEquals(4, used.useCount)
        assertEquals(42L, used.lastUsedAt)
        assertEquals(base.slotId, used.slotId)
        assertTrue(base.publicKeyDer.contentEquals(used.publicKeyDer))
    }

    @Test
    fun `toString renders the identifying fields`() {
        val rendered = entity().toString()

        assertTrue(rendered.contains("slotId=9A"))
        assertTrue(rendered.contains("algorithm=ES256"))
        assertTrue(rendered.contains("hasKey=true"))
    }

    // -------------------------------------------------------------------------
    // PivSlotInfo
    // -------------------------------------------------------------------------

    private fun info(publicKeyDer: ByteArray? = publicKey) = PivSlotInfo(
        slot = PivSlot.AUTHENTICATION,
        algorithm = PivAlgorithm.ES256,
        hasKey = true,
        hasCertificate = true,
        publicKeyDer = publicKeyDer,
        createdAt = 1_700_000_000_000L,
        lastUsedAt = 1_700_000_100_000L,
        useCount = 3
    )

    @Test
    fun `two slot views with the same fields are equal and hash alike`() {
        assertEquals(info(), info())
        assertEquals(info().hashCode(), info().hashCode())
    }

    @Test
    fun `a slot view equals itself and nothing unrelated`() {
        val a = info()

        assertEquals(a, a)
        assertNotEquals(a, null)
        assertFalse(a.equals(PivSlot.AUTHENTICATION))
    }

    @Test
    fun `slot views with equal key content in distinct arrays are equal`() {
        assertEquals(info(byteArrayOf(9, 9)), info(byteArrayOf(9, 9)))
        assertEquals(info(byteArrayOf(9, 9)).hashCode(), info(byteArrayOf(9, 9)).hashCode())
    }

    @Test
    fun `two empty slot views compare equal`() {
        val a = info(publicKeyDer = null)
        val b = info(publicKeyDer = null)

        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
    }

    @Test
    fun `a slot view with a key never equals one without in either direction`() {
        val present = info(publicKeyDer = publicKey)
        val absent = info(publicKeyDer = null)

        assertNotEquals(present, absent)
        assertNotEquals(absent, present)
    }

    @Test
    fun `slot views differing in any single field are not equal`() {
        val base = info()

        assertNotEquals(base, base.copy(slot = PivSlot.DIGITAL_SIGNATURE))
        assertNotEquals(base, base.copy(algorithm = PivAlgorithm.RS2048))
        assertNotEquals(base, base.copy(algorithm = null))
        assertNotEquals(base, base.copy(hasKey = false))
        assertNotEquals(base, base.copy(hasCertificate = false))
        assertNotEquals(base, base.copy(publicKeyDer = byteArrayOf(0)))
        assertNotEquals(base, base.copy(createdAt = 1L))
        assertNotEquals(base, base.copy(createdAt = null))
        assertNotEquals(base, base.copy(lastUsedAt = 2L))
        assertNotEquals(base, base.copy(lastUsedAt = null))
        assertNotEquals(base, base.copy(useCount = 4))
    }

    @Test
    fun `an unused slot view reports a null last-used time`() {
        val fresh = info().copy(lastUsedAt = null, useCount = 0)

        assertNull(fresh.lastUsedAt)
        assertEquals(0, fresh.useCount)
    }

    @Test
    fun `a slot view destructures in declaration order`() {
        val (slot, algorithm, hasKey, hasCertificate) = info()

        assertEquals(PivSlot.AUTHENTICATION, slot)
        assertEquals(PivAlgorithm.ES256, algorithm)
        assertTrue(hasKey)
        assertTrue(hasCertificate)
    }

    @Test
    fun `a slot view renders its fields in toString`() {
        val rendered = info().toString()

        assertTrue(rendered.contains("slot=AUTHENTICATION"))
        assertTrue(rendered.contains("algorithm=ES256"))
        assertTrue(rendered.contains("useCount=3"))
    }
}
