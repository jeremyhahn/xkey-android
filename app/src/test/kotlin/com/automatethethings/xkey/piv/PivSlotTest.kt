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
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for the [PivSlot] enum.
 *
 * Validates slot lookup, alias conventions, primary/retired classification,
 * uniqueness constraints, and enum cardinality.
 */
class PivSlotTest {

    // -------------------------------------------------------------------------
    // fromHexId lookup
    // -------------------------------------------------------------------------

    @Test
    fun `fromHexId returns correct slot for 9A`() {
        val slot = PivSlot.fromHexId("9A")

        assertNotNull(slot)
        assertEquals(PivSlot.AUTHENTICATION, slot)
    }

    @Test
    fun `fromHexId returns correct slot for 9C`() {
        val slot = PivSlot.fromHexId("9C")

        assertNotNull(slot)
        assertEquals(PivSlot.DIGITAL_SIGNATURE, slot)
    }

    @Test
    fun `fromHexId returns correct slot for 9D`() {
        val slot = PivSlot.fromHexId("9D")

        assertNotNull(slot)
        assertEquals(PivSlot.KEY_MANAGEMENT, slot)
    }

    @Test
    fun `fromHexId returns correct slot for 9E`() {
        val slot = PivSlot.fromHexId("9E")

        assertNotNull(slot)
        assertEquals(PivSlot.CARD_AUTHENTICATION, slot)
    }

    @Test
    fun `fromHexId returns correct slot for F9`() {
        val slot = PivSlot.fromHexId("F9")

        assertNotNull(slot)
        assertEquals(PivSlot.ATTESTATION, slot)
    }

    @Test
    fun `fromHexId returns correct slot for retired slot 82`() {
        val slot = PivSlot.fromHexId("82")

        assertNotNull(slot)
        assertEquals(PivSlot.RETIRED_1, slot)
    }

    @Test
    fun `fromHexId returns null for unknown hex`() {
        assertNull(PivSlot.fromHexId("FF"))
        assertNull(PivSlot.fromHexId("00"))
        assertNull(PivSlot.fromHexId("ZZ"))
    }

    @Test
    fun `fromHexId is case insensitive`() {
        assertEquals(PivSlot.AUTHENTICATION, PivSlot.fromHexId("9a"))
        assertEquals(PivSlot.AUTHENTICATION, PivSlot.fromHexId("9A"))
        assertEquals(PivSlot.ATTESTATION, PivSlot.fromHexId("f9"))
        assertEquals(PivSlot.ATTESTATION, PivSlot.fromHexId("F9"))
        assertEquals(PivSlot.RETIRED_9, PivSlot.fromHexId("8a"))
        assertEquals(PivSlot.RETIRED_9, PivSlot.fromHexId("8A"))
    }

    // -------------------------------------------------------------------------
    // keystoreAlias convention
    // -------------------------------------------------------------------------

    @Test
    fun `keystoreAlias uses correct convention`() {
        assertEquals("xkey_piv_9A", PivSlot.AUTHENTICATION.keystoreAlias)
        assertEquals("xkey_piv_9C", PivSlot.DIGITAL_SIGNATURE.keystoreAlias)
        assertEquals("xkey_piv_9D", PivSlot.KEY_MANAGEMENT.keystoreAlias)
        assertEquals("xkey_piv_9E", PivSlot.CARD_AUTHENTICATION.keystoreAlias)
        assertEquals("xkey_piv_F9", PivSlot.ATTESTATION.keystoreAlias)
        assertEquals("xkey_piv_82", PivSlot.RETIRED_1.keystoreAlias)
        assertEquals("xkey_piv_95", PivSlot.RETIRED_20.keystoreAlias)
    }

    @Test
    fun `keystoreAlias follows xkey_piv_ prefix pattern for all slots`() {
        PivSlot.entries.forEach { slot ->
            assertTrue(
                "Alias for ${slot.name} should start with 'xkey_piv_'",
                slot.keystoreAlias.startsWith("xkey_piv_")
            )
            assertEquals(
                "Alias for ${slot.name} should end with its hexId",
                "xkey_piv_${slot.hexId}",
                slot.keystoreAlias
            )
        }
    }

    // -------------------------------------------------------------------------
    // isPrimarySlot classification
    // -------------------------------------------------------------------------

    @Test
    fun `isPrimarySlot returns true for primary slots`() {
        assertTrue(PivSlot.AUTHENTICATION.isPrimarySlot)
        assertTrue(PivSlot.DIGITAL_SIGNATURE.isPrimarySlot)
        assertTrue(PivSlot.KEY_MANAGEMENT.isPrimarySlot)
        assertTrue(PivSlot.CARD_AUTHENTICATION.isPrimarySlot)
        assertTrue(PivSlot.ATTESTATION.isPrimarySlot)
    }

    @Test
    fun `isPrimarySlot returns false for retired slots`() {
        val retiredSlots = PivSlot.entries.filter { it.name.startsWith("RETIRED_") }

        assertTrue(
            "There should be at least one retired slot",
            retiredSlots.isNotEmpty()
        )

        retiredSlots.forEach { slot ->
            assertFalse(
                "${slot.name} should not be a primary slot",
                slot.isPrimarySlot
            )
        }
    }

    @Test
    fun `exactly 5 primary slots exist`() {
        val primaryCount = PivSlot.entries.count { it.isPrimarySlot }
        assertEquals(5, primaryCount)
    }

    @Test
    fun `exactly 20 retired slots exist`() {
        val retiredCount = PivSlot.entries.count { !it.isPrimarySlot }
        assertEquals(20, retiredCount)
    }

    // -------------------------------------------------------------------------
    // Uniqueness and cardinality
    // -------------------------------------------------------------------------

    @Test
    fun `all slots have unique hexIds`() {
        val hexIds = PivSlot.entries.map { it.hexId }
        val uniqueHexIds = hexIds.toSet()

        assertEquals(
            "All hexIds must be unique",
            hexIds.size,
            uniqueHexIds.size
        )
    }

    @Test
    fun `all slots have unique keystoreAliases`() {
        val aliases = PivSlot.entries.map { it.keystoreAlias }
        val uniqueAliases = aliases.toSet()

        assertEquals(
            "All keystoreAliases must be unique",
            aliases.size,
            uniqueAliases.size
        )
    }

    @Test
    fun `enum has 25 entries total`() {
        assertEquals(
            "PivSlot enum should have 5 primary + 20 retired = 25 entries",
            25,
            PivSlot.entries.size
        )
    }

    // -------------------------------------------------------------------------
    // PivAlgorithm verification
    // -------------------------------------------------------------------------

    @Test
    fun `PivAlgorithm ES256 has correct properties`() {
        assertEquals("EC", PivAlgorithm.ES256.keyAlgorithm)
        assertEquals(256, PivAlgorithm.ES256.keySizeBits)
        assertEquals("ECDSA P-256", PivAlgorithm.ES256.displayName)
    }

    @Test
    fun `PivAlgorithm ES384 has correct properties`() {
        assertEquals("EC", PivAlgorithm.ES384.keyAlgorithm)
        assertEquals(384, PivAlgorithm.ES384.keySizeBits)
        assertEquals("ECDSA P-384", PivAlgorithm.ES384.displayName)
    }

    @Test
    fun `PivAlgorithm RS2048 has correct properties`() {
        assertEquals("RSA", PivAlgorithm.RS2048.keyAlgorithm)
        assertEquals(2048, PivAlgorithm.RS2048.keySizeBits)
        assertEquals("RSA 2048", PivAlgorithm.RS2048.displayName)
    }

    @Test
    fun `PivAlgorithm has exactly 3 entries`() {
        assertEquals(3, PivAlgorithm.entries.size)
    }
}
