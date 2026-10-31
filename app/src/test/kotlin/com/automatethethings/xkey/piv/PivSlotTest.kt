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
    fun `every slot maps to its fixed hex id and keystore alias`() {
        val expected = listOf(
            Triple(PivSlot.AUTHENTICATION, "9A", "xkey_piv_9A"),
            Triple(PivSlot.DIGITAL_SIGNATURE, "9C", "xkey_piv_9C"),
            Triple(PivSlot.KEY_MANAGEMENT, "9D", "xkey_piv_9D"),
            Triple(PivSlot.CARD_AUTHENTICATION, "9E", "xkey_piv_9E"),
            Triple(PivSlot.ATTESTATION, "F9", "xkey_piv_F9"),
            Triple(PivSlot.RETIRED_1, "82", "xkey_piv_82"),
            Triple(PivSlot.RETIRED_2, "83", "xkey_piv_83"),
            Triple(PivSlot.RETIRED_3, "84", "xkey_piv_84"),
            Triple(PivSlot.RETIRED_4, "85", "xkey_piv_85"),
            Triple(PivSlot.RETIRED_5, "86", "xkey_piv_86"),
            Triple(PivSlot.RETIRED_6, "87", "xkey_piv_87"),
            Triple(PivSlot.RETIRED_7, "88", "xkey_piv_88"),
            Triple(PivSlot.RETIRED_8, "89", "xkey_piv_89"),
            Triple(PivSlot.RETIRED_9, "8A", "xkey_piv_8A"),
            Triple(PivSlot.RETIRED_10, "8B", "xkey_piv_8B"),
            Triple(PivSlot.RETIRED_11, "8C", "xkey_piv_8C"),
            Triple(PivSlot.RETIRED_12, "8D", "xkey_piv_8D"),
            Triple(PivSlot.RETIRED_13, "8E", "xkey_piv_8E"),
            Triple(PivSlot.RETIRED_14, "8F", "xkey_piv_8F"),
            Triple(PivSlot.RETIRED_15, "90", "xkey_piv_90"),
            Triple(PivSlot.RETIRED_16, "91", "xkey_piv_91"),
            Triple(PivSlot.RETIRED_17, "92", "xkey_piv_92"),
            Triple(PivSlot.RETIRED_18, "93", "xkey_piv_93"),
            Triple(PivSlot.RETIRED_19, "94", "xkey_piv_94"),
            Triple(PivSlot.RETIRED_20, "95", "xkey_piv_95"),
        )

        assertEquals("table must cover every slot", PivSlot.entries.toSet(), expected.map { it.first }.toSet())
        expected.forEach { (slot, hexId, alias) ->
            assertEquals("fromHexId(\"$hexId\") must return $slot", slot, PivSlot.fromHexId(hexId))
            assertEquals("$slot keystoreAlias", alias, slot.keystoreAlias)
        }
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
}
