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
package com.automatethethings.xkey.ca

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1String
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.style.BCStyle
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for [CASubject.toX500Name].
 *
 * This is the only part of the CA subject pipeline that runs without the Android
 * Keystore, and it decides what ends up in the issuer/subject field of every
 * certificate the device signs: RDN ordering, omission of unset components, the
 * fallback common name, and DER escaping of values that contain X.500 separators.
 */
class CASubjectTest {

    /** The raw (unescaped) RDN value, read straight off the ASN.1 string. */
    private fun rdnValue(name: X500Name, oid: ASN1ObjectIdentifier): String? =
        name.getRDNs(oid).firstOrNull()?.first?.value?.let { (it as ASN1String).string }

    private fun rdnOids(name: X500Name): List<ASN1ObjectIdentifier> =
        name.getRDNs().map { it.first.type }

    // -------------------------------------------------------------------------
    // Common name fallback
    // -------------------------------------------------------------------------

    @Test
    fun `toX500Name falls back to the default CN when none is set`() {
        val name = CASubject().toX500Name("xKey Root CA")

        assertEquals(listOf(BCStyle.CN), rdnOids(name))
        assertEquals("xKey Root CA", rdnValue(name, BCStyle.CN))
    }

    @Test
    fun `toX500Name falls back to the default CN when the CN is blank`() {
        val name = CASubject(cn = "   ").toX500Name("xKey Intermediate CA")

        assertEquals("xKey Intermediate CA", rdnValue(name, BCStyle.CN))
    }

    // -------------------------------------------------------------------------
    // RDN composition and ordering
    // -------------------------------------------------------------------------

    @Test
    fun `toX500Name emits RDNs in country to common name order`() {
        val name = CASubject(
            cn = "Acme Root",
            org = "Acme Corp",
            ou = "Security",
            locality = "San Francisco",
            province = "California",
            country = "US"
        ).toX500Name("unused")

        assertEquals(
            listOf(BCStyle.C, BCStyle.ST, BCStyle.L, BCStyle.O, BCStyle.OU, BCStyle.CN),
            rdnOids(name)
        )
        assertEquals("US", rdnValue(name, BCStyle.C))
        assertEquals("California", rdnValue(name, BCStyle.ST))
        assertEquals("San Francisco", rdnValue(name, BCStyle.L))
        assertEquals("Acme Corp", rdnValue(name, BCStyle.O))
        assertEquals("Security", rdnValue(name, BCStyle.OU))
        assertEquals("Acme Root", rdnValue(name, BCStyle.CN))
    }

    @Test
    fun `toX500Name omits blank components`() {
        val name = CASubject(
            cn = "Acme Root",
            org = "Acme Corp",
            ou = "",
            locality = "  ",
            province = "",
            country = "US"
        ).toX500Name("unused")

        assertEquals(listOf(BCStyle.C, BCStyle.O, BCStyle.CN), rdnOids(name))
        assertTrue(name.getRDNs(BCStyle.OU).isEmpty())
        assertTrue(name.getRDNs(BCStyle.L).isEmpty())
        assertTrue(name.getRDNs(BCStyle.ST).isEmpty())
    }

    // -------------------------------------------------------------------------
    // Encoding
    // -------------------------------------------------------------------------

    @Test
    fun `toX500Name escapes X500 separators inside values`() {
        val name = CASubject(cn = "Acme, Inc.", org = "a+b").toX500Name("unused")

        assertEquals("Acme, Inc.", rdnValue(name, BCStyle.CN))
        assertEquals("a+b", rdnValue(name, BCStyle.O))
        // The rendered form escapes the separators so the DN can be re-parsed.
        assertTrue("rendered as $name", name.toString().contains("\\,"))
        assertEquals(name, X500Name(name.toString()))
    }
}
