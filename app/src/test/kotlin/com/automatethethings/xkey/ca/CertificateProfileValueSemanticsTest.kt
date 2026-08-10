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
package com.automatethethings.xkey.ca

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Value-semantics tests for the [CertificateProfile] hierarchy.
 *
 * `CertificateProfileTest` pins what each profile *contains*; this suite pins
 * how profiles behave as values, which is what the request path actually relies
 * on. A profile arrives over the wire as a name, is resolved with
 * [CertificateProfile.fromName], and is then narrowed with `copy(...)` to add
 * the SANs or validity a caller asked for — so name resolution has to be exact
 * and total, `copy` has to recompute the derived `san`, and equality has to
 * distinguish two profiles that differ only in validity.
 */
class CertificateProfileValueSemanticsTest {

    /** Every profile [CertificateProfile.fromName] is able to build. */
    private val allProfiles: List<CertificateProfile> = listOf(
        CertificateProfile.IDevID(),
        CertificateProfile.TLSServer(),
        CertificateProfile.TLSClient(),
        CertificateProfile.CodeSigning(),
        CertificateProfile.Email(),
        CertificateProfile.OCSPResponder(),
        CertificateProfile.Timestamping(),
        CertificateProfile.SubordinateCA()
    )

    // -------------------------------------------------------------------------
    // Name resolution
    // -------------------------------------------------------------------------

    @Test
    fun `every profile name resolves back to an equal profile`() {
        allProfiles.forEach { profile ->
            assertEquals(
                "round trip failed for ${profile.profileName}",
                profile,
                CertificateProfile.fromName(profile.profileName)
            )
        }
    }

    @Test
    fun `profile names are unique`() {
        assertEquals(allProfiles.size, allProfiles.map { it.profileName }.toSet().size)
    }

    @Test
    fun `an unknown profile name is rejected by name`() {
        val error = assertThrows(IllegalArgumentException::class.java) {
            CertificateProfile.fromName("not-a-profile")
        }

        assertEquals("Unknown certificate profile: not-a-profile", error.message)
    }

    @Test
    fun `an empty or blank profile name is rejected`() {
        assertThrows(IllegalArgumentException::class.java) { CertificateProfile.fromName("") }
        assertThrows(IllegalArgumentException::class.java) { CertificateProfile.fromName("  ") }
    }

    @Test
    fun `a profile name with surrounding whitespace is not silently accepted`() {
        // fromName lower-cases but does not trim; a padded name is a caller bug,
        // not a valid profile.
        assertThrows(IllegalArgumentException::class.java) {
            CertificateProfile.fromName(" tls-server ")
        }
    }

    @Test
    fun `mixed case names resolve for every profile`() {
        allProfiles.forEach { profile ->
            assertEquals(
                profile,
                CertificateProfile.fromName(profile.profileName.uppercase())
            )
        }
    }

    // -------------------------------------------------------------------------
    // Equality and copy
    // -------------------------------------------------------------------------

    @Test
    fun `profiles of the same type with the same settings are equal`() {
        allProfiles.forEach { profile ->
            val twin = CertificateProfile.fromName(profile.profileName)
            assertEquals(profile, twin)
            assertEquals(profile.hashCode(), twin.hashCode())
        }
    }

    @Test
    fun `profiles of different types are never equal`() {
        val client: CertificateProfile = CertificateProfile.TLSClient(validityDays = 365)
        val codeSigning: CertificateProfile = CertificateProfile.CodeSigning(validityDays = 365)
        val idevid: CertificateProfile = CertificateProfile.IDevID()
        val timestamping: CertificateProfile = CertificateProfile.Timestamping()

        assertNotEquals(client, codeSigning)
        assertNotEquals(idevid, timestamping)
    }

    @Test
    fun `a shortened validity makes a different profile`() {
        assertNotEquals(
            CertificateProfile.TLSServer(),
            CertificateProfile.TLSServer(validityDays = 90)
        )
        assertEquals(90, CertificateProfile.TLSServer().copy(validityDays = 90).validityDays)
    }

    @Test
    fun `copy recomputes the TLS server SAN`() {
        val base = CertificateProfile.TLSServer()
        assertNull(base.san)

        val withNames = base.copy(
            dnsNames = listOf("api.example.com"),
            ipAddresses = listOf("10.0.0.7")
        )

        assertNotNull(withNames.san)
        assertEquals(listOf("api.example.com"), withNames.san!!.dnsNames)
        assertEquals(listOf("10.0.0.7"), withNames.san!!.ipAddresses)
        assertTrue(withNames.san!!.emailAddresses.isEmpty())
        // The original is untouched.
        assertNull(base.san)
    }

    @Test
    fun `an IP-only TLS server profile still carries a SAN`() {
        val profile = CertificateProfile.TLSServer(ipAddresses = listOf("192.0.2.10"))

        assertNotNull(profile.san)
        assertTrue(profile.san!!.dnsNames.isEmpty())
    }

    @Test
    fun `copy recomputes the email SANs for client and S-MIME profiles`() {
        val client = CertificateProfile.TLSClient().copy(
            emailAddresses = listOf("user@example.com")
        )
        val smime = CertificateProfile.Email().copy(
            emailAddresses = listOf("user@example.com", "admin@example.com")
        )

        assertEquals(listOf("user@example.com"), client.san!!.emailAddresses)
        assertEquals(2, smime.san!!.emailAddresses.size)
        assertTrue(client.san!!.dnsNames.isEmpty())
    }

    @Test
    fun `clearing the addresses again drops the SAN`() {
        val withEmail = CertificateProfile.Email(emailAddresses = listOf("user@example.com"))

        assertNull(withEmail.copy(emailAddresses = emptyList()).san)
    }

    @Test
    fun `a subordinate CA carries its path length constraint through copy`() {
        val delegated = CertificateProfile.SubordinateCA().copy(
            validityDays = 400,
            pathLenConstraint = 2
        )

        assertEquals(400, delegated.validityDays)
        assertEquals(2, delegated.pathLenConstraint)
        assertNotEquals(CertificateProfile.SubordinateCA(), delegated)
        assertEquals("subordinate-ca", delegated.profileName)
    }

    @Test
    fun `toString names the type and its settings`() {
        val profile = CertificateProfile.TLSServer(
            validityDays = 90,
            dnsNames = listOf("api.example.com")
        )

        val text = profile.toString()

        assertTrue(text, text.startsWith("TLSServer("))
        assertTrue(text, text.contains("validityDays=90"))
        assertTrue(text, text.contains("api.example.com"))
    }

    // -------------------------------------------------------------------------
    // SubjectAlternativeNames
    // -------------------------------------------------------------------------

    @Test
    fun `SubjectAlternativeNames compares by content`() {
        val a = SubjectAlternativeNames(
            dnsNames = listOf("example.com"),
            ipAddresses = listOf("10.0.0.1"),
            emailAddresses = listOf("user@example.com")
        )
        val b = a.copy()

        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
        assertNotEquals(a, a.copy(dnsNames = listOf("other.example.com")))
        assertTrue(a.toString().contains("example.com"))
    }

    @Test
    fun `an empty SubjectAlternativeNames is not equal to a populated one`() {
        assertNotEquals(
            SubjectAlternativeNames(),
            SubjectAlternativeNames(dnsNames = listOf("example.com"))
        )
    }
}
