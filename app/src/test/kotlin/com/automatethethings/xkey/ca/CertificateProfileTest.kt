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

import org.bouncycastle.asn1.x509.KeyUsage
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class CertificateProfileTest {

    // -------------------------------------------------------------------------
    // TLSServer Profile
    // -------------------------------------------------------------------------

    @Test
    fun `TLSServer has correct defaults`() {
        val profile = CertificateProfile.TLSServer()

        assertEquals(365, profile.validityDays)
        assertEquals("tls-server", profile.profileName)
        assertNotNull(profile.extendedKeyUsageOIDs)
        assertTrue(profile.extendedKeyUsageOIDs!!.contains("1.3.6.1.5.5.7.3.1"))
        assertNull(profile.san)
    }

    @Test
    fun `TLSServer with custom validity`() {
        val profile = CertificateProfile.TLSServer(validityDays = 90)
        assertEquals(90, profile.validityDays)
    }

    @Test
    fun `TLSServer SAN with DNS names and IPs`() {
        val profile = CertificateProfile.TLSServer(
            dnsNames = listOf("example.com", "www.example.com"),
            ipAddresses = listOf("192.168.1.1")
        )

        assertNotNull(profile.san)
        assertEquals(2, profile.san!!.dnsNames.size)
        assertEquals(1, profile.san!!.ipAddresses.size)
        assertEquals("example.com", profile.san!!.dnsNames[0])
    }

    @Test
    fun `TLSServer SAN is null when no names provided`() {
        val profile = CertificateProfile.TLSServer()
        assertNull(profile.san)
    }

    @Test
    fun `TLSServer has digitalSignature and keyEncipherment key usage`() {
        val profile = CertificateProfile.TLSServer()
        assertTrue(profile.keyUsageBits and KeyUsage.digitalSignature != 0)
        assertTrue(profile.keyUsageBits and KeyUsage.keyEncipherment != 0)
    }

    // -------------------------------------------------------------------------
    // TLSClient Profile
    // -------------------------------------------------------------------------

    @Test
    fun `TLSClient has correct defaults`() {
        val profile = CertificateProfile.TLSClient()

        assertEquals(365, profile.validityDays)
        assertEquals("tls-client", profile.profileName)
        assertTrue(profile.extendedKeyUsageOIDs!!.contains("1.3.6.1.5.5.7.3.2"))
    }

    @Test
    fun `TLSClient SAN with email addresses`() {
        val profile = CertificateProfile.TLSClient(
            emailAddresses = listOf("user@example.com")
        )

        assertNotNull(profile.san)
        assertEquals(1, profile.san!!.emailAddresses.size)
    }

    // -------------------------------------------------------------------------
    // IDevID Profile
    // -------------------------------------------------------------------------

    @Test
    fun `IDevID has correct defaults`() {
        val profile = CertificateProfile.IDevID()

        assertEquals(365, profile.validityDays)
        assertEquals("idevid", profile.profileName)
        assertNull(profile.extendedKeyUsageOIDs)
        assertNull(profile.san)
    }

    // -------------------------------------------------------------------------
    // CodeSigning Profile
    // -------------------------------------------------------------------------

    @Test
    fun `CodeSigning has correct defaults`() {
        val profile = CertificateProfile.CodeSigning()

        assertEquals(365, profile.validityDays)
        assertEquals("code-signing", profile.profileName)
        assertTrue(profile.extendedKeyUsageOIDs!!.contains("1.3.6.1.5.5.7.3.3"))
        assertNull(profile.san)
    }

    // -------------------------------------------------------------------------
    // Email Profile
    // -------------------------------------------------------------------------

    @Test
    fun `Email has correct defaults`() {
        val profile = CertificateProfile.Email()

        assertEquals(365, profile.validityDays)
        assertEquals("email", profile.profileName)
        assertTrue(profile.extendedKeyUsageOIDs!!.contains("1.3.6.1.5.5.7.3.4"))
    }

    @Test
    fun `Email has digitalSignature nonRepudiation keyEncipherment`() {
        val profile = CertificateProfile.Email()
        assertTrue(profile.keyUsageBits and KeyUsage.digitalSignature != 0)
        assertTrue(profile.keyUsageBits and KeyUsage.nonRepudiation != 0)
        assertTrue(profile.keyUsageBits and KeyUsage.keyEncipherment != 0)
    }

    @Test
    fun `Email SAN with email addresses`() {
        val profile = CertificateProfile.Email(
            emailAddresses = listOf("user@example.com", "admin@example.com")
        )

        assertNotNull(profile.san)
        assertEquals(2, profile.san!!.emailAddresses.size)
    }

    // -------------------------------------------------------------------------
    // OCSPResponder Profile
    // -------------------------------------------------------------------------

    @Test
    fun `OCSPResponder has 90 day default validity`() {
        val profile = CertificateProfile.OCSPResponder()

        assertEquals(90, profile.validityDays)
        assertEquals("ocsp-responder", profile.profileName)
        assertTrue(profile.extendedKeyUsageOIDs!!.contains("1.3.6.1.5.5.7.3.9"))
    }

    // -------------------------------------------------------------------------
    // Timestamping Profile
    // -------------------------------------------------------------------------

    @Test
    fun `Timestamping has correct defaults`() {
        val profile = CertificateProfile.Timestamping()

        assertEquals(365, profile.validityDays)
        assertEquals("timestamping", profile.profileName)
        assertTrue(profile.extendedKeyUsageOIDs!!.contains("1.3.6.1.5.5.7.3.8"))
    }

    @Test
    fun `Timestamping has digitalSignature and nonRepudiation`() {
        val profile = CertificateProfile.Timestamping()
        assertTrue(profile.keyUsageBits and KeyUsage.digitalSignature != 0)
        assertTrue(profile.keyUsageBits and KeyUsage.nonRepudiation != 0)
    }

    // -------------------------------------------------------------------------
    // SubordinateCA Profile
    // -------------------------------------------------------------------------

    @Test
    fun `SubordinateCA has 5 year default validity`() {
        val profile = CertificateProfile.SubordinateCA()

        assertEquals(1825, profile.validityDays)
        assertEquals("subordinate-ca", profile.profileName)
        assertNull(profile.extendedKeyUsageOIDs)
    }

    @Test
    fun `SubordinateCA has keyCertSign and cRLSign`() {
        val profile = CertificateProfile.SubordinateCA()
        assertTrue(profile.keyUsageBits and KeyUsage.keyCertSign != 0)
        assertTrue(profile.keyUsageBits and KeyUsage.cRLSign != 0)
    }

    @Test
    fun `SubordinateCA default pathLenConstraint is 0`() {
        val profile = CertificateProfile.SubordinateCA()
        assertEquals(0, profile.pathLenConstraint)
    }

    // -------------------------------------------------------------------------
    // fromName Factory
    // -------------------------------------------------------------------------

    @Test
    fun `fromName creates correct profile types`() {
        assertTrue(CertificateProfile.fromName("tls-server") is CertificateProfile.TLSServer)
        assertTrue(CertificateProfile.fromName("tls-client") is CertificateProfile.TLSClient)
        assertTrue(CertificateProfile.fromName("idevid") is CertificateProfile.IDevID)
        assertTrue(CertificateProfile.fromName("code-signing") is CertificateProfile.CodeSigning)
        assertTrue(CertificateProfile.fromName("email") is CertificateProfile.Email)
        assertTrue(CertificateProfile.fromName("ocsp-responder") is CertificateProfile.OCSPResponder)
        assertTrue(CertificateProfile.fromName("timestamping") is CertificateProfile.Timestamping)
        assertTrue(CertificateProfile.fromName("subordinate-ca") is CertificateProfile.SubordinateCA)
    }

    @Test
    fun `fromName is case insensitive`() {
        assertTrue(CertificateProfile.fromName("TLS-SERVER") is CertificateProfile.TLSServer)
        assertTrue(CertificateProfile.fromName("Tls-Client") is CertificateProfile.TLSClient)
    }

    // -------------------------------------------------------------------------
    // SubjectAlternativeNames
    // -------------------------------------------------------------------------

    @Test
    fun `SubjectAlternativeNames defaults are empty`() {
        val san = SubjectAlternativeNames()

        assertTrue(san.dnsNames.isEmpty())
        assertTrue(san.ipAddresses.isEmpty())
        assertTrue(san.emailAddresses.isEmpty())
    }

    @Test
    fun `SubjectAlternativeNames holds all fields`() {
        val san = SubjectAlternativeNames(
            dnsNames = listOf("example.com"),
            ipAddresses = listOf("10.0.0.1"),
            emailAddresses = listOf("test@example.com")
        )

        assertEquals(1, san.dnsNames.size)
        assertEquals(1, san.ipAddresses.size)
        assertEquals(1, san.emailAddresses.size)
    }
}
