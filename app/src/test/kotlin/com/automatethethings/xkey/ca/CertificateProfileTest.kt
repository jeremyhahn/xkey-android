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
}
