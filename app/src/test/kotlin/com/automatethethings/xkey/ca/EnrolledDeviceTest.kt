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

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for the [EnrolledDevice] value type.
 *
 * `EnrolledDeviceRepository` de-duplicates enrolments with `removeAll { it.deviceId == ... }`
 * and looks devices up by identity, so the hand-written `equals`/`hashCode` (byte-array
 * fields force the override) and the attestation predicates are the parts worth pinning.
 * JSON serialisation is deliberately not covered here: it goes through `android.util.Base64`
 * and `org.json`, neither of which exists in a JVM unit test.
 */
class EnrolledDeviceTest {

    private fun device(
        deviceId: String = "device-1",
        publicKeyHex: String = "aabb",
        ekCertificateDER: ByteArray? = null,
        initialQuote: ByteArray? = null,
        idevidCertificateDER: ByteArray? = null,
        tlsServerCertificateDER: ByteArray? = null,
        tlsClientCertificateDER: ByteArray? = null,
        sshUserCertificate: String? = null,
        sshHostCertificate: String? = null
    ) = EnrolledDevice(
        deviceId = deviceId,
        publicKeyHex = publicKeyHex,
        ekCertificateDER = ekCertificateDER,
        initialQuote = initialQuote,
        idevidCertificateDER = idevidCertificateDER,
        tlsServerCertificateDER = tlsServerCertificateDER,
        tlsClientCertificateDER = tlsClientCertificateDER,
        sshUserCertificate = sshUserCertificate,
        sshHostCertificate = sshHostCertificate,
        enrolledAt = 1_700_000_000_000L,
        trustLevel = "android-ca"
    )

    // -------------------------------------------------------------------------
    // Attestation predicates
    // -------------------------------------------------------------------------

    @Test
    fun `hasFullAttestation requires both an EK certificate and a baseline quote`() {
        assertTrue(
            device(ekCertificateDER = byteArrayOf(1), initialQuote = byteArrayOf(2))
                .hasFullAttestation()
        )
        assertFalse(device(ekCertificateDER = byteArrayOf(1)).hasFullAttestation())
        assertFalse(device(initialQuote = byteArrayOf(2)).hasFullAttestation())
        assertFalse(device().hasFullAttestation())
    }

    @Test
    fun `hasFullAttestation is true even for an empty EK certificate`() {
        // Presence, not content, is what the predicate promises.
        assertTrue(
            device(ekCertificateDER = ByteArray(0), initialQuote = ByteArray(0))
                .hasFullAttestation()
        )
    }

    @Test
    fun `certificate predicates report exactly what is stored`() {
        assertFalse(device().hasIDevIDCertificate())
        assertTrue(device(idevidCertificateDER = byteArrayOf(1)).hasIDevIDCertificate())

        assertFalse(device().hasTLSServerCertificate())
        assertTrue(device(tlsServerCertificateDER = byteArrayOf(1)).hasTLSServerCertificate())

        assertFalse(device().hasTLSClientCertificate())
        assertTrue(device(tlsClientCertificateDER = byteArrayOf(1)).hasTLSClientCertificate())

        assertFalse(device().hasSSHUserCertificate())
        assertTrue(device(sshUserCertificate = "ssh-cert").hasSSHUserCertificate())

        assertFalse(device().hasSSHHostCertificate())
        assertTrue(device(sshHostCertificate = "ssh-cert").hasSSHHostCertificate())
    }

    // -------------------------------------------------------------------------
    // Identity semantics
    // -------------------------------------------------------------------------

    @Test
    fun `devices with the same identity are equal regardless of certificate payloads`() {
        val a = device(idevidCertificateDER = byteArrayOf(1, 2, 3))
        val b = device(idevidCertificateDER = byteArrayOf(9, 9))

        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
    }

    @Test
    fun `devices with different device ids are not equal`() {
        assertNotEquals(device(deviceId = "device-1"), device(deviceId = "device-2"))
    }

    @Test
    fun `devices with different public keys are not equal`() {
        assertNotEquals(device(publicKeyHex = "aabb"), device(publicKeyHex = "ccdd"))
    }

    @Test
    fun `a device is not equal to other types or null`() {
        val enrolled = device()

        assertFalse(enrolled.equals(null))
        assertFalse(enrolled.equals("device-1"))
        assertEquals(enrolled, enrolled)
    }

    // -------------------------------------------------------------------------
    // Quote verification results
    // -------------------------------------------------------------------------

    @Test
    fun `QuoteVerificationResult carries the drifted PCR indexes`() {
        val valid = QuoteVerificationResult.Valid(pcrDrift = listOf(0, 7))

        assertEquals(listOf(0, 7), valid.pcrDrift)
        assertEquals(valid, QuoteVerificationResult.Valid(listOf(0, 7)))
    }

    @Test
    fun `QuoteVerificationResult distinguishes invalid from not enrolled`() {
        val invalid = QuoteVerificationResult.Invalid("pcr mismatch")
        val notEnrolled: QuoteVerificationResult = QuoteVerificationResult.NotEnrolled

        assertEquals("pcr mismatch", invalid.reason)
        assertTrue(notEnrolled is QuoteVerificationResult.NotEnrolled)
        assertNotEquals(invalid, notEnrolled)
    }
}
