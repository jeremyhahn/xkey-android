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
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for the value types the CA hands back to callers and persists.
 *
 * [IssuedCertificate] overrides `equals`/`hashCode` by hand (byte arrays do not
 * compare by content), so the contract is asserted explicitly here — a broken
 * override would silently de-duplicate or fail to de-duplicate issued certificates.
 * The RFC 5280 revocation reason codes and the [CertificateEntity] persistence
 * defaults are pinned so they cannot drift.
 */
class CertificateModelsTest {

    private val certA = byteArrayOf(0x30, 0x01, 0x02, 0x03)
    private val certB = byteArrayOf(0x30, 0x09, 0x08, 0x07)

    private fun issued(
        certificate: ByteArray = certA,
        serial: String = "0a1b2c",
        chain: List<ByteArray> = listOf(certA)
    ) = IssuedCertificate(
        certificate = certificate,
        chain = chain,
        serialNumber = serial,
        subjectDN = "CN=device",
        notAfter = 1_700_000_000_000L,
        fingerprint = "ab".repeat(32)
    )

    // -------------------------------------------------------------------------
    // IssuedCertificate equality
    // -------------------------------------------------------------------------

    @Test
    fun `IssuedCertificate equals compares certificate content and serial`() {
        val first = issued(certificate = certA.copyOf())
        val second = issued(certificate = certA.copyOf())

        assertEquals(first, second)
        assertEquals(first.hashCode(), second.hashCode())
    }

    @Test
    fun `IssuedCertificate differs when the certificate bytes differ`() {
        assertNotEquals(issued(certificate = certA), issued(certificate = certB))
    }

    @Test
    fun `IssuedCertificate differs when the serial differs`() {
        assertNotEquals(issued(serial = "01"), issued(serial = "02"))
    }

    @Test
    fun `IssuedCertificate ignores the chain when comparing`() {
        val short = issued(chain = listOf(certA))
        val long = issued(chain = listOf(certA, certB))

        assertEquals(short, long)
    }

    @Test
    fun `IssuedCertificate is not equal to other types or null`() {
        val cert = issued()

        assertFalse(cert.equals(null))
        assertFalse(cert.equals("not a certificate"))
        assertEquals(cert, cert)
    }

    // -------------------------------------------------------------------------
    // CAInitResult
    // -------------------------------------------------------------------------

    @Test
    fun `CAInitResult distinguishes success from already-initialized and error`() {
        val success: CAInitResult = CAInitResult.Success(certA, certB)
        val existing: CAInitResult = CAInitResult.AlreadyInitialized(certA, certB)
        val error: CAInitResult = CAInitResult.Error("no keystore")

        assertTrue(success is CAInitResult.Success)
        assertTrue(existing is CAInitResult.AlreadyInitialized)
        assertEquals("no keystore", (error as CAInitResult.Error).message)
    }

    // -------------------------------------------------------------------------
    // RFC 5280 CRLReason codes
    // -------------------------------------------------------------------------

    @Test
    fun `CRLReason codes match RFC 5280`() {
        assertEquals(0, AndroidCA.CRLReason.UNSPECIFIED)
        assertEquals(1, AndroidCA.CRLReason.KEY_COMPROMISE)
        assertEquals(2, AndroidCA.CRLReason.CA_COMPROMISE)
        assertEquals(3, AndroidCA.CRLReason.AFFILIATION_CHANGED)
        assertEquals(4, AndroidCA.CRLReason.SUPERSEDED)
        assertEquals(5, AndroidCA.CRLReason.CESSATION_OF_OPERATION)
        assertEquals(6, AndroidCA.CRLReason.CERTIFICATE_HOLD)
        assertEquals(9, AndroidCA.CRLReason.PRIVILEGE_WITHDRAWN)
        assertEquals(10, AndroidCA.CRLReason.AA_COMPROMISE)
    }

    // -------------------------------------------------------------------------
    // CertificateEntity persistence defaults
    // -------------------------------------------------------------------------

    @Test
    fun `CertificateEntity defaults to a live non-CA certificate`() {
        val before = System.currentTimeMillis()
        val entity = CertificateEntity(
            serialNumber = "0a",
            subjectDN = "CN=device",
            issuerDN = "CN=xKey Intermediate CA",
            notBefore = 1L,
            notAfter = 2L,
            profile = "tls-server",
            fingerprint = "ab".repeat(32),
            certificatePEM = "-----BEGIN CERTIFICATE-----"
        )

        assertEquals(0L, entity.id)
        assertNull(entity.chainPEM)
        assertNull(entity.keyId)
        assertNull(entity.deviceId)
        assertFalse(entity.revoked)
        assertNull(entity.revokedAt)
        assertNull(entity.revokedReason)
        assertFalse(entity.isCA)
        assertTrue(entity.createdAt >= before)
    }

    @Test
    fun `CertificateEntity revocation is expressed through copy`() {
        val entity = CertificateEntity(
            serialNumber = "0a",
            subjectDN = "CN=device",
            issuerDN = "CN=xKey Intermediate CA",
            notBefore = 1L,
            notAfter = 2L,
            profile = "tls-server",
            fingerprint = "ab".repeat(32),
            certificatePEM = "pem",
            createdAt = 100L
        )

        val revoked = entity.copy(
            revoked = true,
            revokedAt = 500L,
            revokedReason = AndroidCA.CRLReason.KEY_COMPROMISE
        )

        assertFalse(entity.revoked)
        assertTrue(revoked.revoked)
        assertEquals(500L, revoked.revokedAt)
        assertEquals(1, revoked.revokedReason)
        assertEquals(entity.serialNumber, revoked.serialNumber)
    }

    // -------------------------------------------------------------------------
    // SSH certificate authority defaults
    // -------------------------------------------------------------------------

    @Test
    fun `default SSH user extensions match the OpenSSH permit set`() {
        val extensions = SSHCertificateAuthority.DEFAULT_USER_EXTENSIONS

        assertEquals(
            setOf(
                "permit-X11-forwarding",
                "permit-agent-forwarding",
                "permit-port-forwarding",
                "permit-pty",
                "permit-user-rc"
            ),
            extensions.keys
        )
        assertTrue(extensions.values.all { it.isEmpty() })
    }

    @Test
    fun `IssuedSSHCertificate carries the issued principals and validity window`() {
        val issued = IssuedSSHCertificate(
            certificate = "ssh-ed25519-cert-v01@openssh.com AAAA",
            certificateType = "user",
            serialNumber = 42L,
            keyId = "user@example.com",
            validPrincipals = listOf("root", "deploy"),
            validAfter = 1000L,
            validBefore = 2000L,
            fingerprint = "cd".repeat(32)
        )

        assertEquals("user", issued.certificateType)
        assertEquals(listOf("root", "deploy"), issued.validPrincipals)
        assertEquals(1000L, issued.validAfter)
        assertEquals(2000L, issued.validBefore)
        assertEquals(issued, issued.copy())
    }
}
