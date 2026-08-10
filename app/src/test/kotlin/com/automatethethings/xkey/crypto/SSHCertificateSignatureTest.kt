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
package com.automatethethings.xkey.crypto

import android.util.Base64
import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.unmockkStatic
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * Unit tests for [SSHCertificateEncoder.buildSignedCertificate], the one entry
 * point that depends on `android.util.Base64` (stubbed here with MockK, the
 * same pattern used by `PinManagerTest`).
 *
 * Signatures are produced with the JVM JCE provider so the DER->SSH mpint
 * conversion is exercised against real ECDSA output, including the DER
 * long-form length that a P-521 signature produces.
 */
class SSHCertificateSignatureTest {

    private lateinit var p256: KeyPair
    private lateinit var p521: KeyPair
    private lateinit var rsa: KeyPair

    @Before
    fun setUp() {
        mockkStatic(Base64::class)
        every { Base64.encodeToString(any(), any()) } answers {
            java.util.Base64.getEncoder().encodeToString(firstArg())
        }
        p256 = ec("secp256r1")
        p521 = ec("secp521r1")
        rsa = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
    }

    @After
    fun tearDown() {
        unmockkStatic(Base64::class)
    }

    private fun ec(curve: String): KeyPair =
        KeyPairGenerator.getInstance("EC")
            .apply { initialize(ECGenParameterSpec(curve)) }
            .generateKeyPair()

    private fun signer(key: PrivateKey, algorithm: String): (ByteArray) -> ByteArray = { data ->
        Signature.getInstance(algorithm).apply {
            initSign(key)
            update(data)
        }.sign()
    }

    private fun body(subject: PublicKey, ca: PublicKey): ByteArray =
        SSHCertificateEncoder.buildCertificateBody(
            subjectPublicKey = subject,
            serial = 42L,
            certType = SSHCertificateEncoder.SSH_CERT_TYPE_USER,
            keyId = "alice@example.com",
            validPrincipals = listOf("alice"),
            validAfter = 1_700_000_000L,
            validBefore = 1_800_000_000L,
            criticalOptions = emptyMap(),
            extensions = mapOf("permit-pty" to ""),
            caPublicKey = ca
        )

    /** Reads SSH strings out of a blob. */
    private class SshReader(private val data: ByteArray) {
        private var pos = 0
        val remaining: Int get() = data.size - pos
        fun bytes(): ByteArray {
            var len = 0
            repeat(4) { len = (len shl 8) or (data[pos++].toInt() and 0xFF) }
            val out = data.copyOfRange(pos, pos + len)
            pos += len
            return out
        }
        fun text(): String = String(bytes(), Charsets.UTF_8)
    }

    /** Independent minimal DER SEQUENCE{INTEGER r, INTEGER s} parser. */
    private fun derRS(der: ByteArray): Pair<BigInteger, BigInteger> {
        var i = 0
        require(der[i++].toInt() == 0x30) { "not a SEQUENCE" }
        val first = der[i++].toInt() and 0xFF
        if (first and 0x80 != 0) i += first and 0x7F
        require(der[i++].toInt() == 0x02)
        val rLen = der[i++].toInt() and 0xFF
        val r = BigInteger(der.copyOfRange(i, i + rLen))
        i += rLen
        require(der[i++].toInt() == 0x02)
        val sLen = der[i++].toInt() and 0xFF
        val s = BigInteger(der.copyOfRange(i, i + sLen))
        return r to s
    }

    /**
     * Splits a certificate line into its type token and the decoded blob, and
     * asserts the blob starts with [expectedBody]. Returns the trailing
     * signature blob.
     */
    private fun signatureBlobOf(line: String, expectedBody: ByteArray, expectedType: String): ByteArray {
        val parts = line.split(" ")
        assertEquals("certificate line must be '<type> <base64>'", 2, parts.size)
        assertEquals(expectedType, parts[0])
        val decoded = java.util.Base64.getDecoder().decode(parts[1])
        assertArrayEquals(expectedBody, decoded.copyOfRange(0, expectedBody.size))
        val reader = SshReader(decoded.copyOfRange(expectedBody.size, decoded.size))
        val blob = reader.bytes()
        assertEquals("no bytes may follow the signature", 0, reader.remaining)
        return blob
    }

    @Test
    fun `EC signature is emitted as algorithm plus r and s mpints`() {
        val certBody = body(p256.public, p256.public)
        val rawSignature = signer(p256.private, "SHA256withECDSA")(certBody)

        val line = SSHCertificateEncoder.buildSignedCertificate(
            certBody,
            { rawSignature },
            p256.public
        )

        val blob = signatureBlobOf(
            line,
            certBody,
            "ecdsa-sha2-nistp256-cert-v01@openssh.com"
        )
        val blobReader = SshReader(blob)
        assertEquals("ecdsa-sha2-nistp256", blobReader.text())
        val rs = SshReader(blobReader.bytes())
        assertEquals(0, blobReader.remaining)

        val (expectedR, expectedS) = derRS(rawSignature)
        assertEquals(expectedR, BigInteger(rs.bytes()))
        assertEquals(expectedS, BigInteger(rs.bytes()))
        assertEquals(0, rs.remaining)
    }

    @Test
    fun `EC signature over the body verifies against the CA key`() {
        val certBody = body(p256.public, p256.public)
        var signedInput: ByteArray? = null
        SSHCertificateEncoder.buildSignedCertificate(
            certBody,
            { data ->
                signedInput = data
                signer(p256.private, "SHA256withECDSA")(data)
            },
            p256.public
        )
        assertArrayEquals("the callback must be handed the exact body", certBody, signedInput)
    }

    @Test
    fun `P-521 DER long-form length is decoded correctly`() {
        val certBody = body(p521.public, p521.public)
        val rawSignature = signer(p521.private, "SHA512withECDSA")(certBody)
        // A P-521 signature is long enough that DER uses the 0x81 long form.
        assertTrue(
            "expected DER long-form length, got 0x%02x".format(rawSignature[1]),
            rawSignature[1].toInt() and 0x80 != 0
        )

        val line = SSHCertificateEncoder.buildSignedCertificate(
            certBody,
            { rawSignature },
            p521.public
        )

        val blob = signatureBlobOf(line, certBody, "ecdsa-sha2-nistp521-cert-v01@openssh.com")
        val blobReader = SshReader(blob)
        assertEquals("ecdsa-sha2-nistp521", blobReader.text())
        val rs = SshReader(blobReader.bytes())
        val (expectedR, expectedS) = derRS(rawSignature)
        assertEquals(expectedR, BigInteger(rs.bytes()))
        assertEquals(expectedS, BigInteger(rs.bytes()))
        assertEquals(0, rs.remaining)
    }

    @Test
    fun `RSA signature is embedded verbatim`() {
        val certBody = body(rsa.public, rsa.public)
        val rawSignature = signer(rsa.private, "SHA256withRSA")(certBody)

        val line = SSHCertificateEncoder.buildSignedCertificate(
            certBody,
            { rawSignature },
            rsa.public
        )

        val blob = signatureBlobOf(line, certBody, "ssh-rsa-cert-v01@openssh.com")
        val blobReader = SshReader(blob)
        assertEquals("ssh-rsa", blobReader.text())
        assertArrayEquals(rawSignature, blobReader.bytes())
        assertEquals(0, blobReader.remaining)
    }

    @Test
    fun `cert type token is taken from the body, not the CA key`() {
        // Subject P-384, CA P-256: the line must advertise the subject's type.
        val p384 = ec("secp384r1")
        val certBody = body(p384.public, p256.public)
        val line = SSHCertificateEncoder.buildSignedCertificate(
            certBody,
            signer(p256.private, "SHA256withECDSA"),
            p256.public
        )
        assertEquals("ecdsa-sha2-nistp384-cert-v01@openssh.com", line.split(" ")[0])
    }

    @Test
    fun `unsupported CA key type is rejected`() {
        val dsa = KeyPairGenerator.getInstance("DSA").apply { initialize(1024) }.generateKeyPair()
        val certBody = body(p256.public, p256.public)
        assertThrows(IllegalArgumentException::class.java) {
            SSHCertificateEncoder.buildSignedCertificate(certBody, { ByteArray(8) }, dsa.public)
        }
    }

    @Test
    fun `signature without a DER SEQUENCE tag is rejected`() {
        val certBody = body(p256.public, p256.public)
        val error = assertThrows(IllegalArgumentException::class.java) {
            SSHCertificateEncoder.buildSignedCertificate(
                certBody,
                { byteArrayOf(0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02) },
                p256.public
            )
        }
        assertEquals("Invalid DER signature: expected SEQUENCE tag", error.message)
    }

    @Test
    fun `signature without an INTEGER tag for r is rejected`() {
        val certBody = body(p256.public, p256.public)
        val error = assertThrows(IllegalArgumentException::class.java) {
            SSHCertificateEncoder.buildSignedCertificate(
                certBody,
                { byteArrayOf(0x30, 0x06, 0x03, 0x01, 0x01, 0x02, 0x01, 0x02) },
                p256.public
            )
        }
        assertEquals("Invalid DER signature: expected INTEGER tag for r", error.message)
    }

    @Test
    fun `signature without an INTEGER tag for s is rejected`() {
        val certBody = body(p256.public, p256.public)
        val error = assertThrows(IllegalArgumentException::class.java) {
            SSHCertificateEncoder.buildSignedCertificate(
                certBody,
                { byteArrayOf(0x30, 0x06, 0x02, 0x01, 0x01, 0x03, 0x01, 0x02) },
                p256.public
            )
        }
        assertEquals("Invalid DER signature: expected INTEGER tag for s", error.message)
    }
}
