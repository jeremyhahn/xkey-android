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

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECFieldFp
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.EllipticCurve

/**
 * Unit tests for the pure (framework-free) half of [SSHCertificateEncoder]:
 * the OpenSSH PROTOCOL.certkeys wire format.
 *
 * Every assertion decodes the produced bytes with an independent SSH wire
 * reader defined in this file and checks the concrete field values, rather
 * than round-tripping through the encoder itself. Ed25519 support and the
 * `buildSignedCertificate` entry point depend on `Build.VERSION.SDK_INT` and
 * `android.util.Base64`; the signing path is covered by
 * [SSHCertificateSignatureTest].
 */
class SSHCertificateEncoderTest {

    // -----------------------------------------------------------------------
    // Fixtures (generated once; all key material is immutable and shared)
    // -----------------------------------------------------------------------

    private companion object {
        val p256: KeyPair by lazy { ecKeyPair("secp256r1") }
        val p384: KeyPair by lazy { ecKeyPair("secp384r1") }
        val p521: KeyPair by lazy { ecKeyPair("secp521r1") }
        val rsa: KeyPair by lazy {
            KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        }

        fun ecKeyPair(curve: String): KeyPair =
            KeyPairGenerator.getInstance("EC")
                .apply { initialize(ECGenParameterSpec(curve)) }
                .generateKeyPair()

        /**
         * An EC public key on a curve whose field size the encoder does not
         * support (the JDK no longer ships such a curve, so it is synthesised).
         */
        fun unsupportedCurveKey(fieldBits: Int = 224): ECPublicKey {
            val p = BigInteger.ONE.shiftLeft(fieldBits - 1)
            val curve = EllipticCurve(ECFieldFp(p), BigInteger.ZERO, BigInteger.ONE)
            val generator = ECPoint(BigInteger.ONE, BigInteger.ONE)
            val spec = ECParameterSpec(curve, generator, BigInteger.valueOf(7), 1)
            return object : ECPublicKey {
                override fun getW(): ECPoint = generator
                override fun getParams(): ECParameterSpec = spec
                override fun getAlgorithm(): String = "EC"
                override fun getFormat(): String = "X.509"
                override fun getEncoded(): ByteArray = ByteArray(0)
            }
        }
    }

    /** Minimal reader for the SSH wire format (RFC 4251 §5). */
    private class SshReader(private val data: ByteArray) {
        private var pos = 0

        val remaining: Int get() = data.size - pos

        fun uint32(): Long {
            var value = 0L
            repeat(4) { value = (value shl 8) or (data[pos++].toLong() and 0xFF) }
            return value
        }

        fun uint64(): Long {
            var value = 0L
            repeat(8) { value = (value shl 8) or (data[pos++].toLong() and 0xFF) }
            return value
        }

        fun bytes(): ByteArray {
            val len = uint32().toInt()
            val out = data.copyOfRange(pos, pos + len)
            pos += len
            return out
        }

        fun text(): String = String(bytes(), Charsets.UTF_8)
    }

    /** Decoded view of a certificate body, for field-by-field assertions. */
    private class CertBody(
        val type: String,
        val nonce: ByteArray,
        val curveName: String?,
        val ecPoint: ByteArray?,
        val rsaExponent: ByteArray?,
        val rsaModulus: ByteArray?,
        val serial: Long,
        val certType: Long,
        val keyId: String,
        val principals: List<String>,
        val validAfter: Long,
        val validBefore: Long,
        val criticalOptions: List<Pair<String, String>>,
        val extensions: List<Pair<String, String>>,
        val reserved: ByteArray,
        val signatureKey: ByteArray,
        val trailingBytes: Int
    )

    private fun parseBody(body: ByteArray, ec: Boolean): CertBody {
        val r = SshReader(body)
        val type = r.text()
        val nonce = r.bytes()
        var curveName: String? = null
        var ecPoint: ByteArray? = null
        var rsaE: ByteArray? = null
        var rsaN: ByteArray? = null
        if (ec) {
            curveName = r.text()
            ecPoint = r.bytes()
        } else {
            rsaE = r.bytes()
            rsaN = r.bytes()
        }
        val serial = r.uint64()
        val certType = r.uint32()
        val keyId = r.text()
        val principals = SshReader(r.bytes()).let { pr ->
            val list = mutableListOf<String>()
            while (pr.remaining > 0) list += pr.text()
            list
        }
        val validAfter = r.uint64()
        val validBefore = r.uint64()
        val critical = parseOptions(r.bytes())
        val extensions = parseOptions(r.bytes())
        val reserved = r.bytes()
        val signatureKey = r.bytes()
        return CertBody(
            type, nonce, curveName, ecPoint, rsaE, rsaN, serial, certType, keyId,
            principals, validAfter, validBefore, critical, extensions, reserved,
            signatureKey, r.remaining
        )
    }

    /** Options/extensions are name || string(string(value)) pairs. */
    private fun parseOptions(blob: ByteArray): List<Pair<String, String>> {
        val r = SshReader(blob)
        val out = mutableListOf<Pair<String, String>>()
        while (r.remaining > 0) {
            val name = r.text()
            val wrapped = r.bytes()
            out += name to SshReader(wrapped).text()
        }
        return out
    }

    private fun buildBody(
        subject: java.security.PublicKey = p256.public,
        serial: Long = 0x0102030405060708L,
        certType: Int = SSHCertificateEncoder.SSH_CERT_TYPE_USER,
        keyId: String = "user@example.com",
        principals: List<String> = listOf("alice", "root"),
        validAfter: Long = 1_700_000_000L,
        validBefore: Long = 1_800_000_000L,
        critical: Map<String, String> = emptyMap(),
        extensions: Map<String, String> = emptyMap(),
        ca: java.security.PublicKey = p256.public
    ): ByteArray = SSHCertificateEncoder.buildCertificateBody(
        subjectPublicKey = subject,
        serial = serial,
        certType = certType,
        keyId = keyId,
        validPrincipals = principals,
        validAfter = validAfter,
        validBefore = validBefore,
        criticalOptions = critical,
        extensions = extensions,
        caPublicKey = ca
    )

    // -----------------------------------------------------------------------
    // Primitive wire encoders
    // -----------------------------------------------------------------------

    @Test
    fun `writeUint32 masks the sign bit of a negative int`() {
        val out = ByteArrayOutputStream()
        SSHCertificateEncoder.writeUint32(out, -1)
        assertArrayEquals(ByteArray(4) { 0xFF.toByte() }, out.toByteArray())
    }

    @Test
    fun `padCoordinate returns exact-size input unchanged`() {
        val exact = ByteArray(32) { 0x11 }
        assertArrayEquals(exact, SSHCertificateEncoder.padCoordinate(exact, 32))
    }

    @Test
    fun `padCoordinate drops the BigInteger sign byte`() {
        // A 32-byte magnitude with the high bit set gains a 0x00 sign byte.
        val magnitude = ByteArray(32) { 0xFF.toByte() }
        val signed = BigInteger(1, magnitude).toByteArray()
        assertEquals(33, signed.size)
        assertEquals(0, signed[0].toInt())
        assertArrayEquals(magnitude, SSHCertificateEncoder.padCoordinate(signed, 32))
    }

    @Test
    fun `padCoordinate left-pads a short coordinate with zeros`() {
        val short = byteArrayOf(0x0A, 0x0B)
        val padded = SSHCertificateEncoder.padCoordinate(short, 5)
        assertArrayEquals(byteArrayOf(0, 0, 0, 0x0A, 0x0B), padded)
    }

    // -----------------------------------------------------------------------
    // Key type strings
    // -----------------------------------------------------------------------

    @Test
    fun `getCertTypeString maps each supported key to its cert algorithm`() {
        assertEquals(
            "ecdsa-sha2-nistp256-cert-v01@openssh.com",
            SSHCertificateEncoder.getCertTypeString(p256.public)
        )
        assertEquals(
            "ecdsa-sha2-nistp384-cert-v01@openssh.com",
            SSHCertificateEncoder.getCertTypeString(p384.public)
        )
        assertEquals(
            "ecdsa-sha2-nistp521-cert-v01@openssh.com",
            SSHCertificateEncoder.getCertTypeString(p521.public)
        )
        assertEquals(
            "ssh-rsa-cert-v01@openssh.com",
            SSHCertificateEncoder.getCertTypeString(rsa.public)
        )
    }

    @Test
    fun `getCertTypeString rejects an unsupported EC field size`() {
        val error = assertThrows(IllegalArgumentException::class.java) {
            SSHCertificateEncoder.getCertTypeString(unsupportedCurveKey())
        }
        assertEquals("Unsupported EC field size: 224", error.message)
    }

    // -----------------------------------------------------------------------
    // Public key blobs
    // -----------------------------------------------------------------------

    @Test
    fun `encodePublicKeyBlob writes type, curve and uncompressed point for P-256`() {
        assertEcBlob(p256.public as ECPublicKey, "ecdsa-sha2-nistp256", "nistp256", 32)
    }

    @Test
    fun `encodePublicKeyBlob writes type, curve and uncompressed point for P-384`() {
        assertEcBlob(p384.public as ECPublicKey, "ecdsa-sha2-nistp384", "nistp384", 48)
    }

    @Test
    fun `encodePublicKeyBlob writes type, curve and uncompressed point for P-521`() {
        assertEcBlob(p521.public as ECPublicKey, "ecdsa-sha2-nistp521", "nistp521", 66)
    }

    private fun assertEcBlob(
        key: ECPublicKey,
        expectedType: String,
        expectedCurve: String,
        coordinateSize: Int
    ) {
        val reader = SshReader(SSHCertificateEncoder.encodePublicKeyBlob(key))
        assertEquals(expectedType, reader.text())
        assertEquals(expectedCurve, reader.text())
        val point = reader.bytes()
        assertEquals(0, reader.remaining)
        assertEquals(1 + 2 * coordinateSize, point.size)
        assertEquals(0x04, point[0].toInt())
        val x = point.copyOfRange(1, 1 + coordinateSize)
        val y = point.copyOfRange(1 + coordinateSize, point.size)
        assertEquals(key.w.affineX, BigInteger(1, x))
        assertEquals(key.w.affineY, BigInteger(1, y))
    }

    @Test
    fun `encodePublicKeyBlob writes exponent then modulus for RSA`() {
        val key = rsa.public as RSAPublicKey
        val reader = SshReader(SSHCertificateEncoder.encodePublicKeyBlob(key))
        assertEquals("ssh-rsa", reader.text())
        val e = reader.bytes()
        val n = reader.bytes()
        assertEquals(0, reader.remaining)
        assertArrayEquals(key.publicExponent.toByteArray(), e)
        assertArrayEquals(key.modulus.toByteArray(), n)
        assertEquals(BigInteger.valueOf(65537), BigInteger(e))
        assertEquals(key.modulus, BigInteger(n))
        // A 2048-bit modulus is emitted as a 257-byte mpint (leading sign byte).
        assertEquals(0, n[0].toInt())
        assertEquals(257, n.size)
    }

    @Test
    fun `encodePublicKeyBlob rejects an unsupported EC field size`() {
        assertThrows(IllegalArgumentException::class.java) {
            SSHCertificateEncoder.encodePublicKeyBlob(unsupportedCurveKey())
        }
    }

    // -----------------------------------------------------------------------
    // Certificate body
    // -----------------------------------------------------------------------

    @Test
    fun `buildCertificateBody emits every field of a P-256 user certificate in order`() {
        val body = buildBody()
        val parsed = parseBody(body, ec = true)

        assertEquals("ecdsa-sha2-nistp256-cert-v01@openssh.com", parsed.type)
        assertEquals(32, parsed.nonce.size)
        assertEquals("nistp256", parsed.curveName)
        assertEquals(65, parsed.ecPoint!!.size)
        assertEquals(0x0102030405060708L, parsed.serial)
        assertEquals(SSHCertificateEncoder.SSH_CERT_TYPE_USER.toLong(), parsed.certType)
        assertEquals("user@example.com", parsed.keyId)
        assertEquals(listOf("alice", "root"), parsed.principals)
        assertEquals(1_700_000_000L, parsed.validAfter)
        assertEquals(1_800_000_000L, parsed.validBefore)
        assertTrue(parsed.criticalOptions.isEmpty())
        assertTrue(parsed.extensions.isEmpty())
        assertEquals(0, parsed.reserved.size)
        assertArrayEquals(SSHCertificateEncoder.encodePublicKeyBlob(p256.public), parsed.signatureKey)
        assertEquals("body must contain no trailing bytes", 0, parsed.trailingBytes)
    }

    @Test
    fun `buildCertificateBody embeds the subject public key, not the CA key`() {
        val body = buildBody(subject = p384.public, ca = p256.public)
        val parsed = parseBody(body, ec = true)

        assertEquals("ecdsa-sha2-nistp384-cert-v01@openssh.com", parsed.type)
        assertEquals("nistp384", parsed.curveName)
        assertEquals(97, parsed.ecPoint!!.size)
        assertArrayEquals(SSHCertificateEncoder.encodePublicKeyBlob(p256.public), parsed.signatureKey)
    }

    @Test
    fun `buildCertificateBody writes RSA subject keys as exponent and modulus`() {
        val body = buildBody(subject = rsa.public, ca = rsa.public)
        val parsed = parseBody(body, ec = false)

        assertEquals("ssh-rsa-cert-v01@openssh.com", parsed.type)
        assertEquals(BigInteger.valueOf(65537), BigInteger(parsed.rsaExponent!!))
        assertEquals((rsa.public as RSAPublicKey).modulus, BigInteger(parsed.rsaModulus!!))
        assertEquals(0, parsed.trailingBytes)
    }

    @Test
    fun `buildCertificateBody honours the host certificate type`() {
        val parsed = parseBody(
            buildBody(certType = SSHCertificateEncoder.SSH_CERT_TYPE_HOST),
            ec = true
        )
        assertEquals(2L, parsed.certType)
        assertEquals(2, SSHCertificateEncoder.SSH_CERT_TYPE_HOST)
        assertEquals(1, SSHCertificateEncoder.SSH_CERT_TYPE_USER)
    }

    @Test
    fun `buildCertificateBody uses a fresh 32-byte nonce on every call`() {
        val first = parseBody(buildBody(), ec = true)
        val second = parseBody(buildBody(), ec = true)
        assertEquals(32, first.nonce.size)
        assertEquals(32, second.nonce.size)
        assertNotEquals(first.nonce.toList(), second.nonce.toList())
    }

    @Test
    fun `buildCertificateBody packs an empty principal list as an empty string`() {
        val parsed = parseBody(buildBody(principals = emptyList()), ec = true)
        assertTrue(parsed.principals.isEmpty())
    }

    @Test
    fun `buildCertificateBody preserves principal order and unicode`() {
        val parsed = parseBody(
            buildBody(principals = listOf("zoe", "alice", "bjørn")),
            ec = true
        )
        assertEquals(listOf("zoe", "alice", "bjørn"), parsed.principals)
    }

    @Test
    fun `buildCertificateBody sorts critical options by name`() {
        val parsed = parseBody(
            buildBody(
                critical = linkedMapOf(
                    "source-address" to "192.0.2.0/24",
                    "force-command" to "/usr/bin/true"
                )
            ),
            ec = true
        )
        assertEquals(
            listOf("force-command" to "/usr/bin/true", "source-address" to "192.0.2.0/24"),
            parsed.criticalOptions
        )
    }

    @Test
    fun `buildCertificateBody sorts extensions and wraps empty values as empty strings`() {
        val parsed = parseBody(
            buildBody(
                extensions = linkedMapOf(
                    "permit-pty" to "",
                    "permit-agent-forwarding" to "",
                    "custom" to "value"
                )
            ),
            ec = true
        )
        assertEquals(
            listOf(
                "custom" to "value",
                "permit-agent-forwarding" to "",
                "permit-pty" to ""
            ),
            parsed.extensions
        )
    }

    @Test
    fun `buildCertificateBody double-wraps option values`() {
        // The option payload is string(string(value)): a 4-byte inner length
        // header plus the value itself.
        val body = buildBody(critical = mapOf("force-command" to "/bin/sh"))
        val parsed = parseBody(body, ec = true)
        assertEquals(1, parsed.criticalOptions.size)
        assertEquals("/bin/sh", parsed.criticalOptions[0].second)

        val raw = SshReader(body).let { r ->
            r.text(); r.bytes(); r.text(); r.bytes()  // type, nonce, curve, point
            r.uint64(); r.uint32(); r.text(); r.bytes()  // serial, type, keyId, principals
            r.uint64(); r.uint64()                        // validity window
            r.bytes()                                     // critical options blob
        }
        val optionsReader = SshReader(raw)
        assertEquals("force-command", optionsReader.text())
        val wrapped = optionsReader.bytes()
        assertEquals("/bin/sh".length + 4, wrapped.size)
    }

    @Test
    fun `buildCertificateBody keeps a negative serial as an unsigned uint64`() {
        val parsed = parseBody(buildBody(serial = -1L), ec = true)
        assertEquals(-1L, parsed.serial)
    }

    @Test
    fun `buildCertificateBody rejects an unsupported subject key`() {
        val dsa = KeyPairGenerator.getInstance("DSA").apply { initialize(1024) }.generateKeyPair()
        assertThrows(IllegalArgumentException::class.java) {
            buildBody(subject = dsa.public)
        }
    }

    @Test
    fun `buildCertificateBody rejects an unsupported CA key`() {
        val dsa = KeyPairGenerator.getInstance("DSA").apply { initialize(1024) }.generateKeyPair()
        assertThrows(IllegalArgumentException::class.java) {
            buildBody(ca = dsa.public)
        }
    }
}
