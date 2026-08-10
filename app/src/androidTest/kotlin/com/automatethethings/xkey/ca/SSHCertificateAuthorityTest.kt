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

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.crypto.SSHCertificateEncoder
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * Instrumented tests for [SSHCertificateAuthority].
 *
 * Signing happens with an Android Keystore private key and the certificate is
 * assembled through `android.util.Base64`, so this can only run on a device. The
 * CA key is created under a per-run alias (rather than reusing the real
 * `xkey_intermediate_ca`) so the suite cannot disturb the app's CA state, and it
 * is deleted in `@After`.
 *
 * The certificates are not merely inspected as strings: each one is Base64-decoded
 * and walked field by field with an independent SSH-wire reader, and the trailing
 * signature is converted back to DER and verified against the CA public key. That
 * is the only way to prove the Keystore actually signed the body that was emitted.
 */
@RunWith(AndroidJUnit4::class)
class SSHCertificateAuthorityTest {

    private val caAlias = "xkey_test_sshca_${System.nanoTime()}"

    private lateinit var authority: SSHCertificateAuthority
    private lateinit var caPublicKey: PublicKey
    private lateinit var subjectKey: PublicKey

    @Before
    fun setUp() {
        authority = SSHCertificateAuthority(ApplicationProvider.getApplicationContext())

        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").apply {
            initialize(
                KeyGenParameterSpec.Builder(
                    caAlias,
                    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
                )
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setUserAuthenticationRequired(false)
                    .build()
            )
        }.generateKeyPair()

        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        caPublicKey = keyStore.getCertificate(caAlias).publicKey

        subjectKey = KeyPairGenerator.getInstance("EC")
            .apply { initialize(ECGenParameterSpec("secp256r1")) }
            .generateKeyPair().public
    }

    @After
    fun tearDown() {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (keyStore.containsAlias(caAlias)) keyStore.deleteEntry(caAlias)
    }

    // -------------------------------------------------------------------------
    // OpenSSH wire-format reader
    // -------------------------------------------------------------------------

    /** Minimal independent reader for the OpenSSH certificate encoding. */
    private class SshReader(val data: ByteArray) {
        var pos = 0
            private set

        fun bytes(): ByteArray {
            val len = uint32()
            val out = data.copyOfRange(pos, pos + len)
            pos += len
            return out
        }

        fun text(): String = String(bytes(), Charsets.UTF_8)

        fun uint32(): Int {
            var v = 0
            repeat(4) { v = (v shl 8) or (data[pos++].toInt() and 0xFF) }
            return v
        }

        fun uint64(): Long {
            var v = 0L
            repeat(8) { v = (v shl 8) or (data[pos++].toLong() and 0xFF) }
            return v
        }

        /** Reads a packed list of SSH strings out of one SSH string. */
        fun stringList(): List<String> {
            val inner = SshReader(bytes())
            val out = mutableListOf<String>()
            while (inner.pos < inner.data.size) out.add(inner.text())
            return out
        }

        /** Reads a name -> nested-string map (critical options / extensions). */
        fun optionMap(): Map<String, String> {
            val inner = SshReader(bytes())
            val out = linkedMapOf<String, String>()
            while (inner.pos < inner.data.size) {
                val name = inner.text()
                val wrapped = inner.bytes()
                out[name] = if (wrapped.isEmpty()) "" else SshReader(wrapped).text()
            }
            return out
        }
    }

    /** Everything a decoded certificate carries, plus the body/signature split. */
    private class DecodedCertificate(
        val typeString: String,
        val serial: Long,
        val certType: Int,
        val keyId: String,
        val principals: List<String>,
        val validAfter: Long,
        val validBefore: Long,
        val criticalOptions: Map<String, String>,
        val extensions: Map<String, String>,
        val signatureKeyBlob: ByteArray,
        val body: ByteArray,
        val signatureBlob: ByteArray,
        val raw: ByteArray
    )

    private fun decode(line: String): DecodedCertificate {
        val parts = line.split(" ")
        assertEquals("certificate line must be '<type> <base64>'", 2, parts.size)
        val raw = Base64.decode(parts[1], Base64.NO_WRAP)
        val reader = SshReader(raw)

        val typeString = reader.text()
        reader.bytes()               // nonce
        reader.text()                // curve name
        reader.bytes()               // EC point
        val serial = reader.uint64()
        val certType = reader.uint32()
        val keyId = reader.text()
        val principals = reader.stringList()
        val validAfter = reader.uint64()
        val validBefore = reader.uint64()
        val criticalOptions = reader.optionMap()
        val extensions = reader.optionMap()
        assertEquals("reserved field must be empty", 0, reader.bytes().size)
        val signatureKeyBlob = reader.bytes()

        val bodyEnd = reader.pos
        val signatureBlob = reader.bytes()
        assertEquals("no bytes may follow the signature", raw.size, reader.pos)

        return DecodedCertificate(
            typeString = typeString,
            serial = serial,
            certType = certType,
            keyId = keyId,
            principals = principals,
            validAfter = validAfter,
            validBefore = validBefore,
            criticalOptions = criticalOptions,
            extensions = extensions,
            signatureKeyBlob = signatureKeyBlob,
            body = raw.copyOfRange(0, bodyEnd),
            signatureBlob = signatureBlob,
            raw = raw
        )
    }

    /** Re-encodes the SSH (r, s) signature as DER and verifies it over the body. */
    private fun signatureVerifies(decoded: DecodedCertificate): Boolean {
        val blob = SshReader(decoded.signatureBlob)
        assertEquals("ecdsa-sha2-nistp256", blob.text())
        val rs = SshReader(blob.bytes())
        val r = BigInteger(rs.bytes())
        val s = BigInteger(rs.bytes())

        val der = derSequence(derInteger(r) + derInteger(s))
        return Signature.getInstance("SHA256withECDSA").run {
            initVerify(caPublicKey)
            update(decoded.body)
            verify(der)
        }
    }

    private fun derInteger(value: BigInteger): ByteArray {
        val content = value.toByteArray()
        return byteArrayOf(0x02, content.size.toByte()) + content
    }

    private fun derSequence(content: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(0x30)
        if (content.size < 0x80) {
            out.write(content.size)
        } else {
            out.write(0x81)
            out.write(content.size)
        }
        out.write(content)
        return out.toByteArray()
    }

    private fun sha256Hex(data: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(data).joinToString("") { "%02x".format(it) }

    // -------------------------------------------------------------------------
    // User certificates
    // -------------------------------------------------------------------------

    @Test
    fun aUserCertificateIsSignedByTheKeystoreCaKey() = runBlocking {
        val issued = authority.issueUserCertificate(
            publicKey = subjectKey,
            keyId = "alice@example.com",
            principals = listOf("alice", "root"),
            signingAlias = caAlias
        )

        assertTrue(
            "certificate line must start with the cert type",
            issued.certificate.startsWith("ecdsa-sha2-nistp256-cert-v01@openssh.com ")
        )

        val decoded = decode(issued.certificate)
        assertEquals("ecdsa-sha2-nistp256-cert-v01@openssh.com", decoded.typeString)
        assertEquals(SSHCertificateEncoder.SSH_CERT_TYPE_USER, decoded.certType)
        assertEquals("alice@example.com", decoded.keyId)
        assertEquals(listOf("alice", "root"), decoded.principals)
        assertTrue("the CA key must sign the body", signatureVerifies(decoded))

        assertArrayEquals(
            "the embedded signature key must be the CA public key",
            SSHCertificateEncoder.encodePublicKeyBlob(caPublicKey),
            decoded.signatureKeyBlob
        )
    }

    @Test
    fun aUserCertificateCarriesTheDefaultOpensshExtensions() = runBlocking {
        val issued = authority.issueUserCertificate(
            publicKey = subjectKey,
            keyId = "bob",
            principals = listOf("bob"),
            signingAlias = caAlias
        )

        val decoded = decode(issued.certificate)
        assertEquals(
            SSHCertificateAuthority.DEFAULT_USER_EXTENSIONS.keys.sorted(),
            decoded.extensions.keys.toList()
        )
        assertTrue(decoded.extensions.values.all { it.isEmpty() })
        assertTrue(decoded.criticalOptions.isEmpty())
    }

    @Test
    fun customExtensionsAndCriticalOptionsAreEncodedSorted() = runBlocking {
        val issued = authority.issueUserCertificate(
            publicKey = subjectKey,
            keyId = "restricted",
            principals = listOf("deploy"),
            extensions = mapOf("permit-pty" to ""),
            criticalOptions = mapOf(
                "source-address" to "10.0.0.0/8",
                "force-command" to "/usr/bin/true"
            ),
            signingAlias = caAlias
        )

        val decoded = decode(issued.certificate)
        assertEquals(listOf("permit-pty"), decoded.extensions.keys.toList())
        assertEquals(
            listOf("force-command", "source-address"),
            decoded.criticalOptions.keys.toList()
        )
        assertEquals("/usr/bin/true", decoded.criticalOptions["force-command"])
        assertEquals("10.0.0.0/8", decoded.criticalOptions["source-address"])
        assertTrue(signatureVerifies(decoded))
    }

    @Test
    fun theValidityWindowMatchesTheRequestedNumberOfDays() = runBlocking {
        val issued = authority.issueUserCertificate(
            publicKey = subjectKey,
            keyId = "short-lived",
            principals = listOf("ci"),
            validityDays = 7,
            signingAlias = caAlias
        )

        val decoded = decode(issued.certificate)
        assertEquals(7L * 86_400, decoded.validBefore - decoded.validAfter)
        assertEquals(issued.validAfter, decoded.validAfter)
        assertEquals(issued.validBefore, decoded.validBefore)
        assertEquals(issued.serialNumber, decoded.serial)
        assertTrue(
            "validAfter should be about now (unix seconds)",
            Math.abs(issued.validAfter - System.currentTimeMillis() / 1000) < 120
        )
    }

    @Test
    fun theReportedFingerprintIsTheSha256OfTheEncodedCertificate() = runBlocking {
        val issued = authority.issueUserCertificate(
            publicKey = subjectKey,
            keyId = "fingerprint",
            principals = listOf("fp"),
            signingAlias = caAlias
        )

        val decoded = decode(issued.certificate)
        assertEquals(sha256Hex(decoded.raw), issued.fingerprint)
        assertEquals("user", issued.certificateType)
        assertEquals(listOf("fp"), issued.validPrincipals)
        assertEquals("fingerprint", issued.keyId)
    }

    // -------------------------------------------------------------------------
    // Host certificates
    // -------------------------------------------------------------------------

    @Test
    fun aHostCertificateUsesTheHostTypeAndCarriesNoExtensions() = runBlocking {
        val issued = authority.issueHostCertificate(
            publicKey = subjectKey,
            keyId = "server.example.com",
            hostnames = listOf("server.example.com", "server"),
            signingAlias = caAlias
        )

        val decoded = decode(issued.certificate)
        assertEquals(SSHCertificateEncoder.SSH_CERT_TYPE_HOST, decoded.certType)
        assertEquals(listOf("server.example.com", "server"), decoded.principals)
        assertTrue("host certificates get no extensions", decoded.extensions.isEmpty())
        assertTrue(decoded.criticalOptions.isEmpty())
        assertEquals("host", issued.certificateType)
        assertTrue(signatureVerifies(decoded))
    }

    @Test
    fun hostCertificatesDefaultToTwoYears() = runBlocking {
        val issued = authority.issueHostCertificate(
            publicKey = subjectKey,
            keyId = "long-lived.example.com",
            hostnames = listOf("long-lived.example.com"),
            signingAlias = caAlias
        )

        assertEquals(730L * 86_400, issued.validBefore - issued.validAfter)
    }

    // -------------------------------------------------------------------------
    // Negative paths
    // -------------------------------------------------------------------------

    @Test
    fun aTamperedCertificateBodyNoLongerVerifies() = runBlocking {
        val issued = authority.issueUserCertificate(
            publicKey = subjectKey,
            keyId = "victim",
            principals = listOf("victim"),
            signingAlias = caAlias
        )

        val decoded = decode(issued.certificate)
        // Flip a bit inside the signed body; the signature must stop verifying.
        val tampered = decoded.body.copyOf()
        tampered[tampered.size - 1] = (tampered[tampered.size - 1].toInt() xor 0x01).toByte()

        val verified = Signature.getInstance("SHA256withECDSA").run {
            initVerify(caPublicKey)
            update(tampered)
            val blob = SshReader(decoded.signatureBlob)
            blob.text()
            val rs = SshReader(blob.bytes())
            val der = derSequence(derInteger(BigInteger(rs.bytes())) + derInteger(BigInteger(rs.bytes())))
            verify(der)
        }

        assertFalse("a mutated body must not verify", verified)
    }

    @Test
    fun issuingWithAnUnknownSigningAliasFails() {
        assertThrows(Exception::class.java) {
            runBlocking {
                authority.issueUserCertificate(
                    publicKey = subjectKey,
                    keyId = "nobody",
                    principals = listOf("nobody"),
                    signingAlias = "no_such_ca_alias_${System.nanoTime()}"
                )
            }
        }
    }

    @Test
    fun twoCertificatesForTheSameSubjectDifferByTheirNonce() = runBlocking {
        val first = authority.issueUserCertificate(
            publicKey = subjectKey,
            keyId = "same",
            principals = listOf("same"),
            signingAlias = caAlias
        )
        val second = authority.issueUserCertificate(
            publicKey = subjectKey,
            keyId = "same",
            principals = listOf("same"),
            signingAlias = caAlias
        )

        assertFalse(
            "the random nonce must make each certificate unique",
            first.certificate == second.certificate
        )
        assertFalse(first.fingerprint == second.fingerprint)
    }
}
