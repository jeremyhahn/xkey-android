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

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Security
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Date

/**
 * Covers this device acting as an enrollee: producing an enrollment request an
 * external CA can judge, and adopting only a credential that actually fits it.
 */
@RunWith(AndroidJUnit4::class)
class DeviceIdentityTest {

    private val context: Context = ApplicationProvider.getApplicationContext()
    private lateinit var identity: DeviceIdentity

    @Before
    fun setUp() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
        identity = DeviceIdentity(context)
        identity.reset()
    }

    @After
    fun tearDown() {
        identity.reset()
    }

    @Test
    fun aFreshDevice_reportsItselfUnenrolled() {
        assertFalse("A reset device holds no credential", identity.isEnrolled())
        assertNull(identity.credential())
        assertTrue("No credential means nothing to rely on", identity.isCredentialExpired())
    }

    @Test
    fun enrollmentRequest_bindsTheCaChallengeToTheCsrKey() {
        val challenge = "challenge-${System.nanoTime()}".toByteArray()
        val request = identity.createEnrollmentRequest(challenge)

        val csr = PKCS10CertificationRequest(request.csr)
        val leaf = decode(request.attestationChain.first())

        // The check a CA must not skip: the attested key and the key being
        // certified have to be the same one. Without it, anybody could pair a
        // genuine attestation with a CSR for a key they control.
        assertEquals(
            "The attestation leaf must certify the CSR's key",
            SubjectPublicKeyInfo.getInstance(leaf.publicKey.encoded),
            csr.subjectPublicKeyInfo
        )
    }

    @Test
    fun enrollmentRequest_refusesAnEmptyChallenge() {
        assertThrows(IllegalArgumentException::class.java) {
            identity.createEnrollmentRequest(ByteArray(0))
        }
    }

    @Test
    fun eachEnrollmentRequest_mintsANewKey() {
        val first = identity.createEnrollmentRequest("first".toByteArray())
        val second = identity.createEnrollmentRequest("second".toByteArray())

        // Android binds the challenge at key generation, so a key cannot attest
        // a nonce it was not born with. Reusing one would mean every enrollment
        // after the first replayed the original challenge.
        assertFalse(
            "A second request must not reuse the first key",
            first.csr.contentEquals(second.csr)
        )
    }

    @Test
    fun storingACredential_forADifferentKey_isRefused() {
        identity.createEnrollmentRequest("challenge".toByteArray())

        val stranger = softwareKeyPair()
        val foreign = selfSigned(stranger, "CN=Someone Else")

        val error = assertThrows(DeviceIdentityException::class.java) {
            identity.storeCredential(foreign)
        }
        assertTrue(
            "The refusal should name the mismatch: ${error.message}",
            error.message!!.contains("does not certify")
        )
        assertFalse("A refused credential must not enroll the device", identity.isEnrolled())
    }

    @Test
    fun storingACredential_withNoPendingRequest_isRefused() {
        val stranger = softwareKeyPair()
        val error = assertThrows(DeviceIdentityException::class.java) {
            identity.storeCredential(selfSigned(stranger, "CN=Unsolicited"))
        }
        assertTrue(
            "The refusal should say nothing was pending: ${error.message}",
            error.message!!.contains("No enrollment is pending")
        )
    }

    @Test
    fun aFailedEnrollment_leavesAnExistingCredentialIntact() {
        // Enroll once, so there is something to lose.
        val request = identity.createEnrollmentRequest("first".toByteArray())
        val issued = issueFor(request, "CN=Original CA")
        identity.storeCredential(issued)
        val original = identity.credential()
        assertNotNull(original)

        // Start a second enrollment and have it refused partway.
        identity.createEnrollmentRequest("second".toByteArray())
        assertThrows(DeviceIdentityException::class.java) {
            identity.storeCredential(selfSigned(softwareKeyPair(), "CN=Wrong Key"))
        }

        assertTrue("The device must still be enrolled", identity.isEnrolled())
        assertEquals(
            "The original credential must survive a failed re-enrollment",
            original!!.serialNumber,
            identity.credential()!!.serialNumber
        )
    }

    @Test
    fun aStoredCredential_reportsItsExpiryAsTheReattestationDeadline() {
        val request = identity.createEnrollmentRequest("challenge".toByteArray())
        val issued = issueFor(request, "CN=Cadence CA", validForMillis = ONE_DAY)

        val stored = identity.storeCredential(issued)

        assertTrue("Storing must report success", stored.notAfter > System.currentTimeMillis())
        assertEquals(
            "The reported expiry is the certificate's, not a local setting",
            issued.notAfter.time,
            stored.notAfter
        )
        assertFalse("A day-old credential is still current", identity.isCredentialExpired())
        assertTrue(
            "Past its notAfter the device must re-attest",
            identity.isCredentialExpired(now = issued.notAfter.time + 1)
        )
    }

    @Test
    fun aStoredCredential_keepsTheIssuerChain() {
        val request = identity.createEnrollmentRequest("challenge".toByteArray())
        val issuerKey = softwareKeyPair()
        val issuerCert = selfSigned(issuerKey, "CN=Chain Root")
        val issued = issueFor(request, "CN=Chain CA", issuerKey = issuerKey)

        identity.storeCredential(issued, listOf(issuerCert))

        val chain = identity.credentialChain()
        assertEquals("The issuer chain must round-trip", 1, chain.size)
        assertEquals(issuerCert.subjectX500Principal, chain.first().subjectX500Principal)
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private fun decode(der: ByteArray): X509Certificate =
        java.security.cert.CertificateFactory.getInstance("X.509")
            .generateCertificate(der.inputStream()) as X509Certificate

    private fun softwareKeyPair(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()

    /** Issues a certificate over the CSR's key, as a real CA would. */
    private fun issueFor(
        request: DeviceEnrollmentRequest,
        issuerName: String,
        issuerKey: KeyPair = softwareKeyPair(),
        validForMillis: Long = ONE_DAY
    ): X509Certificate {
        val csr = PKCS10CertificationRequest(request.csr)
        val now = System.currentTimeMillis()
        val builder = JcaX509v3CertificateBuilder(
            X500Name(issuerName),
            BigInteger.valueOf(System.nanoTime()),
            Date(now - ONE_DAY),
            Date(now + validForMillis),
            csr.subject,
            java.security.KeyFactory.getInstance("EC").generatePublic(
                java.security.spec.X509EncodedKeySpec(csr.subjectPublicKeyInfo.encoded)
            )
        )
        return JcaX509CertificateConverter().getCertificate(
            builder.build(JcaContentSignerBuilder(SIG_ALG).build(issuerKey.private))
        )
    }

    private fun selfSigned(keyPair: KeyPair, subject: String): X509Certificate {
        val now = System.currentTimeMillis()
        val builder = JcaX509v3CertificateBuilder(
            X500Name(subject),
            BigInteger.valueOf(System.nanoTime()),
            Date(now - ONE_DAY),
            Date(now + ONE_DAY),
            X500Name(subject),
            keyPair.public
        )
        return JcaX509CertificateConverter().getCertificate(
            builder.build(JcaContentSignerBuilder(SIG_ALG).build(keyPair.private))
        )
    }

    private companion object {
        const val SIG_ALG = "SHA256withECDSA"
        const val ONE_DAY = 24L * 60 * 60 * 1000
    }
}
