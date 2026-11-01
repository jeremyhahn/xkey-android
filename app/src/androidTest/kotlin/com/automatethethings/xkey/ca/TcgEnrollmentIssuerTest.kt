/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
 *
 * This file is part of xkey-android.
 *
 * xkey-android is dual-licensed:
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
import androidx.test.filters.MediumTest
import kotlinx.coroutines.runBlocking
import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.BCStyle
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayInputStream
import java.security.KeyPairGenerator
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec

/**
 * Proves [AndroidCA.issueForPublicKey] can certify a key that arrives as a bare
 * public key, which is what the TCG enrollment ceremony hands it.
 *
 * The TCG single-pass ceremony carries no PKCS#10 — the enrollee's proof of
 * possession is the TCG-CSR-IDEVID's own signature, and the keys to certify
 * arrive as TPM public areas whose private halves are sealed in the desktop's
 * TPM. Issuance therefore cannot go through the request-parsing path, and this
 * suite is what shows the public-key path produces a certificate that chains.
 *
 * It needs the real Android Keystore, which is why it runs on a device. The CA
 * keys and certificates it creates are removed in teardown.
 */
@RunWith(AndroidJUnit4::class)
@MediumTest
class TcgEnrollmentIssuerTest {

    private lateinit var context: Context
    private lateinit var ca: AndroidCA
    private var caWasAlreadyInitialized = false

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        ca = AndroidCA(context)
        caWasAlreadyInitialized = ca.isInitialized()
        if (!caWasAlreadyInitialized) {
            runBlocking {
                ca.initialize(CASubject(cn = "TcgEnrollmentIssuerTest Root", org = "xKey Test"))
            }
        }
    }

    @After
    fun tearDown() {
        // Only tear down what this suite created; a CA that was already present
        // belongs to the app or to another suite.
        if (!caWasAlreadyInitialized) {
            runBlocking { ca.reset() }
        }
    }

    @Test
    fun issuesACertificateOverAKeyItHasNoPrivateHalfOf() = runBlocking {
        val deviceKey = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()

        val subject = X500NameBuilder(BCStyle.INSTANCE).apply {
            addRDN(BCStyle.O, "xKey")
            addRDN(BCStyle.OU, "IDevID")
            addRDN(BCStyle.CN, "tcg-issuer-test")
        }.build()

        val issued = ca.issueForPublicKey(deviceKey.public, subject, CertificateProfile.IDevID())

        val certificate = parse(issued.certificate)
        assertEquals(
            "the certified key must be the one handed in",
            deviceKey.public,
            certificate.publicKey
        )
        assertTrue(certificate.subjectX500Principal.name.contains("tcg-issuer-test"))
        assertNotNull(issued.serialNumber)
        assertEquals(64, issued.fingerprint.length)
    }

    @Test
    fun theIssuedCertificateVerifiesUnderTheIntermediateAndChainsToTheRoot() = runBlocking {
        val deviceKey = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val subject = X500NameBuilder(BCStyle.INSTANCE)
            .addRDN(BCStyle.CN, "tcg-issuer-chain").build()

        val issued = ca.issueForPublicKey(deviceKey.public, subject, CertificateProfile.IDevID())

        val leaf = parse(issued.certificate)
        val intermediate = ca.getIntermediateCertificate()
        val root = ca.getRootCertificate()

        // A signature that does not verify here means the leaf would not chain
        // on the desktop either.
        leaf.verify(intermediate.publicKey)
        intermediate.verify(root.publicKey)

        assertEquals(3, issued.chain.size)
        assertEquals(intermediate, parse(issued.chain[1]))
        assertEquals(root, parse(issued.chain[2]))

        // RFC 5280 compares issuer and subject as encoded names, so the bytes
        // must match and not merely the printed strings.
        assertTrue(
            leaf.issuerX500Principal.encoded.contentEquals(
                intermediate.subjectX500Principal.encoded
            )
        )
    }

    @Test
    fun theIssuedCertificateCarriesTheIDevIDProfileExtensions() = runBlocking {
        val deviceKey = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()
        val subject = X500NameBuilder(BCStyle.INSTANCE)
            .addRDN(BCStyle.CN, "tcg-issuer-extensions").build()

        val certificate = parse(
            ca.issueForPublicKey(deviceKey.public, subject, CertificateProfile.IDevID()).certificate
        )

        assertEquals("an end-entity certificate must not be a CA", -1, certificate.basicConstraints)
        val keyUsage = certificate.keyUsage
        assertNotNull("key usage must be present", keyUsage)
        assertTrue("digitalSignature must be set", keyUsage!![0])
        assertNotNull(
            "a subject key identifier is required for path building",
            certificate.getExtensionValue("2.5.29.14")
        )
        assertNotNull(
            "an authority key identifier is required for path building",
            certificate.getExtensionValue("2.5.29.35")
        )
    }

    private fun newEcKey() = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair().public

    private fun parse(der: ByteArray): X509Certificate =
        CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(der)) as X509Certificate
}
