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
package com.automatethethings.xkey.bootstrap

import android.util.Log
import com.automatethethings.xkey.settings.BootstrapMethod
import com.automatethethings.xkey.settings.BootstrapSettingsData
import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import kotlinx.coroutines.runBlocking
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.Date
import javax.net.ssl.SSLPeerUnverifiedException

/**
 * The SPKI-pinned bootstrap client against a real TLS handshake.
 *
 * `BootstrapClientTest` drives the SPKI branch through an interceptor, so the
 * pinned trust manager and `computeSPKIPin` never run there. Here every fetch
 * goes through [TlsBootstrapServer]: the client's own trust manager sees the
 * chain the server presents, and OkHttp's default hostname verifier (which the
 * SPKI client keeps) checks the leaf against the dialled name.
 */
class BootstrapSpkiTlsTest {

    private val host = TlsBootstrapServer.HOST
    private var server: TlsBootstrapServer? = null

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.i(any(), any()) } returns 0
        every { Log.d(any(), any()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.e(any(), any<String>()) } returns 0
    }

    @After
    fun tearDown() {
        server?.close()
        server = null
        unmockkAll()
    }

    private fun pinOf(certificate: X509Certificate): String =
        MessageDigest.getInstance("SHA-256").digest(certificate.publicKey.encoded)
            .joinToString("") { "%02x".format(it) }

    private fun serve(
        chain: List<X509Certificate>,
        owner: TestCertificate,
        body: ByteArray = TestPki.bundle(2).toByteArray(Charsets.UTF_8),
        status: Int = 200
    ): TlsBootstrapServer =
        TlsBootstrapServer(chain, owner.keyPair.private, status, body).also { server = it }

    private fun client(tls: TlsBootstrapServer, pin: String) = BootstrapClient(
        BootstrapSettingsData(
            methodOrder = listOf(BootstrapMethod.SPKI),
            perMethodTimeoutSeconds = 15,
            daneEnabled = false,
            noiseEnabled = false,
            spkiEnabled = true,
            spkiServerUrl = "https://$host:${tls.port}",
            spkiPinSha256 = pin,
            directEnabled = false
        ),
        TlsBootstrapServer.loopbackClient()
    )

    private fun fetch(tls: TlsBootstrapServer, pin: String): CABundleResult = runBlocking {
        client(tls, pin).fetchWithMethod(BootstrapMethod.SPKI)
    }

    private fun <T : Throwable> assertFetchFails(
        tls: TlsBootstrapServer,
        pin: String,
        expected: Class<T>
    ): T = assertThrows(expected) {
        runBlocking { client(tls, pin).fetchWithMethod(BootstrapMethod.SPKI) }
    }

    /** A CA certificate issued by [issuer], for chains with an intermediate. */
    private fun intermediateCa(issuer: TestCertificate, commonName: String): TestCertificate {
        val keyPair = TestPki.ecKeyPair()
        val subject = X500Name("CN=$commonName")
        val now = System.currentTimeMillis()
        val holder = JcaX509v3CertificateBuilder(
            issuer.subject,
            BigInteger(64, SecureRandom()),
            Date(now - 86_400_000L),
            Date(now + 30L * 86_400_000L),
            subject,
            keyPair.public
        )
            .addExtension(Extension.basicConstraints, true, BasicConstraints(0))
            .addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.keyCertSign or KeyUsage.cRLSign))
            .build(JcaContentSignerBuilder("SHA256withECDSA").build(issuer.keyPair.private))
        return TestCertificate(JcaX509CertificateConverter().getCertificate(holder), keyPair, subject)
    }

    // ------------------------------------------------------------- accepted

    @Test(timeout = 30_000)
    fun aPinnedLeafReturnsTheBundleOverARealHandshake() {
        val leaf = TestPki.selfSigned("SPKI Leaf", dnsNames = listOf(host))
        val tls = serve(listOf(leaf.certificate), leaf)

        val result = fetch(tls, pinOf(leaf.certificate))

        assertEquals(BootstrapMethod.SPKI, result.method)
        assertEquals(2, result.certificateCount)
        assertEquals(1, tls.handshakes)
        assertEquals(listOf("GET /v1/ca/bootstrap HTTP/1.1"), tls.requests)
    }

    @Test(timeout = 30_000)
    fun aPinOnTheIssuingCaAcceptsALeafItReallySigned() {
        val ca = TestPki.selfSigned("SPKI Pinned Root", isCa = true)
        val leaf = TestPki.issuedBy(ca, "SPKI Leaf", dnsNames = listOf(host))
        val tls = serve(listOf(leaf.certificate, ca.certificate), leaf)

        val result = fetch(tls, pinOf(ca.certificate))

        assertEquals(BootstrapMethod.SPKI, result.method)
        assertEquals(1, tls.requests.size)
    }

    @Test(timeout = 30_000)
    fun aPinOnAnIntermediateAcceptsALeafItReallySigned() {
        val root = TestPki.selfSigned("SPKI Root", isCa = true)
        val intermediate = intermediateCa(root, "SPKI Pinned Intermediate")
        val leaf = TestPki.issuedBy(intermediate, "SPKI Leaf", dnsNames = listOf(host))
        val tls = serve(listOf(leaf.certificate, intermediate.certificate, root.certificate), leaf)

        val result = fetch(tls, pinOf(intermediate.certificate))

        assertEquals(BootstrapMethod.SPKI, result.method)
    }

    @Test(timeout = 30_000)
    fun aPinOnTheRootAcceptsALeafThatChainsThroughAnIntermediate() {
        val root = TestPki.selfSigned("SPKI Pinned Root", isCa = true)
        val intermediate = intermediateCa(root, "SPKI Intermediate")
        val leaf = TestPki.issuedBy(intermediate, "SPKI Leaf", dnsNames = listOf(host))
        val tls = serve(listOf(leaf.certificate, intermediate.certificate, root.certificate), leaf)

        val result = fetch(tls, pinOf(root.certificate))

        assertEquals(BootstrapMethod.SPKI, result.method)
    }

    @Test(timeout = 30_000)
    fun anUppercasePinInSettingsMatches() {
        val leaf = TestPki.selfSigned("SPKI Leaf", dnsNames = listOf(host))
        val tls = serve(listOf(leaf.certificate), leaf)

        val result = fetch(tls, pinOf(leaf.certificate).uppercase())

        assertEquals(BootstrapMethod.SPKI, result.method)
    }

    // ------------------------------------------------------------- refused

    @Test(timeout = 30_000)
    fun theDefaultHostnameVerifierStillRefusesALeafForAnotherName() {
        val leaf = TestPki.selfSigned("SPKI Leaf", dnsNames = listOf("other.example.test"))
        val tls = serve(listOf(leaf.certificate), leaf)

        val failure = assertFetchFails(tls, pinOf(leaf.certificate), DirectException::class.java)

        assertTrue(
            "cause was ${failure.cause}",
            failure.cause is SSLPeerUnverifiedException
        )
        assertEquals(emptyList<String>(), tls.requests)
    }

    @Test(timeout = 30_000)
    fun anHttpErrorOverTlsIsReportedWithItsStatus() {
        val leaf = TestPki.selfSigned("SPKI Leaf", dnsNames = listOf(host))
        val tls = serve(listOf(leaf.certificate), leaf, "nope".toByteArray(), status = 500)

        val failure = assertFetchFails(tls, pinOf(leaf.certificate), DirectException::class.java)

        assertEquals(500, failure.httpStatusCode)
        assertEquals(1, tls.requests.size)
    }

    @Test(timeout = 30_000)
    fun aBodyOverTheOneMegabyteCapOverTlsIsRefused() {
        val leaf = TestPki.selfSigned("SPKI Leaf", dnsNames = listOf(host))
        val oversized = ByteArray(1 * 1024 * 1024 + 4096) { 'A'.code.toByte() }
        val tls = serve(listOf(leaf.certificate), leaf, oversized)

        val failure = assertFetchFails(tls, pinOf(leaf.certificate), DirectException::class.java)

        assertTrue(failure.reason, failure.reason.contains("Response too large"))
        assertNotNull(tls.requests.singleOrNull())
    }
}
