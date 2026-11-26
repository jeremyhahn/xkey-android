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
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.util.concurrent.CopyOnWriteArrayList

/**
 * The DANE bootstrap client end to end: a loopback DNS server answers the
 * TLSA query (with the DNSSEC AD bit, as a validating resolver would) and
 * [TlsBootstrapServer] presents a real chain, so the trust manager
 * `createDaneHttpClient` installs is what decides. `BootstrapDaneFetchTest`
 * covers the same branch with an interceptor, where no trust manager runs.
 *
 * The DANE client turns OkHttp's hostname verifier into a pass-through and
 * relies on `DaneVerifier` for name checks, so the DANE-TA name case here is
 * the only guard that the pass-through is safe.
 */
class BootstrapDaneTlsTest {

    private val host = TlsBootstrapServer.HOST

    private var dns: DnsStubServer? = null
    private var server: TlsBootstrapServer? = null
    private val queriedNames = CopyOnWriteArrayList<String>()

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.i(any(), any()) } returns 0
        every { Log.d(any(), any()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.e(any(), any<String>()) } returns 0
        queriedNames.clear()
    }

    @After
    fun tearDown() {
        dns?.close()
        dns = null
        server?.close()
        server = null
        unmockkAll()
    }

    private class Tlsa(val usage: Int, val selector: Int, val matching: Int, val data: ByteArray)

    private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

    /** DANE-EE, SPKI, SHA-256: `3 1 1` over [certificate]'s public key. */
    private fun daneEe(certificate: X509Certificate) = Tlsa(
        TlsaRecord.USAGE_DANE_EE,
        TlsaRecord.SELECTOR_SPKI,
        TlsaRecord.MATCHING_SHA256,
        sha256(certificate.publicKey.encoded)
    )

    /** DANE-TA, full certificate, SHA-256: `2 0 1` over [anchor]. */
    private fun daneTa(anchor: X509Certificate) = Tlsa(
        TlsaRecord.USAGE_DANE_TA,
        TlsaRecord.SELECTOR_FULL_CERT,
        TlsaRecord.MATCHING_SHA256,
        sha256(anchor.encoded)
    )

    private fun startDns(records: List<Tlsa>, flags: Int = DnsWire.FLAGS_OK): DnsStubServer =
        DnsStubServer { query, _ ->
            val name = DnsWire.queriedName(query)
            queriedNames.add(name)
            DnsWire.replyTo(
                query,
                records.map {
                    DnsAnswer(
                        owner = name,
                        type = DnsWire.TYPE_TLSA,
                        rdata = DnsWire.tlsaRdata(it.usage, it.selector, it.matching, it.data)
                    )
                },
                flags = flags
            )
        }.also { dns = it }

    private fun serve(chain: List<X509Certificate>, owner: TestCertificate): TlsBootstrapServer =
        TlsBootstrapServer(chain, owner.keyPair.private, TestPki.bundle(2)).also { server = it }

    private fun client(tls: TlsBootstrapServer, resolver: DnsStubServer) = BootstrapClient(
        BootstrapSettingsData(
            methodOrder = listOf(BootstrapMethod.DANE),
            perMethodTimeoutSeconds = 15,
            daneEnabled = true,
            daneServerUrl = "https://$host:${tls.port}",
            daneDnsServer = resolver.address,
            daneRequireDnssec = true,
            noiseEnabled = false,
            spkiEnabled = false,
            directEnabled = false
        ),
        TlsBootstrapServer.loopbackClient()
    )

    private fun fetch(tls: TlsBootstrapServer, records: List<Tlsa>): CABundleResult = runBlocking {
        client(tls, startDns(records)).fetchWithMethod(BootstrapMethod.DANE)
    }

    private fun assertRefused(tls: TlsBootstrapServer, records: List<Tlsa>): DANEException {
        val failure = assertThrows(DANEException::class.java) {
            runBlocking { client(tls, startDns(records)).fetchWithMethod(BootstrapMethod.DANE) }
        }
        assertEquals("no HTTP request may follow a refused chain", emptyList<String>(), tls.requests)
        assertEquals("the server must not complete a handshake", 0, tls.handshakes)
        return failure
    }

    // ------------------------------------------------------------- DANE-EE

    @Test(timeout = 30_000)
    fun daneEeMatchingTheLeafKeyReturnsTheBundle() {
        // DANE-EE has no name check (RFC 7671 5.1): this leaf carries no SAN.
        val leaf = TestPki.selfSigned("DANE EE Leaf")
        val tls = serve(listOf(leaf.certificate), leaf)

        val result = fetch(tls, listOf(daneEe(leaf.certificate)))

        assertEquals(BootstrapMethod.DANE, result.method)
        assertEquals(2, result.certificateCount)
        assertEquals(listOf("_${tls.port}._tcp.$host."), queriedNames.toList())
        assertEquals(listOf("GET /v1/ca/bootstrap HTTP/1.1"), tls.requests)
    }

    @Test(timeout = 30_000)
    fun daneEeWithALeafThatDoesNotMatchIsRefusedBeforeAnyRequest() {
        val leaf = TestPki.selfSigned("DANE EE Leaf", dnsNames = listOf(host))
        val published = TestPki.selfSigned("DANE EE Published").certificate
        val tls = serve(listOf(leaf.certificate), leaf)

        val failure = assertRefused(tls, listOf(daneEe(published)))

        assertTrue(failure.reason, failure.reason.contains("Network error"))
        assertNotNull(failure.cause)
        assertTrue("the handshake was attempted", tls.connections >= 1)
    }

    // ------------------------------------------------------------- DANE-TA

    @Test(timeout = 30_000)
    fun daneTaNamingAnAnchorTheLeafValidatesToIsAccepted() {
        val anchor = TestPki.selfSigned("DANE TA Anchor", isCa = true)
        val leaf = TestPki.issuedBy(anchor, "DANE TA Leaf", dnsNames = listOf(host))
        val tls = serve(listOf(leaf.certificate, anchor.certificate), leaf)

        val result = fetch(tls, listOf(daneTa(anchor.certificate)))

        assertEquals(BootstrapMethod.DANE, result.method)
        assertEquals(1, tls.requests.size)
    }

    @Test(timeout = 30_000)
    fun daneTaRefusesALeafForAnotherNameDespiteThePassThroughHostnameVerifier() {
        val anchor = TestPki.selfSigned("DANE TA Anchor", isCa = true)
        val leaf = TestPki.issuedBy(anchor, "DANE TA Leaf", dnsNames = listOf("other.example.test"))
        val tls = serve(listOf(leaf.certificate, anchor.certificate), leaf)

        assertRefused(tls, listOf(daneTa(anchor.certificate)))
    }

    @Test(timeout = 30_000)
    fun daneTaRefusesAnAppendedAnchorTheLeafDoesNotChainTo() {
        // The anchor is public; a server holding only its own key appends it.
        val anchor = TestPki.selfSigned("DANE TA Anchor", isCa = true)
        val attacker = TestPki.selfSigned("DANE Attacker Leaf", dnsNames = listOf(host))
        val tls = serve(listOf(attacker.certificate, anchor.certificate), attacker)

        assertRefused(tls, listOf(daneTa(anchor.certificate)))
    }

    // ---------------------------------------------------------- the records

    @Test(timeout = 30_000)
    fun recordsWithOnlyPkixUsagesAreRefused() {
        val anchor = TestPki.selfSigned("DANE PKIX Anchor", isCa = true)
        val leaf = TestPki.issuedBy(anchor, "DANE PKIX Leaf", dnsNames = listOf(host))
        val tls = serve(listOf(leaf.certificate, anchor.certificate), leaf)

        // PKIX-TA (0) and PKIX-EE (1) need WebPKI validation, which a bootstrap
        // client has nothing to anchor; both match the presented chain exactly.
        assertRefused(
            tls,
            listOf(
                Tlsa(0, TlsaRecord.SELECTOR_FULL_CERT, TlsaRecord.MATCHING_SHA256, sha256(anchor.certificate.encoded)),
                Tlsa(1, TlsaRecord.SELECTOR_SPKI, TlsaRecord.MATCHING_SHA256, sha256(leaf.certificate.publicKey.encoded))
            )
        )
    }

    @Test(timeout = 30_000)
    fun anUnsignedTlsaAnswerNeverOpensATlsConnection() {
        val leaf = TestPki.selfSigned("DANE EE Leaf", dnsNames = listOf(host))
        val tls = serve(listOf(leaf.certificate), leaf)
        val resolver = startDns(listOf(daneEe(leaf.certificate)), flags = DnsWire.FLAGS_OK and DnsWire.FLAG_AD.inv())

        val failure = assertThrows(DANEException::class.java) {
            runBlocking { client(tls, resolver).fetchWithMethod(BootstrapMethod.DANE) }
        }

        assertTrue(failure.reason, failure.reason.contains("TLSA lookup failed"))
        assertEquals(0, tls.connections)
    }
}
