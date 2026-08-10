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
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Unit tests for the DANE branch of [BootstrapClient].
 *
 * The instrumented suite can only assert the configuration guard, because DANE
 * resolves TLSA records before it builds a request and there is no resolver to
 * answer it. Here a loopback DNS server supplies the records, and the HTTPS leg
 * is short-circuited by an interceptor -- which works precisely because
 * `createDaneHttpClient` derives its client from the injected one, so the whole
 * branch runs without a TLS server whose chain has to match a TLSA digest.
 */
class BootstrapDaneFetchTest {

    private val host = "kms.example.test"
    private val bootstrapPath = "/v1/ca/bootstrap"

    private var dns: DnsStubServer? = null
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
        unmockkAll()
    }

    /** A resolver that answers every TLSA query with one DANE-EE record. */
    private fun startDns(): DnsStubServer = DnsStubServer { query, _ ->
        val name = DnsWire.queriedName(query)
        queriedNames.add(name)
        DnsWire.replyTo(
            query,
            listOf(
                DnsAnswer(
                    owner = name,
                    type = DnsWire.TYPE_TLSA,
                    rdata = DnsWire.tlsaRdata(
                        TlsaRecord.USAGE_DANE_EE,
                        TlsaRecord.SELECTOR_SPKI,
                        TlsaRecord.MATCHING_SHA256,
                        ByteArray(32) { 0x5A }
                    )
                )
            )
        )
    }.also { dns = it }

    private fun settings(
        serverUrl: String = "https://$host:8443",
        dnsServer: String
    ) = BootstrapSettingsData(
        methodOrder = listOf(BootstrapMethod.DANE),
        perMethodTimeoutSeconds = 15,
        daneEnabled = true,
        daneServerUrl = serverUrl,
        daneDnsServer = dnsServer,
        daneRequireDnssec = true,
        noiseEnabled = false,
        spkiEnabled = false,
        directEnabled = false
    )

    private fun fetch(
        endpoint: StubBootstrapEndpoint,
        serverUrl: String = "https://$host:8443"
    ): CABundleResult = runBlocking {
        BootstrapClient(settings(serverUrl, startDns().address), endpoint.client())
            .fetchWithMethod(BootstrapMethod.DANE)
    }

    private fun <T : Throwable> assertDaneFailure(
        endpoint: StubBootstrapEndpoint,
        serverUrl: String = "https://$host:8443",
        expected: Class<T>
    ): T = assertThrows(expected) {
        runBlocking {
            BootstrapClient(settings(serverUrl, startDns().address), endpoint.client())
                .fetchWithMethod(BootstrapMethod.DANE)
        }
    }

    // ------------------------------------------------------------- happy path

    @Test
    fun returnsTheParsedBundle() {
        val certificate = TestPki.selfSigned("DANE Anchor").certificate
        val endpoint = StubBootstrapEndpoint.serving(TestPki.pem(certificate))

        val result = fetch(endpoint)

        assertEquals(BootstrapMethod.DANE, result.method)
        assertEquals(1, result.certificateCount)
        assertEquals("https://$host:8443$bootstrapPath", endpoint.requests.single().url.toString())
    }

    @Test
    fun queriesTheTlsaRecordForTheConfiguredPort() {
        fetch(StubBootstrapEndpoint.serving(TestPki.bundle(1)))

        assertEquals(listOf("_8443._tcp.$host."), queriedNames.toList())
    }

    @Test
    fun fallsBackToPortFourHundredAndFortyThreeWhenTheUrlOmitsIt() {
        fetch(StubBootstrapEndpoint.serving(TestPki.bundle(1)), serverUrl = "https://$host")

        assertEquals(listOf("_443._tcp.$host."), queriedNames.toList())
    }

    @Test
    fun stripsATrailingSlashFromTheConfiguredUrl() {
        val endpoint = StubBootstrapEndpoint.serving(TestPki.bundle(1))

        fetch(endpoint, serverUrl = "https://$host:8443/")

        assertEquals("https://$host:8443$bootstrapPath", endpoint.requests.single().url.toString())
    }

    @Test
    fun parsesEveryCertificateInAMultiAnchorBundle() {
        assertEquals(3, fetch(StubBootstrapEndpoint.serving(TestPki.bundle(3))).certificateCount)
    }

    // ---------------------------------------------------------------- failures

    @Test
    fun rejectsAnHttpError() {
        val failure = assertDaneFailure(
            StubBootstrapEndpoint.serving("nope", code = 502),
            expected = DANEException::class.java
        )
        assertTrue(failure.reason, failure.reason.contains("HTTP 502"))
    }

    @Test
    fun rejectsAnEmptyBody() {
        val failure = assertDaneFailure(
            StubBootstrapEndpoint.serving(ByteArray(0)),
            expected = DANEException::class.java
        )
        assertTrue(failure.reason, failure.reason.contains("Empty response body"))
    }

    @Test
    fun rejectsABodyOverTheOneMegabyteCap() {
        val oversized = ByteArray(1 * 1024 * 1024 + 4096) { 'A'.code.toByte() }

        val failure = assertDaneFailure(
            StubBootstrapEndpoint.serving(oversized),
            expected = DANEException::class.java
        )
        assertTrue(failure.reason, failure.reason.contains("Response too large"))
    }

    @Test
    fun rejectsABodyWithNoCertificates() {
        val failure = assertDaneFailure(
            StubBootstrapEndpoint.serving("not a bundle"),
            expected = DANEException::class.java
        )
        assertTrue(failure.reason, failure.reason.contains("No valid certificates"))
    }

    @Test
    fun wrapsATransportFailure() {
        val failure = assertDaneFailure(
            StubBootstrapEndpoint.failing(),
            expected = DANEException::class.java
        )
        assertTrue(failure.reason, failure.reason.contains("Network error"))
        assertNotNull(failure.cause)
    }

    @Test
    fun rejectsAServerUrlThatIsNotAUrl() {
        val client = BootstrapClient(
            settings(serverUrl = "ht!tp://[not-a-url", dnsServer = "127.0.0.1:5353"),
            StubBootstrapEndpoint.failing().client()
        )

        val failure = assertThrows(DANEException::class.java) {
            runBlocking { client.fetchWithMethod(BootstrapMethod.DANE) }
        }

        assertTrue(failure.reason, failure.reason.contains("Invalid DANE server URL"))
        assertNotNull(failure.cause)
    }

    @Test(timeout = 30_000)
    fun reportsATlsaLookupFailure() {
        val client = BootstrapClient(
            settings(dnsServer = DnsStubServer.unusedAddress()).copy(perMethodTimeoutSeconds = 5),
            StubBootstrapEndpoint.failing().client()
        )

        val failure = assertThrows(DANEException::class.java) {
            runBlocking { client.fetchWithMethod(BootstrapMethod.DANE) }
        }

        assertTrue(failure.reason, failure.reason.contains("TLSA lookup failed"))
        assertNotNull(failure.cause)
    }

    @Test(timeout = 30_000)
    fun reportsAnUnsignedTlsaAnswerAsALookupFailure() {
        // The resolver requires the AD flag, so an answer that was not
        // DNSSEC-validated must not be usable for bootstrap.
        dns = DnsStubServer { query, _ ->
            DnsWire.replyTo(
                query,
                listOf(
                    DnsAnswer(
                        owner = DnsWire.queriedName(query),
                        type = DnsWire.TYPE_TLSA,
                        rdata = DnsWire.tlsaRdata(3, 1, 1, ByteArray(32))
                    )
                ),
                flags = DnsWire.FLAGS_OK and DnsWire.FLAG_AD.inv()
            )
        }
        val client = BootstrapClient(
            settings(dnsServer = dns!!.address),
            StubBootstrapEndpoint.failing().client()
        )

        val failure = assertThrows(DANEException::class.java) {
            runBlocking { client.fetchWithMethod(BootstrapMethod.DANE) }
        }

        assertTrue(failure.reason, failure.reason.contains("TLSA lookup failed"))
    }
}
