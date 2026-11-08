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

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.settings.BootstrapMethod
import com.automatethethings.xkey.settings.BootstrapSettingsData
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * Instrumented tests for [BootstrapClient].
 *
 * The certificate work needs a real `CertificateFactory` and the settings types
 * come from the Android side of the app, so this runs on a device.
 * `DaneVerifierTest` already covers TLSA matching in the JVM; nothing here
 * repeats it.
 *
 * All traffic is answered by [BootstrapTestServer], an interceptor that
 * short-circuits before any socket opens, so the suite is hermetic: it never
 * resolves DNS and never speaks TLS. The DANE path is the one exception -- it
 * resolves TLSA records before it ever builds a request -- so only its
 * configuration guard is asserted here.
 */
@RunWith(AndroidJUnit4::class)
class BootstrapClientTest {

    private val serverUrl = "https://bootstrap.example.test:8443"
    private val bootstrapPath = "/v1/ca/bootstrap"
    private val validPin = "ab".repeat(32)

    private fun directSettings(url: String = serverUrl) = BootstrapSettingsData(
        methodOrder = listOf(BootstrapMethod.DIRECT),
        daneEnabled = false,
        noiseEnabled = false,
        spkiEnabled = false,
        directEnabled = true,
        directServerUrl = url
    )

    private fun spkiSettings(
        url: String = serverUrl,
        pin: String = validPin
    ) = BootstrapSettingsData(
        methodOrder = listOf(BootstrapMethod.SPKI),
        daneEnabled = false,
        noiseEnabled = false,
        spkiEnabled = true,
        spkiServerUrl = url,
        spkiPinSha256 = pin,
        directEnabled = false
    )

    private fun parse(der: ByteArray): X509Certificate =
        CertificateFactory.getInstance("X.509")
            .generateCertificate(der.inputStream()) as X509Certificate

    // ---------------------------------------------------------------- direct

    @Test
    fun direct_returnsTheParsedBundle() = runBlocking {
        val certificate = BootstrapTestServer.certificate("Direct Anchor")
        val pem = BootstrapTestServer.pem(certificate)
        val server = BootstrapTestServer.serving(pem)
        val client = BootstrapClient(directSettings(), server.client())

        val result = client.fetchWithMethod(BootstrapMethod.DIRECT)

        assertEquals(BootstrapMethod.DIRECT, result.method)
        assertEquals(1, result.certificateCount)
        assertTrue(result.isNotEmpty)
        assertEquals(pem, String(result.bundlePEM, Charsets.UTF_8))
        assertEquals(certificate.subjectX500Principal, parse(result.certificates[0]).subjectX500Principal)
    }

    @Test
    fun direct_requestsTheBootstrapPath() = runBlocking {
        val server = BootstrapTestServer.serving(BootstrapTestServer.bundle(1))
        val client = BootstrapClient(directSettings(), server.client())

        client.fetchWithMethod(BootstrapMethod.DIRECT)

        assertEquals(
            "$serverUrl$bootstrapPath",
            server.singleRequest().url.toString()
        )
    }

    @Test
    fun direct_stripsATrailingSlashFromTheConfiguredUrl() = runBlocking {
        val server = BootstrapTestServer.serving(BootstrapTestServer.bundle(1))
        val client = BootstrapClient(directSettings("$serverUrl/"), server.client())

        client.fetchWithMethod(BootstrapMethod.DIRECT)

        assertEquals("$serverUrl$bootstrapPath", server.singleRequest().url.toString())
    }

    @Test
    fun direct_skipsAnUndecodableBlockButKeepsTheRest() = runBlocking {
        val good = BootstrapTestServer.pem(BootstrapTestServer.certificate("Good Anchor"))
        val garbage = "-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydGlmaWNhdGU=\n-----END CERTIFICATE-----\n"
        val server = BootstrapTestServer.serving(garbage + good)
        val client = BootstrapClient(directSettings(), server.client())

        val result = client.fetchWithMethod(BootstrapMethod.DIRECT)

        assertEquals(1, result.certificateCount)
    }

    @Test
    fun direct_rejectsAnHttpError() {
        val server = BootstrapTestServer.serving("nope", code = 503)
        val client = BootstrapClient(directSettings(), server.client())

        val failure = assertThrows(DirectException::class.java) {
            runBlocking { client.fetchWithMethod(BootstrapMethod.DIRECT) }
        }

        assertEquals(503, failure.httpStatusCode)
    }

    @Test
    fun direct_rejectsAnEmptyBody() {
        val server = BootstrapTestServer.serving(ByteArray(0))
        val client = BootstrapClient(directSettings(), server.client())

        val failure = assertThrows(DirectException::class.java) {
            runBlocking { client.fetchWithMethod(BootstrapMethod.DIRECT) }
        }

        assertTrue(failure.reason, failure.reason.contains("Empty response body"))
    }

    @Test
    fun direct_rejectsABodyOverTheOneMegabyteCap() {
        val oversized = ByteArray(1 * 1024 * 1024 + 4096) { 'A'.code.toByte() }
        val server = BootstrapTestServer.serving(oversized)
        val client = BootstrapClient(directSettings(), server.client())

        val failure = assertThrows(DirectException::class.java) {
            runBlocking { client.fetchWithMethod(BootstrapMethod.DIRECT) }
        }

        assertTrue(failure.reason, failure.reason.contains("Response too large"))
    }

    @Test
    fun direct_acceptsABodyJustUnderTheCap() = runBlocking {
        // Padding before the PEM keeps the body large without making it invalid;
        // the parser scans for BEGIN/END markers rather than requiring a clean file.
        val pem = BootstrapTestServer.pem(BootstrapTestServer.certificate("Padded Anchor"))
        val padding = "#".repeat(1 * 1024 * 1024 - pem.length - 1)
        val server = BootstrapTestServer.serving(padding + pem)
        val client = BootstrapClient(directSettings(), server.client())

        val result = client.fetchWithMethod(BootstrapMethod.DIRECT)

        assertEquals(1, result.certificateCount)
    }

    @Test
    fun direct_rejectsABodyWithNoCertificates() {
        val server = BootstrapTestServer.serving("this is not a certificate bundle")
        val client = BootstrapClient(directSettings(), server.client())

        assertThrows(CertificateParseException::class.java) {
            runBlocking { client.fetchWithMethod(BootstrapMethod.DIRECT) }
        }
    }

    @Test
    fun direct_rejectsAnUnconfiguredUrl() {
        val client = BootstrapClient(directSettings(url = ""), BootstrapTestServer.failing().client())

        val failure = assertThrows(DirectException::class.java) {
            runBlocking { client.fetchWithMethod(BootstrapMethod.DIRECT) }
        }

        assertTrue(failure.reason, failure.reason.contains("not configured"))
    }

    @Test
    fun direct_wrapsATransportFailure() {
        val client = BootstrapClient(directSettings(), BootstrapTestServer.failing().client())

        val failure = assertThrows(DirectException::class.java) {
            runBlocking { client.fetchWithMethod(BootstrapMethod.DIRECT) }
        }

        assertNotNull(failure.cause)
    }

    // ------------------------------------------------------------------ spki

    @Test
    fun spki_returnsTheParsedBundle() = runBlocking {
        val server = BootstrapTestServer.serving(BootstrapTestServer.bundle(2))
        val client = BootstrapClient(spkiSettings(), server.client())

        val result = client.fetchWithMethod(BootstrapMethod.SPKI)

        assertEquals(BootstrapMethod.SPKI, result.method)
        assertEquals(2, result.certificateCount)
        assertEquals("$serverUrl$bootstrapPath", server.singleRequest().url.toString())
    }

    @Test
    fun spki_rejectsAnUnconfiguredUrl() {
        val client = BootstrapClient(spkiSettings(url = ""), BootstrapTestServer.failing().client())

        assertThrows(SPKIException::class.java) {
            runBlocking { client.fetchWithMethod(BootstrapMethod.SPKI) }
        }
    }

    @Test
    fun spki_rejectsAnUnconfiguredPin() {
        val client = BootstrapClient(spkiSettings(pin = ""), BootstrapTestServer.failing().client())

        assertThrows(SPKIException::class.java) {
            runBlocking { client.fetchWithMethod(BootstrapMethod.SPKI) }
        }
    }

    @Test
    fun spki_rejectsAPinThatIsNotASha256() {
        val client = BootstrapClient(
            spkiSettings(pin = "abcdef"),
            BootstrapTestServer.failing().client()
        )

        val failure = assertThrows(BootstrapConfigException::class.java) {
            runBlocking { client.fetchWithMethod(BootstrapMethod.SPKI) }
        }

        assertTrue(failure.reason, failure.reason.contains("64 hex characters"))
    }

    @Test
    fun spki_rejectsAnHttpError() {
        val server = BootstrapTestServer.serving("nope", code = 404)
        val client = BootstrapClient(spkiSettings(), server.client())

        val failure = assertThrows(DirectException::class.java) {
            runBlocking { client.fetchWithMethod(BootstrapMethod.SPKI) }
        }

        assertEquals(404, failure.httpStatusCode)
    }

    @Test
    fun spki_rejectsABodyOverTheOneMegabyteCap() {
        val oversized = ByteArray(1 * 1024 * 1024 + 4096) { 'A'.code.toByte() }
        val server = BootstrapTestServer.serving(oversized)
        val client = BootstrapClient(spkiSettings(), server.client())

        val failure = assertThrows(DirectException::class.java) {
            runBlocking { client.fetchWithMethod(BootstrapMethod.SPKI) }
        }

        assertTrue(failure.reason, failure.reason.contains("Response too large"))
    }

    @Test
    fun spki_rejectsABodyWithNoCertificates() {
        val server = BootstrapTestServer.serving("still not a bundle")
        val client = BootstrapClient(spkiSettings(), server.client())

        assertThrows(CertificateParseException::class.java) {
            runBlocking { client.fetchWithMethod(BootstrapMethod.SPKI) }
        }
    }

    // ----------------------------------------------------------------- noise

    private fun noiseSettings(addr: String, key: String) = BootstrapSettingsData(
        methodOrder = listOf(BootstrapMethod.NOISE),
        daneEnabled = false,
        noiseEnabled = true,
        noiseServerAddr = addr,
        noiseServerStaticKey = key,
        spkiEnabled = false,
        directEnabled = false
    )

    private fun assertNoiseRejects(addr: String, key: String, expected: String) {
        val client = BootstrapClient(noiseSettings(addr, key), BootstrapTestServer.failing().client())

        val failure = assertThrows(NoiseBootstrapException::class.java) {
            runBlocking { client.fetchWithMethod(BootstrapMethod.NOISE) }
        }

        assertTrue(failure.reason, failure.reason.contains(expected))
    }

    @Test
    fun noise_rejectsAnUnconfiguredAddress() {
        assertNoiseRejects("", "ab".repeat(32), "address not configured")
    }

    @Test
    fun noise_rejectsAnUnconfiguredStaticKey() {
        assertNoiseRejects("noise.example.test:8445", "", "static key not configured")
    }

    @Test
    fun noise_rejectsAnOddLengthStaticKey() {
        assertNoiseRejects("noise.example.test:8445", "abc", "Invalid server static key")
    }

    @Test
    fun noise_rejectsAStaticKeyOfTheWrongLength() {
        assertNoiseRejects("noise.example.test:8445", "abcd", "must be 32 bytes")
    }

    @Test
    fun noise_rejectsAnAddressWithoutAPort() {
        assertNoiseRejects("noise.example.test", "ab".repeat(32), "Invalid server address format")
    }

    @Test
    fun noise_rejectsANonNumericPort() {
        assertNoiseRejects("noise.example.test:https", "ab".repeat(32), "Invalid port")
    }

    // ------------------------------------------------------------------ dane

    @Test
    fun dane_rejectsAnUnconfiguredUrl() {
        val settings = BootstrapSettingsData(
            methodOrder = listOf(BootstrapMethod.DANE),
            daneEnabled = true,
            daneServerUrl = "",
            noiseEnabled = false,
            spkiEnabled = false,
            directEnabled = false
        )
        val client = BootstrapClient(settings, BootstrapTestServer.failing().client())

        val failure = assertThrows(DANEException::class.java) {
            runBlocking { client.fetchWithMethod(BootstrapMethod.DANE) }
        }

        assertTrue(failure.reason, failure.reason.contains("not configured"))
    }

    // ------------------------------------------------------- auto-bootstrap

    @Test
    fun autoBootstrap_refusesWhenNoMethodIsEnabled() {
        val settings = BootstrapSettingsData(
            daneEnabled = false,
            noiseEnabled = false,
            spkiEnabled = false,
            directEnabled = false
        )
        val client = BootstrapClient(settings, BootstrapTestServer.failing().client())

        assertThrows(NoMethodsConfiguredException::class.java) {
            runBlocking { client.fetchCABundle() }
        }
    }

    @Test
    fun autoBootstrap_returnsTheFirstMethodThatWorks() = runBlocking {
        val server = BootstrapTestServer.serving(BootstrapTestServer.bundle(1))
        val settings = BootstrapSettingsData(
            methodOrder = listOf(BootstrapMethod.NOISE, BootstrapMethod.DIRECT),
            daneEnabled = false,
            // Enabled but deliberately unconfigured, so it fails before Direct runs.
            noiseEnabled = true,
            noiseServerAddr = "",
            spkiEnabled = false,
            directEnabled = true,
            directServerUrl = serverUrl
        )
        val client = BootstrapClient(settings, server.client())

        val result = client.fetchCABundle()

        assertEquals(BootstrapMethod.DIRECT, result.method)
        assertEquals(1, result.certificateCount)
    }

    @Test
    fun autoBootstrap_skipsADisabledMethodEntirely() = runBlocking {
        val server = BootstrapTestServer.serving(BootstrapTestServer.bundle(1))
        val settings = directSettings().copy(
            methodOrder = listOf(BootstrapMethod.DANE, BootstrapMethod.DIRECT)
        )
        val client = BootstrapClient(settings, server.client())

        val result = client.fetchCABundle()

        assertEquals(BootstrapMethod.DIRECT, result.method)
        // DANE is disabled, so it never resolved TLSA and never issued a request.
        assertEquals(1, server.requests.size)
    }

    @Test
    fun autoBootstrap_reportsEveryAttemptWhenAllMethodsFail() {
        val settings = BootstrapSettingsData(
            methodOrder = listOf(BootstrapMethod.NOISE, BootstrapMethod.SPKI, BootstrapMethod.DIRECT),
            daneEnabled = false,
            noiseEnabled = true,
            noiseServerAddr = "",
            spkiEnabled = true,
            spkiServerUrl = "",
            spkiPinSha256 = validPin,
            directEnabled = true,
            directServerUrl = ""
        )
        val client = BootstrapClient(settings, BootstrapTestServer.failing().client())

        val failure = assertThrows(BootstrapFailedException::class.java) {
            runBlocking { client.fetchCABundle() }
        }

        assertEquals(
            listOf(BootstrapMethod.NOISE, BootstrapMethod.SPKI, BootstrapMethod.DIRECT),
            failure.attempts.map { it.method }
        )
        assertTrue(failure.message!!.contains("all methods failed"))
    }
}
