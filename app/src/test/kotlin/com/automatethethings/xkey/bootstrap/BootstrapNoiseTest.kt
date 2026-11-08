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
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.Base64

/**
 * Unit tests for the Noise_NK bootstrap path of [BootstrapClient].
 *
 * The session that implements the handshake is a private inner class with no
 * seam, so the only honest way to reach its X25519 ladder, HKDF, symmetric-state
 * mixing and ChaCha20-Poly1305 transport is to complete a real exchange against
 * a responder that mirrors it. [NoiseBootstrapResponder] does exactly that over
 * a loopback socket; nothing here touches a routable address.
 *
 * The configuration guards (blank address, malformed key, bad port) already have
 * coverage in `BootstrapClientTest`; this suite is about everything downstream
 * of a successful connect.
 */
class BootstrapNoiseTest {

    private var responder: NoiseBootstrapResponder? = null

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
        responder?.close()
        responder = null
        unmockkAll()
    }

    private fun settingsFor(server: NoiseBootstrapResponder) = BootstrapSettingsData(
        methodOrder = listOf(BootstrapMethod.NOISE),
        perMethodTimeoutSeconds = 15,
        daneEnabled = false,
        noiseEnabled = true,
        noiseServerAddr = server.address,
        noiseServerStaticKey = server.staticPublicKeyHex,
        spkiEnabled = false,
        directEnabled = false
    )

    private fun fetch(server: NoiseBootstrapResponder): CABundleResult = runBlocking {
        BootstrapClient(settingsFor(server), StubBootstrapEndpoint.failing().client())
            .fetchWithMethod(BootstrapMethod.NOISE)
    }

    private fun start(
        reply: (String) -> String,
        encryptHandshakePayload: Boolean = false
    ): NoiseBootstrapResponder =
        NoiseBootstrapResponder(reply, encryptHandshakePayload).also { responder = it }

    private fun der(commonName: String): ByteArray =
        TestPki.selfSigned(commonName).certificate.encoded

    private fun bundleResponse(vararg certificates: ByteArray): String = JSONObject().apply {
        put("bundle_pem", "-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----\n")
        put(
            "certificates",
            JSONArray(certificates.map { Base64.getEncoder().encodeToString(it) })
        )
    }.toString()

    // -------------------------------------------------------------- handshake

    @Test
    fun completesTheHandshakeAndReturnsTheDecryptedBundle() {
        val first = der("Noise Anchor One")
        val second = der("Noise Anchor Two")
        val server = start({ bundleResponse(first, second) })

        val result = fetch(server)

        assertNull("responder failed: ${server.failure}", server.failure)
        assertEquals(BootstrapMethod.NOISE, result.method)
        assertEquals(2, result.certificateCount)
        assertTrue(result.isNotEmpty)
        assertArrayEqualsBytes(first, result.certificates[0])
        assertArrayEqualsBytes(second, result.certificates[1])
    }

    @Test
    fun sendsTheGetCaBundleRequestOverTheEstablishedSession() {
        val server = start({ bundleResponse(der("Noise Request Anchor")) })

        fetch(server)

        assertNull("responder failed: ${server.failure}", server.failure)
        assertEquals(
            "get_ca_bundle",
            JSONObject(server.receivedRequest!!).getString("method")
        )
    }

    @Test
    fun acceptsAnEncryptedPayloadOnTheSecondHandshakeMessage() {
        // A responder that appends an AEAD-protected (empty) payload to `e, ee`
        // drives the client's DecryptAndHash, which the bare form never reaches.
        val certificate = der("Noise Payload Anchor")
        val server = start({ bundleResponse(certificate) }, encryptHandshakePayload = true)

        val result = fetch(server)

        assertNull("responder failed: ${server.failure}", server.failure)
        assertEquals(1, result.certificateCount)
        assertArrayEqualsBytes(certificate, result.certificates[0])
    }

    @Test
    fun rejectsASecondHandshakeMessageShorterThanAPublicKey() {
        val server = NoiseBootstrapResponder(truncatedHandshakeLength = 16).also { responder = it }

        val failure = assertThrows(NoiseBootstrapException::class.java) {
            runBlocking {
                BootstrapClient(settingsFor(server), StubBootstrapEndpoint.failing().client())
                    .fetchWithMethod(BootstrapMethod.NOISE)
            }
        }

        assertTrue(failure.reason, failure.reason.contains("Message too short"))
    }

    @Test
    fun wrapsAConnectionFailure() {
        val settings = BootstrapSettingsData(
            methodOrder = listOf(BootstrapMethod.NOISE),
            perMethodTimeoutSeconds = 5,
            daneEnabled = false,
            noiseEnabled = true,
            noiseServerAddr = NoiseBootstrapResponder.unusedLoopbackAddress(),
            noiseServerStaticKey = "ab".repeat(32),
            spkiEnabled = false,
            directEnabled = false
        )
        val client = BootstrapClient(settings, StubBootstrapEndpoint.failing().client())

        val failure = assertThrows(NoiseBootstrapException::class.java) {
            runBlocking { client.fetchWithMethod(BootstrapMethod.NOISE) }
        }

        assertTrue(failure.reason, failure.reason.contains("Failed to connect"))
        assertNotNull(failure.cause)
    }

    // ------------------------------------------------------------ the payload

    @Test
    fun surfacesAServerReportedError() {
        val server = start({ """{"error":"no bundle configured"}""" })

        val failure = assertThrows(NoiseBootstrapException::class.java) {
            runBlocking {
                BootstrapClient(settingsFor(server), StubBootstrapEndpoint.failing().client())
                    .fetchWithMethod(BootstrapMethod.NOISE)
            }
        }

        assertTrue(failure.reason, failure.reason.contains("no bundle configured"))
    }

    @Test
    fun ignoresAnEmptyErrorField() {
        val certificate = der("Noise Empty Error Anchor")
        val server = start({
            JSONObject(bundleResponse(certificate)).put("error", "").toString()
        })

        assertEquals(1, fetch(server).certificateCount)
    }

    @Test
    fun returnsAnEmptyBundleWhenTheResponseCarriesNoCertificates() {
        val server = start({ "{}" })

        val result = fetch(server)

        assertNull("responder failed: ${server.failure}", server.failure)
        assertEquals(0, result.certificateCount)
        assertFalse(result.isNotEmpty)
        assertEquals(0, result.bundlePEM.size)
    }

    @Test
    fun keepsThePemBundleAlongsideTheDerCertificates() {
        val certificate = TestPki.selfSigned("Noise Pem Anchor").certificate
        val pem = TestPki.pem(certificate)
        val server = start({
            JSONObject().apply {
                put("bundle_pem", pem)
                put(
                    "certificates",
                    JSONArray(listOf(Base64.getEncoder().encodeToString(certificate.encoded)))
                )
            }.toString()
        })

        val result = fetch(server)

        assertEquals(pem, String(result.bundlePEM, Charsets.UTF_8))
        assertEquals(1, result.certificateCount)
    }

    @Test
    fun skipsAnUndecodableCertificateEntryButKeepsTheRest() {
        val good = der("Noise Survivor Anchor")
        val server = start({
            JSONObject().apply {
                put("bundle_pem", "")
                put(
                    "certificates",
                    JSONArray(
                        listOf("not base64 at all", Base64.getEncoder().encodeToString(good))
                    )
                )
            }.toString()
        })

        val result = fetch(server)

        assertEquals(1, result.certificateCount)
        assertArrayEqualsBytes(good, result.certificates[0])
    }

    @Test
    fun rejectsABundleOverTheCertificateCap() {
        val encoded = Base64.getEncoder().encodeToString(der("Noise Flood Anchor"))
        val server = start({
            JSONObject().apply {
                put("bundle_pem", "")
                put("certificates", JSONArray((1..65).map { encoded }))
            }.toString()
        })

        val failure = assertThrows(NoiseBootstrapException::class.java) {
            runBlocking {
                BootstrapClient(settingsFor(server), StubBootstrapEndpoint.failing().client())
                    .fetchWithMethod(BootstrapMethod.NOISE)
            }
        }

        assertTrue(failure.reason, failure.reason.contains("limit is 64"))
    }

    @Test
    fun acceptsABundleExactlyAtTheCertificateCap() {
        val encoded = Base64.getEncoder().encodeToString(der("Noise Capped Anchor"))
        val server = start({
            JSONObject().apply {
                put("bundle_pem", "")
                put("certificates", JSONArray((1..64).map { encoded }))
            }.toString()
        })

        assertEquals(64, fetch(server).certificateCount)
    }

    private fun assertArrayEqualsBytes(expected: ByteArray, actual: ByteArray) {
        assertTrue(
            "expected ${expected.size} bytes to match, got ${actual.size}",
            expected.contentEquals(actual)
        )
    }
}
