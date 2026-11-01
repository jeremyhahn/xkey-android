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
package com.automatethethings.xkey.protocol

import android.util.Base64
import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

/**
 * Unit tests for the IDevID certificate-exchange payloads in `Messages.kt`
 * (`local.getCABundle`, `local.getIDevIDCertificate`,
 * `local.requestIDevIDIssuance`, `local.generateIDevIDCSR`,
 * `local.storeIDevIDCertificate`) and their shared value types
 * [IDevIDCertificateInfo] and [IDevIDSubject].
 *
 * Counterpart: `go-xkms/xkey/pkg/pairing/protocol_idevid.go`. Every binary
 * field on this family crosses the wire base64-encoded, so the tests cover the
 * encode/decode round trip alongside the field names, the optional-field
 * omission rules and the hand-written `equals`/`hashCode` overrides these
 * ByteArray-bearing data classes need.
 *
 * These types call `android.util.Base64`, which is a throwing stub on the JVM,
 * so it is statically mocked here and delegated to `java.util.Base64` (the same
 * approach `PinManagerTest` uses). That keeps the mapping logic under unit test
 * without needing a device.
 */
class IDevIDMessagesTest {

    private fun JSONObject.keySet(): Set<String> = keys().asSequence().toSet()

    private fun b64(text: String): String =
        java.util.Base64.getEncoder().encodeToString(text.toByteArray())

    @Before
    fun setUp() {
        mockkStatic(Base64::class)
        every { Base64.encodeToString(any(), any()) } answers {
            java.util.Base64.getEncoder().encodeToString(firstArg())
        }
        every { Base64.decode(any<String>(), any()) } answers {
            java.util.Base64.getDecoder().decode(firstArg<String>())
        }
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    // -------------------------------------------------------------------------
    // LocalGetCABundleParams
    // -------------------------------------------------------------------------

    @Test
    fun `LocalGetCABundleParams fromJson reads includeRoot and format`() {
        val params = LocalGetCABundleParams.fromJson(
            JSONObject("""{"includeRoot":true,"format":"pem"}""")
        )

        assertEquals(true, params.includeRoot)
        assertEquals("pem", params.format)
    }

    @Test
    fun `LocalGetCABundleParams fromJson leaves both fields null when absent`() {
        val params = LocalGetCABundleParams.fromJson(JSONObject("{}"))

        assertNull(params.includeRoot)
        assertNull(params.format)
    }

    @Test
    fun `LocalGetCABundleParams fromJson treats an explicitly null format as absent`() {
        assertNull(LocalGetCABundleParams.fromJson(JSONObject("""{"format":null}""")).format)
    }

    @Test
    fun `LocalGetCABundleParams toJson omits both fields when null`() {
        assertEquals(emptySet<String>(), LocalGetCABundleParams().toJson().keySet())
    }

    @Test
    fun `LocalGetCABundleParams round-trips through toJson and fromJson`() {
        val original = LocalGetCABundleParams(includeRoot = false, format = "der")

        assertEquals(setOf("includeRoot", "format"), original.toJson().keySet())
        assertEquals(original, LocalGetCABundleParams.fromJson(original.toJson()))
    }

    // -------------------------------------------------------------------------
    // LocalGetCABundleResult
    // -------------------------------------------------------------------------

    @Test
    fun `LocalGetCABundleResult toJson base64-encodes the bundle and each certificate`() {
        val json = LocalGetCABundleResult(
            bundlePem = "PEM-BUNDLE".toByteArray(),
            certificates = listOf("cert-a".toByteArray(), "cert-b".toByteArray()),
            count = 2,
            rootSubject = "CN=xKey Root"
        ).toJson()

        assertEquals(setOf("bundlePem", "certificates", "count", "rootSubject"), json.keySet())
        assertEquals(b64("PEM-BUNDLE"), json.getString("bundlePem"))
        assertEquals(2, json.getJSONArray("certificates").length())
        assertEquals(b64("cert-a"), json.getJSONArray("certificates").getString(0))
        assertEquals(b64("cert-b"), json.getJSONArray("certificates").getString(1))
        assertEquals("CN=xKey Root", json.getString("rootSubject"))
    }

    @Test
    fun `LocalGetCABundleResult toJson omits a null bundlePem and rootSubject`() {
        val json = LocalGetCABundleResult(certificates = emptyList(), count = 0).toJson()

        assertEquals(setOf("certificates", "count"), json.keySet())
        assertEquals(0, json.getJSONArray("certificates").length())
    }

    @Test
    fun `LocalGetCABundleResult fromJson decodes the certificates back to bytes`() {
        val result = LocalGetCABundleResult.fromJson(
            JSONObject("""{"certificates":["${b64("cert-a")}"],"count":1}""")
        )

        assertEquals(1, result.certificates.size)
        assertArrayEquals("cert-a".toByteArray(), result.certificates[0])
        assertNull(result.bundlePem)
        assertNull(result.rootSubject)
    }

    @Test
    fun `LocalGetCABundleResult fromJson defaults count to the certificate list size`() {
        val result = LocalGetCABundleResult.fromJson(
            JSONObject("""{"certificates":["${b64("a")}","${b64("b")}"]}""")
        )

        assertEquals(2, result.count)
    }

    @Test
    fun `LocalGetCABundleResult fromJson tolerates a completely empty result`() {
        val result = LocalGetCABundleResult.fromJson(JSONObject("{}"))

        assertTrue(result.certificates.isEmpty())
        assertEquals(0, result.count)
    }

    @Test
    fun `LocalGetCABundleResult round-trips including its ByteArray equality override`() {
        val original = LocalGetCABundleResult(
            bundlePem = "PEM".toByteArray(),
            certificates = listOf("cert".toByteArray()),
            count = 1,
            rootSubject = "CN=Root"
        )

        val parsed = LocalGetCABundleResult.fromJson(original.toJson())

        assertEquals(original, parsed)
        assertEquals(original.hashCode(), parsed.hashCode())
    }

    // -------------------------------------------------------------------------
    // LocalGetIDevIDCertificateParams / Result
    // -------------------------------------------------------------------------

    @Test
    fun `LocalGetIDevIDCertificateParams toJson omits a null nonce`() {
        assertEquals(emptySet<String>(), LocalGetIDevIDCertificateParams().toJson().keySet())
    }

    @Test
    fun `LocalGetIDevIDCertificateParams round-trips the nonce bytes`() {
        val original = LocalGetIDevIDCertificateParams("nonce".toByteArray())

        val parsed = LocalGetIDevIDCertificateParams.fromJson(original.toJson())

        assertEquals(setOf("nonce"), original.toJson().keySet())
        assertArrayEquals("nonce".toByteArray(), parsed.nonce)
        assertEquals(original, parsed)
    }

    @Test
    fun `LocalGetIDevIDCertificateParams fromJson treats an explicit null nonce as absent`() {
        assertNull(LocalGetIDevIDCertificateParams.fromJson(JSONObject("""{"nonce":null}""")).nonce)
    }

    @Test
    fun `LocalGetIDevIDCertificateResult toJson reports the absence of a certificate`() {
        val json = LocalGetIDevIDCertificateResult(hasCertificate = false).toJson()

        assertEquals(setOf("hasCertificate"), json.keySet())
        assertFalse(json.getBoolean("hasCertificate"))
    }

    @Test
    fun `LocalGetIDevIDCertificateResult toJson emits the chain nonce and info when present`() {
        val json = LocalGetIDevIDCertificateResult(
            hasCertificate = true,
            certificateChain = listOf("leaf".toByteArray(), "root".toByteArray()),
            nonce = "nonce".toByteArray(),
            certificateInfo = sampleCertificateInfo()
        ).toJson()

        assertEquals(setOf("hasCertificate", "certificateChain", "nonce", "certificateInfo"), json.keySet())
        assertEquals(b64("leaf"), json.getJSONArray("certificateChain").getString(0))
        assertEquals(b64("nonce"), json.getString("nonce"))
        assertEquals("CN=device", json.getJSONObject("certificateInfo").getString("subject"))
    }

    @Test
    fun `LocalGetIDevIDCertificateResult fromJson defaults hasCertificate to false`() {
        val result = LocalGetIDevIDCertificateResult.fromJson(JSONObject("{}"))

        assertFalse(result.hasCertificate)
        assertNull(result.certificateChain)
        assertNull(result.nonce)
        assertNull(result.certificateInfo)
    }

    @Test
    fun `LocalGetIDevIDCertificateResult round-trips the full payload`() {
        val original = LocalGetIDevIDCertificateResult(
            hasCertificate = true,
            certificateChain = listOf("leaf".toByteArray(), "root".toByteArray()),
            nonce = "nonce".toByteArray(),
            certificateInfo = sampleCertificateInfo()
        )

        val parsed = LocalGetIDevIDCertificateResult.fromJson(original.toJson())

        assertEquals(original, parsed)
        assertEquals(original.hashCode(), parsed.hashCode())
    }

    // -------------------------------------------------------------------------
    // IDevIDCertificateInfo
    // -------------------------------------------------------------------------

    @Test
    fun `IDevIDCertificateInfo toJson emits the required fields and omits absent optionals`() {
        val json = sampleCertificateInfo().toJson()

        assertEquals(
            setOf(
                "serialNumber", "issuer", "subject", "notBefore", "notAfter", "algorithm",
                "publicKeyAlgorithm", "keySizeBits", "fingerprint", "isCa"
            ),
            json.keySet()
        )
        assertEquals("0a0b", json.getString("serialNumber"))
        assertEquals("CN=issuer", json.getString("issuer"))
        assertEquals(1700000000L, json.getLong("notBefore"))
        assertEquals(1800000000L, json.getLong("notAfter"))
        assertEquals("ECDSA-SHA256", json.getString("algorithm"))
        assertEquals("ECDSA", json.getString("publicKeyAlgorithm"))
        assertEquals(256, json.getInt("keySizeBits"))
        assertFalse(json.getBoolean("isCa"))
    }

    @Test
    fun `IDevIDCertificateInfo toJson emits the usage arrays and hardwareSerial when present`() {
        val json = sampleCertificateInfo().copy(
            isCa = true,
            keyUsage = listOf("digitalSignature", "keyCertSign"),
            extKeyUsage = listOf("clientAuth"),
            hardwareSerial = "SN-123"
        ).toJson()

        assertTrue(json.getBoolean("isCa"))
        assertEquals(2, json.getJSONArray("keyUsage").length())
        assertEquals("digitalSignature", json.getJSONArray("keyUsage").getString(0))
        assertEquals("clientAuth", json.getJSONArray("extKeyUsage").getString(0))
        assertEquals("SN-123", json.getString("hardwareSerial"))
    }

    @Test
    fun `IDevIDCertificateInfo fromJson defaults isCa and the optional lists`() {
        val info = IDevIDCertificateInfo.fromJson(sampleCertificateInfo().toJson())

        assertFalse(info.isCa)
        assertNull(info.keyUsage)
        assertNull(info.extKeyUsage)
        assertNull(info.hardwareSerial)
    }

    @Test
    fun `IDevIDCertificateInfo round-trips through toJson and fromJson`() {
        val original = sampleCertificateInfo().copy(
            isCa = true,
            keyUsage = listOf("digitalSignature"),
            extKeyUsage = listOf("clientAuth"),
            hardwareSerial = "SN-123"
        )

        assertEquals(original, IDevIDCertificateInfo.fromJson(original.toJson()))
    }

    @Test
    fun `IDevIDCertificateInfo fromJson raises when a required field is missing`() {
        assertThrowsAny { IDevIDCertificateInfo.fromJson(JSONObject("""{"serialNumber":"0a"}""")) }
    }

    // -------------------------------------------------------------------------
    // IDevIDSubject
    // -------------------------------------------------------------------------

    @Test
    fun `IDevIDSubject toJson omits every absent attribute`() {
        assertEquals(emptySet<String>(), IDevIDSubject().toJson().keySet())
    }

    @Test
    fun `IDevIDSubject toJson emits every supplied attribute`() {
        val json = fullSubject().toJson()

        assertEquals(
            setOf(
                "commonName", "organization", "organizationalUnit",
                "serialNumber", "country", "locality", "province"
            ),
            json.keySet()
        )
        assertEquals("device-1", json.getString("commonName"))
        assertEquals("ATT", json.getString("organization"))
        assertEquals("Devices", json.getString("organizationalUnit"))
        assertEquals("SN-1", json.getString("serialNumber"))
        assertEquals("US", json.getString("country"))
        assertEquals("Austin", json.getString("locality"))
        assertEquals("TX", json.getString("province"))
    }

    @Test
    fun `IDevIDSubject fromJson treats explicit nulls as absent attributes`() {
        val subject = IDevIDSubject.fromJson(
            JSONObject("""{"commonName":"device-1","organization":null}""")
        )

        assertEquals("device-1", subject.commonName)
        assertNull(subject.organization)
    }

    @Test
    fun `IDevIDSubject round-trips through toJson and fromJson`() {
        val original = fullSubject()

        assertEquals(original, IDevIDSubject.fromJson(original.toJson()))
    }

    // -------------------------------------------------------------------------
    // LocalRequestIDevIDIssuanceParams / Result
    // -------------------------------------------------------------------------

    @Test
    fun `LocalRequestIDevIDIssuanceParams toJson base64-encodes the CSR and omits absent optionals`() {
        val json = LocalRequestIDevIDIssuanceParams(csr = "csr-der".toByteArray()).toJson()

        assertEquals(setOf("csr"), json.keySet())
        assertEquals(b64("csr-der"), json.getString("csr"))
    }

    @Test
    fun `LocalRequestIDevIDIssuanceParams toJson emits csrFormat attestationData and validityDays`() {
        val json = LocalRequestIDevIDIssuanceParams(
            csr = "csr-der".toByteArray(),
            csrFormat = "pkcs10",
            attestationData = "evidence".toByteArray(),
            validityDays = 365
        ).toJson()

        assertEquals(setOf("csr", "csrFormat", "attestationData", "validityDays"), json.keySet())
        assertEquals("pkcs10", json.getString("csrFormat"))
        assertEquals(b64("evidence"), json.getString("attestationData"))
        assertEquals(365, json.getInt("validityDays"))
    }

    @Test
    fun `LocalRequestIDevIDIssuanceParams fromJson rejects a missing csr with INVALID_PARAMS`() {
        val e = assertProtocolException {
            LocalRequestIDevIDIssuanceParams.fromJson(JSONObject("""{"csrFormat":"pkcs10"}"""))
        }

        assertEquals(ErrorCodes.INVALID_PARAMS, e.errorCode)
        assertTrue("message was: ${e.message}", e.message!!.contains("csr"))
    }

    @Test
    fun `LocalRequestIDevIDIssuanceParams round-trips including ByteArray equality`() {
        val original = LocalRequestIDevIDIssuanceParams(
            csr = "csr-der".toByteArray(),
            csrFormat = "tcg-csr-idevid",
            attestationData = "evidence".toByteArray(),
            validityDays = 90
        )

        val parsed = LocalRequestIDevIDIssuanceParams.fromJson(original.toJson())

        assertEquals(original, parsed)
        assertEquals(original.hashCode(), parsed.hashCode())
        assertArrayEquals("csr-der".toByteArray(), parsed.csr)
    }

    @Test
    fun `LocalRequestIDevIDIssuanceResult toJson reports a failure with an error code and message`() {
        val json = LocalRequestIDevIDIssuanceResult(
            issued = false,
            errorCode = "CSR_REJECTED",
            errorMessage = "attestation missing"
        ).toJson()

        assertEquals(setOf("issued", "errorCode", "errorMessage"), json.keySet())
        assertFalse(json.getBoolean("issued"))
        assertEquals("CSR_REJECTED", json.getString("errorCode"))
        assertEquals("attestation missing", json.getString("errorMessage"))
    }

    @Test
    fun `LocalRequestIDevIDIssuanceResult toJson emits the issued certificate and chain`() {
        val json = LocalRequestIDevIDIssuanceResult(
            issued = true,
            certificate = "leaf".toByteArray(),
            certificateChain = listOf("intermediate".toByteArray(), "root".toByteArray()),
            certificateInfo = sampleCertificateInfo()
        ).toJson()

        assertEquals(setOf("issued", "certificate", "certificateChain", "certificateInfo"), json.keySet())
        assertEquals(b64("leaf"), json.getString("certificate"))
        assertEquals(2, json.getJSONArray("certificateChain").length())
    }

    @Test
    fun `LocalRequestIDevIDIssuanceResult fromJson defaults issued to false`() {
        assertFalse(LocalRequestIDevIDIssuanceResult.fromJson(JSONObject("{}")).issued)
    }

    @Test
    fun `LocalRequestIDevIDIssuanceResult round-trips including ByteArray equality`() {
        val original = LocalRequestIDevIDIssuanceResult(
            issued = true,
            certificate = "leaf".toByteArray(),
            certificateChain = listOf("root".toByteArray()),
            certificateInfo = sampleCertificateInfo()
        )

        val parsed = LocalRequestIDevIDIssuanceResult.fromJson(original.toJson())

        assertEquals(original, parsed)
        assertEquals(original.hashCode(), parsed.hashCode())
    }

    // -------------------------------------------------------------------------
    // LocalGenerateIDevIDCSRParams / Result
    // -------------------------------------------------------------------------

    @Test
    fun `LocalGenerateIDevIDCSRParams toJson omits every absent field`() {
        assertEquals(emptySet<String>(), LocalGenerateIDevIDCSRParams().toJson().keySet())
    }

    @Test
    fun `LocalGenerateIDevIDCSRParams toJson nests the subject object`() {
        val json = LocalGenerateIDevIDCSRParams(
            backend = "tpm2",
            keyId = "k",
            algorithm = "ES256",
            subject = fullSubject(),
            csrFormat = "pkcs10"
        ).toJson()

        assertEquals(setOf("backend", "keyId", "algorithm", "subject", "csrFormat"), json.keySet())
        assertEquals("device-1", json.getJSONObject("subject").getString("commonName"))
    }

    @Test
    fun `LocalGenerateIDevIDCSRParams round-trips through toJson and fromJson`() {
        val original = LocalGenerateIDevIDCSRParams("tpm2", "k", "ES256", fullSubject(), "pkcs10")

        assertEquals(original, LocalGenerateIDevIDCSRParams.fromJson(original.toJson()))
    }

    @Test
    fun `LocalGenerateIDevIDCSRParams fromJson leaves an absent subject null`() {
        assertNull(LocalGenerateIDevIDCSRParams.fromJson(JSONObject("""{"backend":"tpm2"}""")).subject)
    }

    @Test
    fun `LocalGenerateIDevIDCSRResult toJson emits the CSR metadata and omits a null publicKey`() {
        val json = LocalGenerateIDevIDCSRResult(
            csr = "csr".toByteArray(),
            csrFormat = "pkcs10",
            keyId = "k",
            backend = "tpm2",
            algorithm = "ES256"
        ).toJson()

        assertEquals(setOf("csr", "csrFormat", "keyId", "backend", "algorithm"), json.keySet())
        assertEquals(b64("csr"), json.getString("csr"))
    }

    @Test
    fun `LocalGenerateIDevIDCSRResult fromJson rejects a missing csr with INTERNAL_ERROR`() {
        val e = assertProtocolException {
            LocalGenerateIDevIDCSRResult.fromJson(
                JSONObject("""{"csrFormat":"pkcs10","keyId":"k","backend":"tpm2","algorithm":"ES256"}""")
            )
        }

        assertEquals(ErrorCodes.INTERNAL_ERROR, e.errorCode)
    }

    @Test
    fun `LocalGenerateIDevIDCSRResult round-trips including its publicKey`() {
        val original = LocalGenerateIDevIDCSRResult(
            csr = "csr".toByteArray(),
            csrFormat = "tcg-csr-idevid",
            keyId = "k",
            backend = "tpm2",
            algorithm = "ES256",
            publicKey = "pub".toByteArray()
        )

        val parsed = LocalGenerateIDevIDCSRResult.fromJson(original.toJson())

        assertEquals(original, parsed)
        assertEquals(original.hashCode(), parsed.hashCode())
        assertArrayEquals("pub".toByteArray(), parsed.publicKey)
    }

    // -------------------------------------------------------------------------
    // LocalStoreIDevIDCertificateParams / Result
    // -------------------------------------------------------------------------

    @Test
    fun `LocalStoreIDevIDCertificateParams toJson emits certificate keyId and the optional chain`() {
        val json = LocalStoreIDevIDCertificateParams(
            certificate = "leaf".toByteArray(),
            chain = listOf("root".toByteArray()),
            keyId = "k",
            backend = "tpm2"
        ).toJson()

        assertEquals(setOf("certificate", "chain", "keyId", "backend"), json.keySet())
        assertEquals(b64("leaf"), json.getString("certificate"))
        assertEquals(b64("root"), json.getJSONArray("chain").getString(0))
    }

    @Test
    fun `LocalStoreIDevIDCertificateParams toJson omits a null chain and backend`() {
        val json = LocalStoreIDevIDCertificateParams(certificate = "leaf".toByteArray(), keyId = "k").toJson()

        assertEquals(setOf("certificate", "keyId"), json.keySet())
    }

    @Test
    fun `LocalStoreIDevIDCertificateParams fromJson rejects a missing certificate with INVALID_PARAMS`() {
        val e = assertProtocolException {
            LocalStoreIDevIDCertificateParams.fromJson(JSONObject("""{"keyId":"k"}"""))
        }

        assertEquals(ErrorCodes.INVALID_PARAMS, e.errorCode)
        assertTrue("message was: ${e.message}", e.message!!.contains("certificate"))
    }

    @Test
    fun `LocalStoreIDevIDCertificateParams fromJson rejects a missing keyId with INVALID_PARAMS`() {
        val e = assertProtocolException {
            LocalStoreIDevIDCertificateParams.fromJson(
                JSONObject("""{"certificate":"${b64("leaf")}"}""")
            )
        }

        assertEquals(ErrorCodes.INVALID_PARAMS, e.errorCode)
        assertTrue("message was: ${e.message}", e.message!!.contains("keyId"))
    }

    @Test
    fun `LocalStoreIDevIDCertificateParams round-trips including ByteArray equality`() {
        val original = LocalStoreIDevIDCertificateParams(
            certificate = "leaf".toByteArray(),
            chain = listOf("intermediate".toByteArray(), "root".toByteArray()),
            keyId = "k",
            backend = "tpm2"
        )

        val parsed = LocalStoreIDevIDCertificateParams.fromJson(original.toJson())

        assertEquals(original, parsed)
        assertEquals(original.hashCode(), parsed.hashCode())
        assertEquals(2, parsed.chain!!.size)
    }

    @Test
    fun `LocalStoreIDevIDCertificateResult toJson reports storage success`() {
        val json = LocalStoreIDevIDCertificateResult(stored = true).toJson()

        assertEquals(setOf("stored"), json.keySet())
        assertTrue(json.getBoolean("stored"))
    }

    @Test
    fun `LocalStoreIDevIDCertificateResult fromJson defaults stored to false`() {
        assertFalse(LocalStoreIDevIDCertificateResult.fromJson(JSONObject("{}")).stored)
    }

    @Test
    fun `LocalStoreIDevIDCertificateResult round-trips with its certificateInfo`() {
        val original = LocalStoreIDevIDCertificateResult(stored = true, certificateInfo = sampleCertificateInfo())

        assertEquals(original, LocalStoreIDevIDCertificateResult.fromJson(original.toJson()))
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private fun sampleCertificateInfo() = IDevIDCertificateInfo(
        serialNumber = "0a0b",
        issuer = "CN=issuer",
        subject = "CN=device",
        notBefore = 1700000000L,
        notAfter = 1800000000L,
        algorithm = "ECDSA-SHA256",
        publicKeyAlgorithm = "ECDSA",
        keySizeBits = 256,
        fingerprint = "aabbcc"
    )

    private fun fullSubject() = IDevIDSubject(
        commonName = "device-1",
        organization = "ATT",
        organizationalUnit = "Devices",
        serialNumber = "SN-1",
        country = "US",
        locality = "Austin",
        province = "TX"
    )

    private fun assertProtocolException(block: () -> Unit): ProtocolException {
        try {
            block()
        } catch (e: ProtocolException) {
            return e
        }
        fail("Expected ProtocolException")
        throw IllegalStateException("unreachable")
    }

    private fun assertThrowsAny(block: () -> Unit) {
        try {
            block()
        } catch (e: Exception) {
            return
        }
        fail("Expected an exception")
    }
}
