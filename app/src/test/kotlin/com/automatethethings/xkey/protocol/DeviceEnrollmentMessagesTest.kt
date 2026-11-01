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
package com.automatethethings.xkey.protocol

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

/**
 * Wire contract for the Android-native device enrollment messages.
 *
 * Nothing is code-shared with go-xkms -- the Kotlin here and the Go structs in
 * `pkg/pairing/protocol_device_enrollment.go` are hand-written twins -- so a
 * renamed JSON key produces no compile error on either side. These tests pin
 * the key names, which is the only thing that catches that drift.
 */
class DeviceEnrollmentMessagesTest {

    @Test
    fun `method names match the go-xkms spelling`() {
        assertEquals(
            "local.getDeviceEnrollmentRequest",
            MethodNames.LOCAL_GET_DEVICE_ENROLLMENT_REQUEST
        )
        assertEquals(
            "local.storeDeviceCredential",
            MethodNames.LOCAL_STORE_DEVICE_CREDENTIAL
        )
    }

    @Test
    fun `the attestation format tag matches the go-xkms constant`() {
        assertEquals("android-key-attestation", ATTESTATION_FORMAT_ANDROID_KEY)
    }

    @Test
    fun `enrollment request params round-trip through their JSON keys`() {
        val params = LocalGetDeviceEnrollmentRequestParams(
            nonce = Base64.getEncoder().encodeToString("challenge".toByteArray()),
            subject = "CN=Test Device, O=xKey"
        )

        val json = params.toJson()
        assertTrue("nonce is the wire key", json.has("nonce"))
        assertTrue("subject is the wire key", json.has("subject"))

        val decoded = LocalGetDeviceEnrollmentRequestParams.fromJson(json)
        assertEquals(params.nonce, decoded.nonce)
        assertEquals(params.subject, decoded.subject)
        assertEquals("challenge", String(decoded.getNonceBytes()))
    }

    @Test
    fun `an absent subject stays absent rather than becoming the string null`() {
        val params = LocalGetDeviceEnrollmentRequestParams(nonce = "AAAA")

        val json = params.toJson()
        assertFalse("an omitted subject must not appear at all", json.has("subject"))

        // getStringOrNull rather than optString: optString turns a JSON null
        // into the four-character string "null", which then reaches the DN
        // parser as a subject.
        assertNull(LocalGetDeviceEnrollmentRequestParams.fromJson(json).subject)
    }

    @Test
    fun `enrollment result round-trips and defaults its format`() {
        val result = LocalGetDeviceEnrollmentRequestResult(
            csr = byteArrayOf(0x30, 0x02, 0x01, 0x00),
            attestationChain = listOf("bGVhZg==", "aW50ZXJtZWRpYXRl"),
            securityLevel = "strongbox",
            platformModel = "Pixel 9"
        )

        val json = result.toJson()
        assertEquals(ATTESTATION_FORMAT_ANDROID_KEY, json.getString("format"))
        assertTrue(json.has("csr"))
        assertTrue(json.has("attestationChain"))
        assertTrue(json.has("securityLevel"))
        assertFalse("an absent serial must be omitted", json.has("platformSerial"))

        val decoded = LocalGetDeviceEnrollmentRequestResult.fromJson(json)
        assertEquals(result, decoded)
        assertEquals(2, decoded.attestationChain.size)
        assertEquals("Pixel 9", decoded.platformModel)
    }

    @Test
    fun `the chain order is preserved because the leaf must be first`() {
        val result = LocalGetDeviceEnrollmentRequestResult(
            csr = byteArrayOf(1),
            attestationChain = listOf("bGVhZg==", "bWlkZGxl", "cm9vdA=="),
            securityLevel = "trusted_environment"
        )

        val decoded = LocalGetDeviceEnrollmentRequestResult.fromJson(result.toJson())

        // The verifier reads index 0 as the attestation leaf. Reordering here
        // would have it check the challenge and the application identity
        // against an intermediate that carries neither.
        assertEquals(listOf("bGVhZg==", "bWlkZGxl", "cm9vdA=="), decoded.attestationChain)
    }

    @Test
    fun `results comparing equal require the same csr bytes`() {
        val base = LocalGetDeviceEnrollmentRequestResult(
            csr = byteArrayOf(1, 2, 3),
            attestationChain = listOf("bGVhZg=="),
            securityLevel = "strongbox"
        )
        val sameContent = base.copy(csr = byteArrayOf(1, 2, 3))
        val different = base.copy(csr = byteArrayOf(1, 2, 4))

        // A data class compares ByteArray by identity unless equals is
        // overridden, which would make every result unequal to its own decode.
        assertEquals(base, sameContent)
        assertEquals(base.hashCode(), sameContent.hashCode())
        assertNotEquals(base, different)
    }

    @Test
    fun `store credential params round-trip with and without a chain`() {
        val withChain = LocalStoreDeviceCredentialParams(
            certificate = "Y2VydA==",
            chain = listOf("aXNzdWVy", "cm9vdA==")
        )
        val decoded = LocalStoreDeviceCredentialParams.fromJson(withChain.toJson())
        assertEquals(withChain.certificate, decoded.certificate)
        assertEquals(withChain.chain, decoded.chain)
        assertEquals("cert", String(decoded.getCertificateBytes()))

        val bare = LocalStoreDeviceCredentialParams(certificate = "Y2VydA==")
        val bareJson = bare.toJson()
        assertFalse("an empty chain is omitted, not sent as []", bareJson.has("chain"))
        assertTrue(LocalStoreDeviceCredentialParams.fromJson(bareJson).chain.isEmpty())
    }

    @Test
    fun `store credential result carries the expiry as the re-attestation deadline`() {
        val result = LocalStoreDeviceCredentialResult(
            stored = true,
            fingerprint = "a".repeat(64),
            notAfter = 1_800_000_000_000L
        )

        val json = result.toJson()
        assertEquals(true, json.getBoolean("stored"))
        assertEquals(64, json.getString("fingerprint").length)

        // notAfter must survive as a long: a JSON int would overflow past 2038
        // and silently move every deadline into the past.
        assertEquals(1_800_000_000_000L, json.getLong("notAfter"))
        assertEquals(result, LocalStoreDeviceCredentialResult.fromJson(json))
    }

    /** Reads the JSON the way the desktop would, to pin key names exactly. */
    private fun LocalGetDeviceEnrollmentRequestResult.wireKeys(): Set<String> {
        val json: JSONObject = toJson()
        return json.keys().asSequence().toSet()
    }

    @Test
    fun `the result sends exactly the keys go-xkms declares`() {
        val full = LocalGetDeviceEnrollmentRequestResult(
            csr = byteArrayOf(1),
            attestationChain = listOf("bGVhZg=="),
            securityLevel = "strongbox",
            platformModel = "Pixel 9",
            platformSerial = "SERIAL123"
        )

        assertEquals(
            setOf(
                "format", "csr", "attestationChain",
                "securityLevel", "platformModel", "platformSerial"
            ),
            full.wireKeys()
        )
    }
}
