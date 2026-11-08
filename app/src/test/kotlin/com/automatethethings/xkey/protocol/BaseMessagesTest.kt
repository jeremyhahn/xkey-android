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

import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.util.Base64

/**
 * Unit tests for the base (un-namespaced) protocol payloads in `Messages.kt`:
 * `generateKey`, `sign`, `deleteKey`, `loadKey`, `getInfo`, plus the
 * `pairing.confirm` and `local.biometricPending` payloads.
 *
 * These are the message shapes go-xkms uses in
 * `go-xkms/xkey/pkg/pairing/protocol.go` (`GenerateKeyParams`, `SignParams`,
 * `DeleteKeyParams`, `LoadKeyParams`, `GetInfoResult`, `PairingConfirmParams`,
 * `PairingConfirmResult`). Each parser is exercised for the happy path, every
 * missing-required-field path (which must raise [ProtocolException]), wrong
 * JSON types and default values, and each serializer asserts the exact set of
 * emitted keys so a rename cannot slip through unnoticed.
 */
class BaseMessagesTest {

    private fun JSONObject.keySet(): Set<String> = keys().asSequence().toSet()

    /** "hello" base64-encoded; used wherever a byte payload is required. */
    private val helloB64 = Base64.getEncoder().encodeToString("hello".toByteArray())

    // -------------------------------------------------------------------------
    // GenerateKeyParams
    // -------------------------------------------------------------------------

    @Test
    fun `GenerateKeyParams fromJson reads credentialId and algorithm`() {
        val params = GenerateKeyParams.fromJson(
            JSONObject("""{"credentialId":"$helloB64","algorithm":-7}""")
        )

        assertEquals(helloB64, params.credentialId)
        assertEquals(CoseAlgorithms.ES256, params.algorithm)
    }

    @Test
    fun `GenerateKeyParams fromJson defaults both policy flags to true`() {
        val params = GenerateKeyParams.fromJson(
            JSONObject("""{"credentialId":"$helloB64","algorithm":-7}""")
        )

        assertTrue(params.requireUserVerification)
        assertTrue(params.preferStrongBox)
    }

    @Test
    fun `GenerateKeyParams fromJson honours explicit policy flags`() {
        val params = GenerateKeyParams.fromJson(
            JSONObject(
                """{"credentialId":"$helloB64","algorithm":-257,
                    "requireUserVerification":false,"preferStrongBox":false}"""
            )
        )

        assertFalse(params.requireUserVerification)
        assertFalse(params.preferStrongBox)
        assertEquals(CoseAlgorithms.RS256, params.algorithm)
    }

    @Test
    fun `GenerateKeyParams fromJson rejects a missing credentialId`() {
        val e = assertProtocolException { GenerateKeyParams.fromJson(JSONObject("""{"algorithm":-7}""")) }

        assertTrue("message was: ${e.message}", e.message!!.contains("credentialId"))
    }

    @Test
    fun `GenerateKeyParams fromJson rejects an explicitly null credentialId`() {
        assertProtocolException {
            GenerateKeyParams.fromJson(JSONObject("""{"credentialId":null,"algorithm":-7}"""))
        }
    }

    @Test
    fun `GenerateKeyParams fromJson rejects a missing algorithm`() {
        val e = assertProtocolException {
            GenerateKeyParams.fromJson(JSONObject("""{"credentialId":"$helloB64"}"""))
        }

        assertTrue("message was: ${e.message}", e.message!!.contains("algorithm"))
    }

    @Test
    fun `GenerateKeyParams fromJson rejects algorithm zero which is the unset sentinel`() {
        assertProtocolException {
            GenerateKeyParams.fromJson(JSONObject("""{"credentialId":"$helloB64","algorithm":0}"""))
        }
    }

    @Test
    fun `GenerateKeyParams fromJson rejects a non-numeric algorithm`() {
        assertProtocolException {
            GenerateKeyParams.fromJson(JSONObject("""{"credentialId":"$helloB64","algorithm":true}"""))
        }
    }

    @Test
    fun `GenerateKeyParams getCredentialIdBytes base64url-decodes the credential id`() {
        val params = GenerateKeyParams(helloB64, CoseAlgorithms.ES256)

        assertArrayEquals("hello".toByteArray(), params.getCredentialIdBytes())
    }

    @Test
    fun `GenerateKeyParams toJson emits exactly the four wire fields with their values`() {
        val json = GenerateKeyParams(
            "aGVsbG8=",
            CoseAlgorithms.ES384,
            requireUserVerification = false,
            preferStrongBox = false
        ).toJson()

        assertEquals(
            setOf("credentialId", "algorithm", "requireUserVerification", "preferStrongBox"),
            json.keySet()
        )
        assertEquals("aGVsbG8=", json.getString("credentialId"))
        assertEquals(-35, json.getInt("algorithm"))
        assertEquals(false, json.getBoolean("requireUserVerification"))
        assertEquals(false, json.getBoolean("preferStrongBox"))
    }

    // -------------------------------------------------------------------------
    // GenerateKeyResult
    // -------------------------------------------------------------------------

    @Test
    fun `GenerateKeyResult toJson emits publicKey and strongBoxBacked and omits a null attestation`() {
        val json = GenerateKeyResult(publicKey = helloB64, attestation = null, strongBoxBacked = true).toJson()

        assertEquals(setOf("publicKey", "strongBoxBacked"), json.keySet())
        assertEquals(helloB64, json.getString("publicKey"))
        assertTrue(json.getBoolean("strongBoxBacked"))
    }

    @Test
    fun `GenerateKeyResult toJson emits attestation when present`() {
        val json = GenerateKeyResult(helloB64, attestation = "QUJD", strongBoxBacked = false).toJson()

        assertEquals(setOf("publicKey", "attestation", "strongBoxBacked"), json.keySet())
        assertEquals("QUJD", json.getString("attestation"))
    }

    @Test
    fun `GenerateKeyResult fromJson defaults attestation to null and strongBoxBacked to false`() {
        val result = GenerateKeyResult.fromJson(JSONObject("""{"publicKey":"$helloB64"}"""))

        assertEquals(helloB64, result.publicKey)
        assertNull(result.attestation)
        assertFalse(result.strongBoxBacked)
    }

    @Test
    fun `GenerateKeyResult round-trips through toJson and fromJson`() {
        val original = GenerateKeyResult(helloB64, "QUJD", strongBoxBacked = true)

        assertEquals(original, GenerateKeyResult.fromJson(original.toJson()))
    }

    @Test
    fun `GenerateKeyResult fromJson raises for a missing publicKey`() {
        // getString propagates a JSONException rather than a ProtocolException.
        assertThrowsAny { GenerateKeyResult.fromJson(JSONObject("""{"strongBoxBacked":true}""")) }
    }

    // -------------------------------------------------------------------------
    // SignParams / SignResult
    // -------------------------------------------------------------------------

    @Test
    fun `SignParams fromJson reads credentialId and dataHash and defaults UV to true`() {
        val params = SignParams.fromJson(
            JSONObject("""{"credentialId":"$helloB64","dataHash":"$helloB64"}""")
        )

        assertEquals(helloB64, params.credentialId)
        assertEquals(helloB64, params.dataHash)
        assertTrue(params.userVerificationRequired)
    }

    @Test
    fun `SignParams fromJson honours an explicit userVerificationRequired false`() {
        val params = SignParams.fromJson(
            JSONObject(
                """{"credentialId":"$helloB64","dataHash":"$helloB64","userVerificationRequired":false}"""
            )
        )

        assertFalse(params.userVerificationRequired)
    }

    @Test
    fun `SignParams fromJson rejects a missing credentialId`() {
        val e = assertProtocolException { SignParams.fromJson(JSONObject("""{"dataHash":"$helloB64"}""")) }

        assertTrue("message was: ${e.message}", e.message!!.contains("credentialId"))
    }

    @Test
    fun `SignParams fromJson rejects a missing dataHash`() {
        val e = assertProtocolException {
            SignParams.fromJson(JSONObject("""{"credentialId":"$helloB64"}"""))
        }

        assertTrue("message was: ${e.message}", e.message!!.contains("dataHash"))
    }

    @Test
    fun `SignParams decodes credentialId and dataHash from base64`() {
        val params = SignParams(helloB64, helloB64)

        assertArrayEquals("hello".toByteArray(), params.getCredentialIdBytes())
        assertArrayEquals("hello".toByteArray(), params.getDataHashBytes())
    }

    @Test
    fun `SignParams toJson emits exactly the three wire fields with their values`() {
        val json = SignParams("aGVsbG8=", "ZGF0YQ==", userVerificationRequired = false).toJson()

        assertEquals(setOf("credentialId", "dataHash", "userVerificationRequired"), json.keySet())
        assertEquals("aGVsbG8=", json.getString("credentialId"))
        assertEquals("ZGF0YQ==", json.getString("dataHash"))
        assertEquals(false, json.getBoolean("userVerificationRequired"))
    }

    @Test
    fun `SignResult toJson emits exactly signature and userVerified`() {
        val json = SignResult("c2ln", true).toJson()

        assertEquals(setOf("signature", "userVerified"), json.keySet())
        assertEquals("c2ln", json.getString("signature"))
        assertTrue(json.getBoolean("userVerified"))
    }

    @Test
    fun `SignResult fromJson defaults userVerified to false`() {
        val result = SignResult.fromJson(JSONObject("""{"signature":"c2ln"}"""))

        assertEquals("c2ln", result.signature)
        assertFalse(result.userVerified)
    }

    @Test
    fun `SignResult round-trips through toJson and fromJson`() {
        val original = SignResult("c2ln", true)

        assertEquals(original, SignResult.fromJson(original.toJson()))
    }

    // -------------------------------------------------------------------------
    // DeleteKeyParams / LoadKeyParams / LoadKeyResult
    // -------------------------------------------------------------------------

    @Test
    fun `DeleteKeyParams fromJson reads credentialId`() {
        val params = DeleteKeyParams.fromJson(JSONObject("""{"credentialId":"$helloB64"}"""))

        assertEquals(helloB64, params.credentialId)
    }

    @Test
    fun `DeleteKeyParams fromJson rejects a missing credentialId`() {
        val e = assertProtocolException { DeleteKeyParams.fromJson(JSONObject("{}")) }

        assertTrue("message was: ${e.message}", e.message!!.contains("credentialId"))
    }

    @Test
    fun `DeleteKeyParams toJson emits exactly credentialId with its value`() {
        val json = DeleteKeyParams("aGVsbG8=").toJson()

        assertEquals(setOf("credentialId"), json.keySet())
        assertEquals("aGVsbG8=", json.getString("credentialId"))
    }

    @Test
    fun `LoadKeyParams fromJson reads credentialId`() {
        assertEquals(
            helloB64,
            LoadKeyParams.fromJson(JSONObject("""{"credentialId":"$helloB64"}""")).credentialId
        )
    }

    @Test
    fun `LoadKeyParams fromJson rejects a missing credentialId`() {
        assertProtocolException { LoadKeyParams.fromJson(JSONObject("{}")) }
    }

    @Test
    fun `LoadKeyParams round-trips through toJson and fromJson`() {
        val original = LoadKeyParams(helloB64)

        assertEquals(setOf("credentialId"), original.toJson().keySet())
        assertEquals(original, LoadKeyParams.fromJson(original.toJson()))
    }

    @Test
    fun `LoadKeyResult toJson emits only exists when the key is absent`() {
        val json = LoadKeyResult(exists = false).toJson()

        assertEquals(setOf("exists"), json.keySet())
        assertFalse(json.getBoolean("exists"))
    }

    @Test
    fun `LoadKeyResult toJson emits publicKey and algorithm when the key exists`() {
        val json = LoadKeyResult(exists = true, publicKey = helloB64, algorithm = CoseAlgorithms.ES256).toJson()

        assertEquals(setOf("exists", "publicKey", "algorithm"), json.keySet())
        assertEquals(helloB64, json.getString("publicKey"))
        assertEquals(CoseAlgorithms.ES256, json.getInt("algorithm"))
    }

    // -------------------------------------------------------------------------
    // GetInfoResult
    // -------------------------------------------------------------------------

    @Test
    fun `GetInfoResult toJson emits the go-xkms contract plus the legacy Android fields`() {
        val json = GetInfoResult(
            version = "1.0.0",
            deviceName = "Pixel 8",
            hasStrongBox = true,
            hasBiometrics = false,
            credentialCount = 3
        ).toJson()

        // go-xkms GetInfoResult (pairing/protocol.go) reads supportedAlgorithms,
        // maxCredentials and currentCredentials; the camelCase trio is the
        // legacy Android spelling, kept for older peers.
        assertEquals(
            setOf(
                "version", "deviceName", "supportedAlgorithms", "maxCredentials",
                "currentCredentials", "hasStrongBox", "hasBiometrics", "credentialCount"
            ),
            json.keySet()
        )
        assertEquals(3, json.getInt("currentCredentials"))
        assertTrue("supportedAlgorithms must not be empty", json.getJSONArray("supportedAlgorithms").length() > 0)
        assertEquals("1.0.0", json.getString("version"))
        assertEquals("Pixel 8", json.getString("deviceName"))
        assertTrue(json.getBoolean("hasStrongBox"))
        assertFalse(json.getBoolean("hasBiometrics"))
        assertEquals(3, json.getInt("credentialCount"))
    }

    // -------------------------------------------------------------------------
    // PairingConfirmParams / PairingConfirmResult
    // -------------------------------------------------------------------------

    @Test
    fun `PairingConfirmParams fromJson reads deviceName and publicKeyHex`() {
        val params = PairingConfirmParams.fromJson(
            JSONObject("""{"deviceName":"core-01","publicKeyHex":"deadbeef"}""")
        )

        assertEquals("core-01", params.deviceName)
        assertEquals("deadbeef", params.publicKeyHex)
    }

    @Test
    fun `PairingConfirmParams fromJson defaults a missing deviceName to Unknown`() {
        val params = PairingConfirmParams.fromJson(JSONObject("""{"publicKeyHex":"deadbeef"}"""))

        assertEquals("Unknown", params.deviceName)
    }

    @Test
    fun `PairingConfirmParams fromJson rejects a missing publicKeyHex with INVALID_PARAMS`() {
        val e = assertProtocolException {
            PairingConfirmParams.fromJson(JSONObject("""{"deviceName":"laptop"}"""))
        }

        assertEquals(ErrorCodes.INVALID_PARAMS, e.errorCode)
        assertTrue("message was: ${e.message}", e.message!!.contains("publicKeyHex"))
    }

    @Test
    fun `PairingConfirmParams toJson emits exactly deviceName and publicKeyHex with their values`() {
        val json = PairingConfirmParams("laptop", "deadbeef").toJson()

        assertEquals(setOf("deviceName", "publicKeyHex"), json.keySet())
        assertEquals("laptop", json.getString("deviceName"))
        assertEquals("deadbeef", json.getString("publicKeyHex"))
    }

    @Test
    fun `PairingConfirmResult toJson emits exactly confirmed and deviceName`() {
        val json = PairingConfirmResult(confirmed = true, deviceName = "Pixel 8").toJson()

        assertEquals(setOf("confirmed", "deviceName"), json.keySet())
        assertTrue(json.getBoolean("confirmed"))
        assertEquals("Pixel 8", json.getString("deviceName"))
    }

    @Test
    fun `PairingConfirmResult toJson reports a rejected pairing`() {
        val json = PairingConfirmResult(confirmed = false, deviceName = "Pixel 8").toJson()

        assertFalse(json.getBoolean("confirmed"))
    }

    // -------------------------------------------------------------------------
    // LocalBiometricPendingParams (phone -> laptop notification)
    // -------------------------------------------------------------------------

    @Test
    fun `LocalBiometricPendingParams toJson emits operation rpName and timeoutSecs`() {
        val json = LocalBiometricPendingParams("sign", "example.com", 45).toJson()

        assertEquals(setOf("operation", "rpName", "timeoutSecs"), json.keySet())
        assertEquals("sign", json.getString("operation"))
        assertEquals("example.com", json.getString("rpName"))
        assertEquals(45, json.getInt("timeoutSecs"))
    }

    @Test
    fun `LocalBiometricPendingParams toJson omits a null rpName and defaults the timeout to 30`() {
        val json = LocalBiometricPendingParams("decrypt", null).toJson()

        assertEquals(setOf("operation", "timeoutSecs"), json.keySet())
        assertEquals(30, json.getInt("timeoutSecs"))
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

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
