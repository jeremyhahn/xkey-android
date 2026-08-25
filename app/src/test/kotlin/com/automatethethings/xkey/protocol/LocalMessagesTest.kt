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
 * Unit tests for the `local.*` request and response payloads in `Messages.kt`
 * (the laptop -> phone half of the pairing protocol).
 *
 * The counterpart definitions live in
 * `go-xkms/xkey/pkg/pairing/protocol_local.go`. Because both sides serialize
 * independently, a renamed JSON key produces no compile error on either side --
 * it just silently drops a field at runtime. Each serializer test therefore
 * asserts the exact emitted key set, and each parser test covers the happy
 * path, the missing-required-field path (which must raise a [ProtocolException]
 * carrying [ErrorCodes.INVALID_PARAMS]), wrong JSON types and defaults.
 *
 * `LocalGenerateKeyResult` gets extra attention: it previously emitted
 * `publicKey`/`strongBoxBacked` where Go expects `publicKeyDer`/`securityLevel`,
 * so the tests below guard both the presence of the correct keys and the
 * absence of the old ones.
 */
class LocalMessagesTest {

    private fun JSONObject.keySet(): Set<String> = keys().asSequence().toSet()

    /** "hello" base64-encoded; stands in for any binary payload on the wire. */
    private val helloB64 = Base64.getEncoder().encodeToString("hello".toByteArray())

    // -------------------------------------------------------------------------
    // LocalGenerateKeyParams
    // -------------------------------------------------------------------------

    @Test
    fun `LocalGenerateKeyParams fromJson accepts an algorithm name string as go-xkms sends it`() {
        val params = LocalGenerateKeyParams.fromJson(
            JSONObject("""{"keyId":"k1","keyType":"signing","algorithm":"ES256"}""")
        )

        assertEquals("k1", params.keyId)
        assertEquals("signing", params.keyType)
        assertEquals(CoseAlgorithms.ES256, params.algorithm)
    }

    @Test
    fun `LocalGenerateKeyParams fromJson accepts a numeric algorithm from legacy callers`() {
        val params = LocalGenerateKeyParams.fromJson(
            JSONObject("""{"keyId":"k1","keyType":"signing","algorithm":-257}""")
        )

        assertEquals(CoseAlgorithms.RS256, params.algorithm)
    }

    @Test
    fun `LocalGenerateKeyParams fromJson accepts a symmetric algorithm alias`() {
        val params = LocalGenerateKeyParams.fromJson(
            JSONObject("""{"keyId":"k1","keyType":"secret","algorithm":"AES-256"}""")
        )

        assertEquals(CoseAlgorithms.A256GCM, params.algorithm)
    }

    @Test
    fun `LocalGenerateKeyParams fromJson defaults label to keyId`() {
        val params = LocalGenerateKeyParams.fromJson(
            JSONObject("""{"keyId":"my-key","keyType":"signing","algorithm":"ES256"}""")
        )

        assertEquals("my-key", params.label)
    }

    @Test
    fun `LocalGenerateKeyParams fromJson defaults the policy flags`() {
        val params = LocalGenerateKeyParams.fromJson(
            JSONObject("""{"keyId":"k","keyType":"signing","algorithm":"ES256"}""")
        )

        assertTrue(params.requireUserVerification)
        assertTrue(params.preferStrongBox)
        assertFalse(params.shareable)
        assertFalse(params.exportable)
        assertFalse(params.isDiscoverable)
        assertNull(params.rpId)
        assertNull(params.rpName)
        assertNull(params.userId)
        assertNull(params.userName)
        assertNull(params.userDisplayName)
    }

    @Test
    fun `LocalGenerateKeyParams fromJson reads the exportable software-key flag`() {
        val params = LocalGenerateKeyParams.fromJson(
            JSONObject("""{"keyId":"k","keyType":"secret","algorithm":"AES-256","exportable":true}""")
        )

        assertTrue(params.exportable)
    }

    @Test
    fun `LocalGenerateKeyParams fromJson reads the FIDO2 fields`() {
        val params = LocalGenerateKeyParams.fromJson(
            JSONObject(
                """{"keyId":"k","keyType":"fido2","algorithm":"ES256","label":"Passkey",
                    "rpId":"example.com","rpName":"Example","userId":"dXNlcg",
                    "userName":"alice","userDisplayName":"Alice A","isDiscoverable":true}"""
            )
        )

        assertEquals("Passkey", params.label)
        assertEquals("example.com", params.rpId)
        assertEquals("Example", params.rpName)
        assertEquals("dXNlcg", params.userId)
        assertEquals("alice", params.userName)
        assertEquals("Alice A", params.userDisplayName)
        assertTrue(params.isDiscoverable)
    }

    @Test
    fun `LocalGenerateKeyParams fromJson rejects a missing keyId with INVALID_PARAMS`() {
        val e = assertProtocolException {
            LocalGenerateKeyParams.fromJson(JSONObject("""{"keyType":"signing","algorithm":"ES256"}"""))
        }

        assertEquals(ErrorCodes.INVALID_PARAMS, e.errorCode)
        assertTrue("message was: ${e.message}", e.message!!.contains("keyId"))
    }

    @Test
    fun `LocalGenerateKeyParams fromJson derives keyType when the peer omits it`() {
        // go-xkms LocalGenerateKeyParams has no keyType field, so requiring it
        // made every xkmsd phone-backend key creation fail. It is now inferred
        // from the algorithm.
        assertEquals(
            KeyTypes.SIGNING,
            LocalGenerateKeyParams.fromJson(JSONObject("""{"keyId":"k","algorithm":"ES256"}""")).keyType
        )
        assertEquals(
            KeyTypes.SECRET,
            LocalGenerateKeyParams.fromJson(JSONObject("""{"keyId":"k","algorithm":"AES256-GCM"}""")).keyType
        )
        assertEquals(
            KeyTypes.HMAC,
            LocalGenerateKeyParams.fromJson(JSONObject("""{"keyId":"k","algorithm":"HMAC-SHA256"}""")).keyType
        )
    }

    @Test
    fun `LocalGenerateKeyParams fromJson accepts the go-xkms symmetric algorithm names`() {
        // pkg/backend/phone/symmetric.go spells these AES128-GCM / AES256-GCM.
        assertEquals(
            CoseAlgorithms.A128GCM,
            LocalGenerateKeyParams.fromJson(JSONObject("""{"keyId":"k","algorithm":"AES128-GCM"}""")).algorithm
        )
        assertEquals(
            CoseAlgorithms.A256GCM,
            LocalGenerateKeyParams.fromJson(JSONObject("""{"keyId":"k","algorithm":"AES256-GCM"}""")).algorithm
        )
    }

    @Test
    fun `LocalGenerateKeyParams fromJson rejects a missing algorithm with INVALID_PARAMS`() {
        val e = assertProtocolException {
            LocalGenerateKeyParams.fromJson(JSONObject("""{"keyId":"k","keyType":"signing"}"""))
        }

        assertEquals(ErrorCodes.INVALID_PARAMS, e.errorCode)
        assertTrue("message was: ${e.message}", e.message!!.contains("algorithm"))
    }

    @Test
    fun `LocalGenerateKeyParams fromJson rejects a blank algorithm string with INVALID_PARAMS`() {
        val e = assertProtocolException {
            LocalGenerateKeyParams.fromJson(JSONObject("""{"keyId":"k","keyType":"signing","algorithm":"  "}"""))
        }

        assertEquals(ErrorCodes.INVALID_PARAMS, e.errorCode)
    }

    @Test
    fun `LocalGenerateKeyParams fromJson rejects an unknown algorithm name with INVALID_ALGORITHM`() {
        val e = assertProtocolException {
            LocalGenerateKeyParams.fromJson(
                JSONObject("""{"keyId":"k","keyType":"signing","algorithm":"NOT-A-REAL-ALG"}""")
            )
        }

        assertEquals(ErrorCodes.INVALID_ALGORITHM, e.errorCode)
    }

    @Test
    fun `LocalGenerateKeyParams fromJson rejects an algorithm of the wrong JSON type`() {
        val e = assertProtocolException {
            LocalGenerateKeyParams.fromJson(
                JSONObject("""{"keyId":"k","keyType":"signing","algorithm":true}""")
            )
        }

        assertEquals(ErrorCodes.INVALID_PARAMS, e.errorCode)
    }

    @Test
    fun `LocalGenerateKeyParams toJson emits every non-FIDO2 field and omits absent FIDO2 fields`() {
        val json = LocalGenerateKeyParams(
            keyId = "k",
            keyType = KeyTypes.SIGNING,
            algorithm = CoseAlgorithms.ES256,
            label = "My Key"
        ).toJson()

        assertEquals(
            setOf(
                "keyId", "keyType", "algorithm", "label", "requireUserVerification",
                "preferStrongBox", "shareable", "exportable", "isDiscoverable"
            ),
            json.keySet()
        )
        assertEquals("k", json.getString("keyId"))
        assertEquals(KeyTypes.SIGNING, json.getString("keyType"))
        assertEquals(CoseAlgorithms.ES256, json.getInt("algorithm"))
        assertEquals("My Key", json.getString("label"))
    }

    @Test
    fun `LocalGenerateKeyParams toJson emits the FIDO2 fields when present`() {
        val json = LocalGenerateKeyParams(
            keyId = "k",
            keyType = KeyTypes.FIDO2,
            algorithm = CoseAlgorithms.ES256,
            label = "Passkey",
            rpId = "example.com",
            rpName = "Example",
            userId = "dXNlcg",
            userName = "alice",
            userDisplayName = "Alice A",
            isDiscoverable = true
        ).toJson()

        assertTrue(json.keySet().containsAll(setOf("rpId", "rpName", "userId", "userName", "userDisplayName")))
        assertTrue(json.getBoolean("isDiscoverable"))
    }

    @Test
    fun `LocalGenerateKeyParams round-trips through toJson and fromJson`() {
        val original = LocalGenerateKeyParams(
            keyId = "k",
            keyType = KeyTypes.FIDO2,
            algorithm = CoseAlgorithms.ES256,
            label = "Passkey",
            requireUserVerification = false,
            preferStrongBox = false,
            shareable = true,
            exportable = true,
            rpId = "example.com",
            rpName = "Example",
            userId = "dXNlcg",
            userName = "alice",
            userDisplayName = "Alice A",
            isDiscoverable = true
        )

        assertEquals(original, LocalGenerateKeyParams.fromJson(original.toJson()))
    }

    // -------------------------------------------------------------------------
    // LocalGenerateKeyResult (go-xkms wire contract)
    // -------------------------------------------------------------------------

    @Test
    fun `LocalGenerateKeyResult toJson uses publicKeyDer and securityLevel not publicKey and strongBoxBacked`() {
        val json = LocalGenerateKeyResult(
            keyId = "k",
            publicKey = helloB64,
            publicKeyCose = null,
            algorithm = "ES256",
            keySizeBits = 256,
            strongBoxBacked = true
        ).toJson()

        assertEquals(setOf("keyId", "publicKeyDer", "algorithm", "keySizeBits", "securityLevel"), json.keySet())
        assertFalse("must not emit the legacy 'publicKey' key", json.has("publicKey"))
        assertFalse("must not emit the legacy 'strongBoxBacked' key", json.has("strongBoxBacked"))
        assertEquals(helloB64, json.getString("publicKeyDer"))
        assertEquals(256, json.getInt("keySizeBits"))
    }

    @Test
    fun `LocalGenerateKeyResult toJson reports securityLevel strongbox for a StrongBox key`() {
        val json = LocalGenerateKeyResult("k", helloB64, null, "ES256", 256, strongBoxBacked = true).toJson()

        assertEquals("strongbox", json.getString("securityLevel"))
    }

    @Test
    fun `LocalGenerateKeyResult toJson reports securityLevel tee for a plain Keystore key`() {
        val json = LocalGenerateKeyResult("k", helloB64, null, "ES256", 256, strongBoxBacked = false).toJson()

        assertEquals("tee", json.getString("securityLevel"))
    }

    @Test
    fun `LocalGenerateKeyResult toJson reports securityLevel software and lets it win over strongbox`() {
        val json = LocalGenerateKeyResult(
            "k", helloB64, null, "AES-256", 256,
            strongBoxBacked = true, softwareBacked = true
        ).toJson()

        assertEquals("software", json.getString("securityLevel"))
    }

    @Test
    fun `LocalGenerateKeyResult toJson omits publicKeyDer when the key has no exportable public part`() {
        val json = LocalGenerateKeyResult("k", "", null, "AES-256", 256, false, softwareBacked = true).toJson()

        assertFalse(json.has("publicKeyDer"))
        assertEquals(setOf("keyId", "algorithm", "keySizeBits", "securityLevel"), json.keySet())
    }

    @Test
    fun `LocalGenerateKeyResult toJson emits publicKeyCose for FIDO2 keys`() {
        val json = LocalGenerateKeyResult("k", helloB64, "Y29zZQ", "ES256", 256, false).toJson()

        assertEquals("Y29zZQ", json.getString("publicKeyCose"))
    }

    // -------------------------------------------------------------------------
    // LocalSignParams / LocalSignResult
    // -------------------------------------------------------------------------

    @Test
    fun `LocalSignParams fromJson reads keyId data and algorithm`() {
        val params = LocalSignParams.fromJson(
            JSONObject("""{"keyId":"k","data":"$helloB64","algorithm":"ES256"}""")
        )

        assertEquals("k", params.keyId)
        assertEquals(helloB64, params.data)
        assertEquals("ES256", params.algorithm)
        assertTrue(params.userVerificationRequired)
    }

    @Test
    fun `LocalSignParams fromJson defaults an omitted algorithm to the empty override`() {
        // go-xkms marks algorithm omitempty: absent means "use the key's own algorithm".
        val params = LocalSignParams.fromJson(JSONObject("""{"keyId":"k","data":"$helloB64"}"""))

        assertEquals("", params.algorithm)
    }

    @Test
    fun `LocalSignParams fromJson rejects a missing keyId with INVALID_PARAMS`() {
        val e = assertProtocolException { LocalSignParams.fromJson(JSONObject("""{"data":"$helloB64"}""")) }

        assertEquals(ErrorCodes.INVALID_PARAMS, e.errorCode)
    }

    @Test
    fun `LocalSignParams fromJson rejects missing data with INVALID_PARAMS`() {
        val e = assertProtocolException { LocalSignParams.fromJson(JSONObject("""{"keyId":"k"}""")) }

        assertEquals(ErrorCodes.INVALID_PARAMS, e.errorCode)
        assertTrue("message was: ${e.message}", e.message!!.contains("data"))
    }

    @Test
    fun `LocalSignParams getDataBytes decodes the base64 payload`() {
        assertArrayEquals("hello".toByteArray(), LocalSignParams("k", helloB64, "ES256").getDataBytes())
    }

    @Test
    fun `LocalSignParams toJson emits exactly the four wire fields`() {
        val json = LocalSignParams("k", helloB64, "ES256").toJson()

        assertEquals(setOf("keyId", "data", "algorithm", "userVerificationRequired"), json.keySet())
    }

    @Test
    fun `LocalSignParams round-trips through toJson and fromJson`() {
        val original = LocalSignParams("k", helloB64, "RS256", userVerificationRequired = false)

        assertEquals(original, LocalSignParams.fromJson(original.toJson()))
    }

    @Test
    fun `LocalSignResult toJson emits exactly signature algorithm and userVerified`() {
        val json = LocalSignResult("c2ln", "ES256", true).toJson()

        assertEquals(setOf("signature", "algorithm", "userVerified"), json.keySet())
        assertEquals("c2ln", json.getString("signature"))
        assertEquals("ES256", json.getString("algorithm"))
        assertTrue(json.getBoolean("userVerified"))
    }

    // -------------------------------------------------------------------------
    // LocalDecryptParams / LocalDecryptResult
    // -------------------------------------------------------------------------

    @Test
    fun `LocalDecryptParams fromJson reads keyId and ciphertext`() {
        val params = LocalDecryptParams.fromJson(JSONObject("""{"keyId":"k","ciphertext":"$helloB64"}"""))

        assertEquals("k", params.keyId)
        assertEquals(helloB64, params.ciphertext)
        assertArrayEquals("hello".toByteArray(), params.getCiphertextBytes())
    }

    @Test
    fun `LocalDecryptParams fromJson rejects a missing keyId with INVALID_PARAMS`() {
        assertEquals(
            ErrorCodes.INVALID_PARAMS,
            assertProtocolException {
                LocalDecryptParams.fromJson(JSONObject("""{"ciphertext":"$helloB64"}"""))
            }.errorCode
        )
    }

    @Test
    fun `LocalDecryptParams fromJson rejects a missing ciphertext with INVALID_PARAMS`() {
        val e = assertProtocolException { LocalDecryptParams.fromJson(JSONObject("""{"keyId":"k"}""")) }

        assertEquals(ErrorCodes.INVALID_PARAMS, e.errorCode)
        assertTrue("message was: ${e.message}", e.message!!.contains("ciphertext"))
    }

    @Test
    fun `LocalDecryptParams round-trips through toJson and fromJson`() {
        val original = LocalDecryptParams("k", helloB64)

        assertEquals(setOf("keyId", "ciphertext"), original.toJson().keySet())
        assertEquals(original, LocalDecryptParams.fromJson(original.toJson()))
    }

    @Test
    fun `LocalDecryptResult toJson emits exactly plaintext`() {
        val json = LocalDecryptResult(helloB64).toJson()

        assertEquals(setOf("plaintext"), json.keySet())
        assertEquals(helloB64, json.getString("plaintext"))
    }

    // -------------------------------------------------------------------------
    // LocalSymmetricParams / LocalSymmetricResult
    // -------------------------------------------------------------------------

    @Test
    fun `LocalSymmetricParams fromJson reads keyId data and optional aad`() {
        val params = LocalSymmetricParams.fromJson(
            JSONObject("""{"keyId":"k","data":"$helloB64","aad":"YWFk"}""")
        )

        assertEquals("k", params.keyId)
        assertEquals(helloB64, params.data)
        assertEquals("YWFk", params.aad)
        assertArrayEquals("hello".toByteArray(), params.getDataBytes())
        assertArrayEquals("aad".toByteArray(), params.getAadBytes())
    }

    @Test
    fun `LocalSymmetricParams fromJson leaves aad null when absent`() {
        val params = LocalSymmetricParams.fromJson(JSONObject("""{"keyId":"k","data":"$helloB64"}"""))

        assertNull(params.aad)
        assertNull(params.getAadBytes())
    }

    @Test
    fun `LocalSymmetricParams fromJson rejects a missing keyId with INVALID_PARAMS`() {
        assertEquals(
            ErrorCodes.INVALID_PARAMS,
            assertProtocolException {
                LocalSymmetricParams.fromJson(JSONObject("""{"data":"$helloB64"}"""))
            }.errorCode
        )
    }

    @Test
    fun `LocalSymmetricParams fromJson rejects missing data with INVALID_PARAMS`() {
        assertEquals(
            ErrorCodes.INVALID_PARAMS,
            assertProtocolException { LocalSymmetricParams.fromJson(JSONObject("""{"keyId":"k"}""")) }.errorCode
        )
    }

    @Test
    fun `LocalSymmetricParams toJson omits aad when null`() {
        assertEquals(setOf("keyId", "data"), LocalSymmetricParams("k", helloB64).toJson().keySet())
    }

    @Test
    fun `LocalSymmetricParams round-trips through toJson and fromJson`() {
        val original = LocalSymmetricParams("k", helloB64, "YWFk")

        assertEquals(setOf("keyId", "data", "aad"), original.toJson().keySet())
        assertEquals(original, LocalSymmetricParams.fromJson(original.toJson()))
    }

    @Test
    fun `LocalSymmetricResult toJson emits the go-xkms payload field plus legacy data`() {
        // go-xkms reads `ciphertext` from an encrypt result and `plaintext`
        // from a decrypt result; `data` is this app's older name, emitted
        // alongside so an older peer keeps working.
        assertEquals(
            setOf("ciphertext", "data"),
            LocalSymmetricResult(helloB64, LocalSymmetricResult.FIELD_CIPHERTEXT).toJson().keySet()
        )
        assertEquals(
            setOf("plaintext", "data"),
            LocalSymmetricResult(helloB64, LocalSymmetricResult.FIELD_PLAINTEXT).toJson().keySet()
        )
    }

    @Test
    fun `LocalSymmetricParams fromJson accepts the go-xkms field names`() {
        assertEquals(
            helloB64,
            LocalSymmetricParams.fromJson(JSONObject("""{"keyId":"k","plaintext":"$helloB64"}""")).data
        )
        assertEquals(
            helloB64,
            LocalSymmetricParams.fromJson(JSONObject("""{"keyId":"k","ciphertext":"$helloB64"}""")).data
        )
        // Legacy name still accepted.
        assertEquals(
            helloB64,
            LocalSymmetricParams.fromJson(JSONObject("""{"keyId":"k","data":"$helloB64"}""")).data
        )
    }

    // -------------------------------------------------------------------------
    // LocalHMACParams / LocalHMACResult
    // -------------------------------------------------------------------------

    @Test
    fun `LocalHMACParams fromJson reads keyId and data`() {
        val params = LocalHMACParams.fromJson(JSONObject("""{"keyId":"k","data":"$helloB64"}"""))

        assertEquals("k", params.keyId)
        assertArrayEquals("hello".toByteArray(), params.getDataBytes())
    }

    @Test
    fun `LocalHMACParams fromJson rejects missing fields with INVALID_PARAMS`() {
        assertEquals(
            ErrorCodes.INVALID_PARAMS,
            assertProtocolException { LocalHMACParams.fromJson(JSONObject("""{"data":"$helloB64"}""")) }.errorCode
        )
        assertEquals(
            ErrorCodes.INVALID_PARAMS,
            assertProtocolException { LocalHMACParams.fromJson(JSONObject("""{"keyId":"k"}""")) }.errorCode
        )
    }

    @Test
    fun `LocalHMACParams round-trips through toJson and fromJson`() {
        val original = LocalHMACParams("k", helloB64)

        assertEquals(setOf("keyId", "data"), original.toJson().keySet())
        assertEquals(original, LocalHMACParams.fromJson(original.toJson()))
    }

    @Test
    fun `LocalHMACResult toJson emits exactly mac`() {
        val json = LocalHMACResult("bWFj").toJson()

        assertEquals(setOf("mac"), json.keySet())
        assertEquals("bWFj", json.getString("mac"))
    }

    // -------------------------------------------------------------------------
    // LocalECDHParams / LocalECDHResult
    // -------------------------------------------------------------------------

    @Test
    fun `LocalECDHParams fromJson reads keyId and peerPublicKey`() {
        val params = LocalECDHParams.fromJson(
            JSONObject("""{"keyId":"k","peerPublicKey":"$helloB64"}""")
        )

        assertEquals("k", params.keyId)
        assertArrayEquals("hello".toByteArray(), params.getPeerPublicKeyBytes())
    }

    @Test
    fun `LocalECDHParams fromJson rejects a missing peerPublicKey with INVALID_PARAMS`() {
        val e = assertProtocolException { LocalECDHParams.fromJson(JSONObject("""{"keyId":"k"}""")) }

        assertEquals(ErrorCodes.INVALID_PARAMS, e.errorCode)
        assertTrue("message was: ${e.message}", e.message!!.contains("peerPublicKey"))
    }

    @Test
    fun `LocalECDHParams fromJson rejects a missing keyId with INVALID_PARAMS`() {
        assertEquals(
            ErrorCodes.INVALID_PARAMS,
            assertProtocolException {
                LocalECDHParams.fromJson(JSONObject("""{"peerPublicKey":"$helloB64"}"""))
            }.errorCode
        )
    }

    @Test
    fun `LocalECDHParams round-trips through toJson and fromJson`() {
        val original = LocalECDHParams("k", helloB64)

        assertEquals(setOf("keyId", "peerPublicKey"), original.toJson().keySet())
        assertEquals(original, LocalECDHParams.fromJson(original.toJson()))
    }

    @Test
    fun `LocalECDHResult toJson emits exactly sharedSecret`() {
        assertEquals(setOf("sharedSecret"), LocalECDHResult("c2VjcmV0").toJson().keySet())
    }

    // -------------------------------------------------------------------------
    // LocalGetPublicKeyParams / LocalGetPublicKeyResult
    // -------------------------------------------------------------------------

    @Test
    fun `LocalGetPublicKeyParams fromJson defaults the format to der`() {
        val params = LocalGetPublicKeyParams.fromJson(JSONObject("""{"keyId":"k"}"""))

        assertEquals(ExportFormats.DER, params.format)
    }

    @Test
    fun `LocalGetPublicKeyParams fromJson honours every export format`() {
        listOf(ExportFormats.DER, ExportFormats.PEM, ExportFormats.SSH, ExportFormats.COSE).forEach { format ->
            val params = LocalGetPublicKeyParams.fromJson(
                JSONObject("""{"keyId":"k","format":"$format"}""")
            )
            assertEquals(format, params.format)
        }
    }

    @Test
    fun `LocalGetPublicKeyParams fromJson rejects a missing keyId with INVALID_PARAMS`() {
        assertEquals(
            ErrorCodes.INVALID_PARAMS,
            assertProtocolException { LocalGetPublicKeyParams.fromJson(JSONObject("""{"format":"pem"}""")) }.errorCode
        )
    }

    @Test
    fun `LocalGetPublicKeyParams round-trips through toJson and fromJson`() {
        val original = LocalGetPublicKeyParams("k", ExportFormats.SSH)

        assertEquals(setOf("keyId", "format"), original.toJson().keySet())
        assertEquals(original, LocalGetPublicKeyParams.fromJson(original.toJson()))
    }

    @Test
    fun `LocalGetPublicKeyResult toJson emits exactly publicKey format and algorithm`() {
        val json = LocalGetPublicKeyResult(helloB64, ExportFormats.DER, "ES256").toJson()

        assertEquals(setOf("publicKey", "format", "algorithm"), json.keySet())
        assertEquals(ExportFormats.DER, json.getString("format"))
        assertEquals("ES256", json.getString("algorithm"))
    }

    // -------------------------------------------------------------------------
    // LocalListKeysParams / KeyInfo / LocalListKeysResult
    // -------------------------------------------------------------------------

    @Test
    fun `LocalListKeysParams fromJson tolerates null params meaning no filter`() {
        val params = LocalListKeysParams.fromJson(null)

        assertNull(params.keyType)
        assertNull(params.source)
    }

    @Test
    fun `LocalListKeysParams fromJson reads the keyType and source filters`() {
        val params = LocalListKeysParams.fromJson(
            JSONObject("""{"keyType":"fido2","source":"local"}""")
        )

        assertEquals(KeyTypes.FIDO2, params.keyType)
        assertEquals("local", params.source)
    }

    @Test
    fun `LocalListKeysParams toJson omits absent filters`() {
        assertEquals(emptySet<String>(), LocalListKeysParams().toJson().keySet())
        assertEquals(setOf("keyType"), LocalListKeysParams(keyType = KeyTypes.TLS).toJson().keySet())
        assertEquals(setOf("source"), LocalListKeysParams(source = "xkmsd").toJson().keySet())
    }

    @Test
    fun `KeyInfo toJson emits every non-FIDO2 field`() {
        val json = sampleKeyInfo().toJson()

        assertTrue(
            json.keySet().containsAll(
                setOf(
                    "keyId", "keyType", "algorithm", "label", "keySizeBits", "strongBoxBacked",
                    "shareable", "source", "useCount", "createdAt", "lastUsedAt",
                    "isDiscoverable", "signCount"
                )
            )
        )
        assertEquals("k1", json.getString("keyId"))
        assertEquals(256, json.getInt("keySizeBits"))
        assertEquals(4L, json.getLong("useCount"))
        assertEquals(1000L, json.getLong("createdAt"))
        assertEquals(2000L, json.getLong("lastUsedAt"))
    }

    @Test
    fun `KeyInfo toJson omits null FIDO2 fields`() {
        val json = sampleKeyInfo().toJson()

        assertFalse(json.has("rpId"))
        assertFalse(json.has("rpName"))
        assertFalse(json.has("userName"))
        assertFalse(json.has("userDisplayName"))
    }

    @Test
    fun `KeyInfo toJson emits FIDO2 fields for a passkey`() {
        val json = sampleKeyInfo().copy(
            keyType = KeyTypes.FIDO2,
            rpId = "example.com",
            rpName = "Example",
            userName = "alice",
            userDisplayName = "Alice A",
            isDiscoverable = true,
            signCount = 9
        ).toJson()

        assertEquals("example.com", json.getString("rpId"))
        assertEquals("Example", json.getString("rpName"))
        assertEquals("alice", json.getString("userName"))
        assertEquals("Alice A", json.getString("userDisplayName"))
        assertTrue(json.getBoolean("isDiscoverable"))
        assertEquals(9L, json.getLong("signCount"))
    }

    @Test
    fun `LocalListKeysResult toJson emits a keys array and a count`() {
        val json = LocalListKeysResult(listOf(sampleKeyInfo(), sampleKeyInfo().copy(keyId = "k2")), 2).toJson()

        assertEquals(setOf("keys", "count"), json.keySet())
        assertEquals(2, json.getInt("count"))
        assertEquals(2, json.getJSONArray("keys").length())
        assertEquals("k1", json.getJSONArray("keys").getJSONObject(0).getString("keyId"))
        assertEquals("k2", json.getJSONArray("keys").getJSONObject(1).getString("keyId"))
    }

    @Test
    fun `LocalListKeysResult toJson emits an empty array when there are no keys`() {
        val json = LocalListKeysResult(emptyList(), 0).toJson()

        assertEquals(0, json.getJSONArray("keys").length())
        assertEquals(0, json.getInt("count"))
    }

    // -------------------------------------------------------------------------
    // LocalGetKeyInfoParams / LocalSetKeyPolicyParams
    // -------------------------------------------------------------------------

    @Test
    fun `LocalGetKeyInfoParams fromJson reads keyId`() {
        assertEquals("k", LocalGetKeyInfoParams.fromJson(JSONObject("""{"keyId":"k"}""")).keyId)
    }

    @Test
    fun `LocalGetKeyInfoParams fromJson rejects a missing keyId with INVALID_PARAMS`() {
        assertEquals(
            ErrorCodes.INVALID_PARAMS,
            assertProtocolException { LocalGetKeyInfoParams.fromJson(JSONObject("{}")) }.errorCode
        )
    }

    @Test
    fun `LocalSetKeyPolicyParams fromJson leaves shareable null when the field is absent`() {
        val params = LocalSetKeyPolicyParams.fromJson(JSONObject("""{"keyId":"k"}"""))

        assertEquals("k", params.keyId)
        assertNull("absent means 'do not change'", params.shareable)
    }

    @Test
    fun `LocalSetKeyPolicyParams fromJson reads an explicit shareable flag`() {
        assertEquals(
            true,
            LocalSetKeyPolicyParams.fromJson(JSONObject("""{"keyId":"k","shareable":true}""")).shareable
        )
        assertEquals(
            false,
            LocalSetKeyPolicyParams.fromJson(JSONObject("""{"keyId":"k","shareable":false}""")).shareable
        )
    }

    @Test
    fun `LocalSetKeyPolicyParams fromJson rejects a missing keyId with INVALID_PARAMS`() {
        assertEquals(
            ErrorCodes.INVALID_PARAMS,
            assertProtocolException {
                LocalSetKeyPolicyParams.fromJson(JSONObject("""{"shareable":true}"""))
            }.errorCode
        )
    }

    @Test
    fun `LocalSetKeyPolicyParams fromJson raises on a non-boolean shareable`() {
        // getBoolean is strict and raises a JSONException, which is not wrapped.
        assertThrowsAny {
            LocalSetKeyPolicyParams.fromJson(JSONObject("""{"keyId":"k","shareable":"maybe"}"""))
        }
    }

    // -------------------------------------------------------------------------
    // LocalAttestKeyParams / LocalAttestKeyResult
    // -------------------------------------------------------------------------

    @Test
    fun `LocalAttestKeyParams fromJson reads keyId and nonce`() {
        val params = LocalAttestKeyParams.fromJson(
            JSONObject("""{"keyId":"k","nonce":"$helloB64"}""")
        )

        assertEquals("k", params.keyId)
        assertArrayEquals("hello".toByteArray(), params.getNonceBytes())
    }

    @Test
    fun `LocalAttestKeyParams fromJson rejects a missing nonce with INVALID_PARAMS`() {
        val e = assertProtocolException { LocalAttestKeyParams.fromJson(JSONObject("""{"keyId":"k"}""")) }

        assertEquals(ErrorCodes.INVALID_PARAMS, e.errorCode)
        assertTrue("message was: ${e.message}", e.message!!.contains("nonce"))
    }

    @Test
    fun `LocalAttestKeyParams round-trips through toJson and fromJson`() {
        val original = LocalAttestKeyParams("k", helloB64)

        assertEquals(setOf("keyId", "nonce"), original.toJson().keySet())
        assertEquals(original, LocalAttestKeyParams.fromJson(original.toJson()))
    }

    @Test
    fun `LocalAttestKeyResult toJson emits the certificate chain as an array`() {
        val json = LocalAttestKeyResult(listOf("bGVhZg", "cm9vdA"), "strongbox", helloB64).toJson()

        assertEquals(setOf("certificateChain", "securityLevel", "nonce"), json.keySet())
        assertEquals(2, json.getJSONArray("certificateChain").length())
        assertEquals("bGVhZg", json.getJSONArray("certificateChain").getString(0))
        assertEquals("cm9vdA", json.getJSONArray("certificateChain").getString(1))
        assertEquals("strongbox", json.getString("securityLevel"))
        assertEquals(helloB64, json.getString("nonce"))
    }

    @Test
    fun `LocalAttestKeyResult toJson emits an empty chain array when there are no certificates`() {
        val json = LocalAttestKeyResult(emptyList(), "software", helloB64).toJson()

        assertEquals(0, json.getJSONArray("certificateChain").length())
    }

    // -------------------------------------------------------------------------
    // LocalAttestDeviceParams / LocalAttestDeviceResult
    // -------------------------------------------------------------------------

    /** A 32-byte challenge — the only length protocol v2 accepts. */
    private val nonceB64 = Base64.getEncoder().encodeToString(ByteArray(32) { it.toByte() })

    @Test
    fun `LocalAttestDeviceParams fromJson reads a version 2 request`() {
        val params = LocalAttestDeviceParams.fromJson(
            JSONObject("""{"protocolVersion":2,"nonce":"$nonceB64","purpose":"reattest"}""")
        )

        assertEquals(2, params.protocolVersion)
        assertEquals("reattest", params.purpose)
        assertArrayEquals(ByteArray(32) { it.toByte() }, params.getNonceBytes())
    }

    @Test
    fun `LocalAttestDeviceParams fromJson rejects a missing nonce with INVALID_PARAMS`() {
        assertEquals(
            ErrorCodes.INVALID_PARAMS,
            assertProtocolException {
                LocalAttestDeviceParams.fromJson(JSONObject("""{"protocolVersion":2,"purpose":"pair"}"""))
            }.errorCode
        )
    }

    /**
     * Version 1 embedded the pairing nonce in the attested key's certificate and
     * could not carry a stable device identity (go-xkms#129). This prover never
     * answers it: a peer asking for the weaker exchange must not simply get it.
     */
    @Test
    fun `LocalAttestDeviceParams fromJson refuses a version 1 request`() {
        assertEquals(
            ErrorCodes.ATTEST_PROTOCOL_DOWNGRADE,
            assertProtocolException {
                LocalAttestDeviceParams.fromJson(
                    JSONObject("""{"protocolVersion":1,"nonce":"$nonceB64","purpose":"pair"}""")
                )
            }.errorCode
        )
    }

    @Test
    fun `LocalAttestDeviceParams fromJson refuses a request carrying no version at all`() {
        assertEquals(
            ErrorCodes.ATTEST_PROTOCOL_DOWNGRADE,
            assertProtocolException {
                LocalAttestDeviceParams.fromJson(JSONObject("""{"nonce":"$nonceB64","purpose":"pair"}"""))
            }.errorCode
        )
    }

    @Test
    fun `LocalAttestDeviceParams fromJson refuses an unknown purpose`() {
        assertEquals(
            ErrorCodes.INVALID_PARAMS,
            assertProtocolException {
                LocalAttestDeviceParams.fromJson(
                    JSONObject("""{"protocolVersion":2,"nonce":"$nonceB64","purpose":"enroll"}""")
                )
            }.errorCode
        )
    }

    /**
     * The transcript is fixed width, so a short challenge would produce a
     * signature over bytes the desktop cannot rebuild — and a weaker challenge
     * besides.
     */
    @Test
    fun `LocalAttestDeviceParams getNonceBytes refuses a nonce that is not 32 bytes`() {
        val params = LocalAttestDeviceParams.fromJson(
            JSONObject("""{"protocolVersion":2,"nonce":"$helloB64","purpose":"pair"}""")
        )

        assertEquals(ErrorCodes.INVALID_PARAMS, assertProtocolException { params.getNonceBytes() }.errorCode)
    }

    /**
     * The wire removal has to be real: a desktop that still sends the old
     * `channelBinding` must be parsed as though it had not, so there is nothing
     * for a future regression to reach for.
     */
    @Test
    fun `LocalAttestDeviceParams ignores a channelBinding a stale peer still sends`() {
        val params = LocalAttestDeviceParams.fromJson(
            JSONObject("""{"protocolVersion":2,"nonce":"$nonceB64","purpose":"pair","channelBinding":"$nonceB64"}""")
        )

        assertEquals(setOf("protocolVersion", "nonce", "purpose"), params.toJson().keySet())
        assertEquals(LocalAttestDeviceParams(2, nonceB64, "pair"), params)
    }

    @Test
    fun `LocalAttestDeviceParams round-trips through toJson and fromJson`() {
        val original = LocalAttestDeviceParams(2, nonceB64, "pair")

        assertEquals(
            "the v2 request carries no channelBinding; see LocalAttestDeviceParams",
            setOf("protocolVersion", "nonce", "purpose"),
            original.toJson().keySet()
        )
        assertEquals(original, LocalAttestDeviceParams.fromJson(original.toJson()))
    }

    @Test
    fun `LocalAttestDeviceResult toJson emits the version 2 fields go-xkms expects`() {
        val json = LocalAttestDeviceResult(
            protocolVersion = 2,
            format = "android-keystore",
            certificateChain = listOf("bGVhZg"),
            securityLevel = "strongbox",
            nonce = nonceB64,
            purpose = "pair",
            signature = "c2ln",
            signatureAlgorithm = "ES256",
            bootState = 0,
            deviceLocked = true,
            verifiedBootKey = "a2V5",
            verifiedBootHash = "aGFzaA"
        ).toJson()

        assertEquals(
            setOf(
                "protocolVersion", "format", "certificateChain", "securityLevel",
                "nonce", "purpose", "signature", "signatureAlgorithm",
                "bootState", "deviceLocked", "verifiedBootKey", "verifiedBootHash"
            ),
            json.keySet()
        )
        assertEquals(2, json.getInt("protocolVersion"))
        assertEquals("android-keystore", json.getString("format"))
        assertEquals("pair", json.getString("purpose"))
        assertEquals("c2ln", json.getString("signature"))
        assertEquals("ES256", json.getString("signatureAlgorithm"))
        assertEquals(0, json.getInt("bootState"))
        assertTrue(json.getBoolean("deviceLocked"))
        assertEquals("a2V5", json.getString("verifiedBootKey"))
        assertEquals("aGFzaA", json.getString("verifiedBootHash"))
    }

    // -------------------------------------------------------------------------
    // LocalGetCapabilitiesResult
    // -------------------------------------------------------------------------

    @Test
    fun `LocalGetCapabilitiesResult toJson emits the go-xkms contract plus the legacy Android fields`() {
        val json = LocalGetCapabilitiesResult(
            algorithms = listOf("ES256", "RS256"),
            keyTypes = listOf(KeyTypes.FIDO2, KeyTypes.SIGNING),
            hasStrongBox = true,
            hasBiometrics = true,
            supportsAttestation = true,
            supportsECDH = false,
            supportsSymmetric = true,
            supportsHMAC = false,
            maxKeys = 100
        ).toJson()

        // go-xkms LocalGetCapabilitiesResult reads supportedAlgorithms,
        // strongBoxAvailable, attestationSupport, currentKeyCount,
        // supportedFormats, version and deviceName. The rest is the legacy
        // Android spelling, kept for older peers.
        assertEquals(
            setOf(
                "version", "deviceName", "supportedAlgorithms", "strongBoxAvailable",
                "currentKeyCount", "supportedFormats", "attestationSupport",
                "algorithms", "keyTypes", "hasStrongBox", "hasBiometrics", "supportsAttestation",
                "supportsECDH", "supportsSymmetric", "supportsHMAC", "maxKeys"
            ),
            json.keySet()
        )
        assertEquals(2, json.getJSONArray("algorithms").length())
        assertEquals("ES256", json.getJSONArray("algorithms").getString(0))
        assertEquals(KeyTypes.FIDO2, json.getJSONArray("keyTypes").getString(0))
        assertFalse(json.getBoolean("supportsECDH"))
        assertEquals(100, json.getInt("maxKeys"))
    }

    // -------------------------------------------------------------------------
    // FIDO2 discovery and assertion payloads
    // -------------------------------------------------------------------------

    @Test
    fun `LocalListFido2CredentialsParams fromJson reads rpId`() {
        val params = LocalListFido2CredentialsParams.fromJson(JSONObject("""{"rpId":"example.com"}"""))

        assertEquals("example.com", params.rpId)
    }

    @Test
    fun `LocalListFido2CredentialsParams fromJson rejects a missing rpId with INVALID_PARAMS`() {
        val e = assertProtocolException { LocalListFido2CredentialsParams.fromJson(JSONObject("{}")) }

        assertEquals(ErrorCodes.INVALID_PARAMS, e.errorCode)
        assertTrue("message was: ${e.message}", e.message!!.contains("rpId"))
    }

    @Test
    fun `LocalListFido2CredentialsParams round-trips through toJson and fromJson`() {
        val original = LocalListFido2CredentialsParams("example.com")

        assertEquals(setOf("rpId"), original.toJson().keySet())
        assertEquals(original, LocalListFido2CredentialsParams.fromJson(original.toJson()))
    }

    @Test
    fun `Fido2CredentialInfo toJson emits the required fields and omits the optional nulls`() {
        val json = Fido2CredentialInfo(
            credentialId = helloB64,
            rpId = "example.com",
            rpName = null,
            userId = null,
            userName = null,
            userDisplayName = null,
            isDiscoverable = false,
            createdAt = 1234L
        ).toJson()

        assertEquals(setOf("credentialId", "rpId", "isDiscoverable", "createdAt"), json.keySet())
        assertEquals(1234L, json.getLong("createdAt"))
    }

    @Test
    fun `Fido2CredentialInfo toJson emits every optional field when present`() {
        val json = Fido2CredentialInfo(
            credentialId = helloB64,
            rpId = "example.com",
            rpName = "Example",
            userId = "dXNlcg",
            userName = "alice",
            userDisplayName = "Alice A",
            isDiscoverable = true,
            createdAt = 1234L
        ).toJson()

        assertEquals(
            setOf(
                "credentialId", "rpId", "rpName", "userId", "userName",
                "userDisplayName", "isDiscoverable", "createdAt"
            ),
            json.keySet()
        )
    }

    @Test
    fun `LocalListFido2CredentialsResult toJson wraps the credentials in an array`() {
        val credential = Fido2CredentialInfo(helloB64, "example.com", null, null, null, null, true, 1L)

        val json = LocalListFido2CredentialsResult(listOf(credential)).toJson()

        assertEquals(setOf("credentials"), json.keySet())
        assertEquals(1, json.getJSONArray("credentials").length())
        assertEquals("example.com", json.getJSONArray("credentials").getJSONObject(0).getString("rpId"))
    }

    @Test
    fun `LocalListFido2CredentialsResult toJson emits an empty array when nothing matches`() {
        assertEquals(0, LocalListFido2CredentialsResult(emptyList()).toJson().getJSONArray("credentials").length())
    }

    @Test
    fun `LocalSignFido2AssertionParams fromJson reads all fields and defaults UV to true`() {
        val params = LocalSignFido2AssertionParams.fromJson(
            JSONObject(
                """{"credentialId":"$helloB64","clientDataHash":"$helloB64","rpId":"example.com"}"""
            )
        )

        assertEquals("example.com", params.rpId)
        assertTrue(params.userVerificationRequired)
        assertArrayEquals("hello".toByteArray(), params.getCredentialIdBytes())
        assertArrayEquals("hello".toByteArray(), params.getClientDataHashBytes())
    }

    @Test
    fun `LocalSignFido2AssertionParams fromJson rejects each missing required field with INVALID_PARAMS`() {
        val cases = mapOf(
            "credentialId" to """{"clientDataHash":"$helloB64","rpId":"example.com"}""",
            "clientDataHash" to """{"credentialId":"$helloB64","rpId":"example.com"}""",
            "rpId" to """{"credentialId":"$helloB64","clientDataHash":"$helloB64"}"""
        )

        cases.forEach { (missingField, json) ->
            val e = assertProtocolException { LocalSignFido2AssertionParams.fromJson(JSONObject(json)) }
            assertEquals("missing $missingField", ErrorCodes.INVALID_PARAMS, e.errorCode)
            assertTrue("message was: ${e.message}", e.message!!.contains(missingField))
        }
    }

    @Test
    fun `LocalSignFido2AssertionParams round-trips through toJson and fromJson`() {
        val original = LocalSignFido2AssertionParams(helloB64, helloB64, "example.com", false)

        assertEquals(
            setOf("credentialId", "clientDataHash", "rpId", "userVerificationRequired"),
            original.toJson().keySet()
        )
        assertEquals(original, LocalSignFido2AssertionParams.fromJson(original.toJson()))
    }

    @Test
    fun `LocalSignFido2AssertionResult toJson emits the assertion fields and omits a null userHandle`() {
        val json = LocalSignFido2AssertionResult("YXV0aA", "c2ln", null, 7L).toJson()

        assertEquals(setOf("authenticatorData", "signature", "signCount"), json.keySet())
        assertEquals("YXV0aA", json.getString("authenticatorData"))
        assertEquals("c2ln", json.getString("signature"))
        assertEquals(7L, json.getLong("signCount"))
    }

    @Test
    fun `LocalSignFido2AssertionResult toJson emits userHandle when present`() {
        val json = LocalSignFido2AssertionResult("YXV0aA", "c2ln", "dXNlcg", 7L).toJson()

        assertEquals("dXNlcg", json.getString("userHandle"))
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private fun sampleKeyInfo() = KeyInfo(
        keyId = "k1",
        keyType = KeyTypes.SIGNING,
        algorithm = "ES256",
        label = "Signing key",
        keySizeBits = 256,
        strongBoxBacked = true,
        shareable = false,
        source = "local",
        useCount = 4,
        createdAt = 1000L,
        lastUsedAt = 2000L
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
