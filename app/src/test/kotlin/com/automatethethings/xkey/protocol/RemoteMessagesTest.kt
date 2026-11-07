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
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Unit tests for the `remote.*` payloads in `Messages.kt` (the phone -> laptop
 * half of the protocol, served by the xkmsd bridge).
 *
 * Here the phone is the *initiator*: it serializes the params and parses the
 * results, so the risk profile is inverted relative to `local.*`. The `toJson`
 * tests pin the parameter names go-xkms unmarshals in
 * `go-xkms/xkey/pkg/pairing/protocol_remote.go` (including the `omitempty`
 * fields that must be dropped when null), while the `fromJson` tests cover
 * result parsing, the optional-field defaults, and what happens when a required
 * result field is missing.
 */
class RemoteMessagesTest {

    private fun JSONObject.keySet(): Set<String> = keys().asSequence().toSet()

    // -------------------------------------------------------------------------
    // RemoteBackendInfo / RemoteListBackendsResult
    // -------------------------------------------------------------------------

    @Test
    fun `RemoteBackendInfo fromJson reads the name type and capability flags`() {
        val info = RemoteBackendInfo.fromJson(
            JSONObject(
                """{"name":"tpm2","type":"tpm2","hardwareBacked":true,"signing":true,
                    "decryption":true,"symmetricCrypto":false,"keyAgreement":true,"attestation":true}"""
            )
        )

        assertEquals("tpm2", info.name)
        assertEquals("tpm2", info.type)
        assertTrue(info.hardwareBacked)
        assertTrue(info.signing)
        assertTrue(info.decryption)
        assertFalse(info.symmetricCrypto)
        assertTrue(info.keyAgreement)
        assertTrue(info.attestation)
    }

    @Test
    fun `RemoteBackendInfo fromJson defaults every absent capability flag to false`() {
        val info = RemoteBackendInfo.fromJson(JSONObject("""{"name":"software","type":"software"}"""))

        assertFalse(info.hardwareBacked)
        assertFalse(info.signing)
        assertFalse(info.decryption)
        assertFalse(info.symmetricCrypto)
        assertFalse(info.keyAgreement)
        assertFalse(info.attestation)
    }

    @Test
    fun `RemoteBackendInfo fromJson raises when the required name is missing`() {
        assertThrowsAny { RemoteBackendInfo.fromJson(JSONObject("""{"type":"software"}""")) }
    }

    @Test
    fun `RemoteBackendInfo toJson emits exactly the eight wire fields`() {
        val json = sampleBackend().toJson()

        assertEquals(
            setOf(
                "name", "type", "hardwareBacked", "signing", "decryption",
                "symmetricCrypto", "keyAgreement", "attestation"
            ),
            json.keySet()
        )
    }

    @Test
    fun `RemoteBackendInfo round-trips through toJson and fromJson`() {
        val original = sampleBackend()

        assertEquals(original, RemoteBackendInfo.fromJson(original.toJson()))
    }

    @Test
    fun `RemoteListBackendsResult fromJson reads every backend in the array`() {
        val result = RemoteListBackendsResult.fromJson(
            JSONObject("""{"backends":[{"name":"tpm2","type":"tpm2"},{"name":"soft","type":"software"}]}""")
        )

        assertEquals(2, result.backends.size)
        assertEquals("tpm2", result.backends[0].name)
        assertEquals("soft", result.backends[1].name)
    }

    @Test
    fun `RemoteListBackendsResult fromJson accepts an empty backend list`() {
        assertTrue(RemoteListBackendsResult.fromJson(JSONObject("""{"backends":[]}""")).backends.isEmpty())
    }

    @Test
    fun `RemoteListBackendsResult fromJson raises when the backends array is missing`() {
        assertThrowsAny { RemoteListBackendsResult.fromJson(JSONObject("{}")) }
    }

    @Test
    fun `RemoteListBackendsResult round-trips through toJson and fromJson`() {
        val original = RemoteListBackendsResult(listOf(sampleBackend()))

        assertEquals(setOf("backends"), original.toJson().keySet())
        assertEquals(original, RemoteListBackendsResult.fromJson(original.toJson()))
    }

    // -------------------------------------------------------------------------
    // RemoteListKeysParams / RemoteKeyInfo / RemoteListKeysResult
    // -------------------------------------------------------------------------

    @Test
    fun `RemoteKeyInfo fromJson reads all fields`() {
        val info = RemoteKeyInfo.fromJson(
            JSONObject(
                """{"keyId":"k","backend":"tpm2","algorithm":"ES256",
                    "keySizeBits":256,"label":"my key","createdAt":1700000000}"""
            )
        )

        assertEquals("k", info.keyId)
        assertEquals("tpm2", info.backend)
        assertEquals("ES256", info.algorithm)
        assertEquals(256, info.keySizeBits)
        assertEquals("my key", info.label)
        assertEquals(1700000000L, info.createdAt)
    }

    @Test
    fun `RemoteKeyInfo fromJson raises when a required field is missing`() {
        assertThrowsAny { RemoteKeyInfo.fromJson(JSONObject("""{"backend":"tpm2","algorithm":"ES256"}""")) }
    }

    @Test
    fun `RemoteKeyInfo round-trips through toJson and fromJson`() {
        val original = RemoteKeyInfo("k", "tpm2", "ES256", 256, "my key", 1700000000L)

        assertEquals(
            setOf("keyId", "backend", "algorithm", "keySizeBits", "label", "createdAt"),
            original.toJson().keySet()
        )
        assertEquals(original, RemoteKeyInfo.fromJson(original.toJson()))
    }

    @Test
    fun `RemoteListKeysResult round-trips through toJson and fromJson`() {
        val original = RemoteListKeysResult(
            listOf(RemoteKeyInfo("k1", "tpm2", "ES256", 256, "a", 1L))
        )

        assertEquals(setOf("keys"), original.toJson().keySet())
        assertEquals(original, RemoteListKeysResult.fromJson(original.toJson()))
    }

    @Test
    fun `RemoteListKeysResult fromJson raises when the keys array is missing`() {
        assertThrowsAny { RemoteListKeysResult.fromJson(JSONObject("{}")) }
    }

    // -------------------------------------------------------------------------
    // remote.getPublicKey
    // -------------------------------------------------------------------------

    @Test
    fun `RemoteGetPublicKeyResult round-trips through toJson and fromJson`() {
        val original = RemoteGetPublicKeyResult("cHVi", "pem", "ES256")

        assertEquals(setOf("publicKey", "format", "algorithm"), original.toJson().keySet())
        assertEquals(original, RemoteGetPublicKeyResult.fromJson(original.toJson()))
    }

    @Test
    fun `RemoteGetPublicKeyResult fromJson raises when publicKey is missing`() {
        assertThrowsAny {
            RemoteGetPublicKeyResult.fromJson(JSONObject("""{"format":"pem","algorithm":"ES256"}"""))
        }
    }

    // -------------------------------------------------------------------------
    // remote.sign / remote.verify
    // -------------------------------------------------------------------------

    @Test
    fun `RemoteSignResult round-trips through toJson and fromJson`() {
        val original = RemoteSignResult("c2ln", "ES256")

        assertEquals(setOf("signature", "algorithm"), original.toJson().keySet())
        assertEquals(original, RemoteSignResult.fromJson(original.toJson()))
    }

    @Test
    fun `RemoteSignResult fromJson raises when the signature is missing`() {
        assertThrowsAny { RemoteSignResult.fromJson(JSONObject("""{"algorithm":"ES256"}""")) }
    }

    @Test
    fun `RemoteVerifyParams toJson emits data and signature and omits a null algorithm`() {
        val json = RemoteVerifyParams("tpm2", "k", "ZGF0YQ", "c2ln").toJson()

        assertEquals(setOf("backend", "keyId", "data", "signature"), json.keySet())
    }

    @Test
    fun `RemoteVerifyResult fromJson reads the boolean verdict`() {
        assertTrue(RemoteVerifyResult.fromJson(JSONObject("""{"valid":true}""")).valid)
        assertFalse(RemoteVerifyResult.fromJson(JSONObject("""{"valid":false}""")).valid)
    }

    @Test
    fun `RemoteVerifyResult fromJson raises when valid is missing`() {
        assertThrowsAny { RemoteVerifyResult.fromJson(JSONObject("{}")) }
    }

    @Test
    fun `RemoteVerifyResult toJson emits exactly valid`() {
        assertEquals(setOf("valid"), RemoteVerifyResult(true).toJson().keySet())
    }

    // -------------------------------------------------------------------------
    // remote.encrypt / remote.decrypt
    // -------------------------------------------------------------------------

    @Test
    fun `RemoteEncryptResult round-trips through toJson and fromJson`() {
        val original = RemoteEncryptResult("Y3Q")

        assertEquals(setOf("ciphertext"), original.toJson().keySet())
        assertEquals(original, RemoteEncryptResult.fromJson(original.toJson()))
    }

    @Test
    fun `RemoteDecryptParams toJson omits the optional algorithm and aad`() {
        assertEquals(
            setOf("backend", "keyId", "ciphertext"),
            RemoteDecryptParams("soft", "k", "Y3Q").toJson().keySet()
        )
    }

    @Test
    fun `RemoteDecryptParams toJson emits the optional algorithm and aad when set`() {
        val json = RemoteDecryptParams("soft", "k", "Y3Q", "AES-256", "YWFk").toJson()

        assertEquals(setOf("backend", "keyId", "ciphertext", "algorithm", "aad"), json.keySet())
    }

    @Test
    fun `RemoteDecryptResult round-trips through toJson and fromJson`() {
        val original = RemoteDecryptResult("cHQ")

        assertEquals(setOf("plaintext"), original.toJson().keySet())
        assertEquals(original, RemoteDecryptResult.fromJson(original.toJson()))
    }

    // -------------------------------------------------------------------------
    // remote.deriveKey
    // -------------------------------------------------------------------------

    @Test
    fun `RemoteDeriveKeyResult round-trips through toJson and fromJson`() {
        val original = RemoteDeriveKeyResult("c2VjcmV0")

        assertEquals(setOf("sharedSecret"), original.toJson().keySet())
        assertEquals(original, RemoteDeriveKeyResult.fromJson(original.toJson()))
    }

    // -------------------------------------------------------------------------
    // remote.generateKey / remote.getKeyInfo / remote.deleteKey
    // -------------------------------------------------------------------------

    @Test
    fun `RemoteGenerateKeyResult fromJson tolerates a symmetric key with no public part`() {
        val result = RemoteGenerateKeyResult.fromJson(
            JSONObject("""{"keyId":"k","algorithm":"AES-256","backend":"soft"}""")
        )

        assertNull(result.publicKey)
        assertEquals(0, result.keySizeBits)
    }

    @Test
    fun `RemoteGenerateKeyResult round-trips through toJson and fromJson`() {
        val original = RemoteGenerateKeyResult("k", "cHVi", "ES256", 256, "tpm2")

        assertEquals(
            setOf("keyId", "publicKey", "algorithm", "keySizeBits", "backend"),
            original.toJson().keySet()
        )
        assertEquals(original, RemoteGenerateKeyResult.fromJson(original.toJson()))
    }

    @Test
    fun `RemoteGenerateKeyResult toJson omits a null publicKey`() {
        val json = RemoteGenerateKeyResult("k", null, "AES-256", 256, "soft").toJson()

        assertFalse(json.has("publicKey"))
    }

    @Test
    fun `RemoteGetKeyInfoParams toJson emits exactly backend and keyId`() {
        assertEquals(setOf("backend", "keyId"), RemoteGetKeyInfoParams("tpm2", "k").toJson().keySet())
    }

    @Test
    fun `RemoteGetKeyInfoResult fromJson defaults the optional metadata`() {
        val result = RemoteGetKeyInfoResult.fromJson(
            JSONObject("""{"keyId":"k","backend":"tpm2","algorithm":"ES256"}""")
        )

        assertEquals(0, result.keySizeBits)
        assertEquals("", result.label)
        assertEquals(0L, result.createdAt)
        assertFalse(result.hardwareBacked)
        assertFalse(result.exportable)
    }

    @Test
    fun `RemoteGetKeyInfoResult round-trips through toJson and fromJson`() {
        val original = RemoteGetKeyInfoResult("k", "tpm2", "ES256", 256, "my key", 5L, true, false)

        assertEquals(
            setOf(
                "keyId", "backend", "algorithm", "keySizeBits",
                "label", "createdAt", "hardwareBacked", "exportable"
            ),
            original.toJson().keySet()
        )
        assertEquals(original, RemoteGetKeyInfoResult.fromJson(original.toJson()))
    }

    @Test
    fun `RemoteDeleteKeyParams toJson emits exactly backend and keyId`() {
        assertEquals(setOf("backend", "keyId"), RemoteDeleteKeyParams("tpm2", "k").toJson().keySet())
    }

    @Test
    fun `RemoteDeleteKeyResult round-trips through toJson and fromJson`() {
        val original = RemoteDeleteKeyResult(true)

        assertEquals(setOf("deleted"), original.toJson().keySet())
        assertEquals(original, RemoteDeleteKeyResult.fromJson(original.toJson()))
    }

    @Test
    fun `RemoteDeleteKeyResult fromJson raises when deleted is missing`() {
        assertThrowsAny { RemoteDeleteKeyResult.fromJson(JSONObject("{}")) }
    }

    // -------------------------------------------------------------------------
    // remote.attestKey
    // -------------------------------------------------------------------------

    @Test
    fun `RemoteAttestKeyParams toJson emits exactly backend keyId and nonce`() {
        assertEquals(
            setOf("backend", "keyId", "nonce"),
            RemoteAttestKeyParams("tpm2", "k", "bm9uY2U").toJson().keySet()
        )
    }

    @Test
    fun `RemoteAttestKeyResult fromJson reads the chain and the optional attestationData`() {
        val result = RemoteAttestKeyResult.fromJson(
            JSONObject(
                """{"format":"tpm2","certificateChain":["bGVhZg","cm9vdA"],
                    "attestationData":"cXVvdGU","nonce":"bm9uY2U"}"""
            )
        )

        assertEquals("tpm2", result.format)
        assertEquals(listOf("bGVhZg", "cm9vdA"), result.certificateChain)
        assertEquals("cXVvdGU", result.attestationData)
        assertEquals("bm9uY2U", result.nonce)
    }

    @Test
    fun `RemoteAttestKeyResult fromJson leaves attestationData null when absent`() {
        val result = RemoteAttestKeyResult.fromJson(
            JSONObject("""{"format":"pkcs11","certificateChain":[],"nonce":"bm9uY2U"}""")
        )

        assertNull(result.attestationData)
        assertTrue(result.certificateChain.isEmpty())
    }

    @Test
    fun `RemoteAttestKeyResult fromJson raises when the certificate chain is missing`() {
        assertThrowsAny {
            RemoteAttestKeyResult.fromJson(JSONObject("""{"format":"tpm2","nonce":"bm9uY2U"}"""))
        }
    }

    @Test
    fun `RemoteAttestKeyResult toJson omits a null attestationData`() {
        val json = RemoteAttestKeyResult("tpm2", listOf("bGVhZg"), null, "bm9uY2U").toJson()

        assertEquals(setOf("format", "certificateChain", "nonce"), json.keySet())
    }

    @Test
    fun `RemoteAttestKeyResult round-trips through toJson and fromJson`() {
        val original = RemoteAttestKeyResult("tpm2", listOf("bGVhZg", "cm9vdA"), "cXVvdGU", "bm9uY2U")

        assertEquals(original, RemoteAttestKeyResult.fromJson(original.toJson()))
    }

    // -------------------------------------------------------------------------
    // remote.attestDevice
    // -------------------------------------------------------------------------

    @Test
    fun `RemoteAttestDeviceParams fromJson reads the nonce`() {
        assertEquals(
            "bm9uY2U",
            RemoteAttestDeviceParams.fromJson(JSONObject("""{"nonce":"bm9uY2U"}""")).nonce
        )
    }

    @Test
    fun `RemoteAttestDeviceParams fromJson rejects a missing nonce with INVALID_PARAMS`() {
        val e = assertProtocolException { RemoteAttestDeviceParams.fromJson(JSONObject("{}")) }

        assertEquals(ErrorCodes.INVALID_PARAMS, e.errorCode)
    }

    @Test
    fun `RemoteAttestDeviceParams round-trips through toJson and fromJson`() {
        val original = RemoteAttestDeviceParams("bm9uY2U")

        assertEquals(setOf("nonce"), original.toJson().keySet())
        assertEquals(original, RemoteAttestDeviceParams.fromJson(original.toJson()))
    }

    @Test
    fun `RemoteAttestDeviceResult fromJson reads a full TPM2 attestation`() {
        val result = RemoteAttestDeviceResult.fromJson(
            JSONObject(
                """{"format":"tpm2","certificateChain":["ZWs","YWs"],"securityLevel":"hardware",
                    "nonce":"bm9uY2U","bootHashHex":"abcd","bootStateVerified":true,
                    "firmwareVersion":"7.2.1"}"""
            )
        )

        assertEquals("tpm2", result.format)
        assertEquals(listOf("ZWs", "YWs"), result.certificateChain)
        assertEquals("hardware", result.securityLevel)
        assertEquals("bm9uY2U", result.nonce)
        assertEquals("abcd", result.bootHashHex)
        assertTrue(result.bootStateVerified)
        assertEquals("7.2.1", result.firmwareVersion)
    }

    @Test
    fun `RemoteAttestDeviceResult fromJson falls back to safe defaults for an empty result`() {
        val result = RemoteAttestDeviceResult.fromJson(JSONObject("{}"))

        assertEquals("unknown", result.format)
        assertTrue(result.certificateChain.isEmpty())
        assertEquals("software", result.securityLevel)
        assertEquals("", result.nonce)
        assertNull(result.bootHashHex)
        assertFalse("an unverified boot state must never default to true", result.bootStateVerified)
        assertNull(result.firmwareVersion)
    }

    @Test
    fun `RemoteAttestDeviceResult toJson omits the null optional fields`() {
        val json = RemoteAttestDeviceResult(
            format = "software",
            certificateChain = emptyList(),
            securityLevel = "software",
            nonce = "bm9uY2U",
            bootHashHex = null,
            bootStateVerified = false,
            firmwareVersion = null
        ).toJson()

        assertEquals(
            setOf("format", "certificateChain", "securityLevel", "nonce", "bootStateVerified"),
            json.keySet()
        )
    }

    @Test
    fun `RemoteAttestDeviceResult round-trips through toJson and fromJson`() {
        val original = RemoteAttestDeviceResult(
            format = "tpm2",
            certificateChain = listOf("ZWs"),
            securityLevel = "hardware",
            nonce = "bm9uY2U",
            bootHashHex = "abcd",
            bootStateVerified = true,
            firmwareVersion = "7.2.1"
        )

        assertEquals(original, RemoteAttestDeviceResult.fromJson(original.toJson()))
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private fun sampleBackend() = RemoteBackendInfo(
        name = "tpm2",
        type = "tpm2",
        hardwareBacked = true,
        signing = true,
        decryption = false,
        symmetricCrypto = false,
        keyAgreement = true,
        attestation = true
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
