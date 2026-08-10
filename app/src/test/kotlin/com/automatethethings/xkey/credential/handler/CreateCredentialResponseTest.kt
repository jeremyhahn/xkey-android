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
package com.automatethethings.xkey.credential.handler

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest
import java.util.Base64

/**
 * Tests for the registration (attestation) response format produced by
 * CreateCredentialHandler.buildAttestationResponse().
 *
 * Since the method is private, these tests replicate the same response-building
 * logic and verify the JSON structure that relying parties will receive.
 */
class CreateCredentialResponseTest {

    private val rpId = "webauthn.io"
    private val credentialId = ByteArray(32) { it.toByte() }
    private val publicKeyCose = ByteArray(77) // typical COSE_Key size
    // DER/SPKI encoded public key (distinct from COSE) — typical EC P-256 SPKI size is 91 bytes
    private val publicKeyDer = ByteArray(91) { (it + 0x30).toByte() }

    @Test
    fun `attestation response contains required top-level fields`() {
        val response = buildTestAttestationResponse(clientDataJsonBase64 = null)
        val json = JSONObject(response)

        assertTrue("Response must have 'id'", json.has("id"))
        assertTrue("Response must have 'rawId'", json.has("rawId"))
        assertEquals("public-key", json.getString("type"))
        assertEquals("platform", json.getString("authenticatorAttachment"))
        assertTrue("Response must have 'response' object", json.has("response"))
        assertTrue("Response must have 'clientExtensionResults'", json.has("clientExtensionResults"))
    }

    @Test
    fun `attestation response id and rawId match`() {
        val response = buildTestAttestationResponse(clientDataJsonBase64 = null)
        val json = JSONObject(response)

        assertEquals(json.getString("id"), json.getString("rawId"))
    }

    @Test
    fun `attestation response inner object contains attestationObject`() {
        val response = buildTestAttestationResponse(clientDataJsonBase64 = null)
        val json = JSONObject(response)
        val inner = json.getJSONObject("response")

        assertTrue("Inner response must have 'attestationObject'", inner.has("attestationObject"))
        assertTrue("Inner response must have 'authenticatorData'", inner.has("authenticatorData"))
        assertTrue("Inner response must have 'publicKeyAlgorithm'", inner.has("publicKeyAlgorithm"))
        assertTrue("Inner response must have 'publicKey'", inner.has("publicKey"))
        assertEquals(-7, inner.getInt("publicKeyAlgorithm"))

        val transports = inner.getJSONArray("transports")
        assertEquals(1, transports.length())
        assertEquals("internal", transports.getString(0))
    }

    @Test
    fun `attestation response includes clientDataJSON when provided`() {
        val clientDataJsonBase64 = Base64.getUrlEncoder().withoutPadding()
            .encodeToString("""{"type":"webauthn.create","challenge":"abc","origin":"https://webauthn.io"}""".toByteArray())

        val response = buildTestAttestationResponse(clientDataJsonBase64 = clientDataJsonBase64)
        val json = JSONObject(response)
        val inner = json.getJSONObject("response")

        assertTrue("Inner response must have 'clientDataJSON'", inner.has("clientDataJSON"))
        assertEquals(clientDataJsonBase64, inner.getString("clientDataJSON"))
    }

    @Test
    fun `attestation response omits clientDataJSON when null`() {
        val response = buildTestAttestationResponse(clientDataJsonBase64 = null)
        val json = JSONObject(response)
        val inner = json.getJSONObject("response")

        assertTrue("Inner response must NOT have 'clientDataJSON'", !inner.has("clientDataJSON"))
    }

    @Test
    fun `publicKey field uses DER SPKI format not COSE`() {
        val response = buildTestAttestationResponse(clientDataJsonBase64 = null)
        val json = JSONObject(response)
        val inner = json.getJSONObject("response")

        val publicKeyBase64 = inner.getString("publicKey")
        val publicKeyBytes = Base64.getUrlDecoder().decode(publicKeyBase64)

        // publicKey should be DER/SPKI (91 bytes for EC P-256), not COSE (77 bytes)
        assertTrue("publicKey should be DER/SPKI format (${publicKeyDer.size} bytes), got ${publicKeyBytes.size}",
            publicKeyDer.contentEquals(publicKeyBytes))

        // Verify it's NOT the COSE key
        assertTrue("publicKey must not be the COSE-encoded key",
            !publicKeyCose.contentEquals(publicKeyBytes))
    }

    @Test
    fun `authenticatorData contains COSE public key`() {
        val response = buildTestAttestationResponse(clientDataJsonBase64 = null)
        val json = JSONObject(response)
        val inner = json.getJSONObject("response")

        val authDataBase64 = inner.getString("authenticatorData")
        val authDataBytes = Base64.getUrlDecoder().decode(authDataBase64)

        // COSE key is at the end of authData: rpIdHash(32) + flags(1) + signCount(4) + aaguid(16) + credIdLen(2) + credId(32) = 87
        val coseKeyInAuthData = authDataBytes.sliceArray(87 until authDataBytes.size)
        assertTrue("authenticatorData should contain the COSE public key",
            publicKeyCose.contentEquals(coseKeyInAuthData))
    }

    @Test
    fun `attestation object CBOR starts with map header`() {
        val authData = buildTestAuthData()
        val attestationObject = buildTestAttestationObject(authData)

        // First byte should be 0xA3 (CBOR map with 3 items)
        assertEquals("Attestation object should start with CBOR map(3)", 0xA3.toByte(), attestationObject[0])
    }

    @Test
    fun `attestation object contains fmt none`() {
        val authData = buildTestAuthData()
        val attestationObject = buildTestAttestationObject(authData)

        // After map header (0xA3), text "fmt" then "none"
        assertEquals(0x63.toByte(), attestationObject[1]) // text(3)
        assertEquals('f'.code.toByte(), attestationObject[2])
        assertEquals('m'.code.toByte(), attestationObject[3])
        assertEquals('t'.code.toByte(), attestationObject[4])
        assertEquals(0x64.toByte(), attestationObject[5]) // text(4)
        assertEquals('n'.code.toByte(), attestationObject[6])
        assertEquals('o'.code.toByte(), attestationObject[7])
        assertEquals('n'.code.toByte(), attestationObject[8])
        assertEquals('e'.code.toByte(), attestationObject[9])
    }

    @Test
    fun `auth data starts with rpIdHash`() {
        val authData = buildTestAuthData()
        val expectedRpIdHash = MessageDigest.getInstance("SHA-256").digest(rpId.toByteArray())

        val actualRpIdHash = authData.sliceArray(0 until 32)
        assertTrue("Auth data should start with SHA-256 of rpId", expectedRpIdHash.contentEquals(actualRpIdHash))
    }

    @Test
    fun `auth data flags include UP UV AT`() {
        val authData = buildTestAuthData()
        val flags = authData[32].toInt() and 0xFF

        assertTrue("UP flag should be set", flags and 0x01 != 0)
        assertTrue("UV flag should be set", flags and 0x04 != 0)
        assertTrue("AT flag should be set", flags and 0x40 != 0)
    }

    @Test
    fun `auth data contains credential id at correct offset`() {
        val authData = buildTestAuthData()
        // rpIdHash(32) + flags(1) + signCount(4) + aaguid(16) + credIdLen(2) = offset 55
        val credIdLen = ((authData[53].toInt() and 0xFF) shl 8) or (authData[54].toInt() and 0xFF)
        assertEquals(32, credIdLen)

        val embeddedCredId = authData.sliceArray(55 until 55 + 32)
        assertTrue("Auth data should contain the credential ID", credentialId.contentEquals(embeddedCredId))
    }

    // --- Helper methods replicating CreateCredentialHandler logic ---

    private fun buildTestAttestationResponse(clientDataJsonBase64: String?): String {
        val rpIdHash = MessageDigest.getInstance("SHA-256").digest(rpId.toByteArray())
        val flags: Byte = (0x01 or 0x04 or 0x40).toByte()
        val signCount = ByteArray(4)
        val aaguid = ByteArray(16)
        val credIdLength = byteArrayOf(
            ((credentialId.size shr 8) and 0xFF).toByte(),
            (credentialId.size and 0xFF).toByte()
        )
        val authData = rpIdHash + flags + signCount + aaguid + credIdLength + credentialId + publicKeyCose
        val attestationObject = buildTestAttestationObject(authData)

        val b64Flags = Base64.getUrlEncoder().withoutPadding()
        val response = JSONObject().apply {
            put("id", b64Flags.encodeToString(credentialId))
            put("rawId", b64Flags.encodeToString(credentialId))
            put("type", "public-key")
            put("authenticatorAttachment", "platform")
            put("response", JSONObject().apply {
                if (clientDataJsonBase64 != null) {
                    put("clientDataJSON", clientDataJsonBase64)
                }
                put("attestationObject", b64Flags.encodeToString(attestationObject))
                put("authenticatorData", b64Flags.encodeToString(authData))
                put("publicKeyAlgorithm", -7)
                put("publicKey", b64Flags.encodeToString(publicKeyDer))
                put("transports", org.json.JSONArray().apply {
                    put("internal")
                })
            })
            put("clientExtensionResults", JSONObject())
        }
        return response.toString()
    }

    private fun buildTestAuthData(): ByteArray {
        val rpIdHash = MessageDigest.getInstance("SHA-256").digest(rpId.toByteArray())
        val flags: Byte = (0x01 or 0x04 or 0x40).toByte()
        val signCount = ByteArray(4)
        val aaguid = ByteArray(16)
        val credIdLength = byteArrayOf(
            ((credentialId.size shr 8) and 0xFF).toByte(),
            (credentialId.size and 0xFF).toByte()
        )
        return rpIdHash + flags + signCount + aaguid + credIdLength + credentialId + publicKeyCose
    }

    private fun buildTestAttestationObject(authData: ByteArray): ByteArray {
        val buffer = java.io.ByteArrayOutputStream()
        buffer.write(0xA3)
        buffer.write(0x63)
        buffer.write("fmt".toByteArray())
        buffer.write(0x64)
        buffer.write("none".toByteArray())
        buffer.write(0x67)
        buffer.write("attStmt".toByteArray())
        buffer.write(0xA0)
        buffer.write(0x68)
        buffer.write("authData".toByteArray())
        if (authData.size <= 23) {
            buffer.write(0x40 or authData.size)
        } else if (authData.size <= 255) {
            buffer.write(0x58)
            buffer.write(authData.size)
        } else {
            buffer.write(0x59)
            buffer.write(authData.size shr 8)
            buffer.write(authData.size and 0xFF)
        }
        buffer.write(authData)
        return buffer.toByteArray()
    }
}
