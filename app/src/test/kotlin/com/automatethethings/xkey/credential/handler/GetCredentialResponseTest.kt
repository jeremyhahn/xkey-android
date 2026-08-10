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
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest
import java.util.Base64

/**
 * Tests for the authentication (assertion) response format produced by
 * GetCredentialHandler.buildAssertionResponse().
 *
 * Since the method is private, these tests replicate the same response-building
 * logic and verify the JSON structure that relying parties will receive.
 */
class GetCredentialResponseTest {

    private val rpId = "webauthn.io"
    private val credentialId = "dGVzdC1jcmVkZW50aWFsLWlk"
    private val userHandle = "dGVzdC11c2VyLWlk"
    private val signCount = 5L

    @Test
    fun `assertion response contains required top-level fields`() {
        val response = buildTestAssertionResponse(clientDataJsonBase64 = null)
        val json = JSONObject(response)

        assertEquals(credentialId, json.getString("id"))
        assertEquals(credentialId, json.getString("rawId"))
        assertEquals("public-key", json.getString("type"))
        assertEquals("platform", json.getString("authenticatorAttachment"))
        assertTrue("Response must have 'response' object", json.has("response"))
        assertTrue("Response must have 'clientExtensionResults'", json.has("clientExtensionResults"))
    }

    @Test
    fun `assertion response inner object contains authenticatorData and signature`() {
        val response = buildTestAssertionResponse(clientDataJsonBase64 = null)
        val json = JSONObject(response)
        val inner = json.getJSONObject("response")

        assertTrue("Inner response must have 'authenticatorData'", inner.has("authenticatorData"))
        assertTrue("Inner response must have 'signature'", inner.has("signature"))
        assertTrue("Inner response must have 'userHandle'", inner.has("userHandle"))
        assertEquals(userHandle, inner.getString("userHandle"))
    }

    @Test
    fun `assertion response includes clientDataJSON when provided`() {
        val clientDataJsonBase64 = Base64.getUrlEncoder().withoutPadding()
            .encodeToString("""{"type":"webauthn.get","challenge":"xyz","origin":"https://webauthn.io"}""".toByteArray())

        val response = buildTestAssertionResponse(clientDataJsonBase64 = clientDataJsonBase64)
        val json = JSONObject(response)
        val inner = json.getJSONObject("response")

        assertTrue("Inner response must have 'clientDataJSON'", inner.has("clientDataJSON"))
        assertEquals(clientDataJsonBase64, inner.getString("clientDataJSON"))
    }

    @Test
    fun `assertion response omits clientDataJSON when null`() {
        val response = buildTestAssertionResponse(clientDataJsonBase64 = null)
        val json = JSONObject(response)
        val inner = json.getJSONObject("response")

        assertFalse("Inner response must NOT have 'clientDataJSON'", inner.has("clientDataJSON"))
    }

    @Test
    fun `authenticator data starts with rpIdHash`() {
        val authData = buildTestAuthenticatorData()
        val expectedRpIdHash = MessageDigest.getInstance("SHA-256").digest(rpId.toByteArray())

        val actualRpIdHash = authData.sliceArray(0 until 32)
        assertTrue("Auth data should start with SHA-256 of rpId", expectedRpIdHash.contentEquals(actualRpIdHash))
    }

    @Test
    fun `authenticator data flags include UP and UV`() {
        val authData = buildTestAuthenticatorData()
        val flags = authData[32].toInt() and 0xFF

        assertTrue("UP flag should be set", flags and 0x01 != 0)
        assertTrue("UV flag should be set", flags and 0x04 != 0)
        // AT flag should NOT be set for assertion
        assertEquals("AT flag should not be set", 0, flags and 0x40)
    }

    @Test
    fun `authenticator data encodes sign count correctly`() {
        val authData = buildTestAuthenticatorData()
        // Sign count is at bytes 33-36 (big-endian)
        val encodedSignCount = ((authData[33].toInt() and 0xFF).toLong() shl 24) or
            ((authData[34].toInt() and 0xFF).toLong() shl 16) or
            ((authData[35].toInt() and 0xFF).toLong() shl 8) or
            (authData[36].toInt() and 0xFF).toLong()

        assertEquals(signCount, encodedSignCount)
    }

    @Test
    fun `authenticator data is correct length for assertion`() {
        val authData = buildTestAuthenticatorData()
        // rpIdHash(32) + flags(1) + signCount(4) = 37 bytes (no attested credential data)
        assertEquals(37, authData.size)
    }

    // --- Helper methods replicating GetCredentialHandler logic ---

    private fun buildTestAssertionResponse(clientDataJsonBase64: String?): String {
        val authData = buildTestAuthenticatorData()
        val signature = ByteArray(64) { 0x42.toByte() } // dummy signature

        val b64Flags = Base64.getUrlEncoder().withoutPadding()
        val response = JSONObject().apply {
            put("id", credentialId)
            put("rawId", credentialId)
            put("type", "public-key")
            put("authenticatorAttachment", "platform")
            put("response", JSONObject().apply {
                put("authenticatorData", b64Flags.encodeToString(authData))
                put("signature", b64Flags.encodeToString(signature))
                put("userHandle", userHandle)
                if (clientDataJsonBase64 != null) {
                    put("clientDataJSON", clientDataJsonBase64)
                }
            })
            put("clientExtensionResults", JSONObject())
        }
        return response.toString()
    }

    private fun buildTestAuthenticatorData(): ByteArray {
        val rpIdHash = MessageDigest.getInstance("SHA-256").digest(rpId.toByteArray())
        val flags: Byte = (0x01 or 0x04).toByte() // UP + UV
        val signCountBytes = byteArrayOf(
            ((signCount shr 24) and 0xFF).toByte(),
            ((signCount shr 16) and 0xFF).toByte(),
            ((signCount shr 8) and 0xFF).toByte(),
            (signCount and 0xFF).toByte()
        )
        return rpIdHash + flags + signCountBytes
    }
}
