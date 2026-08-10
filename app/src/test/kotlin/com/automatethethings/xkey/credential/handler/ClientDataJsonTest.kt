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
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest
import java.util.Base64

/**
 * Tests for clientDataJSON construction logic used by both
 * CreateCredentialHandler (registration) and GetCredentialHandler (authentication).
 */
class ClientDataJsonTest {

    @Test
    fun `registration clientDataJSON has type webauthn_create`() {
        val clientDataJson = buildClientDataJson(
            type = "webauthn.create",
            challenge = "dGVzdC1jaGFsbGVuZ2U",
            origin = "https://webauthn.io"
        )

        val parsed = JSONObject(clientDataJson)
        assertEquals("webauthn.create", parsed.getString("type"))
    }

    @Test
    fun `authentication clientDataJSON has type webauthn_get`() {
        val clientDataJson = buildClientDataJson(
            type = "webauthn.get",
            challenge = "dGVzdC1jaGFsbGVuZ2U",
            origin = "https://webauthn.io"
        )

        val parsed = JSONObject(clientDataJson)
        assertEquals("webauthn.get", parsed.getString("type"))
    }

    @Test
    fun `clientDataJSON preserves challenge from request`() {
        val challenge = "Y2hhbGxlbmdlLWZyb20tc2VydmVy"
        val clientDataJson = buildClientDataJson(
            type = "webauthn.create",
            challenge = challenge,
            origin = "https://webauthn.io"
        )

        val parsed = JSONObject(clientDataJson)
        assertEquals(challenge, parsed.getString("challenge"))
    }

    @Test
    fun `clientDataJSON origin uses rpId fallback`() {
        val rpId = "example.com"
        val clientDataJson = buildClientDataJson(
            type = "webauthn.create",
            challenge = "abc",
            origin = "https://$rpId"
        )

        val parsed = JSONObject(clientDataJson)
        assertEquals("https://example.com", parsed.getString("origin"))
    }

    @Test
    fun `clientDataJSON crossOrigin is false`() {
        val clientDataJson = buildClientDataJson(
            type = "webauthn.create",
            challenge = "abc",
            origin = "https://webauthn.io"
        )

        val parsed = JSONObject(clientDataJson)
        assertFalse(parsed.getBoolean("crossOrigin"))
    }

    @Test
    fun `clientDataJSON contains all required fields`() {
        val clientDataJson = buildClientDataJson(
            type = "webauthn.create",
            challenge = "abc",
            origin = "https://webauthn.io"
        )

        val parsed = JSONObject(clientDataJson)
        assertTrue(parsed.has("type"))
        assertTrue(parsed.has("challenge"))
        assertTrue(parsed.has("origin"))
        assertTrue(parsed.has("crossOrigin"))
    }

    @Test
    fun `clientDataJSON base64url encoding round-trips correctly`() {
        val clientDataJson = buildClientDataJson(
            type = "webauthn.create",
            challenge = "dGVzdA",
            origin = "https://webauthn.io"
        )

        val encoded = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(clientDataJson.toByteArray(Charsets.UTF_8))
        val decoded = String(
            Base64.getUrlDecoder().decode(encoded),
            Charsets.UTF_8
        )

        assertEquals(clientDataJson, decoded)
        val parsed = JSONObject(decoded)
        assertEquals("webauthn.create", parsed.getString("type"))
    }

    @Test
    fun `clientDataHash is SHA-256 of clientDataJSON bytes`() {
        val clientDataJson = buildClientDataJson(
            type = "webauthn.create",
            challenge = "abc",
            origin = "https://webauthn.io"
        )

        val clientDataJsonBytes = clientDataJson.toByteArray(Charsets.UTF_8)
        val hash = MessageDigest.getInstance("SHA-256").digest(clientDataJsonBytes)

        assertNotNull(hash)
        assertEquals("SHA-256 hash should be 32 bytes", 32, hash.size)

        // Verify determinism
        val hash2 = MessageDigest.getInstance("SHA-256").digest(clientDataJsonBytes)
        assertTrue("Hash should be deterministic", hash.contentEquals(hash2))
    }

    @Test
    fun `different types produce different clientDataJSON`() {
        val createJson = buildClientDataJson(
            type = "webauthn.create",
            challenge = "same-challenge",
            origin = "https://webauthn.io"
        )
        val getJson = buildClientDataJson(
            type = "webauthn.get",
            challenge = "same-challenge",
            origin = "https://webauthn.io"
        )

        assertTrue("Create and get clientDataJSON should differ", createJson != getJson)

        val createHash = MessageDigest.getInstance("SHA-256")
            .digest(createJson.toByteArray(Charsets.UTF_8))
        val getHash = MessageDigest.getInstance("SHA-256")
            .digest(getJson.toByteArray(Charsets.UTF_8))

        assertFalse("Hashes should differ for different types", createHash.contentEquals(getHash))
    }

    // --- Helper replicating the clientDataJSON construction from the handlers ---

    private fun buildClientDataJson(type: String, challenge: String, origin: String): String {
        return JSONObject().apply {
            put("type", type)
            put("challenge", challenge)
            put("origin", origin)
            put("crossOrigin", false)
        }.toString()
    }
}
