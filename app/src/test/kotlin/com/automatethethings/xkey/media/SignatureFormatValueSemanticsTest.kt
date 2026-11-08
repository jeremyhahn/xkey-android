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
package com.automatethethings.xkey.media

import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * Unit tests for the full round trip and the strict half of the parsers in
 * [SignatureEntry] / [ContentAuthenticityData].
 *
 * `SignatureFormatTest` covers the wire field names and the lenient defaults.
 * This suite covers:
 *
 *  - a multi-signer manifest surviving JSON with its order, roles and an absent
 *    signer name intact;
 *  - the *required* fields, i.e. the malformed-input branches that must throw
 *    rather than silently produce a manifest with an empty hash or signature —
 *    a signature over a blank content hash would verify against anything;
 *  - non-default `version` / `hashAlgorithm` values, so a future manifest
 *    revision is preserved verbatim rather than being rewritten to v1/SHA-256.
 */
class SignatureFormatValueSemanticsTest {

    private fun entry(
        keyFingerprint: String = "SHA256:abc123",
        signerName: String? = "Alice",
        algorithm: String = "ES256",
        value: String = "MEUCIQD",
        timestamp: String = "2026-01-15T10:30:00Z",
        role: SignerRole = SignerRole.CREATOR
    ) = SignatureEntry(keyFingerprint, signerName, algorithm, value, timestamp, role)

    private fun data(
        version: Int = 1,
        contentHash: String = "e".repeat(64),
        hashAlgorithm: String = "SHA-256",
        signatures: List<SignatureEntry> = listOf(entry())
    ) = ContentAuthenticityData(version, contentHash, hashAlgorithm, signatures)

    // -------------------------------------------------------------------------
    // Non-default manifest revisions
    // -------------------------------------------------------------------------

    @Test
    fun `a non-default version and hash algorithm survive a round trip`() {
        val future = data(version = 7, hashAlgorithm = "SHA-512", contentHash = "0".repeat(128))

        val restored = ContentAuthenticityData.fromJsonString(future.toJsonString())

        assertEquals(7, restored.version)
        assertEquals("SHA-512", restored.hashAlgorithm)
        assertEquals("0".repeat(128), restored.contentHash)
    }

    @Test
    fun `a manifest with three roles preserves order and roles through JSON`() {
        val manifest = data(
            signatures = listOf(
                entry(role = SignerRole.CREATOR, signerName = "Alice"),
                entry(role = SignerRole.WITNESS, signerName = "Bob"),
                entry(role = SignerRole.ATTESTOR, signerName = null)
            )
        )

        val restored = ContentAuthenticityData.fromJsonString(manifest.toJsonString())

        assertEquals(manifest, restored)
        assertNull(restored.signatures[2].signerName)
    }

    // -------------------------------------------------------------------------
    // Required fields: malformed input must fail loudly
    // -------------------------------------------------------------------------

    @Test
    fun `SignatureEntry fromJson rejects a missing keyFingerprint`() {
        val json = JSONObject()
            .put("algorithm", "ES256")
            .put("value", "sig")
            .put("timestamp", "2026-01-01T00:00:00Z")

        assertThrows(JSONException::class.java) { SignatureEntry.fromJson(json) }
    }

    @Test
    fun `SignatureEntry fromJson rejects a missing algorithm`() {
        val json = JSONObject()
            .put("keyFingerprint", "fp")
            .put("value", "sig")
            .put("timestamp", "2026-01-01T00:00:00Z")

        assertThrows(JSONException::class.java) { SignatureEntry.fromJson(json) }
    }

    @Test
    fun `SignatureEntry fromJson rejects a missing signature value`() {
        val json = JSONObject()
            .put("keyFingerprint", "fp")
            .put("algorithm", "ES256")
            .put("timestamp", "2026-01-01T00:00:00Z")

        assertThrows(JSONException::class.java) { SignatureEntry.fromJson(json) }
    }

    @Test
    fun `SignatureEntry fromJson rejects a missing timestamp`() {
        val json = JSONObject()
            .put("keyFingerprint", "fp")
            .put("algorithm", "ES256")
            .put("value", "sig")

        assertThrows(JSONException::class.java) { SignatureEntry.fromJson(json) }
    }

    @Test
    fun `SignatureEntry fromJson treats an explicit JSON null signerName as absent`() {
        val json = JSONObject()
            .put("keyFingerprint", "fp")
            .put("signerName", JSONObject.NULL)
            .put("algorithm", "ES256")
            .put("value", "sig")
            .put("timestamp", "2026-01-01T00:00:00Z")

        assertNull(SignatureEntry.fromJson(json).signerName)
    }

    @Test
    fun `ContentAuthenticityData fromJson rejects a missing signatures array`() {
        val json = JSONObject().put("contentHash", "abc")

        assertThrows(JSONException::class.java) { ContentAuthenticityData.fromJson(json) }
    }

    @Test
    fun `ContentAuthenticityData fromJson rejects a missing content hash`() {
        val json = JSONObject().put("signatures", JSONArray())

        assertThrows(JSONException::class.java) { ContentAuthenticityData.fromJson(json) }
    }

    @Test
    fun `ContentAuthenticityData fromJson rejects a malformed entry inside the array`() {
        val json = JSONObject()
            .put("contentHash", "abc")
            .put("signatures", JSONArray().put(JSONObject().put("keyFingerprint", "fp")))

        assertThrows(JSONException::class.java) { ContentAuthenticityData.fromJson(json) }
    }
}
