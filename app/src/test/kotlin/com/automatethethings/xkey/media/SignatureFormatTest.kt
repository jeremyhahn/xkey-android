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
package com.automatethethings.xkey.media

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Unit tests for [SignatureEntry], [ContentAuthenticityData], and [SignerRole]
 * serialization and deserialization.
 */
class SignatureFormatTest {

    private fun createSampleEntry(
        role: SignerRole = SignerRole.CREATOR,
        signerName: String? = "Alice"
    ): SignatureEntry = SignatureEntry(
        keyFingerprint = "SHA256:abc123def456",
        signerName = signerName,
        algorithm = "ES256",
        value = "MEUCIQD...base64sig...",
        timestamp = "2025-01-15T10:30:00Z",
        role = role
    )

    private fun createSampleData(
        signatures: List<SignatureEntry> = listOf(createSampleEntry())
    ): ContentAuthenticityData = ContentAuthenticityData(
        contentHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        signatures = signatures
    )

    // -------------------------------------------------------------------------
    // SignatureEntry tests
    // -------------------------------------------------------------------------

    @Test
    fun `SignatureEntry toJson produces valid JSON with all fields`() {
        val entry = createSampleEntry()
        val json = entry.toJson()

        assertEquals("SHA256:abc123def456", json.getString("keyFingerprint"))
        assertEquals("Alice", json.getString("signerName"))
        assertEquals("ES256", json.getString("algorithm"))
        assertEquals("MEUCIQD...base64sig...", json.getString("value"))
        assertEquals("2025-01-15T10:30:00Z", json.getString("timestamp"))
        assertEquals("CREATOR", json.getString("role"))
    }

    @Test
    fun `SignatureEntry fromJson handles missing signerName`() {
        val json = JSONObject().apply {
            put("keyFingerprint", "SHA256:test")
            put("algorithm", "ES256")
            put("value", "sig")
            put("timestamp", "2025-01-01T00:00:00Z")
        }
        val entry = SignatureEntry.fromJson(json)

        assertNull(entry.signerName)
    }

    @Test
    fun `SignatureEntry fromJson defaults role to CREATOR`() {
        val json = JSONObject().apply {
            put("keyFingerprint", "SHA256:test")
            put("algorithm", "ES256")
            put("value", "sig")
            put("timestamp", "2025-01-01T00:00:00Z")
        }
        val entry = SignatureEntry.fromJson(json)

        assertEquals(SignerRole.CREATOR, entry.role)
    }

    @Test
    fun `SignatureEntry fromJson handles invalid role gracefully`() {
        val json = JSONObject().apply {
            put("keyFingerprint", "SHA256:test")
            put("algorithm", "ES256")
            put("value", "sig")
            put("timestamp", "2025-01-01T00:00:00Z")
            put("role", "INVALID_ROLE")
        }
        val entry = SignatureEntry.fromJson(json)

        assertEquals(SignerRole.CREATOR, entry.role)
    }

    // -------------------------------------------------------------------------
    // ContentAuthenticityData tests
    // -------------------------------------------------------------------------

    @Test
    fun `ContentAuthenticityData toJson produces valid JSON`() {
        val data = createSampleData()
        val json = data.toJson()

        assertEquals(1, json.getInt("version"))
        assertEquals(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            json.getString("contentHash")
        )
        assertEquals("SHA-256", json.getString("hashAlgorithm"))
        assertEquals(1, json.getJSONArray("signatures").length())
    }

    @Test
    fun `ContentAuthenticityData fromJson defaults missing version to 1`() {
        val json = JSONObject().apply {
            put("contentHash", "abc123")
            put("signatures", org.json.JSONArray())
        }
        val data = ContentAuthenticityData.fromJson(json)

        assertEquals(1, data.version)
    }
}
