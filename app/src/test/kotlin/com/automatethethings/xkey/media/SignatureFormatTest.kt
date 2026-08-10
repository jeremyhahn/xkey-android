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
import org.junit.Assert.assertTrue
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
    fun `SignatureEntry toJson omits null signerName`() {
        val entry = createSampleEntry(signerName = null)
        val json = entry.toJson()

        assertTrue(!json.has("signerName") || json.isNull("signerName"))
    }

    @Test
    fun `SignatureEntry fromJson round-trips correctly`() {
        val original = createSampleEntry()
        val json = original.toJson()
        val restored = SignatureEntry.fromJson(json)

        assertEquals(original.keyFingerprint, restored.keyFingerprint)
        assertEquals(original.signerName, restored.signerName)
        assertEquals(original.algorithm, restored.algorithm)
        assertEquals(original.value, restored.value)
        assertEquals(original.timestamp, restored.timestamp)
        assertEquals(original.role, restored.role)
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
    // SignerRole tests
    // -------------------------------------------------------------------------

    @Test
    fun `all SignerRole values are serializable`() {
        val roles = SignerRole.values()

        assertEquals(3, roles.size)
        assertTrue(roles.contains(SignerRole.CREATOR))
        assertTrue(roles.contains(SignerRole.WITNESS))
        assertTrue(roles.contains(SignerRole.ATTESTOR))
    }

    @Test
    fun `SignerRole round-trips through SignatureEntry serialization`() {
        SignerRole.values().forEach { role ->
            val entry = createSampleEntry(role = role)
            val json = entry.toJson()
            val restored = SignatureEntry.fromJson(json)

            assertEquals(role, restored.role)
        }
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
    fun `ContentAuthenticityData fromJson round-trips correctly`() {
        val original = createSampleData()
        val jsonString = original.toJsonString()
        val restored = ContentAuthenticityData.fromJsonString(jsonString)

        assertEquals(original.version, restored.version)
        assertEquals(original.contentHash, restored.contentHash)
        assertEquals(original.hashAlgorithm, restored.hashAlgorithm)
        assertEquals(original.signatures.size, restored.signatures.size)
        assertEquals(original.signatures[0].keyFingerprint, restored.signatures[0].keyFingerprint)
        assertEquals(original.signatures[0].value, restored.signatures[0].value)
    }

    @Test
    fun `ContentAuthenticityData with multiple SignatureEntry items`() {
        val entries = listOf(
            createSampleEntry(role = SignerRole.CREATOR),
            createSampleEntry(role = SignerRole.WITNESS, signerName = "Bob"),
            createSampleEntry(role = SignerRole.ATTESTOR, signerName = "Charlie")
        )
        val data = createSampleData(signatures = entries)
        val jsonString = data.toJsonString()
        val restored = ContentAuthenticityData.fromJsonString(jsonString)

        assertEquals(3, restored.signatures.size)
        assertEquals(SignerRole.CREATOR, restored.signatures[0].role)
        assertEquals(SignerRole.WITNESS, restored.signatures[1].role)
        assertEquals(SignerRole.ATTESTOR, restored.signatures[2].role)
        assertEquals("Bob", restored.signatures[1].signerName)
        assertEquals("Charlie", restored.signatures[2].signerName)
    }

    @Test
    fun `ContentAuthenticityData empty signatures list`() {
        val data = createSampleData(signatures = emptyList())
        val jsonString = data.toJsonString()
        val restored = ContentAuthenticityData.fromJsonString(jsonString)

        assertEquals(0, restored.signatures.size)
    }

    @Test
    fun `ContentAuthenticityData version defaults to 1`() {
        val data = ContentAuthenticityData(
            contentHash = "deadbeef",
            signatures = emptyList()
        )

        assertEquals(1, data.version)

        val json = data.toJson()
        assertEquals(1, json.getInt("version"))
    }

    @Test
    fun `ContentAuthenticityData hashAlgorithm defaults to SHA-256`() {
        val data = ContentAuthenticityData(
            contentHash = "deadbeef",
            signatures = emptyList()
        )

        assertEquals("SHA-256", data.hashAlgorithm)

        val json = data.toJson()
        assertEquals("SHA-256", json.getString("hashAlgorithm"))
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
