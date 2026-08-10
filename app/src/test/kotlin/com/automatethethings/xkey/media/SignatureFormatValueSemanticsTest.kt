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
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for the value semantics and the strict half of the parsers in
 * [SignatureEntry] / [ContentAuthenticityData].
 *
 * `SignatureFormatTest` covers the happy-path round trip. This suite covers what
 * that one leaves untouched:
 *
 *  - the generated `equals`/`hashCode`/`copy`/`componentN`/`toString` members,
 *    which matter because signature entries are compared and copied whenever a
 *    co-signer is appended to an existing manifest;
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
    // SignatureEntry value semantics
    // -------------------------------------------------------------------------

    @Test
    fun `two entries with the same fields are equal and hash alike`() {
        val a = entry()
        val b = entry()

        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
        assertEquals(a, a)
    }

    @Test
    fun `entries differing in any single field are not equal`() {
        val base = entry()

        assertNotEquals(base, entry(keyFingerprint = "SHA256:other"))
        assertNotEquals(base, entry(signerName = "Bob"))
        assertNotEquals(base, entry(signerName = null))
        assertNotEquals(base, entry(algorithm = "ES384"))
        assertNotEquals(base, entry(value = "MEUCIQE"))
        assertNotEquals(base, entry(timestamp = "2026-01-15T10:30:01Z"))
        assertNotEquals(base, entry(role = SignerRole.WITNESS))
    }

    @Test
    fun `an entry is never equal to an unrelated value`() {
        assertFalse(entry().equals("SHA256:abc123"))
        assertFalse(entry().equals(null))
    }

    @Test
    fun `copy replaces only the named field`() {
        val creator = entry()

        val witness = creator.copy(role = SignerRole.WITNESS, signerName = "Bob")

        assertEquals(SignerRole.WITNESS, witness.role)
        assertEquals("Bob", witness.signerName)
        assertEquals(creator.keyFingerprint, witness.keyFingerprint)
        assertEquals(creator.algorithm, witness.algorithm)
        assertEquals(creator.value, witness.value)
        assertEquals(creator.timestamp, witness.timestamp)
        assertEquals("the original is untouched", SignerRole.CREATOR, creator.role)
    }

    @Test
    fun `an entry destructures in declaration order`() {
        val (fingerprint, signerName, algorithm, value, timestamp, role) =
            entry(role = SignerRole.ATTESTOR)

        assertEquals("SHA256:abc123", fingerprint)
        assertEquals("Alice", signerName)
        assertEquals("ES256", algorithm)
        assertEquals("MEUCIQD", value)
        assertEquals("2026-01-15T10:30:00Z", timestamp)
        assertEquals(SignerRole.ATTESTOR, role)
    }

    @Test
    fun `an entry renders its fields in toString`() {
        val text = entry().toString()

        assertTrue(text, text.contains("SHA256:abc123"))
        assertTrue(text, text.contains("Alice"))
        assertTrue(text, text.contains("CREATOR"))
    }

    // -------------------------------------------------------------------------
    // ContentAuthenticityData value semantics
    // -------------------------------------------------------------------------

    @Test
    fun `two manifests with the same fields are equal and hash alike`() {
        assertEquals(data(), data())
        assertEquals(data().hashCode(), data().hashCode())
    }

    @Test
    fun `manifests differing in any single field are not equal`() {
        val base = data()

        assertNotEquals(base, data(version = 2))
        assertNotEquals(base, data(contentHash = "f".repeat(64)))
        assertNotEquals(base, data(hashAlgorithm = "SHA-512"))
        assertNotEquals(base, data(signatures = emptyList()))
        assertNotEquals(base, data(signatures = listOf(entry(), entry(signerName = "Bob"))))
    }

    @Test
    fun `copy appends a co-signer without disturbing the hash`() {
        val original = data()

        val cosigned = original.copy(
            signatures = original.signatures + entry(signerName = "Bob", role = SignerRole.WITNESS)
        )

        assertEquals(original.contentHash, cosigned.contentHash)
        assertEquals(original.version, cosigned.version)
        assertEquals(2, cosigned.signatures.size)
        assertEquals("the original list is not mutated", 1, original.signatures.size)
    }

    @Test
    fun `a manifest destructures in declaration order`() {
        val (version, contentHash, hashAlgorithm, signatures) =
            data(version = 3, hashAlgorithm = "SHA-512")

        assertEquals(3, version)
        assertEquals("e".repeat(64), contentHash)
        assertEquals("SHA-512", hashAlgorithm)
        assertEquals(1, signatures.size)
    }

    @Test
    fun `a manifest renders its fields in toString`() {
        val text = data().toString()

        assertTrue(text, text.contains("e".repeat(64)))
        assertTrue(text, text.contains("SHA-256"))
    }

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
    fun `fromJson keeps an explicit non-default hash algorithm`() {
        val json = JSONObject()
            .put("contentHash", "abc")
            .put("hashAlgorithm", "BLAKE2b-256")
            .put("signatures", JSONArray())

        assertEquals("BLAKE2b-256", ContentAuthenticityData.fromJson(json).hashAlgorithm)
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

    @Test
    fun `fromJsonString rejects text that is not JSON`() {
        assertThrows(JSONException::class.java) {
            ContentAuthenticityData.fromJsonString("XKEY_SIG:not-actually-json")
        }
    }

    @Test
    fun `toJsonString emits a parseable document`() {
        val text = data().toJsonString()

        // The manifest is embedded in an EXIF UserComment, so it has to be a
        // single self-contained JSON document with no stray framing.
        assertTrue(text, text.startsWith("{") && text.endsWith("}"))
        assertEquals(1, JSONObject(text).getJSONArray("signatures").length())
    }
}
