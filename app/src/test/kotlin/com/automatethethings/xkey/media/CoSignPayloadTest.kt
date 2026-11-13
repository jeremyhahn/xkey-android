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
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset

/**
 * Unit tests for the co-sign QR payloads: the owner's request, the witness's
 * response, the ATTESTOR entry built from a response and the duplicate-signer
 * refusal.
 */
class CoSignPayloadTest {

    private val sha256Hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    private val ownerFp = "a1b2c3d4e5f6"
    private val witnessFp = "f5e6d7c8b9a0"
    private val sigB64 = "MEUCIQDxAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGw=="

    private val fixedClock: Clock = Clock.fixed(Instant.parse("2026-11-13T08:15:30Z"), ZoneOffset.UTC)

    private fun requestJson(
        v: Any? = 1,
        hash: String? = sha256Hash,
        alg: String? = "SHA-256",
        from: String? = ownerFp
    ): String = JSONObject().apply {
        v?.let { put("v", it) }
        hash?.let { put("hash", it) }
        alg?.let { put("alg", it) }
        from?.let { put("from", it) }
    }.toString()

    private fun responseJson(
        v: Any? = 1,
        sig: String? = sigB64,
        fp: String? = witnessFp,
        name: String? = "Bob",
        alg: String? = "ES256"
    ): String = JSONObject().apply {
        v?.let { put("v", it) }
        sig?.let { put("sig", it) }
        fp?.let { put("fp", it) }
        name?.let { put("name", it) }
        alg?.let { put("alg", it) }
    }.toString()

    private fun <T> ok(result: CoSignParseResult<T>): T = when (result) {
        is CoSignParseResult.Ok -> result.value
        is CoSignParseResult.Failed -> { fail("expected Ok, got ${result.error}"); throw AssertionError() }
    }

    private fun <T> error(result: CoSignParseResult<T>): CoSignPayloadError = when (result) {
        is CoSignParseResult.Ok -> { fail("expected an error, got ${result.value}"); throw AssertionError() }
        is CoSignParseResult.Failed -> result.error
    }

    private fun ownerData(): ContentAuthenticityData = ContentAuthenticityData(
        contentHash = sha256Hash,
        signatures = listOf(
            SignatureEntry(
                keyFingerprint = ownerFp,
                signerName = "Alice",
                algorithm = "ES256",
                value = "b3duZXI=",
                timestamp = "2026-11-12T10:00:00Z",
                role = SignerRole.CREATOR
            )
        )
    )

    // --- request ---

    @Test
    fun `valid request round-trips`() {
        val request = ok(CoSignPayload.parseRequest(requestJson()))
        assertEquals(CoSignRequest(sha256Hash, "SHA-256", ownerFp), request)
        assertEquals(request, ok(CoSignPayload.parseRequest(request.toJsonString())))
        val json = JSONObject(request.toJsonString())
        assertEquals(1, json.getInt("v"))
        assertEquals(sha256Hash, json.getString("hash"))
        assertEquals("SHA-256", json.getString("alg"))
        assertEquals(ownerFp, json.getString("from"))
    }

    @Test
    fun `request accepts SHA-384 and SHA-512 hashes of their digest length`() {
        ok(CoSignPayload.parseRequest(requestJson(hash = "ab".repeat(48), alg = "SHA-384")))
        ok(CoSignPayload.parseRequest(requestJson(hash = "cd".repeat(64), alg = "SHA-512")))
    }

    @Test
    fun `request with an unknown version is refused`() {
        assertEquals(CoSignPayloadError.UnsupportedVersion(2), error(CoSignPayload.parseRequest(requestJson(v = 2))))
    }

    @Test
    fun `request missing each field gives MissingField for that field`() {
        assertEquals(CoSignPayloadError.MissingField("v"), error(CoSignPayload.parseRequest(requestJson(v = null))))
        assertEquals(CoSignPayloadError.MissingField("hash"), error(CoSignPayload.parseRequest(requestJson(hash = null))))
        assertEquals(CoSignPayloadError.MissingField("alg"), error(CoSignPayload.parseRequest(requestJson(alg = null))))
        assertEquals(CoSignPayloadError.MissingField("from"), error(CoSignPayload.parseRequest(requestJson(from = null))))
        assertEquals(CoSignPayloadError.MissingField("from"), error(CoSignPayload.parseRequest(requestJson(from = ""))))
    }

    @Test
    fun `request hash that is not lowercase hex of the digest length is refused`() {
        val bad = listOf(
            sha256Hash.uppercase(),
            sha256Hash.dropLast(2),
            sha256Hash + "00",
            sha256Hash.dropLast(1) + "g",
            "ab".repeat(48) // SHA-384 length under SHA-256
        )
        bad.forEach { hash ->
            assertEquals(hash, CoSignPayloadError.InvalidHash, error(CoSignPayload.parseRequest(requestJson(hash = hash))))
        }
    }

    @Test
    fun `request with an unsupported hash algorithm is refused`() {
        assertEquals(
            CoSignPayloadError.UnsupportedHashAlgorithm("MD5"),
            error(CoSignPayload.parseRequest(requestJson(hash = "ab".repeat(16), alg = "MD5")))
        )
    }

    @Test
    fun `a payload that is not a JSON object is refused`() {
        assertEquals(CoSignPayloadError.NotJson, error(CoSignPayload.parseRequest("otpauth://totp/x?secret=ABC")))
        assertEquals(CoSignPayloadError.NotJson, error(CoSignPayload.parseResponse("[1,2]")))
    }

    @Test
    fun `a version that is not a number is refused as unsupported`() {
        assertEquals(CoSignPayloadError.UnsupportedVersion(null), error(CoSignPayload.parseRequest(requestJson(v = "one"))))
    }

    @Test
    fun `request built from signature data carries its hash and algorithm`() {
        val request = CoSignRequest.of(ownerData(), ownerFp)
        assertEquals(CoSignRequest(sha256Hash, "SHA-256", ownerFp), request)
    }

    @Test
    fun `request hash bytes decode the hex digest`() {
        val bytes = CoSignRequest("00ff10".padEnd(64, '0'), "SHA-256", ownerFp).hashBytes()
        assertEquals(32, bytes.size)
        assertEquals(0x00.toByte(), bytes[0])
        assertEquals(0xff.toByte(), bytes[1])
        assertEquals(0x10.toByte(), bytes[2])
    }

    // --- response ---

    @Test
    fun `valid response round-trips`() {
        val response = ok(CoSignPayload.parseResponse(responseJson()))
        assertEquals(CoSignResponse(sigB64, witnessFp, "Bob", "ES256"), response)
        assertEquals(response, ok(CoSignPayload.parseResponse(response.toJsonString())))
        val json = JSONObject(response.toJsonString())
        assertEquals(1, json.getInt("v"))
        assertEquals(sigB64, json.getString("sig"))
        assertEquals(witnessFp, json.getString("fp"))
        assertEquals("Bob", json.getString("name"))
        assertEquals("ES256", json.getString("alg"))
    }

    @Test
    fun `response with an unknown version is refused`() {
        assertEquals(CoSignPayloadError.UnsupportedVersion(0), error(CoSignPayload.parseResponse(responseJson(v = 0))))
    }

    @Test
    fun `response missing each field gives MissingField for that field`() {
        assertEquals(CoSignPayloadError.MissingField("v"), error(CoSignPayload.parseResponse(responseJson(v = null))))
        assertEquals(CoSignPayloadError.MissingField("sig"), error(CoSignPayload.parseResponse(responseJson(sig = null))))
        assertEquals(CoSignPayloadError.MissingField("fp"), error(CoSignPayload.parseResponse(responseJson(fp = null))))
        assertEquals(CoSignPayloadError.MissingField("name"), error(CoSignPayload.parseResponse(responseJson(name = null))))
        assertEquals(CoSignPayloadError.MissingField("alg"), error(CoSignPayload.parseResponse(responseJson(alg = null))))
    }

    @Test
    fun `response with a non-base64 signature is refused`() {
        assertEquals(CoSignPayloadError.InvalidSignature, error(CoSignPayload.parseResponse(responseJson(sig = "not base64!!"))))
        assertEquals(CoSignPayloadError.InvalidSignature, error(CoSignPayload.parseResponse(responseJson(sig = "QUJD="))))
    }

    @Test
    fun `each error kind is distinct`() {
        val errors = listOf(
            CoSignPayloadError.NotJson,
            CoSignPayloadError.UnsupportedVersion(2),
            CoSignPayloadError.MissingField("hash"),
            CoSignPayloadError.UnsupportedHashAlgorithm("MD5"),
            CoSignPayloadError.InvalidHash,
            CoSignPayloadError.InvalidSignature
        )
        assertEquals(errors.size, errors.map { it::class }.toSet().size)
    }

    // --- ATTESTOR entry ---

    @Test
    fun `response becomes an ATTESTOR entry timestamped by the clock`() {
        val response = ok(CoSignPayload.parseResponse(responseJson()))
        val entry = response.toAttestorEntry(fixedClock)
        assertEquals(SignerRole.ATTESTOR, entry.role)
        assertEquals(witnessFp, entry.keyFingerprint)
        assertEquals("Bob", entry.signerName)
        assertEquals("ES256", entry.algorithm)
        assertEquals(sigB64, entry.value)
        assertEquals("2026-11-13T08:15:30Z", entry.timestamp)
        assertEquals(Instant.parse("2026-11-13T08:15:30Z"), Instant.parse(entry.timestamp))
    }

    @Test
    fun `appending a new signer adds the entry`() {
        val data = ownerData()
        val entry = CoSignResponse(sigB64, witnessFp, "Bob", "ES256").toAttestorEntry(fixedClock)
        val result = CoSignPayload.appendAttestor(data, entry)
        assertTrue(result is CoSignAppendResult.Appended)
        val updated = (result as CoSignAppendResult.Appended).data
        assertEquals(data.signatures + entry, updated.signatures)
        assertEquals(data.contentHash, updated.contentHash)
    }

    @Test
    fun `a response whose fp is already a signer is refused and the data is unchanged`() {
        val data = ownerData()
        val before = data.toJsonString()
        val entry = CoSignResponse(sigB64, ownerFp, "Alice", "ES256").toAttestorEntry(fixedClock)
        val result = CoSignPayload.appendAttestor(data, entry)
        assertEquals(CoSignAppendResult.DuplicateSigner(ownerFp), result)
        assertEquals(before, data.toJsonString())
        assertEquals(1, data.signatures.size)
    }

    @Test
    fun `duplicate signer check ignores fingerprint case`() {
        val data = ownerData()
        val entry = CoSignResponse(sigB64, ownerFp.uppercase(), "Alice", "ES256").toAttestorEntry(fixedClock)
        assertTrue(CoSignPayload.appendAttestor(data, entry) is CoSignAppendResult.DuplicateSigner)
    }

    @Test
    fun `a second witness after the first is appended`() {
        val first = CoSignResponse(sigB64, witnessFp, "Bob", "ES256").toAttestorEntry(fixedClock)
        val once = (CoSignPayload.appendAttestor(ownerData(), first) as CoSignAppendResult.Appended).data
        val second = CoSignResponse(sigB64, "0011223344", "Carol", "ES256").toAttestorEntry(fixedClock)
        val twice = CoSignPayload.appendAttestor(once, second)
        assertTrue(twice is CoSignAppendResult.Appended)
        assertEquals(3, (twice as CoSignAppendResult.Appended).data.signatures.size)
        assertNotEquals(once, twice.data)
    }
}
