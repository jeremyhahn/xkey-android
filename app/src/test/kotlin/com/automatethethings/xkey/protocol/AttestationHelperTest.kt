/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
 *
 * This file is part of xkey-android.
 *
 * xkey-android is dual-licensed:
 *
 * 1. GNU Affero General Public License v3.0 (AGPL-3.0)
 *    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
 *
 * 2. Commercial License
 *    Contact licensing@automatethethings.com for commercial licensing options.
 */
package com.automatethethings.xkey.protocol

import android.content.Context
import android.util.Base64
import android.util.Log
import com.automatethethings.xkey.ble.BleClient
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.slot
import io.mockk.unmockkAll
import kotlinx.coroutines.test.runTest
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.IOException
import java.security.MessageDigest

/**
 * Unit tests for [AttestationHelper] — the phone-as-verifier half of the
 * attestation exchange, where the phone challenges the paired desktop to prove
 * its identity (`remote.attestDevice`) rather than attesting itself.
 *
 * Counterpart: the `remote.attestDevice` responder in go-xkms
 * (`xkey/pkg/pairing`). Nothing about this exchange is compiler-checked across
 * the two implementations, so the tests pin the exact request envelope
 * (`jsonrpc`, `method`, `params.nonce`) and the exact result field names the
 * phone reads back (`nonce`, `format`, `securityLevel`, `bootHashHex`,
 * `bootStateVerified`, `certificateChain`).
 *
 * The freshness check is the security-relevant part: the desktop must echo the
 * 32-byte challenge nonce verbatim, and a response that does not is rejected
 * as a replay rather than accepted.
 *
 * [BleClient] is mocked so the exchange runs without a radio, and
 * `android.util.Base64`/`android.util.Log` — throwing stubs on the JVM — are
 * statically mocked and delegated to `java.util.Base64` the way
 * [IDevIDMessagesTest] does.
 */
class AttestationHelperTest {

    private lateinit var helper: AttestationHelper
    private lateinit var client: BleClient

    /** The request the helper put on the wire, captured per call. */
    private val sentRequests = mutableListOf<ByteArray>()

    @Before
    fun setUp() {
        sentRequests.clear()

        mockkStatic(Base64::class)
        every { Base64.encodeToString(any(), any()) } answers {
            java.util.Base64.getEncoder().encodeToString(firstArg())
        }
        every { Base64.decode(any<String>(), any()) } answers {
            java.util.Base64.getDecoder().decode(firstArg<String>())
        }

        mockkStatic(Log::class)
        every { Log.d(any(), any()) } returns 0
        every { Log.i(any(), any()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.e(any(), any<String>()) } returns 0
        every { Log.e(any(), any<String>(), any<Throwable>()) } returns 0

        client = mockk()
        helper = AttestationHelper(mockk<Context>(relaxed = true))
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    // -------------------------------------------------------------------------
    // Request envelope — what the desktop actually receives
    // -------------------------------------------------------------------------

    @Test
    fun `the request is a jsonrpc 2_0 remote_attestDevice call`() = runTest {
        respondWith { successResult(it) }

        helper.requestLaptopAttestation(client)

        val request = sentRequest()
        assertEquals("2.0", request.getString("jsonrpc"))
        assertEquals("remote.attestDevice", request.getString("method"))
        assertTrue("the request must carry an id", request.has("id"))
        assertTrue("the request must carry params", request.has("params"))
    }

    @Test
    fun `the challenge nonce is 32 random bytes carried base64 in params`() = runTest {
        respondWith { successResult(it) }

        helper.requestLaptopAttestation(client)

        val nonce = java.util.Base64.getDecoder()
            .decode(sentRequest().getJSONObject("params").getString("nonce"))
        assertEquals(32, nonce.size)
        assertFalse("an all-zero nonce is not random", nonce.all { it == 0.toByte() })
    }

    @Test
    fun `each attestation request uses a fresh nonce`() = runTest {
        respondWith { successResult(it) }

        helper.requestLaptopAttestation(client)
        helper.requestLaptopAttestation(client)

        assertEquals(2, sentRequests.size)
        assertNotEquals(nonceOf(0), nonceOf(1))
    }

    // -------------------------------------------------------------------------
    // Success
    // -------------------------------------------------------------------------

    @Test
    fun `a well-formed response is mapped onto every AttestationResult field`() = runTest {
        respondWith { nonce ->
            successResult(nonce, format = "tpm2", securityLevel = "hardware")
                .put("bootHashHex", "deadbeef")
                .put("bootStateVerified", true)
        }

        val result = helper.requestLaptopAttestation(client)

        assertTrue(result is AttestationHelper.AttestationResult.Success)
        result as AttestationHelper.AttestationResult.Success
        assertEquals("tpm2", result.format)
        assertEquals("hardware", result.securityLevel)
        assertEquals("deadbeef", result.bootHashHex)
        assertTrue(result.bootStateVerified)
    }

    @Test
    fun `the device fingerprint is the SHA-256 of the root certificate`() = runTest {
        val leaf = "leaf-certificate".toByteArray()
        val root = "root-certificate".toByteArray()
        respondWith { nonce ->
            successResult(nonce).put("certificateChain", chainOf(leaf, root))
        }

        val result = helper.requestLaptopAttestation(client)
            as AttestationHelper.AttestationResult.Success

        // The root is the LAST element of the chain, not the first.
        assertEquals(sha256Hex(root), result.deviceFingerprint)
        assertNotEquals(sha256Hex(leaf), result.deviceFingerprint)
    }

    @Test
    fun `a single-certificate chain fingerprints that certificate`() = runTest {
        val only = "self-signed".toByteArray()
        respondWith { nonce -> successResult(nonce).put("certificateChain", chainOf(only)) }

        val result = helper.requestLaptopAttestation(client)
            as AttestationHelper.AttestationResult.Success

        assertEquals(sha256Hex(only), result.deviceFingerprint)
    }

    @Test
    fun `a response without a certificate chain yields no fingerprint`() = runTest {
        respondWith { successResult(it) }

        val result = helper.requestLaptopAttestation(client)
            as AttestationHelper.AttestationResult.Success

        assertNull(result.deviceFingerprint)
    }

    @Test
    fun `an empty certificate chain yields no fingerprint`() = runTest {
        respondWith { nonce -> successResult(nonce).put("certificateChain", JSONArray()) }

        val result = helper.requestLaptopAttestation(client)
            as AttestationHelper.AttestationResult.Success

        assertNull(result.deviceFingerprint)
    }

    @Test
    fun `optional boot fields default to absent and unverified`() = runTest {
        respondWith { successResult(it) }

        val result = helper.requestLaptopAttestation(client)
            as AttestationHelper.AttestationResult.Success

        assertNull("bootHashHex is optional", result.bootHashHex)
        assertFalse("an absent bootStateVerified must not read as verified", result.bootStateVerified)
    }

    @Test
    fun `an explicitly null bootHashHex reads as absent`() = runTest {
        respondWith { nonce -> successResult(nonce).put("bootHashHex", JSONObject.NULL) }

        val result = helper.requestLaptopAttestation(client)
            as AttestationHelper.AttestationResult.Success

        assertNull(result.bootHashHex)
    }

    // -------------------------------------------------------------------------
    // Replay rejection
    // -------------------------------------------------------------------------

    @Test
    fun `a response echoing a different nonce is rejected as a replay`() = runTest {
        respondWith {
            // Ignore the challenge and echo a nonce of our own.
            successResult(ByteArray(32) { 0x5A })
        }

        val result = helper.requestLaptopAttestation(client)

        assertTrue(result is AttestationHelper.AttestationResult.Failure)
        assertEquals(
            "Nonce mismatch - attestation rejected",
            (result as AttestationHelper.AttestationResult.Failure).reason
        )
    }

    @Test
    fun `a truncated nonce echo is rejected`() = runTest {
        respondWith { nonce -> successResult(nonce.copyOfRange(0, 16)) }

        val result = helper.requestLaptopAttestation(client)

        assertTrue(result is AttestationHelper.AttestationResult.Failure)
    }

    // -------------------------------------------------------------------------
    // Error responses and transport failures
    // -------------------------------------------------------------------------

    @Test
    fun `a jsonrpc error response surfaces its message`() = runTest {
        respondWithRaw {
            JSONObject().put(
                "error",
                JSONObject().put("code", -32601).put("message", "method not supported")
            )
        }

        val result = helper.requestLaptopAttestation(client)

        assertEquals(
            "method not supported",
            (result as AttestationHelper.AttestationResult.Failure).reason
        )
    }

    @Test
    fun `an error response without a message falls back to Unknown error`() = runTest {
        respondWithRaw { JSONObject().put("error", JSONObject().put("code", -32000)) }

        val result = helper.requestLaptopAttestation(client)

        assertEquals("Unknown error", (result as AttestationHelper.AttestationResult.Failure).reason)
    }

    @Test
    fun `a response with neither result nor error is a failure, not a crash`() = runTest {
        respondWithRaw { JSONObject().put("jsonrpc", "2.0").put("id", 1) }

        assertTrue(
            helper.requestLaptopAttestation(client)
                is AttestationHelper.AttestationResult.Failure
        )
    }

    @Test
    fun `a result missing a mandatory field is a failure, not a crash`() = runTest {
        respondWithRaw { nonce ->
            // No `format`, which the helper reads with getString.
            JSONObject().put(
                "result",
                JSONObject()
                    .put("nonce", java.util.Base64.getEncoder().encodeToString(nonce))
                    .put("securityLevel", "hardware")
            )
        }

        assertTrue(
            helper.requestLaptopAttestation(client)
                is AttestationHelper.AttestationResult.Failure
        )
    }

    @Test
    fun `a non-JSON response body is a failure, not a crash`() = runTest {
        coEvery { client.sendRequest(any()) } answers {
            sentRequests.add(firstArg())
            "not json at all".toByteArray()
        }

        assertTrue(
            helper.requestLaptopAttestation(client)
                is AttestationHelper.AttestationResult.Failure
        )
    }

    @Test
    fun `a transport failure is reported as its message`() = runTest {
        coEvery { client.sendRequest(any()) } throws IOException("BLE link dropped")

        assertEquals(
            "BLE link dropped",
            (helper.requestLaptopAttestation(client)
                as AttestationHelper.AttestationResult.Failure).reason
        )
    }

    @Test
    fun `a transport failure with no message falls back to Unknown error`() = runTest {
        coEvery { client.sendRequest(any()) } throws IOException()

        assertEquals(
            "Unknown error",
            (helper.requestLaptopAttestation(client)
                as AttestationHelper.AttestationResult.Failure).reason
        )
    }

    // -------------------------------------------------------------------------
    // Result value semantics
    // -------------------------------------------------------------------------

    @Test
    fun `Success compares by value`() {
        val a = AttestationHelper.AttestationResult.Success("tpm2", "hardware", "aa", true, "ff")
        val b = AttestationHelper.AttestationResult.Success("tpm2", "hardware", "aa", true, "ff")

        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
        assertNotEquals(a, b.copy(securityLevel = "software"))
        assertTrue(a.toString().contains("tpm2"))
    }

    @Test
    fun `Failure compares by value`() {
        val a = AttestationHelper.AttestationResult.Failure("nope")

        assertEquals(a, AttestationHelper.AttestationResult.Failure("nope"))
        assertEquals(
            a.hashCode(),
            AttestationHelper.AttestationResult.Failure("nope").hashCode()
        )
        assertNotEquals(a, a.copy(reason = "different"))
        assertTrue(a.toString().contains("nope"))
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /** Answers every request with `{"result": <build(challengeNonce)>}`. */
    private fun respondWith(build: (ByteArray) -> JSONObject) {
        respondWithRaw { nonce -> JSONObject().put("result", build(nonce)) }
    }

    /** Answers every request with the exact envelope [build] returns. */
    private fun respondWithRaw(build: (ByteArray) -> JSONObject) {
        val captured = slot<ByteArray>()
        coEvery { client.sendRequest(capture(captured)) } answers {
            sentRequests.add(captured.captured)
            val nonce = java.util.Base64.getDecoder().decode(
                JSONObject(String(captured.captured, Charsets.UTF_8))
                    .getJSONObject("params")
                    .getString("nonce")
            )
            build(nonce).toString().toByteArray(Charsets.UTF_8)
        }
    }

    private fun successResult(
        nonce: ByteArray,
        format: String = "tpm2",
        securityLevel: String = "hardware"
    ): JSONObject = JSONObject()
        .put("nonce", java.util.Base64.getEncoder().encodeToString(nonce))
        .put("format", format)
        .put("securityLevel", securityLevel)

    private fun chainOf(vararg certificates: ByteArray): JSONArray = JSONArray().apply {
        certificates.forEach { put(java.util.Base64.getEncoder().encodeToString(it)) }
    }

    private fun sentRequest(index: Int = 0): JSONObject =
        JSONObject(String(sentRequests[index], Charsets.UTF_8))

    private fun nonceOf(index: Int): String =
        sentRequest(index).getJSONObject("params").getString("nonce")

    private fun sha256Hex(data: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(data).joinToString("") { "%02x".format(it) }
}
