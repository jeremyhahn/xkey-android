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

package com.automatethethings.xkey.ble.fido

import com.automatethethings.xkey.crypto.CborEncoder
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Malformed CTAP2 messages end to end: fragmented MSG frames reach a
 * [FidoBleSession] wired to a real [Ctap2Authenticator]. Each answers one
 * CTAP2 error status in one reply, the credential backend is never called,
 * and the session serves the next valid request on the same connection.
 */
class Ctap2MalformedMessageTest {

    private val frameSize = 20
    private val sent = mutableListOf<ByteArray>()
    private val hash = ByteArray(32) { (it + 1).toByte() }

    /** Counts every backend call; nothing in these tests should make one before the last valid request. */
    private class CountingBackend : FidoCredentialBackend {
        var calls = 0
        override val userVerificationAvailable = true
        override val strictUserVerification = false

        override suspend fun credentials(rpId: String): List<FidoCredential> {
            calls++
            return emptyList()
        }

        override suspend fun checkUser(rpId: String, registering: Boolean): UserCheck {
            calls++
            return UserCheck.VERIFIED
        }

        override suspend fun chooseCredential(rpId: String, candidates: List<FidoCredential>): FidoCredential? {
            calls++
            return null
        }

        override suspend fun sign(
            credential: FidoCredential,
            authenticatorData: (signCount: Long) -> ByteArray,
            clientDataHash: ByteArray
        ): SignedAssertion {
            calls++
            throw AssertionError("sign called")
        }

        override suspend fun create(request: CredentialRequest): NewCredential {
            calls++
            throw AssertionError("create called")
        }
    }

    private val backend = CountingBackend()

    private fun TestScope.session() = FidoBleSession(
        handler = Ctap2Authenticator(backend),
        scope = backgroundScope,
        send = { sent += it },
        maxFrameSize = { frameSize },
        keepaliveIntervalMillis = 100
    )

    private fun b(vararg values: Int) = ByteArray(values.size) { values[it].toByte() }

    private fun validAssertion(): ByteArray =
        b(Ctap2.CMD_GET_ASSERTION) + CborEncoder.encode(mapOf(1 to "example.com", 2 to hash))

    /** A getAssertion whose CBOR ends four bytes early, inside the clientDataHash. */
    private fun truncated(): ByteArray = validAssertion().let { it.copyOfRange(0, it.size - 4) }

    /** A makeCredential whose pubKeyCredParams array claims 2^31 entries. */
    private fun oversizedArray(): ByteArray =
        b(Ctap2.CMD_MAKE_CREDENTIAL, 0xA2, 0x01, 0x58, 0x20) + hash + b(0x04, 0x9A, 0x80, 0x00, 0x00, 0x00) + ByteArray(24) { 0x01 }

    /** A getAssertion whose extensions nest arrays sixty deep. */
    private fun deepNesting(): ByteArray =
        b(Ctap2.CMD_GET_ASSERTION, 0xA3, 0x01, 0x6B) + "example.com".toByteArray() +
            b(0x02, 0x58, 0x20) + hash + b(0x04, 0xA1, 0x61, 0x78) + ByteArray(60) { 0x81.toByte() } + b(0x01)

    /** A getAssertion that sends clientDataHash twice. */
    private fun duplicateKey(): ByteArray =
        b(Ctap2.CMD_GET_ASSERTION, 0xA3, 0x01, 0x6B) + "example.com".toByteArray() +
            b(0x02, 0x58, 0x20) + hash + b(0x02, 0x58, 0x20) + ByteArray(32)

    private fun TestScope.send(session: FidoBleSession, request: ByteArray) {
        sent.clear()
        FidoBle.fragment(FidoBle.CMD_MSG, request, frameSize).forEach { session.onControlPointWrite(it) }
        runCurrent()
    }

    /** The one reply to the last request: a MSG carrying a CTAP2 status and its body. */
    private fun reply(): ByteArray {
        val frames = sent.filter { it[0] != FidoBle.CMD_KEEPALIVE }
        assertTrue("a reply was sent", frames.isNotEmpty())
        val reassembler = FidoBleReassembler()
        var result: FidoBleReassembler.Result = FidoBleReassembler.Result.Incomplete
        frames.forEach {
            assertTrue("one reply, no frame after it", result is FidoBleReassembler.Result.Incomplete)
            result = reassembler.accept(it)
        }
        val complete = result as FidoBleReassembler.Result.Complete
        assertEquals(FidoBle.CMD_MSG, complete.command)
        return complete.data
    }

    /** [request] answers exactly [status] with no body and no backend call; getInfo then answers OK. */
    private fun TestScope.assertRefusedThenUsable(session: FidoBleSession, label: String, request: ByteArray, status: Int) {
        assertTrue("$label spans several frames", FidoBle.fragment(FidoBle.CMD_MSG, request, frameSize).count() > 1)
        send(session, request)
        assertArrayEquals(label, b(status), reply())
        assertEquals("$label: backend calls", 0, backend.calls)

        send(session, b(Ctap2.CMD_GET_INFO))
        val info = reply()
        assertEquals("$label: getInfo after it", Ctap2.OK, info[0].toInt() and 0xFF)
        assertTrue("$label: getInfo has a body", info.size > 1)
    }

    @Test
    fun `truncated CBOR answers ERR_INVALID_CBOR and the session serves the next request`() = runTest {
        assertRefusedThenUsable(session(), "truncated", truncated(), Ctap2.ERR_INVALID_CBOR)
    }

    @Test
    fun `an oversized declared array answers ERR_INVALID_CBOR and the session serves the next request`() = runTest {
        assertRefusedThenUsable(session(), "oversized array", oversizedArray(), Ctap2.ERR_INVALID_CBOR)
    }

    @Test
    fun `deep nesting answers ERR_INVALID_CBOR and the session serves the next request`() = runTest {
        assertRefusedThenUsable(session(), "deep nesting", deepNesting(), Ctap2.ERR_INVALID_CBOR)
    }

    @Test
    fun `a duplicate map key answers ERR_INVALID_CBOR and the session serves the next request`() = runTest {
        assertRefusedThenUsable(session(), "duplicate key", duplicateKey(), Ctap2.ERR_INVALID_CBOR)
    }

    @Test
    fun `malformed messages in a row on one connection never reach the backend, and a valid one then does`() = runTest {
        val session = session()
        for ((label, request) in listOf(
            "truncated" to truncated(),
            "oversized array" to oversizedArray(),
            "deep nesting" to deepNesting(),
            "duplicate key" to duplicateKey()
        )) {
            assertRefusedThenUsable(session, label, request, Ctap2.ERR_INVALID_CBOR)
        }

        // The well-formed assertion the truncated one was cut from reaches the backend.
        send(session, validAssertion())
        val status = reply()[0].toInt() and 0xFF
        assertTrue("valid request reaches the backend", backend.calls > 0)
        assertTrue("valid request is not a CBOR error", status != Ctap2.ERR_INVALID_CBOR)
    }
}
