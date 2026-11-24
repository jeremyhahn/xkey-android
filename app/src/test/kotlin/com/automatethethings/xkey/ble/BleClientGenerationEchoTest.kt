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

package com.automatethethings.xkey.ble

import android.util.Log
import com.automatethethings.xkey.protocol.ErrorCodes
import com.automatethethings.xkey.protocol.MethodNames
import com.automatethethings.xkey.protocol.SessionBindingProvider
import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import java.security.SecureRandom
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test

/**
 * The errors [BleClient] writes itself for a request the desktop sends on a
 * phone-initiated session (`dispatchInboundRequest`) carry the request's
 * `generation`: an unserved method, no handler, and a handler that throws.
 * The served answer comes from the handler, which echoes it itself.
 */
class BleClientGenerationEchoTest {

    private var harness: BleClientHarness? = null

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.v(any(), any<String>()) } returns 0
        every { Log.d(any(), any<String>()) } returns 0
        every { Log.i(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.e(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>(), any()) } returns 0
        every { Log.e(any(), any<String>(), any()) } returns 0
    }

    @After
    fun tearDown() {
        harness?.close()
        harness = null
        unmockkAll()
    }

    @Test
    fun anUnservedMethodIsRefusedWithTheGeneration(): Unit = runBlocking {
        val h = connected(ThrowingHandler())

        h.desktopSends("""{"jsonrpc":"2.0","id":5,"generation":50,"method":"local.listKeys"}""".toByteArray())

        val answer = String(h.awaitResponses(1)[0], Charsets.UTF_8)
        assertEquals("50", rawGeneration(answer))
        assertEquals(ErrorCodes.METHOD_NOT_FOUND, errorCode(answer))
    }

    @Test
    fun noHandlerIsRefusedWithTheGeneration(): Unit = runBlocking {
        val h = connected(null)

        h.desktopSends(attestRequest(id = 6, generation = 60))

        val answer = String(h.awaitResponses(1)[0], Charsets.UTF_8)
        assertEquals("60", rawGeneration(answer))
        assertEquals(ErrorCodes.METHOD_NOT_FOUND, errorCode(answer))
    }

    @Test
    fun aFailingHandlerIsAnsweredWithTheGeneration(): Unit = runBlocking {
        val h = connected(ThrowingHandler())

        h.desktopSends(attestRequest(id = 7, generation = 70))

        val answer = String(h.awaitResponses(1)[0], Charsets.UTF_8)
        assertEquals("70", rawGeneration(answer))
        assertEquals(ErrorCodes.INTERNAL_ERROR, errorCode(answer))
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private suspend fun connected(handler: PhoneInitiatedRequestHandler?): BleClientHarness {
        val h = BleClientHarness(inboundRequests = handler).also { harness = it }
        h.client.connect(h.address, ByteArray(32).also { SecureRandom().nextBytes(it) })
        return h
    }

    private class ThrowingHandler : PhoneInitiatedRequestHandler {
        override suspend fun handle(
            request: ByteArray,
            binding: SessionBindingProvider,
            peerPublicKeyHex: String?
        ): ByteArray = throw IllegalStateException("attestation unavailable")
    }

    private fun attestRequest(id: Long, generation: Long): ByteArray =
        ("""{"jsonrpc":"2.0","id":$id,"generation":$generation,""" +
            """"method":"${MethodNames.LOCAL_ATTEST_DEVICE}","params":{"purpose":"pair"}}""").toByteArray()

    private fun errorCode(answer: String): Int =
        JSONObject(answer).optJSONObject("error")?.getInt("code")
            ?: throw AssertionError("expected an error, got $answer")

    private companion object {
        /** The `generation` member's number exactly as written, or null when absent. */
        fun rawGeneration(json: String): String? =
            Regex(""""generation":(\d+)[,}]""").find(json)?.groupValues?.get(1)
    }
}
