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

package com.automatethethings.xkey.transport

import android.util.Log
import com.automatethethings.xkey.protocol.ErrorCodes
import com.automatethethings.xkey.protocol.Request
import com.automatethethings.xkey.protocol.Response
import com.automatethethings.xkey.protocol.TransportMethods
import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * A reply too large for one stream frame (over 65519 plaintext bytes: the
 * 65535-byte frame less the 16-byte Noise tag) is answered with an
 * INTERNAL_ERROR carrying the request's id and generation, instead of being
 * written: the connection stays up, no nonce is spent, and the next request
 * on it is answered.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class StreamOversizedReplyTest {

    private lateinit var harness: StreamSessionHarness
    private lateinit var mainThread: ExecutorService

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
        // runRequest answers every desktop request on Dispatchers.Main.
        mainThread = Executors.newSingleThreadExecutor()
        Dispatchers.setMain(mainThread.asCoroutineDispatcher())
        harness = StreamSessionHarness(transportMethods = listOf(SizedReplies))
    }

    @After
    fun tearDown() {
        harness.close()
        Dispatchers.resetMain()
        mainThread.shutdownNow()
        unmockkAll()
    }

    @Test
    fun anOversizedReplyIsAnsweredWithAnInternalErrorAndTheConnectionGoesOn() = runBlocking {
        val desktop = harness.connectPaired()

        val refused = desktop.sized(id = 4, generation = 40, size = 70_000)

        assertEquals(4, refused.getInt("id"))
        assertEquals(40, refused.getInt("generation"))
        assertFalse(refused.has("result"))
        val error = refused.getJSONObject("error")
        assertEquals(ErrorCodes.INTERNAL_ERROR, error.getInt("code"))
        assertTrue(error.getString("message"), error.getString("message").contains("does not fit one frame"))

        // The same connection, and the next nonce on both sides, still work.
        val next = desktop.sized(id = 5, generation = 41, size = 200)
        assertEquals(5, next.getInt("id"))
        assertEquals(41, next.getInt("generation"))
        assertTrue(next.has("result"))
        desktop.close()
    }

    @Test
    fun aReplyOfExactlyTheLargestPlaintextGoesOutUnchanged() = runBlocking {
        val desktop = harness.connectPaired()

        val sent = desktop.sizedFrame(id = 6, generation = 42, size = LARGEST_PLAINTEXT)

        assertEquals(LARGEST_PLAINTEXT, sent.size)
        val reply = JSONObject(String(sent, Charsets.UTF_8))
        assertEquals(6, reply.getInt("id"))
        assertTrue(reply.has("result"))
        desktop.close()
    }

    @Test
    fun aReplyOneByteOverTheLargestPlaintextIsReplaced() = runBlocking {
        val desktop = harness.connectPaired()

        val reply = JSONObject(String(desktop.sizedFrame(id = 7, generation = 43, size = LARGEST_PLAINTEXT + 1), Charsets.UTF_8))

        assertEquals(7, reply.getInt("id"))
        assertEquals(43, reply.getInt("generation"))
        assertEquals(ErrorCodes.INTERNAL_ERROR, reply.getJSONObject("error").getInt("code"))
        assertTrue(
            reply.getJSONObject("error").getString("message"),
            reply.getJSONObject("error").getString("message").contains("${LARGEST_PLAINTEXT + 1} bytes")
        )

        val next = desktop.sized(id = 8, generation = 44, size = 200)
        assertEquals(8, next.getInt("id"))
        assertTrue(next.has("result"))
        desktop.close()
    }

    /** Asks for a reply of [size] plaintext bytes and returns the decrypted answer. */
    private fun DesktopPeer.sized(id: Long, generation: Long, size: Int): JSONObject =
        JSONObject(String(sizedFrame(id, generation, size), Charsets.UTF_8))

    /** Asks for a reply of [size] plaintext bytes and returns the decrypted answer's bytes. */
    private fun DesktopPeer.sizedFrame(id: Long, generation: Long, size: Int): ByteArray {
        val request = JSONObject()
            .put("jsonrpc", "2.0")
            .put("id", id)
            .put("method", METHOD)
            .put("params", JSONObject().put("size", size))
            .put("generation", generation)
        send(noise.encrypt(request.toString().toByteArray()))
        return noise.decrypt(read())
    }

    /** Serves [METHOD] with a reply whose JSON, generation included, is exactly `params.size` bytes. */
    private object SizedReplies : TransportMethods {
        override fun handles(method: String): Boolean = method == METHOD

        override suspend fun handle(request: Request): Response {
            val size = request.params!!.getInt("size")
            val empty = reply(request, "").toJson().size
            return reply(request, "x".repeat(size - empty))
        }

        private fun reply(request: Request, pad: String) =
            Response.success(request.id, JSONObject().put("pad", pad), generation = request.generation)
    }

    private companion object {
        const val METHOD = "test.sizedReply"

        /** The 65535-byte frame less the 16-byte Noise tag. */
        const val LARGEST_PLAINTEXT = StreamMessageFraming.MAX_MESSAGE_SIZE - 16
    }
}
