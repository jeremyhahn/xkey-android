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
package com.automatethethings.xkey.remote

import com.automatethethings.xkey.protocol.ErrorCodes
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.protocol.Response
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import io.mockk.slot
import io.mockk.unmockkAll
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.test.runTest
import org.json.JSONException
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Unit tests for [BidirectionalMessageRouter].
 *
 * The router is the correlation point for the phone -> desktop direction of the
 * pairing protocol: it must hand inbound `local.*` requests to the
 * [RequestHandler] while resolving responses to outbound `remote.*` requests
 * against the pending [CompletableDeferred] registered by the client that sent
 * them. These tests cover id correlation, concurrent in-flight requests,
 * unknown/duplicate ids, unregistration, connection-loss cancellation, and the
 * classification rules that decide "request" vs. "response".
 *
 * [RequestHandler] is mocked (its real constructor needs Android Keystore) and
 * `android.util.Log` is stubbed since it is unavailable on the JVM.
 */
class BidirectionalMessageRouterTest {

    private lateinit var requestHandler: RequestHandler
    private lateinit var router: BidirectionalMessageRouter

    @Before
    fun setUp() {
        stubAndroidLog()
        requestHandler = mockk()
        router = BidirectionalMessageRouter(requestHandler)
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    private fun bytes(json: String): ByteArray = json.toByteArray(Charsets.UTF_8)

    // -------------------------------------------------------------------------
    // Request routing (laptop -> phone)
    // -------------------------------------------------------------------------

    @Test
    fun `message with method is delegated to the request handler`() = runTest {
        val incoming = bytes("""{"id":7,"method":"local.ping","params":{}}""")
        val handlerReply = bytes("""{"id":7,"result":{"pong":true}}""")
        val captured = slot<ByteArray>()
        coEvery { requestHandler.handleRawRequest(capture(captured)) } returns handlerReply

        val out = router.processMessage(incoming)

        assertSame(handlerReply, out)
        assertEquals(String(incoming), String(captured.captured))
    }

    @Test
    fun `message with both method and result is treated as a request`() = runTest {
        // "method" wins the classification: a peer that echoes a result alongside
        // a method must still be served as a request, never silently swallowed.
        val incoming = bytes("""{"id":8,"method":"local.getInfo","result":{"x":1}}""")
        coEvery { requestHandler.handleRawRequest(any()) } returns bytes("""{"id":8,"result":{}}""")

        val out = router.processMessage(incoming)

        assertEquals("""{"id":8,"result":{}}""", String(out!!))
        coVerify(exactly = 1) { requestHandler.handleRawRequest(any()) }
    }

    @Test
    fun `message with explicit null method is treated as a request`() = runTest {
        val incoming = bytes("""{"id":9,"method":null,"params":{}}""")
        coEvery { requestHandler.handleRawRequest(any()) } returns bytes("""{"id":9,"result":{}}""")

        router.processMessage(incoming)

        coVerify(exactly = 1) { requestHandler.handleRawRequest(any()) }
    }

    @Test
    fun `message with neither method nor result nor error goes to the handler`() = runTest {
        val incoming = bytes("""{"id":10,"result":null,"error":null}""")
        coEvery { requestHandler.handleRawRequest(any()) } returns bytes("""{"id":10,"result":{}}""")

        router.processMessage(incoming)

        coVerify(exactly = 1) { requestHandler.handleRawRequest(any()) }
    }

    @Test
    fun `malformed json propagates to the caller`() = runTest {
        var thrown: Throwable? = null
        try {
            router.processMessage(bytes("not json at all"))
        } catch (e: JSONException) {
            thrown = e
        }
        assertTrue("expected a JSONException for malformed input", thrown is JSONException)
        coVerify(exactly = 0) { requestHandler.handleRawRequest(any()) }
    }

    // -------------------------------------------------------------------------
    // Response routing (phone -> laptop replies)
    // -------------------------------------------------------------------------

    @Test
    fun `success response resolves the matching pending request`() = runTest {
        val deferred = CompletableDeferred<Response>()
        router.registerPendingResponse(42L, deferred)

        val out = router.processMessage(bytes("""{"id":42,"result":{"valid":true}}"""))

        assertNull("responses must not produce a reply", out)
        val response = deferred.await()
        assertEquals(42L, response.id)
        assertTrue(response.isSuccess())
        assertTrue(response.result!!.getBoolean("valid"))
        coVerify(exactly = 0) { requestHandler.handleRawRequest(any()) }
    }

    @Test
    fun `error response resolves the matching pending request`() = runTest {
        val deferred = CompletableDeferred<Response>()
        router.registerPendingResponse(43L, deferred)

        val out = router.processMessage(
            bytes("""{"id":43,"error":{"code":-32001,"message":"key not found"}}""")
        )

        assertNull(out)
        val response = deferred.await()
        assertTrue(response.isError())
        assertEquals(ErrorCodes.KEY_NOT_FOUND, response.error!!.code)
        assertEquals("key not found", response.error!!.message)
    }

    @Test
    fun `response for an unknown id is dropped without error`() = runTest {
        val out = router.processMessage(bytes("""{"id":999,"result":{"ok":true}}"""))

        assertNull(out)
        coVerify(exactly = 0) { requestHandler.handleRawRequest(any()) }
    }

    @Test
    fun `a pending request is consumed by the first response only`() = runTest {
        val deferred = CompletableDeferred<Response>()
        router.registerPendingResponse(55L, deferred)

        router.processMessage(bytes("""{"id":55,"result":{"n":1}}"""))
        // A duplicate response for the same id must not throw and must not
        // change the already-resolved value.
        router.processMessage(bytes("""{"id":55,"result":{"n":2}}"""))

        assertEquals(1, deferred.await().result!!.getInt("n"))
    }

    @Test
    fun `removePendingResponse unregisters so a late response is dropped`() = runTest {
        val deferred = CompletableDeferred<Response>()
        router.registerPendingResponse(60L, deferred)
        router.removePendingResponse(60L)

        val out = router.processMessage(bytes("""{"id":60,"result":{"ok":true}}"""))

        assertNull(out)
        assertFalse(deferred.isCompleted)
    }

    @Test
    fun `removePendingResponse for an unknown id is a no-op`() {
        router.removePendingResponse(12345L)
        router.cancelAllPending()
    }

    @Test
    fun `registering the same id twice leaves only the newest deferred resolvable`() = runTest {
        val stale = CompletableDeferred<Response>()
        val fresh = CompletableDeferred<Response>()
        router.registerPendingResponse(70L, stale)
        router.registerPendingResponse(70L, fresh)

        router.processMessage(bytes("""{"id":70,"result":{"ok":true}}"""))

        assertTrue(fresh.isCompleted)
        assertFalse("the replaced deferred is orphaned", stale.isCompleted)
    }

    @Test
    fun `unparseable response leaves the pending request untouched`() = runTest {
        // No "id" field: Response.fromJson rejects it, the router swallows the
        // failure and the caller is left waiting for its own timeout.
        val deferred = CompletableDeferred<Response>()
        router.registerPendingResponse(80L, deferred)

        val out = router.processMessage(bytes("""{"result":{"ok":true}}"""))

        assertNull(out)
        assertFalse(deferred.isCompleted)
    }

    // -------------------------------------------------------------------------
    // Connection loss
    // -------------------------------------------------------------------------

    @Test
    fun `cancelAllPending completes every pending request with an internal error`() = runTest {
        val a = CompletableDeferred<Response>()
        val b = CompletableDeferred<Response>()
        router.registerPendingResponse(101L, a)
        router.registerPendingResponse(102L, b)

        router.cancelAllPending()

        for ((id, deferred) in listOf(101L to a, 102L to b)) {
            val response = deferred.await()
            assertEquals(id, response.id)
            assertTrue(response.isError())
            assertEquals(ErrorCodes.INTERNAL_ERROR, response.error!!.code)
            assertEquals("Connection lost", response.error!!.message)
        }
    }

    @Test
    fun `cancelAllPending clears the registry so later responses find nothing`() = runTest {
        val deferred = CompletableDeferred<Response>()
        router.registerPendingResponse(110L, deferred)
        router.cancelAllPending()

        val first = deferred.await()
        router.processMessage(bytes("""{"id":110,"result":{"late":true}}"""))

        assertTrue("the cancelled result must not be overwritten", first.isError())
    }

    @Test
    fun `cancelAllPending on an empty registry is a no-op`() {
        router.cancelAllPending()
        router.cancelAllPending()
    }

    @Test
    fun `requests still route after a connection loss`() = runTest {
        router.cancelAllPending()
        coEvery { requestHandler.handleRawRequest(any()) } returns bytes("""{"id":1,"result":{}}""")

        val out = router.processMessage(bytes("""{"id":1,"method":"local.ping"}"""))

        assertEquals("""{"id":1,"result":{}}""", String(out!!))
    }
}
