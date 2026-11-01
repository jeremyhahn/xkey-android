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
package com.automatethethings.xkey.protocol

import org.json.JSONException
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Unit tests for the JSON-RPC message envelope defined in `Messages.kt`:
 * [Request], [Response], [ErrorObject] and [ProtocolException].
 *
 * The envelope is the outermost layer of the wire contract shared with the
 * go-xkms desktop client (`go-xkms/xkey/pkg/pairing/protocol.go`, types
 * `RPCRequest`, `RPCResponse` and `RPCError`), so these tests pin the exact
 * field names (`id`, `method`, `params`, `result`, `error`, `code`, `message`,
 * `data`) as well as the parser's failure modes. A silent change to any of them
 * breaks pairing without a compile error, which is why the assertions check the
 * serialized key set rather than only round-tripping values.
 */
class ProtocolEnvelopeTest {

    private fun JSONObject.keySet(): Set<String> = keys().asSequence().toSet()

    // -------------------------------------------------------------------------
    // Request.fromJson
    // -------------------------------------------------------------------------

    @Test
    fun `Request fromJson parses id method and params`() {
        val request = Request.fromJson("""{"id":42,"method":"local.sign","params":{"keyId":"k1"}}""")

        assertEquals(42L, request.id)
        assertEquals("local.sign", request.method)
        assertEquals("k1", request.params!!.getString("keyId"))
    }

    @Test
    fun `Request fromJson accepts a request with no params`() {
        val request = Request.fromJson("""{"id":1,"method":"ping"}""")

        assertEquals(1L, request.id)
        assertEquals("ping", request.method)
        assertNull(request.params)
    }

    @Test
    fun `Request fromJson treats explicit null params as absent`() {
        val request = Request.fromJson("""{"id":1,"method":"ping","params":null}""")

        assertNull(request.params)
    }

    @Test
    fun `Request fromJson accepts id zero`() {
        val request = Request.fromJson("""{"id":0,"method":"ping"}""")

        assertEquals(0L, request.id)
    }

    @Test
    fun `Request fromJson parses from UTF-8 bytes`() {
        val bytes = """{"id":7,"method":"getInfo"}""".toByteArray(Charsets.UTF_8)

        val request = Request.fromJson(bytes)

        assertEquals(7L, request.id)
        assertEquals("getInfo", request.method)
    }

    @Test
    fun `Request fromJson rejects a missing id`() {
        val e = assertProtocolException { Request.fromJson("""{"method":"ping"}""") }

        assertTrue("message was: ${e.message}", e.message!!.contains("id"))
    }

    @Test
    fun `Request fromJson rejects a negative id`() {
        assertProtocolException { Request.fromJson("""{"id":-5,"method":"ping"}""") }
    }

    @Test
    fun `Request fromJson rejects a missing method`() {
        val e = assertProtocolException { Request.fromJson("""{"id":1}""") }

        assertTrue("message was: ${e.message}", e.message!!.contains("method"))
    }

    @Test
    fun `Request fromJson rejects an explicitly null method`() {
        assertProtocolException { Request.fromJson("""{"id":1,"method":null}""") }
    }

    @Test
    fun `Request fromJson rejects params that are not an object`() {
        val e = assertProtocolException { Request.fromJson("""{"id":1,"method":"ping","params":"nope"}""") }

        assertTrue("message was: ${e.message}", e.message!!.startsWith("Invalid JSON"))
    }

    @Test
    fun `Request fromJson rejects malformed JSON`() {
        val e = assertProtocolException { Request.fromJson("""{"id":1,"method":""") }

        assertTrue("message was: ${e.message}", e.message!!.startsWith("Invalid JSON"))
    }

    // -------------------------------------------------------------------------
    // Request.toJson
    // -------------------------------------------------------------------------

    @Test
    fun `Request toJsonString emits exactly id method and params`() {
        val request = Request(9, "local.hmac", JSONObject().put("keyId", "k"))

        val json = JSONObject(request.toJsonString())

        assertEquals(setOf("id", "method", "params"), json.keySet())
        assertEquals(9L, json.getLong("id"))
        assertEquals("local.hmac", json.getString("method"))
        assertEquals("k", json.getJSONObject("params").getString("keyId"))
    }

    @Test
    fun `Request toJsonString omits params when null`() {
        val json = JSONObject(Request(3, "ping").toJsonString())

        assertEquals(setOf("id", "method"), json.keySet())
    }

    // -------------------------------------------------------------------------
    // Response construction invariants
    // -------------------------------------------------------------------------

    @Test(expected = IllegalArgumentException::class)
    fun `Response rejects having neither result nor error`() {
        Response(1, result = null, error = null)
    }

    @Test
    fun `Response success factory produces a success response`() {
        val response = Response.success(5, JSONObject().put("pong", true))

        assertTrue(response.isSuccess())
        assertFalse(response.isError())
        assertEquals(5L, response.id)
        assertTrue(response.result!!.getBoolean("pong"))
    }

    @Test
    fun `Response error factory produces an error response with code and message`() {
        val response = Response.error(6, ErrorCodes.KEY_NOT_FOUND, "no such key")

        assertFalse(response.isSuccess())
        assertTrue(response.isError())
        assertEquals(ErrorCodes.KEY_NOT_FOUND, response.error!!.code)
        assertEquals("no such key", response.error!!.message)
        assertNull(response.error!!.data)
    }

    @Test
    fun `Response error factory accepts a prebuilt ErrorObject`() {
        val errorObject = ErrorObject(ErrorCodes.PIN_LOCKED, "locked", JSONObject().put("retries", 0))

        val response = Response.error(7, errorObject)

        assertEquals(errorObject, response.error)
        assertEquals(0, response.error!!.data!!.getInt("retries"))
    }

    // -------------------------------------------------------------------------
    // Response.fromJson
    // -------------------------------------------------------------------------

    @Test
    fun `Response fromJson parses a success response`() {
        val response = Response.fromJson("""{"id":12,"result":{"pong":true}}""")

        assertTrue(response.isSuccess())
        assertEquals(12L, response.id)
        assertTrue(response.result!!.getBoolean("pong"))
        assertNull(response.error)
    }

    @Test
    fun `Response fromJson parses an error response`() {
        val response = Response.fromJson(
            """{"id":13,"error":{"code":-32601,"message":"Unknown method: foo"}}"""
        )

        assertTrue(response.isError())
        assertEquals(ErrorCodes.METHOD_NOT_FOUND, response.error!!.code)
        assertEquals("Unknown method: foo", response.error!!.message)
        assertNull(response.result)
    }

    @Test
    fun `Response fromJson parses from UTF-8 bytes`() {
        val response = Response.fromJson("""{"id":14,"result":{}}""".toByteArray(Charsets.UTF_8))

        assertEquals(14L, response.id)
        assertTrue(response.isSuccess())
    }

    @Test
    fun `Response fromJson rejects a missing id`() {
        val e = assertProtocolException { Response.fromJson("""{"result":{}}""") }

        assertTrue("message was: ${e.message}", e.message!!.contains("id"))
    }

    @Test
    fun `Response fromJson rejects having neither result nor error`() {
        val e = assertProtocolException { Response.fromJson("""{"id":1}""") }

        assertTrue("message was: ${e.message}", e.message!!.contains("result"))
    }

    @Test
    fun `Response fromJson treats explicit nulls as absent and rejects the response`() {
        assertProtocolException { Response.fromJson("""{"id":1,"result":null,"error":null}""") }
    }

    @Test(expected = IllegalArgumentException::class)
    fun `Response fromJson rejects a response carrying both result and error`() {
        // The init-block invariant fires; it is not wrapped into a ProtocolException.
        Response.fromJson("""{"id":1,"result":{},"error":{"code":-1,"message":"x"}}""")
    }

    @Test
    fun `Response fromJson rejects an error member that is not an object`() {
        val e = assertProtocolException { Response.fromJson("""{"id":1,"error":"boom"}""") }

        assertTrue("message was: ${e.message}", e.message!!.startsWith("Invalid JSON"))
    }

    @Test
    fun `Response fromJson rejects malformed JSON`() {
        assertProtocolException { Response.fromJson("""not json at all""") }
    }

    // -------------------------------------------------------------------------
    // Response.toJson
    // -------------------------------------------------------------------------

    @Test
    fun `Response toJsonString of a success emits exactly id and result`() {
        val json = JSONObject(Response.success(21, JSONObject().put("ok", true)).toJsonString())

        assertEquals(setOf("id", "result"), json.keySet())
        assertEquals(21L, json.getLong("id"))
        assertTrue(json.getJSONObject("result").getBoolean("ok"))
    }

    @Test
    fun `Response toJsonString of an error emits exactly id and error`() {
        val json = JSONObject(Response.error(22, ErrorCodes.INVALID_PARAMS, "bad").toJsonString())

        assertEquals(setOf("id", "error"), json.keySet())
        assertEquals(setOf("code", "message"), json.getJSONObject("error").keySet())
        assertEquals(ErrorCodes.INVALID_PARAMS, json.getJSONObject("error").getInt("code"))
        assertEquals("bad", json.getJSONObject("error").getString("message"))
    }

    @Test
    fun `Response toJson round-trips an error response including data`() {
        val original = Response.error(
            32,
            ErrorCodes.PIN_INCORRECT,
            "wrong pin",
            JSONObject().put("retriesLeft", 2)
        )

        val parsed = Response.fromJson(original.toJson())

        assertEquals(ErrorCodes.PIN_INCORRECT, parsed.error!!.code)
        assertEquals("wrong pin", parsed.error!!.message)
        assertEquals(2, parsed.error!!.data!!.getInt("retriesLeft"))
    }

    // -------------------------------------------------------------------------
    // ErrorObject
    // -------------------------------------------------------------------------

    @Test
    fun `ErrorObject fromJson reads code message and data`() {
        val error = ErrorObject.fromJson(
            JSONObject("""{"code":-32010,"message":"bad algo","data":{"algorithm":"XX"}}""")
        )

        assertEquals(ErrorCodes.INVALID_ALGORITHM, error.code)
        assertEquals("bad algo", error.message)
        assertEquals("XX", error.data!!.getString("algorithm"))
    }

    @Test
    fun `ErrorObject fromJson defaults a missing code to INTERNAL_ERROR`() {
        val error = ErrorObject.fromJson(JSONObject("""{"message":"oops"}"""))

        assertEquals(ErrorCodes.INTERNAL_ERROR, error.code)
    }

    @Test
    fun `ErrorObject fromJson defaults a missing message to Unknown error`() {
        val error = ErrorObject.fromJson(JSONObject("""{"code":-1}"""))

        assertEquals("Unknown error", error.message)
    }

    @Test
    fun `ErrorObject fromJson defaults a non-numeric code to INTERNAL_ERROR`() {
        val error = ErrorObject.fromJson(JSONObject("""{"code":true,"message":"x"}"""))

        assertEquals(ErrorCodes.INTERNAL_ERROR, error.code)
    }

    @Test
    fun `ErrorObject fromJson treats explicit null data as absent`() {
        val error = ErrorObject.fromJson(JSONObject("""{"code":-1,"message":"x","data":null}"""))

        assertNull(error.data)
    }

    @Test
    fun `ErrorObject toJson emits exactly code and message when data is null`() {
        val json = ErrorObject(-32001, "missing").toJson()

        assertEquals(setOf("code", "message"), json.keySet())
    }

    @Test
    fun `ErrorObject toJson emits data when present`() {
        val json = ErrorObject(-32001, "missing", JSONObject().put("keyId", "k")).toJson()

        assertEquals(setOf("code", "message", "data"), json.keySet())
        assertEquals("k", json.getJSONObject("data").getString("keyId"))
    }

    // -------------------------------------------------------------------------
    // ProtocolException
    // -------------------------------------------------------------------------

    @Test
    fun `ProtocolException defaults its error code to INTERNAL_ERROR`() {
        assertEquals(ErrorCodes.INTERNAL_ERROR, ProtocolException("boom").errorCode)
    }

    @Test
    fun `ProtocolException carries an explicit error code and cause`() {
        val cause = JSONException("root cause")

        val e = ProtocolException("boom", cause, ErrorCodes.INVALID_PARAMS)

        assertEquals(ErrorCodes.INVALID_PARAMS, e.errorCode)
        assertEquals(cause, e.cause)
        assertEquals("boom", e.message)
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private fun assertProtocolException(block: () -> Unit): ProtocolException {
        try {
            block()
        } catch (e: ProtocolException) {
            return e
        }
        fail("Expected ProtocolException")
        throw IllegalStateException("unreachable")
    }
}
