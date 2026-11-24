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

import android.app.KeyguardManager
import android.app.NotificationManager
import android.content.Context
import android.os.Looper
import android.util.Log
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.KeyDao
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Every answer [RequestHandler.handleRawRequest] writes carries the request's
 * `id` exactly as sent: JSON-RPC lets the id be a string or a number, and a
 * client matches an answer to its request by that value. A string id is
 * served; a message whose id cannot be read is answered with `"id":null`,
 * never with an id the client did not send.
 *
 * Compares the raw JSON text of the answer, as [GenerationEchoTest] does.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class RequestIdEchoTest {

    private lateinit var handler: RequestHandler

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

        // BiometricNotificationHelper builds a Handler on the main looper.
        mockkStatic(Looper::class)
        every { Looper.getMainLooper() } returns mockk(relaxed = true)

        val keyDao = mockk<KeyDao>(relaxed = true)
        val database = mockk<XKeyDatabase>(relaxed = true)
        every { database.keyDao() } returns keyDao
        mockkObject(XKeyDatabase.Companion)
        every { XKeyDatabase.getInstance(any()) } returns database

        Dispatchers.setMain(UnconfinedTestDispatcher())

        val context = mockk<Context>(relaxed = true)
        every { context.getSystemService(Context.KEYGUARD_SERVICE) } returns
            mockk<KeyguardManager>(relaxed = true)
        every { context.getSystemService(NotificationManager::class.java) } returns
            mockk<NotificationManager>(relaxed = true)

        handler = RequestHandler(
            context = context,
            keystoreManager = mockk<KeystoreManager>(relaxed = true),
            biometricLauncher = null,
            sessionAuthManager = null,
            pairedDeviceRepository = null
        )
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
        unmockkAll()
    }

    // -----------------------------------------------------------------
    // The handler path
    // -----------------------------------------------------------------

    @Test
    fun `a string id is served and echoed`() = runTest {
        val response = answer("""{"id":"abc","method":"ping"}""")

        assertEquals("\"abc\"", rawId(response))
        assertEquals(true, JSONObject(response).getJSONObject("result").getBoolean("pong"))
    }

    @Test
    fun `a string of digits stays a string`() = runTest {
        val response = answer("""{"id":"12","method":"ping"}""")

        assertEquals("\"12\"", rawId(response))
        assertEquals("12", JSONObject(response).get("id"))
    }

    @Test
    fun `an integer above Long MAX_VALUE is echoed digit for digit`() = runTest {
        val response = answer("""{"id":$UINT64_MAX,"method":"ping"}""")

        assertEquals(UINT64_MAX, rawId(response))
        assertTrue(JSONObject(response).has("result"))
    }

    @Test
    fun `an unknown method echoes the string id`() = runTest {
        val response = answer("""{"id":"abc","method":"no.suchMethod"}""")

        assertEquals("\"abc\"", rawId(response))
        assertEquals(ErrorCodes.METHOD_NOT_FOUND, errorCode(response))
    }

    @Test
    fun `a string id holding a comma and a brace is echoed whole`() = runTest {
        val response = answer("""{"id":"a,b}c","method":"ping"}""")

        assertEquals("a,b}c", JSONObject(response).getString("id"))
        assertTrue(JSONObject(response).has("result"))
    }

    @Test
    fun `an id after params is echoed`() = runTest {
        val response = answer("""{"method":"ping","params":{"id":7},"id":"abc"}""")

        assertEquals("\"abc\"", rawId(response))
        assertTrue(JSONObject(response).has("result"))
    }

    @Test
    fun `an object id is answered with a null id`() = runTest {
        val response = answer("""{"id":{"n":1},"method":"ping"}""")

        assertEquals("null", rawId(response))
        assertTrue(JSONObject(response).has("error"))
    }

    @Test
    fun `a fractional id is answered with a null id`() = runTest {
        val response = answer("""{"id":1.5,"method":"ping"}""")

        assertEquals("null", rawId(response))
        assertTrue(JSONObject(response).has("error"))
    }

    @Test
    fun `a missing id is answered with a null id`() = runTest {
        val response = answer("""{"method":"ping"}""")

        assertEquals("null", rawId(response))
        assertTrue(JSONObject(response).has("error"))
    }

    // -----------------------------------------------------------------
    // RpcId
    // -----------------------------------------------------------------

    @Test
    fun `RpcId reads and writes each id form unchanged`() {
        for (id in listOf("\"abc\"", "\"12\"", "0", "42", UINT64_MAX, "-9223372036854775808")) {
            val read = RpcId.read("""{"id":$id,"method":"ping"}""")!!
            assertEquals(id, read.toString())
            assertEquals(id, rawId(JSONObject().put("id", read.toJsonValue()).toString()))
        }
    }

    @Test
    fun `RpcId keeps a string of digits a string`() {
        assertEquals("12", RpcId.read("""{"id":"12"}""")!!.toJsonValue())
        assertEquals(null, RpcId.read("""{"id":"12"}""")!!.longValueOrNull())
        assertEquals(RpcId.of(12), RpcId.read("""{"id":12}"""))
    }

    @Test
    fun `RpcId reads an integer above Long MAX_VALUE digit for digit`() {
        val id = RpcId.read("""{"id":$UINT64_MAX}""")!!

        assertEquals(UINT64_MAX, id.toString())
        assertEquals(null, id.longValueOrNull())
    }

    @Test
    fun `RpcId caps an id at MAX_JSON_BYTES of its JSON form`() {
        val atCap = "\"" + "x".repeat(RpcId.MAX_JSON_BYTES - 2) + "\""
        val overCap = "\"" + "x".repeat(RpcId.MAX_JSON_BYTES - 1) + "\""

        assertEquals(atCap, RpcId.read("""{"id":$atCap}""")?.toString())
        assertEquals(null, RpcId.read("""{"id":$overCap}"""))
        assertEquals(null, RpcId.read("""{"id":${UINT64_MAX}0}"""))
    }

    @Test
    fun `the widest Long id is exactly MAX_JSON_BYTES`() {
        assertEquals(RpcId.MAX_JSON_BYTES, RpcId.of(Long.MIN_VALUE).toString().toByteArray(Charsets.UTF_8).size)
    }

    @Test
    fun `RpcId NULL writes a null id`() {
        assertEquals("""{"id":null}""", JSONObject().put("id", RpcId.NULL.toJsonValue()).toString())
        assertEquals(RpcId.NULL, RpcId.read("""{"id":null}"""))
        assertEquals(null, RpcId.read("""{"method":"ping"}"""))
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private suspend fun answer(request: String): String =
        String(handler.handleRawRequest(request.toByteArray(Charsets.UTF_8)), Charsets.UTF_8)

    private fun errorCode(response: String): Int = JSONObject(response).getJSONObject("error").getInt("code")

    private companion object {
        const val UINT64_MAX = "18446744073709551615"

        /** The top-level `id` member's value exactly as written, or null when absent. */
        fun rawId(json: String): String? {
            val top = JSONObject(json)
            if (!top.has("id")) return null
            // The answer's own members come first at depth one; nested ids sit inside result or error.
            return Regex(""""id":("(?:[^"\\]|\\.)*"|-?\d+|null)[,}]""").findAll(json)
                .map { it.groupValues[1] }
                .firstOrNull { depthAt(json, json.indexOf("\"id\":$it")) == 1 }
        }

        /** The object nesting depth at [offset] of [json], outside strings. */
        fun depthAt(json: String, offset: Int): Int {
            var depth = 0
            var inString = false
            var i = 0
            while (i < offset) {
                val c = json[i]
                when {
                    inString && c == '\\' -> i++
                    c == '"' -> inString = !inString
                    !inString && (c == '{' || c == '[') -> depth++
                    !inString && (c == '}' || c == ']') -> depth--
                }
                i++
            }
            return depth
        }
    }
}
