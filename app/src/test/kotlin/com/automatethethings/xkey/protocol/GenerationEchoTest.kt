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
import com.automatethethings.xkey.storage.entity.KeyEntity
import io.mockk.coEvery
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
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test

/**
 * Every response echoes its request's `generation` verbatim (#10, the phone
 * half of go-xkms#128): the initiator's router delivers a response only when
 * both `id` and `generation` match, so a response without it is dropped.
 *
 * This drives the real [RequestHandler] through [RequestHandler.handleRawRequest],
 * the entry every transport uses, and compares the response's raw JSON text:
 * a uint64 above [Long.MAX_VALUE] must come back as the same number, not a
 * string and not rounded through a Double. Only the handler's Android edges
 * are mocked, as in [AttestationPolicyCallerPeerTest].
 */
@OptIn(ExperimentalCoroutinesApi::class)
class GenerationEchoTest {

    private lateinit var keystoreManager: KeystoreManager
    private lateinit var keyDao: KeyDao
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

        keyDao = mockk(relaxed = true)
        val database = mockk<XKeyDatabase>(relaxed = true)
        // No key has a pending deletion.
        every { database.keyPolicyDao() } returns mockk<com.automatethethings.xkey.storage.dao.KeyPolicyDao>(relaxed = true) { io.mockk.coEvery { deletion(any()) } returns null }
        every { database.keyDao() } returns keyDao
        mockkObject(XKeyDatabase.Companion)
        every { XKeyDatabase.getInstance(any()) } returns database

        Dispatchers.setMain(UnconfinedTestDispatcher())

        val context = mockk<Context>(relaxed = true)
        every { context.getSystemService(Context.KEYGUARD_SERVICE) } returns
            mockk<KeyguardManager>(relaxed = true)
        every { context.getSystemService(NotificationManager::class.java) } returns
            mockk<NotificationManager>(relaxed = true)

        keystoreManager = mockk(relaxed = true)
        handler = RequestHandler(
            context = context,
            keystoreManager = keystoreManager,
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
    // Success, one method of each handler family
    // -----------------------------------------------------------------

    @Test
    fun `a base method echoes the generation on success`() = runTest {
        val response = answer("""{"id":1,"generation":42,"method":"ping"}""")

        assertEquals("42", rawGeneration(response))
        assertEquals(true, JSONObject(response).getJSONObject("result").getBoolean("pong"))
    }

    @Test
    fun `a local method echoes the generation on success`() = runTest {
        coEvery { keyDao.getByKeyId("k1") } returns mockk<KeyEntity>(relaxed = true)
        every { keystoreManager.getPublicKeyPEM("k1") } returns "PEM"

        val response = answer(
            """{"id":2,"generation":43,"method":"local.getPublicKey","params":{"keyId":"k1","format":"${ExportFormats.PEM}"}}"""
        )

        assertEquals("43", rawGeneration(response))
        assertEquals("PEM", JSONObject(response).getJSONObject("result").getString("publicKey"))
    }

    // -----------------------------------------------------------------
    // Errors, one of each kind
    // -----------------------------------------------------------------

    @Test
    fun `an unknown method echoes the generation`() = runTest {
        val response = answer("""{"id":3,"generation":44,"method":"local.definitelyNotAMethod"}""")

        assertEquals("44", rawGeneration(response))
        assertEquals(ErrorCodes.METHOD_NOT_FOUND, errorCode(response))
        assertEquals(3L, JSONObject(response).getLong("id"))
    }

    @Test
    fun `invalid params echo the generation`() = runTest {
        val response = answer("""{"id":4,"generation":45,"method":"local.getPublicKey"}""")

        assertEquals("45", rawGeneration(response))
        assertEquals(ErrorCodes.INVALID_PARAMS, errorCode(response))
    }

    @Test
    fun `a handler error echoes the generation`() = runTest {
        coEvery { keyDao.getByKeyId("missing") } returns null

        val response = answer(
            """{"id":5,"generation":46,"method":"local.getPublicKey","params":{"keyId":"missing"}}"""
        )

        assertEquals("46", rawGeneration(response))
        assertEquals(ErrorCodes.KEY_NOT_FOUND, errorCode(response))
    }

    @Test
    fun `an internal error echoes the generation`() = runTest {
        coEvery { keyDao.getByKeyId("boom") } throws IllegalStateException("database closed")

        val response = answer(
            """{"id":6,"generation":47,"method":"local.getPublicKey","params":{"keyId":"boom"}}"""
        )

        assertEquals("47", rawGeneration(response))
        assertEquals(ErrorCodes.INTERNAL_ERROR, errorCode(response))
    }

    // -----------------------------------------------------------------
    // The value range: a uint64, digit for digit
    // -----------------------------------------------------------------

    @Test
    fun `zero round-trips exactly`() = runTest {
        assertEquals("0", rawGeneration(answer("""{"id":7,"generation":0,"method":"ping"}""")))
    }

    @Test
    fun `Long MAX_VALUE round-trips exactly`() = runTest {
        val response = answer("""{"id":8,"generation":${Long.MAX_VALUE},"method":"ping"}""")

        assertEquals(Long.MAX_VALUE.toString(), rawGeneration(response))
    }

    @Test
    fun `the largest uint64 round-trips exactly`() = runTest {
        val response = answer("""{"id":9,"generation":$UINT64_MAX,"method":"ping"}""")

        assertEquals(UINT64_MAX, rawGeneration(response))
    }

    @Test
    fun `a generation after the params is still echoed`() = runTest {
        val response = answer("""{"id":10,"method":"ping","params":{"generation":1},"generation":$UINT64_MAX}""")

        assertEquals(UINT64_MAX, rawGeneration(response))
    }

    // -----------------------------------------------------------------
    // Nothing to echo
    // -----------------------------------------------------------------

    @Test
    fun `a request without a generation gets a response without one`() = runTest {
        val response = answer("""{"id":11,"method":"ping"}""")

        assertFalse(JSONObject(response).has(GENERATION_KEY))
        assertFalse(response.contains(GENERATION_KEY))
    }

    @Test
    fun `an error to a request without a generation carries none`() = runTest {
        val response = answer("""{"id":12,"method":"local.definitelyNotAMethod"}""")

        assertFalse(response.contains(GENERATION_KEY))
    }

    @Test
    fun `a generation inside params is not the request's`() = runTest {
        val response = answer("""{"id":13,"method":"ping","params":{"generation":5}}""")

        assertFalse(response.contains(GENERATION_KEY))
    }

    // -----------------------------------------------------------------
    // Requests that do not parse
    // -----------------------------------------------------------------

    @Test
    fun `a request missing its id echoes the generation with id 0`() = runTest {
        val response = answer("""{"generation":48,"method":"ping"}""")

        assertEquals("48", rawGeneration(response))
        assertEquals(0L, JSONObject(response).getLong("id"))
        assertEquals(ErrorCodes.INTERNAL_ERROR, errorCode(response))
    }

    @Test
    fun `a request truncated after its generation still echoes it`() = runTest {
        val response = answer("""{"id":14,"generation":$UINT64_MAX,"method":""")

        assertEquals(UINT64_MAX, rawGeneration(response))
    }

    @Test
    fun `a request malformed before its generation carries none`() = runTest {
        val response = answer("""{"id":15,,"generation":49,"method":"ping"}""")

        assertFalse(response.contains(GENERATION_KEY))
    }

    @Test
    fun `text that is not JSON gets an error without a generation`() = runTest {
        val response = answer("not json")

        assertFalse(response.contains(GENERATION_KEY))
    }

    // -----------------------------------------------------------------
    // readGeneration and the envelope
    // -----------------------------------------------------------------

    @Test
    fun `readGeneration reads only a top-level uint64`() {
        assertEquals(0uL, readGeneration("""{"generation":0}"""))
        assertEquals(ULong.MAX_VALUE, readGeneration("""{ "id" : 1 , "generation" : $UINT64_MAX }"""))
        assertNull(readGeneration("""{"id":1}"""))
        assertNull(readGeneration("""{"params":{"generation":1}}"""))
        assertNull(readGeneration("""{"generation":"7"}"""))
        assertNull(readGeneration("""{"generation":-1}"""))
        assertNull(readGeneration("""{"generation":1.5}"""))
        assertNull(readGeneration("""{"generation":1e3}"""))
        assertNull(readGeneration("""{"generation":07}"""))
        assertNull(readGeneration("""{"generation":18446744073709551616}"""))
        assertNull(readGeneration("""{"generation":null}"""))
        assertNull(readGeneration("[1]"))
        assertNull(readGeneration(""))
    }

    @Test
    fun `Response toJsonString writes the generation as a number`() {
        val text = Response.success(1, JSONObject(), generation = ULong.MAX_VALUE).toJsonString()

        assertEquals(UINT64_MAX, rawGeneration(text))
        assertEquals(ULong.MAX_VALUE, Response.fromJson(text).generation)
    }

    private suspend fun answer(request: String): String =
        String(handler.handleRawRequest(request.toByteArray(Charsets.UTF_8)), Charsets.UTF_8)

    private fun errorCode(response: String): Int = JSONObject(response).getJSONObject("error").getInt("code")

    private companion object {
        const val UINT64_MAX = "18446744073709551615"

        /** The `generation` member's number exactly as written, or null when it is absent or not a number. */
        fun rawGeneration(json: String): String? =
            Regex(""""generation":(\d+)[,}]""").find(json)?.groupValues?.get(1)
    }
}
