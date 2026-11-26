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
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.settings.InMemorySharedPreferences
import com.automatethethings.xkey.settings.PairedDeviceRepository
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import java.lang.reflect.InvocationTargetException
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Every answer the stream transports write themselves carries the request's
 * `id` exactly as the desktop sent it: a JSON-RPC client matches an answer to
 * its request by that value, so a string id must come back as the same
 * string (not -1, not a number) and an integer wider than a Long must come
 * back digit for digit. Covers [StreamPairingSession]'s `rejectUnpaired`,
 * the repeated `pairing.confirm` refusal, `handlePairingConfirm`'s refusals
 * and `confirmAlreadyPaired`.
 */
class StreamIdEchoTest {

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
        unmockkAll()
    }

    @Test
    fun rejectUnpairedEchoesTheIdAsSent() = runBlocking {
        for (id in IDS) {
            val answer = gatedSession(PairedDeviceRepository(InMemorySharedPreferences()))
                .interceptOrRoute("""{"jsonrpc":"2.0","id":$id,"method":"local.getCapabilities"}""".toByteArray())

            assertEquals(id, rawId(answer))
            assertEquals(ErrorCodes.PAIRING_REQUIRED, errorCode(answer))
        }
    }

    @Test
    fun theRepeatedPairingConfirmRefusalEchoesTheIdAsSent() {
        val session = gatedSession(PairedDeviceRepository(InMemorySharedPreferences()))
        val refuse = StreamPairingSession::class.java
            .getDeclaredMethod("refuseRepeatedConfirm", ByteArray::class.java)
            .apply { isAccessible = true }
        for (id in IDS) {
            val answer = try {
                refuse.invoke(session, confirm(id, "ab".repeat(32))) as ByteArray
            } catch (e: InvocationTargetException) {
                throw e.targetException
            }

            assertEquals(id, rawId(answer))
            assertEquals(ErrorCodes.PAIRING_REJECTED, errorCode(answer))
        }
    }

    @Test
    fun pairingConfirmWithoutAStoreEchoesTheIdAsSent() = runBlocking {
        for (id in IDS) {
            val answer = gatedSession(null).interceptOrRoute(confirm(id, "ab".repeat(32)))

            assertEquals(id, rawId(answer))
            assertEquals(ErrorCodes.PAIRING_REJECTED, errorCode(answer))
        }
    }

    @Test
    fun pairingConfirmWithoutAPeerIdentityEchoesTheIdAsSent() = runBlocking {
        for (id in IDS) {
            val answer = gatedSession(PairedDeviceRepository(InMemorySharedPreferences()))
                .interceptOrRoute(confirm(id, "ab".repeat(32)))

            assertEquals(id, rawId(answer))
            assertEquals(ErrorCodes.PAIRING_REJECTED, errorCode(answer))
        }
    }

    @Test
    fun confirmAlreadyPairedEchoesTheIdAsSent() {
        for (id in IDS) {
            val answer = confirmAlreadyPaired(confirm(id, "ab".repeat(32)))

            assertEquals(id, rawId(answer))
            assertTrue(JSONObject(String(answer!!, Charsets.UTF_8)).getJSONObject("result").getBoolean("confirmed"))
        }
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private fun gatedSession(repo: PairedDeviceRepository?) = StreamPairingSession(
        requestHandler = mockk<RequestHandler>(relaxed = true),
        messageRouter = null,
        pairingCallback = null,
        pairedDeviceRepository = repo,
        transportLabel = "TEST",
    )

    /** A pairing.confirm whose `id` member is the JSON text [id], exactly as written. */
    private fun confirm(id: String, key: String) =
        ("""{"jsonrpc":"2.0","id":$id,"method":"pairing.confirm",""" +
            """"params":{"publicKeyHex":"$key","deviceName":"desktop"}}""").toByteArray()

    private fun rawId(answer: ByteArray?): String? {
        assertNotNull("the request must be answered", answer)
        return rawId(String(answer!!, Charsets.UTF_8))
    }

    private fun errorCode(answer: ByteArray?): Int {
        val text = String(answer!!, Charsets.UTF_8)
        return JSONObject(text).optJSONObject("error")?.getInt("code")
            ?: throw AssertionError("expected an error, got $text")
    }

    private companion object {
        /** The ids sent, as JSON text: a string, a string of digits, and uint64 max. */
        val IDS = listOf("\"abc\"", "\"12\"", "18446744073709551615")

        /** The `id` member's value exactly as written, or null when absent. */
        fun rawId(json: String): String? =
            Regex(""""id":("(?:[^"\\]|\\.)*"|-?\d+|null)[,}]""").find(json)?.groupValues?.get(1)
    }
}
