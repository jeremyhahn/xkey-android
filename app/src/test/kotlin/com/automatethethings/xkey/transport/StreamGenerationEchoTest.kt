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
import com.automatethethings.xkey.ble.PairingConfirmationCallback
import com.automatethethings.xkey.protocol.ErrorCodes
import com.automatethethings.xkey.protocol.Request
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.protocol.Response
import com.automatethethings.xkey.protocol.TransportMethods
import com.automatethethings.xkey.settings.InMemorySharedPreferences
import com.automatethethings.xkey.settings.PairedDeviceRepository
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Every answer the stream transports write themselves, before or instead of
 * the shared handler, carries the request's `generation`: the desktop
 * matches a reply to its request by it, and an answer without it is dropped
 * as stale. Covers [StreamPairingSession]'s `rejectUnpaired`,
 * `handlePairingConfirm` (success and each refusal), `confirmAlreadyPaired`
 * and `routeTransportMethod`.
 */
class StreamGenerationEchoTest {

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

    // -----------------------------------------------------------------
    // Gated paths, driven without a connection
    // -----------------------------------------------------------------

    @Test
    fun rejectUnpairedEchoesTheGeneration() = runBlocking {
        val answer = gatedSession(PairedDeviceRepository(InMemorySharedPreferences()))
            .interceptOrRoute("""{"jsonrpc":"2.0","id":7,"generation":70,"method":"local.getCapabilities"}""".toByteArray())

        assertEquals("70", rawGeneration(answer))
        assertEquals(ErrorCodes.PAIRING_REQUIRED, errorCode(answer))
    }

    @Test
    fun pairingConfirmWithoutARepositoryEchoesTheGeneration() = runBlocking {
        val answer = gatedSession(null).interceptOrRoute(confirm(id = 8, generation = 80, key = "ab".repeat(32)))

        assertEquals("80", rawGeneration(answer))
        assertEquals(ErrorCodes.PAIRING_REJECTED, errorCode(answer))
    }

    @Test
    fun pairingConfirmWithoutAPeerIdentityEchoesTheGeneration() = runBlocking {
        val answer = gatedSession(PairedDeviceRepository(InMemorySharedPreferences()))
            .interceptOrRoute(confirm(id = 9, generation = 90, key = "ab".repeat(32)))

        assertEquals("90", rawGeneration(answer))
        assertEquals(ErrorCodes.PAIRING_REJECTED, errorCode(answer))
    }

    @Test
    fun confirmAlreadyPairedEchoesTheGeneration() {
        val answer = confirmAlreadyPaired(confirm(id = 10, generation = 100, key = "ab".repeat(32)))

        assertEquals("100", rawGeneration(answer))
        assertTrue(JSONObject(String(answer!!, Charsets.UTF_8)).getJSONObject("result").getBoolean("confirmed"))
    }

    // -----------------------------------------------------------------
    // Paths that need a handshaken desktop
    // -----------------------------------------------------------------

    @Test
    fun anApprovedPairingConfirmEchoesTheGeneration() = runBlocking {
        StreamSessionHarness(pairingCallback = callback(approve = true)).use { harness ->
            val desktop = harness.connectUnpaired()

            val reply = desktop.raw(confirmText(id = 11, generation = 110, key = desktop.publicKeyHex))

            assertEquals("110", rawGeneration(reply))
            assertTrue("expected success, got $reply", JSONObject(reply).has("result"))
            desktop.close()
        }
    }

    @Test
    fun aRejectedPairingConfirmEchoesTheGeneration() = runBlocking {
        StreamSessionHarness(pairingCallback = callback(approve = false)).use { harness ->
            val desktop = harness.connectUnpaired()

            val reply = desktop.raw(confirmText(id = 12, generation = 120, key = desktop.publicKeyHex))

            assertEquals("120", rawGeneration(reply))
            assertEquals(ErrorCodes.PAIRING_REJECTED, errorCode(reply))
            desktop.close()
        }
    }

    @Test
    fun aMismatchedPairingKeyEchoesTheGeneration() = runBlocking {
        StreamSessionHarness(pairingCallback = callback(approve = true)).use { harness ->
            val desktop = harness.connectUnpaired()

            val reply = desktop.raw(confirmText(id = 13, generation = 130, key = "cd".repeat(32)))

            assertEquals("130", rawGeneration(reply))
            assertEquals(ErrorCodes.PAIRING_REJECTED, errorCode(reply))
            desktop.close()
        }
    }

    @Test
    fun aPairingConfirmOnAConfirmedSessionEchoesTheGeneration() = runBlocking {
        StreamSessionHarness().use { harness ->
            val desktop = harness.connectPaired()

            val reply = desktop.raw(confirmText(id = 14, generation = 140, key = desktop.publicKeyHex))

            assertEquals("140", rawGeneration(reply))
            assertTrue("expected success, got $reply", JSONObject(reply).has("result"))
            desktop.close()
        }
    }

    @Test
    fun aTransportMethodEchoesTheGenerationOnSuccessAndError() = runBlocking {
        val family = object : TransportMethods {
            override fun handles(method: String) = method.startsWith("test.")
            override suspend fun handle(request: Request): Response =
                if (request.method == "test.ok") {
                    Response.success(request.id, JSONObject().put("ok", true))
                } else {
                    Response.error(request.id, ErrorCodes.INVALID_PARAMS, "refused")
                }
        }
        StreamSessionHarness(transportMethods = listOf(family)).use { harness ->
            val desktop = harness.connectPaired()

            val ok = desktop.raw("""{"jsonrpc":"2.0","id":15,"generation":150,"method":"test.ok"}""")
            val refused = desktop.raw("""{"jsonrpc":"2.0","id":16,"generation":160,"method":"test.no"}""")

            assertEquals("150", rawGeneration(ok))
            assertTrue(JSONObject(ok).getJSONObject("result").getBoolean("ok"))
            assertEquals("160", rawGeneration(refused))
            assertEquals(ErrorCodes.INVALID_PARAMS, errorCode(refused))
            desktop.close()
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

    private fun callback(approve: Boolean) = object : PairingConfirmationCallback {
        override suspend fun onPairingConfirmationRequired(deviceName: String, publicKeyFingerprint: String) = approve
    }

    /** Sends [json] exactly as written, so the `generation` literal is ours. */
    private fun DesktopPeer.raw(json: String): String {
        send(noise.encrypt(json.toByteArray()))
        return readEncrypted().toString()
    }

    private fun confirmText(id: Long, generation: Long, key: String) =
        """{"jsonrpc":"2.0","id":$id,"generation":$generation,"method":"pairing.confirm",""" +
            """"params":{"publicKeyHex":"$key","deviceName":"desktop"}}"""

    private fun confirm(id: Long, generation: Long, key: String) = confirmText(id, generation, key).toByteArray()

    private fun rawGeneration(answer: ByteArray?): String? {
        assertNotNull("the request must be answered", answer)
        return rawGeneration(String(answer!!, Charsets.UTF_8))
    }

    private fun errorCode(answer: ByteArray?): Int = errorCode(String(answer!!, Charsets.UTF_8))

    private fun errorCode(answer: String): Int =
        JSONObject(answer).optJSONObject("error")?.getInt("code")
            ?: throw AssertionError("expected an error, got $answer")

    private companion object {
        /** The `generation` member's number exactly as written, or null when absent. */
        fun rawGeneration(json: String): String? =
            Regex(""""generation":(\d+)[,}]""").find(json)?.groupValues?.get(1)
    }
}
