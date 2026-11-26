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
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import kotlinx.coroutines.test.runTest
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The pairing gate of a [StreamPairingSession] built without a paired-device
 * repository: it has no way to approve a peer, so it refuses every request
 * instead of serving them unpaired.
 */
class StreamPairingSessionGateTest {

    private lateinit var handler: RequestHandler
    private lateinit var pairing: StreamPairingSession

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
        handler = mockk(relaxed = true)
        pairing = StreamPairingSession(
            requestHandler = handler,
            messageRouter = null,
            pairingCallback = null,
            pairedDeviceRepository = null,
            transportLabel = "TEST",
        )
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun aRequestIsRefusedWithoutARepository() = runTest {
        val answer = pairing.interceptOrRoute(
            """{"jsonrpc":"2.0","id":7,"method":"local.getCapabilities"}""".toByteArray()
        )

        val error = errorOf(answer)
        assertEquals(ErrorCodes.PAIRING_REQUIRED, error.getInt("code"))
        coVerify(exactly = 0) { handler.handleRawRequest(any()) }
    }

    @Test
    fun pairingConfirmIsRefusedWithoutARepository() = runTest {
        val key = "ab".repeat(32)
        val answer = pairing.interceptOrRoute(
            """{"jsonrpc":"2.0","id":8,"method":"pairing.confirm","params":{"publicKeyHex":"$key","deviceName":"d"}}"""
                .toByteArray()
        )

        val code = errorOf(answer).getInt("code")
        assertTrue("code $code", code == ErrorCodes.PAIRING_REJECTED || code == ErrorCodes.PAIRING_REQUIRED)
        coVerify(exactly = 0) { handler.handleRawRequest(any()) }
    }

    private fun errorOf(answer: ByteArray?): JSONObject {
        assertNotNull("the request must be answered", answer)
        val envelope = JSONObject(String(answer!!, Charsets.UTF_8))
        return envelope.optJSONObject("error") ?: throw AssertionError("expected an error, got $envelope")
    }
}
