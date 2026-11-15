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

import android.content.Context
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.sync.SyncEngine
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.unmockkAll
import kotlinx.coroutines.test.runTest
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The row's routing rule, end to end on one router: the phone's `remote.*`
 * requests (key operations, sync, PIV) go out on the desktop's session and
 * their replies come back to the waiting client, never to the phone's own
 * handler; a `local.*` request from the desktop goes to the phone's handler
 * and nothing is sent to the desktop.
 */
class RemoteLocalRoutingTest {

    private lateinit var handler: RequestHandler
    private lateinit var router: BidirectionalMessageRouter
    private lateinit var desktop: ScriptedMessageSender
    private lateinit var context: Context

    private val localAnswer = """{"jsonrpc":"2.0","id":7,"result":{"keys":[]}}"""

    @Before
    fun setUp() {
        stubAndroidLog()
        mockkConstructor(SyncEngine::class)
        context = mockk()
        every { context.applicationContext } returns context

        handler = mockk()
        coEvery { handler.handleRawRequest(any()) } returns localAnswer.toByteArray(Charsets.UTF_8)
        router = BidirectionalMessageRouter(handler)
        desktop = ScriptedMessageSender(router)
        desktop.replyWith { request ->
            val result = when (request.method) {
                "remote.listKeys" -> """{"keys":[{"keyId":"k1","backend":"tpm2","algorithm":"rsa-2048"}]}"""
                "remote.syncStatus" -> """{"device_id":"desk-1","store_checksums":null}"""
                "remote.pivListSlots" -> """{"slots":[{"slot":"9a","has_key":true,"has_certificate":false}]}"""
                else -> error("the desktop got ${request.method}")
            }
            """{"id":${request.id},"result":$result}"""
        }
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `remote key, sync and PIV requests go to the desktop and their replies return to the client`() = runTest {
        val session = desktopOf(desktop, router)
        val keys = RemoteKeyClient(session, requestTimeoutMs = 5_000L)
        val sync = RemoteSyncClient(context, session, requestTimeoutMs = 5_000L)

        assertEquals("k1", keys.listKeys("tpm2").single().keyId)
        assertEquals("desk-1", sync.syncStatus().deviceId)
        assertEquals("9a", keys.pivListSlots().single().slot)

        assertEquals(
            listOf("remote.listKeys", "remote.syncStatus", "remote.pivListSlots"),
            desktop.sent.map { it.method }
        )
        coVerify(exactly = 0) { handler.handleRawRequest(any()) }
    }

    @Test
    fun `a local request from the desktop goes to the phone's handler and nothing to the desktop`() = runTest {
        val request = JSONObject().put("jsonrpc", "2.0").put("id", 7).put("method", "local.listKeys")
            .toString().toByteArray(Charsets.UTF_8)

        val answer = router.processMessage(request)

        assertEquals(localAnswer, answer?.toString(Charsets.UTF_8))
        coVerify(exactly = 1) { handler.handleRawRequest(request) }
        assertTrue("nothing goes to the desktop", desktop.sent.isEmpty())
    }
}
