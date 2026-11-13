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

import com.automatethethings.xkey.protocol.RequestHandler
import io.mockk.mockk
import io.mockk.unmockkAll
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Before
import org.junit.Test

/** JVM tests for request ids that outlive the [RemoteKeyClient] that took them. */
class RemoteKeyClientRequestIdsTest {

    private val router = BidirectionalMessageRouter(mockk<RequestHandler>())
    private val sender = ScriptedMessageSender(router)

    private fun backends(name: String) =
        """{"backends":[{"name":"$name","type":"tpm2","hardwareBacked":true,"signing":true,""" +
            """"decryption":false,"symmetricCrypto":false,"keyAgreement":false,"attestation":true}]}"""

    @Before
    fun setUp() = stubAndroidLog()

    @After
    fun tearDown() = unmockkAll()

    @Test
    fun `a replacement client on the same router never takes a cancelled request's reply`() = runTest {
        val cancelled = launch { RemoteKeyClient(sender, router).listBackends() }
        runCurrent()
        cancelled.cancel()
        runCurrent()

        // The first client is gone; a new one is built on the same live router.
        val second = async { RemoteKeyClient(sender, router).listBackends() }
        runCurrent()

        val (lateRequest, ownRequest) = sender.sent
        assertNotEquals(lateRequest.id, ownRequest.id)
        router.processMessage("""{"id":${lateRequest.id},"result":${backends("stale")}}""".toByteArray())
        router.processMessage("""{"id":${ownRequest.id},"result":${backends("tpm2")}}""".toByteArray())

        assertEquals("tpm2", second.await().single().name)
    }
}
