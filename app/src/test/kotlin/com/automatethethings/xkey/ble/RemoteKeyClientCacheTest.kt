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
package com.automatethethings.xkey.ble

import com.automatethethings.xkey.protocol.MethodNames
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.remote.BidirectionalMessageRouter
import com.automatethethings.xkey.remote.MessageSender
import com.automatethethings.xkey.remote.ScriptedMessageSender
import com.automatethethings.xkey.remote.stubAndroidLog
import io.mockk.mockk
import io.mockk.unmockkAll
import kotlinx.coroutines.async
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Before
import org.junit.Test

/** JVM tests for [RemoteKeyClientCache], the one `remote.*` client per desktop router. */
class RemoteKeyClientCacheTest {

    private val router = BidirectionalMessageRouter(mockk<RequestHandler>())
    private val sender = ScriptedMessageSender(router)
    private var transport: Pair<MessageSender, BidirectionalMessageRouter>? = sender to router
    private val cache = RemoteKeyClientCache { transport }

    @Before
    fun setUp() = stubAndroidLog()

    @After
    fun tearDown() = unmockkAll()

    @Test
    fun `no desktop session gives no client`() {
        transport = null
        assertNull(cache.client())
    }

    @Test
    fun `one router keeps one client and a new router gets a new one`() {
        val first = cache.client()
        assertSame(first, cache.client())
        val other = BidirectionalMessageRouter(mockk<RequestHandler>())
        transport = ScriptedMessageSender(other) to other
        assertNotSame(first, cache.client())
    }

    @Test
    fun `overlapping device attestation and listBackends each get their own reply`() = runTest {
        val attestation = async { cache.attestDevice(ByteArray(32)) }
        val backends = async { cache.client()!!.listBackends() }
        runCurrent()

        val attestRequest = sender.sent.single { it.method == MethodNames.REMOTE_ATTEST_DEVICE }
        val listRequest = sender.sent.single { it.method == MethodNames.REMOTE_LIST_BACKENDS }
        assertNotEquals(attestRequest.id, listRequest.id)
        val nonce = attestRequest.params!!.getString("nonce")

        router.processMessage(
            ("""{"id":${listRequest.id},"result":{"backends":[{"name":"tpm2","type":"tpm2",""" +
                """"hardwareBacked":true,"signing":true,"decryption":false,"symmetricCrypto":false,""" +
                """"keyAgreement":false,"attestation":true}]}}""").toByteArray()
        )
        router.processMessage(
            ("""{"id":${attestRequest.id},"result":{"format":"tpm2","certificateChain":[],""" +
                """"securityLevel":"tee","nonce":"$nonce","bootStateVerified":true}}""").toByteArray()
        )

        assertEquals("tpm2", backends.await().single().name)
        assertEquals("tee", attestation.await()!!.securityLevel)
    }
}
