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

import com.automatethethings.xkey.protocol.MethodNames
import com.automatethethings.xkey.protocol.RequestHandler
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
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/** JVM tests for [DesktopSessions]: one key client per router, and who is on which transport. */
class DesktopSessionsTest {

    private val desktopA = "aa".repeat(32)
    private val desktopB = "bb".repeat(32)

    /** One transport's router and the scripted desktop behind it. */
    private class Link {
        val router = BidirectionalMessageRouter(mockk<RequestHandler>())
        val sender = ScriptedMessageSender(router)
        fun transport(established: Boolean = true) = DesktopTransport(sender, router, established)
    }

    private val ble = Link()
    private val tcp = Link()
    private var live: List<DesktopTransport> = listOf(ble.transport())
    private var confirmed: String? = desktopA
    private val sessions = DesktopSessions({ live }, { confirmed })

    private val backendsReply =
        """{"backends":[{"name":"tpm2","type":"tpm2","hardwareBacked":true,"signing":true,""" +
            """"decryption":false,"symmetricCrypto":false,"keyAgreement":false,"attestation":true}]}"""

    @Before
    fun setUp() = stubAndroidLog()

    @After
    fun tearDown() = unmockkAll()

    @Test
    fun `no desktop session gives no client and no session`() {
        live = emptyList()
        assertNull(sessions.client())
        assertNull(sessions.session())
    }

    @Test
    fun `one router keeps one client and another router gets its own`() {
        val first = sessions.client()
        assertSame(first, sessions.client())
        live = listOf(tcp.transport())
        assertNotSame(first, sessions.client())
    }

    @Test
    fun `the session pairs the confirmed peer with the client of its own transport`() = runTest {
        live = listOf(tcp.transport())
        confirmed = desktopB
        val session = sessions.session()!!
        assertEquals(desktopB, session.peerPublicKeyHex)
        tcp.sender.succeedWith(backendsReply)
        session.client.listBackends()
        assertEquals(1, tcp.sender.sent.size)
        assertTrue(ble.sender.sent.isEmpty())
    }

    @Test
    fun `A on BLE and B confirmed on TCP never yields B with A's client`() {
        live = listOf(ble.transport(), tcp.transport())
        confirmed = desktopB
        assertNull(sessions.session())

        // B still handshaking on TCP: the confirmed field may be about to change hands.
        live = listOf(ble.transport(), tcp.transport(established = false))
        confirmed = desktopA
        assertNull(sessions.session())

        // A session not yet established names nobody.
        live = listOf(tcp.transport(established = false))
        assertNull(sessions.session())
    }

    @Test
    fun `A then B then A keeps the reply of A's outstanding request`() = runTest {
        val first = async { sessions.client()!!.listBackends() }
        runCurrent()
        live = listOf(tcp.transport())
        sessions.client()
        live = listOf(ble.transport())
        val second = async { sessions.client()!!.listKeys("tpm2") }
        runCurrent()

        val (firstRequest, secondRequest) = ble.sender.sent
        assertNotEquals(firstRequest.id, secondRequest.id)
        ble.router.processMessage("""{"id":${firstRequest.id},"result":$backendsReply}""".toByteArray())
        ble.router.processMessage("""{"id":${secondRequest.id},"result":{"keys":[]}}""".toByteArray())

        assertEquals("tpm2", first.await().single().name)
        assertTrue(second.await().isEmpty())
    }

    @Test
    fun `device attestation goes only to the named peer`() = runTest {
        assertNull(sessions.attestDevice(desktopB, ByteArray(32)))
        assertTrue(ble.sender.sent.isEmpty())
    }

    @Test
    fun `overlapping device attestation and listBackends each get their own reply`() = runTest {
        val attestation = async { sessions.attestDevice(desktopA, ByteArray(32)) }
        val backends = async { sessions.client()!!.listBackends() }
        runCurrent()

        val attestRequest = ble.sender.sent.single { it.method == MethodNames.REMOTE_ATTEST_DEVICE }
        val listRequest = ble.sender.sent.single { it.method == MethodNames.REMOTE_LIST_BACKENDS }
        assertNotEquals(attestRequest.id, listRequest.id)
        val nonce = attestRequest.params!!.getString("nonce")

        ble.router.processMessage("""{"id":${listRequest.id},"result":$backendsReply}""".toByteArray())
        ble.router.processMessage(
            ("""{"id":${attestRequest.id},"result":{"format":"tpm2","certificateChain":[],""" +
                """"securityLevel":"tee","nonce":"$nonce","bootStateVerified":true}}""").toByteArray()
        )

        assertEquals("tpm2", backends.await().single().name)
        assertEquals("tee", attestation.await()!!.securityLevel)
    }
}
