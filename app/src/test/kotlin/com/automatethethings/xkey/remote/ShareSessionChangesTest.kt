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
import kotlinx.coroutines.flow.take
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The sharing sheet follows the desktop session while it is open: a desktop
 * connecting, its peer being confirmed and it going away each emit, so the
 * sheet shows or hides its desktop section to match.
 */
class ShareSessionChangesTest {

    private lateinit var router: BidirectionalMessageRouter
    private lateinit var sender: ScriptedMessageSender
    private val peer = "ab".repeat(32)

    @Before
    fun setUp() {
        stubAndroidLog()
        router = BidirectionalMessageRouter(mockk<RequestHandler>())
        sender = ScriptedMessageSender(router)
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    /** The session as the service would snapshot it with [peerHex] confirmed on the connection. */
    private fun session(peerHex: String?): ShareSession {
        sender.confirmedPeer = peerHex
        return ShareSession.of(listOf(ShareSession.Transport(sender, router))) { true }!!
    }

    @Test
    fun `connect, confirm and disconnect each emit once`() = runTest {
        // What the service would answer on successive polls.
        val polls = ArrayDeque(
            listOf<ShareSession?>(
                null,                 // sheet opens, no desktop
                null,
                session(null),        // desktop connects, not yet confirmed
                session(null),
                session(peer),        // pairing confirmed
                session(peer),
                null                  // desktop goes away
            )
        )
        val seen = shareSessionChanges(periodMs = 100) { polls.removeFirstOrNull() }.take(4).toList()

        assertEquals(4, seen.size)
        assertNull(seen[0])
        assertSame(sender, seen[1]!!.sender)
        assertNull(seen[1]!!.peerPublicKeyHex)
        assertEquals(peer, seen[2]!!.peerPublicKeyHex)
        assertNull(seen[3])
    }

    /**
     * A transport may build a fresh sender on every lookup: sessions are told
     * apart by the connection their sender is bound to, never by the sender
     * object, so a fresh sender on one connection is the same session and a
     * sender on another connection is not.
     */
    @Test
    fun `fresh senders bound to one connection are one session`() {
        val connection = Any()
        fun freshSender(on: Any) = object : MessageSender {
            override val binding: Any get() = on
            override fun confirmedConnection() = ConfirmedConnection(peer, on)
            override suspend fun sendEncryptedMessage(data: ByteArray) = Unit
        }
        fun lookup(on: Any): ShareSession =
            ShareSession.of(listOf(ShareSession.Transport(freshSender(on), router))) { it.sameAs(lookup(on)) }!!

        val first = lookup(connection)
        val second = lookup(connection)
        assertNotSame(first.sender, second.sender)
        assertTrue("a fresh sender on the same connection is the same session", first.sameAs(second))
        assertTrue("the session stays current across fresh lookups", first.isCurrent())
        assertFalse("another connection is another session", first.sameAs(lookup(Any())))
    }

    @Test
    fun `a session moving to another transport emits`() = runTest {
        val otherRouter = BidirectionalMessageRouter(mockk<RequestHandler>())
        val other = ScriptedMessageSender(otherRouter).apply { confirmedPeer = peer }
        val moved = ShareSession.of(listOf(ShareSession.Transport(other, otherRouter))) { true }!!
        val polls = ArrayDeque(listOf<ShareSession?>(session(peer), session(peer), moved))
        val seen = shareSessionChanges(periodMs = 100) { polls.removeFirstOrNull() ?: moved }.take(2).toList()
        assertSame(sender, seen[0]!!.sender)
        assertSame(other, seen[1]!!.sender)
    }
}
