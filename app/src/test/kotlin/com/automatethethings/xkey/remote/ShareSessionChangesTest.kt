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
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
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

    private fun session(peerHex: String?): ShareSession =
        ShareSession.of(listOf(ShareSession.Transport(sender, router)), peerHex) { true }!!

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

    @Test
    fun `a session moving to another transport emits`() = runTest {
        val otherRouter = BidirectionalMessageRouter(mockk<RequestHandler>())
        val other = ScriptedMessageSender(otherRouter)
        val moved = ShareSession.of(listOf(ShareSession.Transport(other, otherRouter)), peer) { true }!!
        val polls = ArrayDeque(listOf<ShareSession?>(session(peer), session(peer), moved))
        val seen = shareSessionChanges(periodMs = 100) { polls.removeFirstOrNull() ?: moved }.take(2).toList()
        assertSame(sender, seen[0]!!.sender)
        assertSame(other, seen[1]!!.sender)
    }
}
