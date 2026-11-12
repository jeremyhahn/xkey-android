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
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test

/**
 * The sharing sheet's desktop section shows only what the live session
 * allows: a refresh suspended in its decision never re-shows the section
 * after a disconnect, nor applies a decision taken on a replaced session.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class DesktopSectionRefreshTest {

    private lateinit var router: BidirectionalMessageRouter
    private lateinit var sender: ScriptedMessageSender
    private val peerA = "aa".repeat(32)
    private val peerB = "bb".repeat(32)

    /** What the section showed, in order; null is hidden. */
    private val shown = mutableListOf<DesktopShareDecision?>()
    private val decisions = mutableMapOf<String?, CompletableDeferred<DesktopShareDecision>>()
    private var current: ShareSession? = null

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

    /** A session on a fresh connection that confirms [peerHex]. */
    private fun session(peerHex: String?): ShareSession {
        sender.confirmedPeer = peerHex
        sender.connection = Any()
        return ShareSession.of(listOf(ShareSession.Transport(sender, router))) { true }!!
    }

    private fun decision(peerHex: String?) = decisions.getOrPut(peerHex) { CompletableDeferred() }

    private fun TestScope.refresher() = DesktopSectionRefresh(
        scope = this,
        currentSession = { current },
        decide = { s -> decision(s.peerPublicKeyHex).await() },
        show = { shown += it }
    )

    @Test
    fun `a disconnect overtaking a suspended refresh leaves the section hidden`() = runTest {
        val refresh = refresher()
        current = session(peerA)
        refresh.refresh()
        runCurrent() // suspended in its decision

        current = null // the desktop disconnects; the watcher refreshes
        refresh.refresh()
        decision(peerA).complete(DesktopShareDecision.PUBLIC_KEY)
        advanceUntilIdle()

        assertEquals(listOf<DesktopShareDecision?>(null), shown)
    }

    @Test
    fun `a disconnect the watcher has not seen yet still keeps the section hidden`() = runTest {
        val refresh = refresher()
        current = session(peerA)
        refresh.refresh()
        runCurrent()

        current = null // no refresh yet: the next poll is 500 ms away
        decision(peerA).complete(DesktopShareDecision.PUBLIC_KEY)
        advanceUntilIdle()

        assertEquals(listOf<DesktopShareDecision?>(null), shown)
    }

    @Test
    fun `a decision taken on a replaced session is never applied`() = runTest {
        val refresh = refresher()
        current = session(peerA)
        refresh.refresh()
        runCurrent()

        current = session(peerB) // another desktop is confirmed
        refresh.refresh()
        decision(peerB).complete(DesktopShareDecision.POLICY_DENIED)
        advanceUntilIdle()
        decision(peerA).complete(DesktopShareDecision.PUBLIC_KEY)
        advanceUntilIdle()

        assertEquals(listOf<DesktopShareDecision?>(DesktopShareDecision.POLICY_DENIED), shown)
    }
}
