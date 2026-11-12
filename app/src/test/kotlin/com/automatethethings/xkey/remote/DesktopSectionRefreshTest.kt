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
 * after a disconnect, nor applies a decision taken on a replaced session,
 * and a key that fails to load is reported instead of escaping the refresh.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class DesktopSectionRefreshTest {

    private lateinit var router: BidirectionalMessageRouter
    private lateinit var sender: ScriptedMessageSender
    private val peerA = "aa".repeat(32)
    private val peerB = "bb".repeat(32)

    /** What the section showed, in order; null is hidden. */
    private val shown = mutableListOf<DesktopShareDecision?>()
    /** The load failures the section reported, in order. */
    private val failures = mutableListOf<Throwable>()
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
        show = { shown += it },
        failed = { failures += it }
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

    @Test
    fun `a key that fails to load is reported and never escapes the refresh`() = runTest {
        val refresh = refresher()
        current = session(peerA)
        refresh.refresh()
        runCurrent()

        // e.g. the desktop deleted the software key between the store's
        // existence check and its read
        decision(peerA).completeExceptionally(java.io.IOException("the key file is gone"))
        advanceUntilIdle()

        assertEquals(emptyList<DesktopShareDecision?>(), shown)
        assertEquals("the key file is gone", failures.single().message)
    }

    @Test
    fun `a load failure on a replaced session decides again on the new one`() = runTest {
        val refresh = refresher()
        current = session(peerA)
        refresh.refresh()
        runCurrent()

        current = session(peerB) // not yet seen by the watcher
        decision(peerA).completeExceptionally(java.io.IOException("the key file is gone"))
        runCurrent()
        decision(peerB).complete(DesktopShareDecision.PUBLIC_KEY)
        advanceUntilIdle()

        assertEquals(listOf<DesktopShareDecision?>(DesktopShareDecision.PUBLIC_KEY), shown)
        assertEquals(emptyList<Throwable>(), failures)
    }

    @Test
    fun `a cancelled refresh reports no failure`() = runTest {
        val refresh = refresher()
        current = session(peerA)
        refresh.refresh()
        runCurrent()

        refresh.cancel()
        advanceUntilIdle()

        assertEquals(emptyList<DesktopShareDecision?>(), shown)
        assertEquals(emptyList<Throwable>(), failures)
    }
}
