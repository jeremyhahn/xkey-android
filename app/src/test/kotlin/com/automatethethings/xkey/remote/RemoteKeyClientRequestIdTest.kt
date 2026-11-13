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
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test

/**
 * Request ids for [RemoteKeyClient] come from one counter per
 * [BidirectionalMessageRouter], so two clients on one router (the PIV screens
 * and device attestation) never register the same id in its pending table.
 */
class RemoteKeyClientRequestIdTest {

    private lateinit var router: BidirectionalMessageRouter
    private lateinit var sender: ScriptedMessageSender

    @Before
    fun setUp() {
        stubAndroidLog()
        router = BidirectionalMessageRouter(mockk<RequestHandler>())
        sender = ScriptedMessageSender(router)
        sender.succeedWith("""{"slots":[]}""")
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `two clients on one router never reuse a request id`() = runTest {
        val first = RemoteKeyClient(desktopOf(sender, router))
        val second = RemoteKeyClient(desktopOf(sender, router))

        first.pivListSlots()
        second.pivListSlots()
        first.pivListSlots()
        second.pivListSlots()

        val ids = sender.sent.map { it.id }
        assertEquals(ids.toString(), ids.size, ids.toSet().size)
    }

    @Test
    fun `a fresh router starts its ids at the base value`() = runTest {
        RemoteKeyClient(desktopOf(sender, router)).pivListSlots()

        assertEquals(1_000_000L, sender.lastRequest.id)
    }
}
