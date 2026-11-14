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

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/** The per-connection sender cache: one sender per live connection, gone with its connection. */
class ConnectionSendersTest {

    private class Conn { var live = true }

    private val zeroed = mutableListOf<Conn>()
    private val senders = ConnectionSenders<Conn> { zeroed += it }

    private fun lookup(c: Conn) = senders.senderFor(c, { it.live }) { _ ->
        object : SessionSender {
            override suspend fun sendEncryptedMessage(data: ByteArray) = Unit
        }
    }

    @Test
    fun `lookups on one live connection share one sender`() {
        val c = Conn()
        assertSame(lookup(c), lookup(c))
        assertTrue(senders.holds(c))
    }

    @Test
    fun `another connection replaces the entry`() {
        val a = Conn()
        val b = Conn()
        val first = lookup(a)
        assertNotSame(first, lookup(b))
        assertFalse(senders.holds(a))
        assertTrue(senders.holds(b))
    }

    @Test
    fun `an ended connection gets no sender and caches none`() {
        val c = Conn().apply { live = false }
        assertNull(lookup(c))
        assertTrue(senders.isEmpty)
    }

    @Test
    fun `retiring a connection drops its sender and zeroes its keys`() = runBlocking {
        val c = Conn()
        lookup(c)
        c.live = false
        senders.retire(c)
        assertTrue(senders.isEmpty)
        assertEquals(listOf(c), zeroed)
        assertNull("no lookup re-caches it", lookup(c))
    }

    @Test
    fun `retiring another connection keeps the live one's sender`() = runBlocking {
        val current = Conn()
        val ended = Conn().apply { live = false }
        val sender = lookup(current)
        senders.retire(ended)
        assertSame(sender, lookup(current))
        assertEquals(listOf(ended), zeroed)
    }
}
