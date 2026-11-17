/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
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

package com.automatethethings.xkey.ble.fido

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The FIDO BLE request loop: reassemble the client's control point writes,
 * answer PING, run MSG through the CTAP2 authenticator with KEEPALIVE frames
 * while it waits, stop it on CANCEL, and fragment every reply to the
 * notification size.
 */
class FidoBleSessionTest {

    private val sent = mutableListOf<ByteArray>()

    /** A CTAP2 handler that waits on [gate] and reports a user action pending. */
    private class GatedHandler : FidoMessageHandler {
        val gate = CompletableDeferred<ByteArray>()
        var cancelled = false
        override suspend fun handle(request: ByteArray, onUserActionNeeded: () -> Unit): ByteArray {
            onUserActionNeeded()
            try {
                return gate.await()
            } catch (e: kotlinx.coroutines.CancellationException) {
                cancelled = true
                throw e
            }
        }
    }

    private fun TestScope.session(handler: FidoMessageHandler, frameSize: Int = 20) =
        FidoBleSession(
            handler = handler,
            scope = backgroundScope,
            send = { sent += it },
            maxFrameSize = { frameSize },
            keepaliveIntervalMillis = 100
        )

    private fun write(session: FidoBleSession, command: Byte, data: ByteArray, frameSize: Int = 20) =
        FidoBle.fragment(command, data, frameSize).forEach { session.onControlPointWrite(it) }

    private fun reply(): FidoBleReassembler.Result.Complete {
        val r = FidoBleReassembler()
        var result: FidoBleReassembler.Result = FidoBleReassembler.Result.Incomplete
        sent.filter { it[0] != FidoBle.CMD_KEEPALIVE }.forEach { result = r.accept(it) }
        return result as FidoBleReassembler.Result.Complete
    }

    @Test
    fun `PING is echoed`() = runTest {
        val session = session(GatedHandler())

        write(session, FidoBle.CMD_PING, ByteArray(40) { it.toByte() })
        runCurrent()

        val echo = reply()
        assertEquals(FidoBle.CMD_PING, echo.command)
        assertArrayEquals(ByteArray(40) { it.toByte() }, echo.data)
    }

    @Test
    fun `MSG is answered with the authenticator's response in frames of the notification size`() = runTest {
        val handler = GatedHandler()
        val session = session(handler, frameSize = 23)
        val response = ByteArray(100) { 0x55 }

        write(session, FidoBle.CMD_MSG, byteArrayOf(0x04), frameSize = 23)
        runCurrent()
        handler.gate.complete(response)
        runCurrent()

        assertTrue(sent.all { it.size <= 23 })
        val msg = reply()
        assertEquals(FidoBle.CMD_MSG, msg.command)
        assertArrayEquals(response, msg.data)
    }

    @Test
    fun `KEEPALIVE frames report UP_NEEDED while the authenticator waits for the user`() = runTest {
        val handler = GatedHandler()
        val session = session(handler)

        write(session, FidoBle.CMD_MSG, byteArrayOf(0x02))
        runCurrent()
        advanceTimeBy(350)

        val keepalives = sent.filter { it[0] == FidoBle.CMD_KEEPALIVE }
        assertTrue("expected keepalives, got ${keepalives.size}", keepalives.size >= 3)
        keepalives.forEach {
            assertArrayEquals(FidoBle.keepaliveFrame(FidoBle.KEEPALIVE_UP_NEEDED), it)
        }

        handler.gate.complete(byteArrayOf(0))
        runCurrent()
        val after = sent.size
        advanceTimeBy(500)
        assertEquals("no keepalive after the reply", after, sent.size)
    }

    @Test
    fun `CANCEL stops the pending request, which answers CTAP2_ERR_KEEPALIVE_CANCEL`() = runTest {
        val handler = GatedHandler()
        val session = session(handler)

        write(session, FidoBle.CMD_MSG, byteArrayOf(0x02))
        runCurrent()
        write(session, FidoBle.CMD_CANCEL, ByteArray(0))
        runCurrent()

        assertTrue(handler.cancelled)
        val msg = reply()
        assertEquals(FidoBle.CMD_MSG, msg.command)
        assertArrayEquals(byteArrayOf(Ctap2.ERR_KEEPALIVE_CANCEL.toByte()), msg.data)
    }

    @Test
    fun `CANCEL with no request pending sends nothing`() = runTest {
        val session = session(GatedHandler())

        write(session, FidoBle.CMD_CANCEL, ByteArray(0))
        runCurrent()

        assertTrue(sent.isEmpty())
    }

    @Test
    fun `a second MSG while one is pending answers ERR_BUSY`() = runTest {
        val session = session(GatedHandler())

        write(session, FidoBle.CMD_MSG, byteArrayOf(0x02))
        runCurrent()
        sent.clear()
        write(session, FidoBle.CMD_MSG, byteArrayOf(0x04))
        runCurrent()

        assertArrayEquals(FidoBle.errorFrame(FidoBle.ERR_BUSY), sent.first { it[0] != FidoBle.CMD_KEEPALIVE })
    }

    @Test
    fun `an unknown command answers ERR_INVALID_CMD`() = runTest {
        val session = session(GatedHandler())

        session.onControlPointWrite(byteArrayOf(0x90.toByte(), 0, 0))
        runCurrent()

        assertArrayEquals(FidoBle.errorFrame(FidoBle.ERR_INVALID_CMD), sent.single())
    }

    @Test
    fun `a framing error answers an ERROR frame with its code`() = runTest {
        val session = session(GatedHandler())

        session.onControlPointWrite(byteArrayOf(0x05, 1, 2))
        runCurrent()

        assertArrayEquals(FidoBle.errorFrame(FidoBle.ERR_INVALID_SEQ), sent.single())
    }

    @Test
    fun `close cancels a pending request and sends nothing more`() = runTest {
        val handler = GatedHandler()
        val session = session(handler)

        write(session, FidoBle.CMD_MSG, byteArrayOf(0x02))
        runCurrent()
        session.close()
        runCurrent()
        val after = sent.size
        advanceTimeBy(500)

        assertTrue(handler.cancelled)
        assertEquals(after, sent.size)
        assertTrue(sent.none { it[0] == FidoBle.CMD_MSG })
    }
}
