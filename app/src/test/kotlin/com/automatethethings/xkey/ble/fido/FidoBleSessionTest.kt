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

    private fun msgReplies() = sent.count { it[0] == FidoBle.CMD_MSG }

    @Test
    fun `CANCEL before the request starts still answers CTAP2_ERR_KEEPALIVE_CANCEL once`() = runTest {
        val session = session(GatedHandler())

        // No runCurrent between them: the request's coroutine has not run yet.
        write(session, FidoBle.CMD_MSG, byteArrayOf(0x02))
        write(session, FidoBle.CMD_CANCEL, ByteArray(0))
        runCurrent()
        advanceTimeBy(500)

        assertEquals("exactly one response", 1, msgReplies())
        assertArrayEquals(byteArrayOf(Ctap2.ERR_KEEPALIVE_CANCEL.toByte()), reply().data)
        assertTrue("no keepalive after the response", sent.last()[0] == FidoBle.CMD_MSG)
    }

    @Test
    fun `a handler that fails answers CTAP2_ERR_OTHER rather than nothing`() = runTest {
        val failing = object : FidoMessageHandler {
            override suspend fun handle(request: ByteArray, onUserActionNeeded: () -> Unit): ByteArray =
                throw IllegalStateException("Keystore unavailable")
        }
        val session = session(failing)

        write(session, FidoBle.CMD_MSG, byteArrayOf(0x02))
        runCurrent()

        assertEquals("exactly one response", 1, msgReplies())
        assertArrayEquals(byteArrayOf(Ctap2.ERR_OTHER.toByte()), reply().data)
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

    /**
     * A handler that, once cancelled, still has cleanup to finish (a prompt
     * to dismiss, a row to roll back) before it ends.
     */
    private class SlowUnwindHandler : FidoMessageHandler {
        val cleanup = CompletableDeferred<Unit>()
        override suspend fun handle(request: ByteArray, onUserActionNeeded: () -> Unit): ByteArray {
            try {
                kotlinx.coroutines.awaitCancellation()
            } finally {
                kotlinx.coroutines.withContext(kotlinx.coroutines.NonCancellable) { cleanup.await() }
            }
        }
    }

    @Test
    fun `a MSG while a cancelled request unwinds answers ERR_BUSY and the first still answers KEEPALIVE_CANCEL`() =
        runTest {
            val handler = SlowUnwindHandler()
            val session = session(handler)

            write(session, FidoBle.CMD_MSG, byteArrayOf(0x02))
            runCurrent()
            write(session, FidoBle.CMD_CANCEL, ByteArray(0))
            runCurrent()
            write(session, FidoBle.CMD_MSG, byteArrayOf(0x04))
            runCurrent()

            assertTrue(
                "the second MSG is refused while the first unwinds",
                sent.any { it.contentEquals(FidoBle.errorFrame(FidoBle.ERR_BUSY)) }
            )
            assertEquals("no response before cleanup ends", 0, msgReplies())

            handler.cleanup.complete(Unit)
            runCurrent()

            assertEquals("exactly one response", 1, msgReplies())
            assertArrayEquals(byteArrayOf(Ctap2.ERR_KEEPALIVE_CANCEL.toByte()), reply().data)
        }

    @Test
    fun `a MSG after the cancelled request has answered runs`() = runTest {
        val handler = SlowUnwindHandler()
        val second = GatedHandler()
        var calls = 0
        val session = session(object : FidoMessageHandler {
            override suspend fun handle(request: ByteArray, onUserActionNeeded: () -> Unit): ByteArray =
                if (calls++ == 0) handler.handle(request, onUserActionNeeded) else second.handle(request, onUserActionNeeded)
        })

        write(session, FidoBle.CMD_MSG, byteArrayOf(0x02))
        runCurrent()
        write(session, FidoBle.CMD_CANCEL, ByteArray(0))
        handler.cleanup.complete(Unit)
        runCurrent()
        sent.clear()
        write(session, FidoBle.CMD_MSG, byteArrayOf(0x04))
        runCurrent()
        second.gate.complete(byteArrayOf(0x00))
        runCurrent()

        assertTrue(sent.none { it.contentEquals(FidoBle.errorFrame(FidoBle.ERR_BUSY)) })
        assertArrayEquals(byteArrayOf(0x00), reply().data)
    }

    /**
     * Sends from real threads: the GATT callback thread for PING and the
     * dispatcher's for KEEPALIVE and the MSG reply, with a slow [onSend].
     */
    private fun threadedSession(
        handler: FidoMessageHandler,
        frames: MutableList<ByteArray>,
        onSend: (ByteArray) -> Unit
    ) = FidoBleSession(
        handler = handler,
        scope = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.Default),
        send = { onSend(it); synchronized(frames) { frames += it } },
        maxFrameSize = { 20 },
        keepaliveIntervalMillis = 10
    )

    /** True when every message's fragments arrived together, nothing between them. */
    private fun wholeMessages(frames: List<ByteArray>): Boolean {
        var remaining = 0
        for (f in frames) {
            val isInit = f[0].toInt() and 0x80 != 0
            if (remaining > 0) {
                if (isInit) return false
                remaining -= f.size - 1
            } else {
                if (!isInit) return false
                val length = ((f[1].toInt() and 0xFF) shl 8) or (f[2].toInt() and 0xFF)
                remaining = length - (f.size - 3)
            }
        }
        return remaining <= 0
    }

    @Test
    fun `a KEEPALIVE never lands between the fragments of another reply`() {
        val frames = mutableListOf<ByteArray>()
        var slowed = false
        val session = threadedSession(GatedHandler(), frames) { frame ->
            // Hold the PING reply after its first fragment, long enough for
            // several keepalive intervals: its first continuation (the only
            // ones sent while the MSG waits) is held before it is sent.
            if (frame[0].toInt() and 0x80 == 0 && !slowed) {
                slowed = true
                Thread.sleep(150)
            }
        }
        FidoBle.fragment(FidoBle.CMD_MSG, byteArrayOf(0x02), 20).forEach { session.onControlPointWrite(it) }
        Thread.sleep(50)

        FidoBle.fragment(FidoBle.CMD_PING, ByteArray(100) { 1 }, 20).forEach { session.onControlPointWrite(it) }
        Thread.sleep(50)
        session.close()

        val snapshot = synchronized(frames) { frames.toList() }
        assertTrue("fragments interleaved: ${snapshot.map { it[0] }}", wholeMessages(snapshot))
    }

    @Test
    fun `no KEEPALIVE follows the reply it was cancelled for`() {
        val frames = mutableListOf<ByteArray>()
        val handler = GatedHandler()
        var released = false
        val session = threadedSession(handler, frames) { frame ->
            // The reply becomes ready while a keepalive is being sent.
            if (frame[0] == FidoBle.CMD_KEEPALIVE && !released) {
                released = true
                handler.gate.complete(ByteArray(60) { 0x55 })
                Thread.sleep(100)
            }
        }
        FidoBle.fragment(FidoBle.CMD_MSG, byteArrayOf(0x02), 20).forEach { session.onControlPointWrite(it) }
        Thread.sleep(400)

        val snapshot = synchronized(frames) { frames.toList() }
        assertTrue("fragments interleaved: ${snapshot.map { it[0] }}", wholeMessages(snapshot))
        assertEquals("the reply is the last frame sent", FidoBle.CMD_MSG, snapshot.last { it[0].toInt() and 0x80 != 0 }[0])
        session.close()
    }
}
