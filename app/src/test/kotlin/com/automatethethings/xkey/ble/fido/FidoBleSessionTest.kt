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

import com.automatethethings.xkey.testing.ThreadWait
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

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
    fun `an incomplete request times out with ERR_REQ_TIMEOUT and the next command on the connection runs`() = runTest {
        val session = session(GatedHandler())
        val ping = ByteArray(40) { it.toByte() }

        // Only the first fragment arrives; the rest never does.
        session.onControlPointWrite(FidoBle.fragment(FidoBle.CMD_PING, ping, 20).first())
        runCurrent()
        assertTrue("nothing is answered before the deadline", sent.isEmpty())
        advanceTimeBy(10_000)
        runCurrent()

        assertEquals(1, sent.size)
        assertArrayEquals(FidoBle.errorFrame(FidoBle.ERR_REQ_TIMEOUT), sent.single())

        sent.clear()
        write(session, FidoBle.CMD_PING, ping)
        runCurrent()
        advanceTimeBy(10_000)
        runCurrent()

        val echo = reply()
        assertEquals(FidoBle.CMD_PING, echo.command)
        assertArrayEquals(ping, echo.data)
        assertTrue("a whole request starts no timeout", sent.none { it[0] == FidoBle.CMD_ERROR })
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
     * The threads a threaded session runs on: a pool the test owns, so a
     * test can see each thread's state and wait until every coroutine the
     * session launched has finished.
     */
    private class Threaded(size: Int) : AutoCloseable {
        val threads: MutableList<Thread> = Collections.synchronizedList(mutableListOf())
        private val executor = Executors.newFixedThreadPool(size) { task ->
            Thread(task, "fido-session-test").also {
                it.isDaemon = true
                threads += it
            }
        }
        private val job = SupervisorJob()
        val scope = CoroutineScope(job + executor.asCoroutineDispatcher())

        /** Waits until the session's coroutines (requests, keepalive loops) have all ended. */
        fun awaitIdle() = runBlocking {
            withTimeout(ThreadWait.HANG_GUARD_MILLIS) {
                while (true) {
                    val running = job.children.toList()
                    if (running.isEmpty()) break
                    running.forEach { it.join() }
                }
            }
        }

        override fun close() {
            job.cancel()
            executor.shutdownNow()
        }
    }

    /**
     * Sends from real threads: the test thread for PING, as the GATT
     * callback thread does, and [threads] for KEEPALIVE and the MSG reply,
     * with [onSend] called before each frame is recorded.
     */
    private fun threadedSession(
        handler: FidoMessageHandler,
        frames: MutableList<ByteArray>,
        threads: Threaded,
        onSend: (ByteArray) -> Unit
    ) = FidoBleSession(
        handler = handler,
        scope = threads.scope,
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
        val firstKeepalive = CountDownLatch(1)
        val keepaliveAfterHold = CountDownLatch(1)
        val holding = AtomicBoolean(false)
        val held = AtomicBoolean(false)
        val keepaliveDuringHold = AtomicBoolean(false)
        Threaded(1).use { threads ->
            val session = threadedSession(GatedHandler(), frames, threads) { frame ->
                if (frame[0] == FidoBle.CMD_KEEPALIVE) {
                    if (holding.get()) keepaliveDuringHold.set(true)
                    if (held.get()) keepaliveAfterHold.countDown()
                    firstKeepalive.countDown()
                } else if (frame[0].toInt() and 0x80 == 0 && holding.compareAndSet(false, true)) {
                    // Hold the PING reply after its first fragment until a
                    // keepalive contends for the send: its thread waits on
                    // the send lock, or, were the lock missing, has sent.
                    ThreadWait.until("a KEEPALIVE contends with the PING reply") {
                        keepaliveDuringHold.get() || threads.threads.any { it.state == Thread.State.BLOCKED }
                    }
                    holding.set(false)
                    held.set(true)
                }
            }
            FidoBle.fragment(FidoBle.CMD_MSG, byteArrayOf(0x02), 20).forEach { session.onControlPointWrite(it) }
            ThreadWait.await(firstKeepalive, "the MSG's keepalive loop sends")

            FidoBle.fragment(FidoBle.CMD_PING, ByteArray(100) { 1 }, 20).forEach { session.onControlPointWrite(it) }
            ThreadWait.await(keepaliveAfterHold, "a KEEPALIVE goes once the PING reply is let through")
            session.close()
            threads.awaitIdle()
        }

        val snapshot = synchronized(frames) { frames.toList() }
        assertTrue("fragments interleaved: ${snapshot.map { it[0] }}", wholeMessages(snapshot))
    }

    @Test
    fun `no KEEPALIVE follows the reply it was cancelled for`() {
        val frames = mutableListOf<ByteArray>()
        val gate = CompletableDeferred<ByteArray>()
        val handlerThread = AtomicReference<Thread>()
        val handlerResumed = CountDownLatch(1)
        val handler = object : FidoMessageHandler {
            override suspend fun handle(request: ByteArray, onUserActionNeeded: () -> Unit): ByteArray {
                onUserActionNeeded()
                val reply = gate.await()
                handlerThread.set(Thread.currentThread())
                handlerResumed.countDown()
                return reply
            }
        }
        val replySent = CountDownLatch(1)
        val released = AtomicBoolean(false)
        Threaded(2).use { threads ->
            val session = threadedSession(handler, frames, threads) { frame ->
                // The reply becomes ready while a keepalive is being sent, and
                // this send is held until the handler has returned and waits
                // (for the keepalive loop to end, or for the send lock).
                if (frame[0] == FidoBle.CMD_KEEPALIVE && released.compareAndSet(false, true)) {
                    gate.complete(ByteArray(60) { 0x55 })
                    ThreadWait.await(handlerResumed, "the handler resumes on the other thread")
                    val waiting = setOf(Thread.State.WAITING, Thread.State.BLOCKED)
                    ThreadWait.until("the handler's thread waits for the keepalive") {
                        handlerThread.get().state in waiting
                    }
                }
                if (frame[0] == FidoBle.CMD_MSG) replySent.countDown()
            }
            FidoBle.fragment(FidoBle.CMD_MSG, byteArrayOf(0x02), 20).forEach { session.onControlPointWrite(it) }
            ThreadWait.await(replySent, "the MSG reply is sent")
            // Every coroutine of the session has ended: nothing can be sent after this.
            threads.awaitIdle()
            session.close()
        }

        val snapshot = synchronized(frames) { frames.toList() }
        assertTrue("fragments interleaved: ${snapshot.map { it[0] }}", wholeMessages(snapshot))
        assertEquals("the reply is the last frame sent", FidoBle.CMD_MSG, snapshot.last { it[0].toInt() and 0x80 != 0 }[0])
    }
}
