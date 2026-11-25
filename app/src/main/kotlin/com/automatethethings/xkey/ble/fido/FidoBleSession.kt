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

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/**
 * One BLE client's FIDO request loop.
 *
 * Control point writes are reassembled into messages. PING is echoed; MSG is
 * handed to [handler] while KEEPALIVE frames (PROCESSING, or UP_NEEDED once
 * the handler waits for the user) go out every [keepaliveIntervalMillis];
 * CANCEL stops the pending MSG, which then answers
 * CTAP2_ERR_KEEPALIVE_CANCEL. One MSG runs at a time, until it has cleaned up
 * and its response goes out; another answers ERR_BUSY. Replies are fragmented
 * to [maxFrameSize], and every message's frames reach [send] together. A
 * request not received whole within [reassemblyTimeoutMillis] of its first
 * frame answers ERROR ERR_REQ_TIMEOUT and is dropped.
 *
 * [onControlPointWrite] and [close] are called from one thread (the GATT
 * callback thread); [send] must queue frames in order and must not call back
 * into the session.
 */
class FidoBleSession(
    private val handler: FidoMessageHandler,
    private val scope: CoroutineScope,
    private val send: (frame: ByteArray) -> Unit,
    private val maxFrameSize: () -> Int,
    private val keepaliveIntervalMillis: Long = KEEPALIVE_INTERVAL_MILLIS,
    private val reassemblyTimeoutMillis: Long = REASSEMBLY_TIMEOUT_MILLIS
) {
    private val reassembler = FidoBleReassembler()

    /**
     * One MSG, from dispatch until it has sent its one response and finished
     * its cleanup. The cancel flag is this request's own, so a MSG arriving
     * while a cancelled one unwinds cannot clear it.
     */
    private class Request {
        @Volatile
        var cancelRequested = false

        @Volatile
        var job: Job? = null
    }

    /** The request in flight; cleared only by that request, as its response goes out or it ends. */
    private val current = AtomicReference<Request?>(null)

    /** Held while one whole message's frames are handed to [send]. */
    private val sendLock = Any()

    @Volatile
    private var closed = false

    /** Expires the message being reassembled; null when no message is partly received. */
    private var reassemblyDeadline: Job? = null

    fun onControlPointWrite(frame: ByteArray) = synchronized(this) {
        if (closed) return@synchronized
        when (val result = reassembler.accept(frame)) {
            FidoBleReassembler.Result.Incomplete -> startReassemblyDeadline()
            is FidoBleReassembler.Result.Error -> {
                stopReassemblyDeadline()
                sendMessage(listOf(FidoBle.errorFrame(result.code)))
            }
            is FidoBleReassembler.Result.Complete -> {
                stopReassemblyDeadline()
                dispatch(result.command, result.data)
            }
        }
    }

    /**
     * The CTAP BLE framing timeout: a message must arrive whole within
     * [reassemblyTimeoutMillis] of its first frame. Otherwise the client is
     * answered ERROR ERR_REQ_TIMEOUT and the partial message is dropped, so
     * the next command on this connection starts afresh. Caller holds the
     * session lock.
     */
    private fun startReassemblyDeadline() {
        if (reassemblyDeadline != null) return
        reassemblyDeadline = scope.launch {
            delay(reassemblyTimeoutMillis)
            val deadline = coroutineContext[Job]
            synchronized(this@FidoBleSession) {
                // A newer message or a finished one owns the deadline now.
                if (closed || reassemblyDeadline !== deadline) return@synchronized
                reassemblyDeadline = null
                reassembler.reset()
                sendMessage(listOf(FidoBle.errorFrame(FidoBle.ERR_REQ_TIMEOUT)))
            }
        }
    }

    /** Caller holds the session lock. */
    private fun stopReassemblyDeadline() {
        reassemblyDeadline?.cancel()
        reassemblyDeadline = null
    }

    /** Stop any pending request; nothing more is sent. */
    fun close() = synchronized(this) {
        closed = true
        stopReassemblyDeadline()
        current.get()?.job?.cancel()
        reassembler.reset()
    }

    private fun dispatch(command: Byte, data: ByteArray) {
        when (command) {
            FidoBle.CMD_PING -> reply(FidoBle.CMD_PING, data)
            FidoBle.CMD_CANCEL -> current.get()?.let {
                it.cancelRequested = true
                it.job?.cancel()
            }
            FidoBle.CMD_MSG -> {
                // Busy until the request in flight has answered and cleaned
                // up, cancelled or not: not merely until its job is cancelled.
                val request = Request()
                if (!current.compareAndSet(null, request)) {
                    sendMessage(listOf(FidoBle.errorFrame(FidoBle.ERR_BUSY)))
                    return
                }
                // ATOMIC: the body runs even if CANCEL lands first, so the request is answered.
                request.job = scope.launch(start = CoroutineStart.ATOMIC) { run(request, data) }
            }
            else -> sendMessage(listOf(FidoBle.errorFrame(FidoBle.ERR_INVALID_CMD)))
        }
    }

    private suspend fun run(request: Request, data: ByteArray) {
        try {
            val waitingForUser = AtomicBoolean(false)
            val keepalive = scope.launch {
                while (isActive) {
                    delay(keepaliveIntervalMillis)
                    sendMessage(
                        listOf(
                            FidoBle.keepaliveFrame(
                                if (waitingForUser.get()) FidoBle.KEEPALIVE_UP_NEEDED else FidoBle.KEEPALIVE_PROCESSING
                            )
                        )
                    )
                }
            }
            // Exactly one MSG response per request, unless the session is closed.
            val response = try {
                handler.handle(data) { waitingForUser.set(true) }
            } catch (e: CancellationException) {
                if (!request.cancelRequested) throw e
                byteArrayOf(Ctap2.ERR_KEEPALIVE_CANCEL.toByte())
            } catch (e: Exception) {
                byteArrayOf(Ctap2.ERR_OTHER.toByte())
            } finally {
                // Joined, so no keepalive is sent after the response.
                withContext(NonCancellable) { keepalive.cancelAndJoin() }
            }
            val frames = FidoBle.fragment(FidoBle.CMD_MSG, response, maxFrameSize())
            synchronized(sendLock) {
                // Free before the frames leave: the client may write its next MSG as soon as it has them.
                current.compareAndSet(request, null)
                if (!closed) frames.forEach(send)
            }
        } finally {
            current.compareAndSet(request, null)
        }
    }

    private fun reply(command: Byte, data: ByteArray) = sendMessage(FidoBle.fragment(command, data, maxFrameSize()))

    /**
     * The one way frames leave the session: all of one message's frames
     * (MSG, PING, ERROR and KEEPALIVE alike) are handed to [send] under one
     * lock, so no other message's frame lands between them. Nothing is sent
     * once the session is closed.
     */
    private fun sendMessage(frames: List<ByteArray>) = synchronized(sendLock) {
        if (!closed) frames.forEach(send)
    }

    companion object {
        /** CTAP 2.1 asks for a KEEPALIVE at least every 500 ms while processing. */
        const val KEEPALIVE_INTERVAL_MILLIS = 400L

        /** How long a message may take to arrive whole, from its first frame. */
        const val REASSEMBLY_TIMEOUT_MILLIS = 3_000L
    }
}
