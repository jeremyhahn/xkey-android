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
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicBoolean

/**
 * One BLE client's FIDO request loop.
 *
 * Control point writes are reassembled into messages. PING is echoed; MSG is
 * handed to [handler] while KEEPALIVE frames (PROCESSING, or UP_NEEDED once
 * the handler waits for the user) go out every [keepaliveIntervalMillis];
 * CANCEL stops the pending MSG, which then answers
 * CTAP2_ERR_KEEPALIVE_CANCEL. One MSG runs at a time; another answers
 * ERR_BUSY. Replies are fragmented to [maxFrameSize].
 *
 * [onControlPointWrite] and [close] are called from one thread (the GATT
 * callback thread); [send] must queue frames in order.
 */
class FidoBleSession(
    private val handler: FidoMessageHandler,
    private val scope: CoroutineScope,
    private val send: (frame: ByteArray) -> Unit,
    private val maxFrameSize: () -> Int,
    private val keepaliveIntervalMillis: Long = KEEPALIVE_INTERVAL_MILLIS
) {
    private val reassembler = FidoBleReassembler()

    @Volatile
    private var pending: Job? = null

    @Volatile
    private var cancelRequested = false

    @Volatile
    private var closed = false

    fun onControlPointWrite(frame: ByteArray) {
        if (closed) return
        when (val result = reassembler.accept(frame)) {
            FidoBleReassembler.Result.Incomplete -> Unit
            is FidoBleReassembler.Result.Error -> send(FidoBle.errorFrame(result.code))
            is FidoBleReassembler.Result.Complete -> dispatch(result.command, result.data)
        }
    }

    /** Stop any pending request; nothing more is sent. */
    fun close() {
        closed = true
        pending?.cancel()
        pending = null
        reassembler.reset()
    }

    private fun dispatch(command: Byte, data: ByteArray) {
        when (command) {
            FidoBle.CMD_PING -> reply(FidoBle.CMD_PING, data)
            FidoBle.CMD_CANCEL -> pending?.let {
                cancelRequested = true
                it.cancel()
            }
            FidoBle.CMD_MSG -> {
                if (pending?.isActive == true) {
                    send(FidoBle.errorFrame(FidoBle.ERR_BUSY))
                    return
                }
                cancelRequested = false
                // ATOMIC: the body runs even when CANCEL lands before the
                // coroutine starts, so that request still gets its answer.
                pending = scope.launch(start = CoroutineStart.ATOMIC) { run(data) }
            }
            else -> send(FidoBle.errorFrame(FidoBle.ERR_INVALID_CMD))
        }
    }

    private suspend fun run(request: ByteArray) {
        val waitingForUser = AtomicBoolean(false)
        val keepalive = scope.launch {
            while (isActive) {
                delay(keepaliveIntervalMillis)
                if (closed) return@launch
                send(
                    FidoBle.keepaliveFrame(
                        if (waitingForUser.get()) FidoBle.KEEPALIVE_UP_NEEDED else FidoBle.KEEPALIVE_PROCESSING
                    )
                )
            }
        }
        // The one way a request ends: exactly one MSG response, whether the
        // authenticator answered, the client cancelled (even before the
        // request started) or the authenticator failed. Only a closed session
        // answers nothing.
        val response = try {
            handler.handle(request) { waitingForUser.set(true) }
        } catch (e: CancellationException) {
            if (!cancelRequested) throw e
            byteArrayOf(Ctap2.ERR_KEEPALIVE_CANCEL.toByte())
        } catch (e: Exception) {
            byteArrayOf(Ctap2.ERR_OTHER.toByte())
        } finally {
            keepalive.cancel()
        }
        if (!closed) reply(FidoBle.CMD_MSG, response)
    }

    private fun reply(command: Byte, data: ByteArray) {
        FidoBle.fragment(command, data, maxFrameSize()).forEach(send)
    }

    companion object {
        /** CTAP 2.1 asks for a KEEPALIVE at least every 500 ms while processing. */
        const val KEEPALIVE_INTERVAL_MILLIS = 400L
    }
}
