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

import java.io.ByteArrayOutputStream
import java.util.UUID

/**
 * FIDO BLE transport constants and framing (CTAP 2.1, section "Bluetooth
 * Smart / Bluetooth Low Energy Technology").
 *
 * A message is one CMD frame `CMD | HLEN | LLEN | DATA` followed by as many
 * CONT frames `SEQ | DATA` as it needs. CMD has its high bit set; SEQ counts
 * from 0 to 0x7F and wraps to 0. A frame is at most the client's
 * fidoControlPointLength when the client writes, and the ATT MTU less three
 * when the authenticator notifies.
 */
object FidoBle {

    /** The FIDO GATT service, 16-bit UUID 0xFFFD. */
    val SERVICE_UUID: UUID = UUID.fromString("0000fffd-0000-1000-8000-00805f9b34fb")

    /** Client writes request frames here (write). */
    val CONTROL_POINT_UUID: UUID = UUID.fromString("f1d0fff1-deaf-adda-1234-56789abcdef0")

    /** The authenticator notifies response frames here (notify). */
    val STATUS_UUID: UUID = UUID.fromString("f1d0fff2-deaf-adda-1234-56789abcdef0")

    /** Largest frame the client may write, 2 bytes big-endian (read). */
    val CONTROL_POINT_LENGTH_UUID: UUID = UUID.fromString("f1d0fff3-deaf-adda-1234-56789abcdef0")

    /** Protocol versions offered and selected, one byte (read, write). */
    val SERVICE_REVISION_BITFIELD_UUID: UUID = UUID.fromString("f1d0fff4-deaf-adda-1234-56789abcdef0")

    /** Client Characteristic Configuration descriptor. */
    val CCCD_UUID: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

    /** fidoServiceRevisionBitfield bit for FIDO2 (CTAP2); U2F is not offered. */
    const val SERVICE_REVISION_FIDO2: Byte = 0x20

    const val CMD_PING: Byte = 0x81.toByte()
    const val CMD_KEEPALIVE: Byte = 0x82.toByte()
    const val CMD_MSG: Byte = 0x83.toByte()
    const val CMD_CANCEL: Byte = 0xBE.toByte()
    const val CMD_ERROR: Byte = 0xBF.toByte()

    const val ERR_INVALID_CMD = 0x01
    const val ERR_INVALID_PAR = 0x02
    const val ERR_INVALID_LEN = 0x03
    const val ERR_INVALID_SEQ = 0x04
    const val ERR_REQ_TIMEOUT = 0x05
    const val ERR_BUSY = 0x06
    const val ERR_OTHER = 0x7F

    const val KEEPALIVE_PROCESSING = 0x01
    const val KEEPALIVE_UP_NEEDED = 0x02

    /** Largest message, request or response, this authenticator accepts. */
    const val MAX_MESSAGE_SIZE = 1024

    /** Largest frame a client may write; 512 is the largest ATT attribute value. */
    const val CONTROL_POINT_LENGTH = 512

    /** Smallest usable frame: the 3-byte CMD header plus one data byte. */
    private const val MIN_FRAME_SIZE = 4

    /**
     * Split [data] into a CMD frame and CONT frames of at most [maxFrameSize]
     * bytes each.
     */
    fun fragment(command: Byte, data: ByteArray, maxFrameSize: Int): List<ByteArray> {
        require(maxFrameSize >= MIN_FRAME_SIZE) { "frame size $maxFrameSize is below $MIN_FRAME_SIZE" }
        require(data.size <= 0xFFFF) { "message of ${data.size} bytes exceeds the 16-bit length" }
        val frames = mutableListOf<ByteArray>()
        val first = minOf(data.size, maxFrameSize - 3)
        frames += byteArrayOf(command, (data.size shr 8).toByte(), data.size.toByte()) +
            data.copyOfRange(0, first)
        var offset = first
        var seq = 0
        while (offset < data.size) {
            val n = minOf(data.size - offset, maxFrameSize - 1)
            frames += byteArrayOf(seq.toByte()) + data.copyOfRange(offset, offset + n)
            offset += n
            seq = (seq + 1) and 0x7F
        }
        return frames
    }

    /** An ERROR frame carrying [code]. */
    fun errorFrame(code: Int): ByteArray = byteArrayOf(CMD_ERROR, 0, 1, code.toByte())

    /** A KEEPALIVE frame carrying [status]. */
    fun keepaliveFrame(status: Int): ByteArray = byteArrayOf(CMD_KEEPALIVE, 0, 1, status.toByte())
}

/**
 * Reassembles the frames a client writes to fidoControlPoint into messages.
 *
 * An error drops the message in progress; the caller answers the client with
 * [FidoBle.errorFrame] and the next message starts with a fresh CMD frame.
 */
class FidoBleReassembler(private val maxMessageSize: Int = FidoBle.MAX_MESSAGE_SIZE) {

    sealed interface Result {
        /** More CONT frames are expected. */
        object Incomplete : Result

        /** A whole message arrived. */
        class Complete(val command: Byte, val data: ByteArray) : Result

        /** The frame broke the framing rules; [code] is a FIDO BLE error code. */
        data class Error(val code: Int) : Result
    }

    private var command: Byte = 0
    private var expected = 0
    private var nextSeq = 0
    private var buffer: ByteArrayOutputStream? = null

    fun accept(frame: ByteArray): Result {
        if (frame.isEmpty()) return fail(FidoBle.ERR_INVALID_LEN)
        val first = frame[0].toInt() and 0xFF
        return if (first and 0x80 != 0) acceptCommand(frame) else acceptContinuation(frame, first)
    }

    fun reset() {
        buffer = null
        expected = 0
        nextSeq = 0
    }

    private fun acceptCommand(frame: ByteArray): Result {
        if (buffer != null) return fail(FidoBle.ERR_INVALID_SEQ)
        if (frame.size < 3) return fail(FidoBle.ERR_INVALID_LEN)
        val length = ((frame[1].toInt() and 0xFF) shl 8) or (frame[2].toInt() and 0xFF)
        val carried = frame.size - 3
        if (length > maxMessageSize || carried > length) return fail(FidoBle.ERR_INVALID_LEN)
        if (carried == length) return Result.Complete(frame[0], frame.copyOfRange(3, frame.size))
        command = frame[0]
        expected = length
        nextSeq = 0
        buffer = ByteArrayOutputStream(length).apply { write(frame, 3, carried) }
        return Result.Incomplete
    }

    private fun acceptContinuation(frame: ByteArray, seq: Int): Result {
        val current = buffer ?: return fail(FidoBle.ERR_INVALID_SEQ)
        if (seq != nextSeq) return fail(FidoBle.ERR_INVALID_SEQ)
        val carried = frame.size - 1
        if (current.size() + carried > expected) return fail(FidoBle.ERR_INVALID_LEN)
        current.write(frame, 1, carried)
        nextSeq = (nextSeq + 1) and 0x7F
        if (current.size() < expected) return Result.Incomplete
        val done = Result.Complete(command, current.toByteArray())
        reset()
        return done
    }

    private fun fail(code: Int): Result {
        reset()
        return Result.Error(code)
    }
}
