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
package com.automatethethings.xkey.transport

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

/**
 * Length-prefixed message framing shared by the stream-based pairing transports
 * (USB Accessory and TCP).
 *
 * Frame format: `[2-byte big-endian length][payload]`. Each frame carries
 * exactly one Noise message. The 2-byte prefix caps a frame at
 * [MAX_MESSAGE_SIZE] (65535) bytes, which matches the Noise protocol's maximum
 * message size (flynn/noise `MaxMsgLen` on the go-xkms peer). A length cannot
 * exceed the maximum on read because two bytes encode at most 65535, so only
 * [writeMessage] needs to guard against oversize payloads.
 */
object StreamMessageFraming {
    /** Length prefix size in bytes. */
    const val LENGTH_PREFIX_SIZE = 2

    /**
     * Maximum frame payload size (65535 bytes), matching the Noise protocol
     * maximum message size enforced by the go-xkms peer (flynn/noise).
     */
    const val MAX_MESSAGE_SIZE = 65535

    /**
     * Reads a single length-prefixed message from [input].
     *
     * @return the framed payload (empty if the length prefix was zero).
     * @throws IOException if the stream closes before a full frame is read.
     */
    fun readMessage(input: InputStream): ByteArray {
        val lengthBuf = ByteArray(LENGTH_PREFIX_SIZE)
        readFully(input, lengthBuf)

        val length = ((lengthBuf[0].toInt() and 0xFF) shl 8) or (lengthBuf[1].toInt() and 0xFF)
        if (length == 0) {
            return ByteArray(0)
        }

        val payload = ByteArray(length)
        readFully(input, payload)
        return payload
    }

    /**
     * Writes [data] to [output] as a single length-prefixed message and flushes.
     *
     * @throws MessageTooLargeException if [data] exceeds [MAX_MESSAGE_SIZE].
     * @throws IOException if the write fails.
     */
    fun writeMessage(output: OutputStream, data: ByteArray) {
        if (data.size > MAX_MESSAGE_SIZE) {
            throw MessageTooLargeException(
                "Message length ${data.size} exceeds maximum $MAX_MESSAGE_SIZE"
            )
        }

        val header = byteArrayOf(
            ((data.size ushr 8) and 0xFF).toByte(),
            (data.size and 0xFF).toByte()
        )
        output.write(header)
        output.write(data)
        output.flush()
    }

    /**
     * Reads exactly [buffer].size bytes from [input], blocking until full.
     */
    private fun readFully(input: InputStream, buffer: ByteArray) {
        var offset = 0
        while (offset < buffer.size) {
            val bytesRead = input.read(buffer, offset, buffer.size - offset)
            if (bytesRead < 0) {
                throw IOException("Stream closed, read $offset of ${buffer.size} bytes")
            }
            offset += bytesRead
        }
    }
}
