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

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream

/**
 * Unit tests for [StreamMessageFraming] — the 2-byte big-endian length-prefixed
 * framing shared by the USB and TCP pairing transports — and the
 * [MessageTooLargeException] it raises.
 */
class StreamMessageFramingTest {

    // ---- Framing round-trip ----

    @Test
    fun `write then read round-trips the payload`() {
        val payload = byteArrayOf(1, 2, 3, 4, 5, 42, -1, 0, 127)
        val out = ByteArrayOutputStream()
        StreamMessageFraming.writeMessage(out, payload)

        val read = StreamMessageFraming.readMessage(ByteArrayInputStream(out.toByteArray()))
        assertArrayEquals(payload, read)
    }

    @Test
    fun `empty payload round-trips`() {
        val out = ByteArrayOutputStream()
        StreamMessageFraming.writeMessage(out, ByteArray(0))

        // Header only: 0x00 0x00
        assertArrayEquals(byteArrayOf(0, 0), out.toByteArray())

        val read = StreamMessageFraming.readMessage(ByteArrayInputStream(out.toByteArray()))
        assertEquals(0, read.size)
    }

    @Test
    fun `header is 2-byte big-endian length`() {
        val out = ByteArrayOutputStream()
        StreamMessageFraming.writeMessage(out, ByteArray(0x0105) { 7 }) // length 261

        val framed = out.toByteArray()
        // 261 = 0x0105 -> big-endian [0x01, 0x05]
        assertEquals(0x01.toByte(), framed[0])
        assertEquals(0x05.toByte(), framed[1])
        assertEquals(2 + 261, framed.size)
    }

    @Test
    fun `max-size payload of 65535 round-trips`() {
        val payload = ByteArray(StreamMessageFraming.MAX_MESSAGE_SIZE) { (it and 0xFF).toByte() }
        val out = ByteArrayOutputStream()
        StreamMessageFraming.writeMessage(out, payload)

        // Header 0xFFFF + 65535 payload bytes
        assertEquals(2 + 65535, out.toByteArray().size)
        val read = StreamMessageFraming.readMessage(ByteArrayInputStream(out.toByteArray()))
        assertArrayEquals(payload, read)
    }

    @Test
    fun `writing more than 65535 bytes throws MessageTooLargeException`() {
        val tooLarge = ByteArray(StreamMessageFraming.MAX_MESSAGE_SIZE + 1)
        val ex = assertThrows(MessageTooLargeException::class.java) {
            StreamMessageFraming.writeMessage(ByteArrayOutputStream(), tooLarge)
        }
        assertTrue(ex.message!!.contains("65535"))
    }

    @Test
    fun `read reassembles a payload delivered one byte per read`() {
        val payload = byteArrayOf(10, 20, 30, 40, 50)
        val out = ByteArrayOutputStream()
        StreamMessageFraming.writeMessage(out, payload)

        // Stream that returns at most one byte per read() call, exercising readFully.
        val drip = object : InputStream() {
            private val data = out.toByteArray()
            private var pos = 0
            override fun read(): Int = if (pos < data.size) data[pos++].toInt() and 0xFF else -1
            override fun read(b: ByteArray, off: Int, len: Int): Int {
                if (pos >= data.size) return -1
                b[off] = data[pos++]
                return 1
            }
        }

        val read = StreamMessageFraming.readMessage(drip)
        assertArrayEquals(payload, read)
    }

    @Test
    fun `read on a truncated stream throws IOException`() {
        // Length prefix claims 4 bytes but only 2 are present.
        val truncated = byteArrayOf(0x00, 0x04, 0x11, 0x22)
        assertThrows(IOException::class.java) {
            StreamMessageFraming.readMessage(ByteArrayInputStream(truncated))
        }
    }

    // ---- Edges of the length prefix ----

    @Test
    fun `a zero length prefix returns an empty array and reads no further`() {
        val input = ByteArrayInputStream(byteArrayOf(0x00, 0x00, 0x05, 0x06))

        val read = StreamMessageFraming.readMessage(input)

        assertEquals(0, read.size)
        assertEquals("the next frame's bytes are left unread", 2, input.available())
    }

    @Test
    fun `a 0xFFFF prefix reads 65535 bytes`() {
        val body = ByteArray(65535) { (it * 31 and 0xFF).toByte() }
        val input = ByteArrayInputStream(byteArrayOf(0xFF.toByte(), 0xFF.toByte()) + body + byteArrayOf(0x7E))

        val read = StreamMessageFraming.readMessage(input)

        assertArrayEquals(body, read)
        assertEquals("only the frame is consumed", 1, input.available())
    }

    @Test
    fun `a header split across two reads is reassembled`() {
        val input = ChunkedInputStream(listOf(byteArrayOf(0x00), byteArrayOf(0x03, 0x0A, 0x0B, 0x0C)))

        val read = StreamMessageFraming.readMessage(input)

        assertArrayEquals(byteArrayOf(0x0A, 0x0B, 0x0C), read)
    }

    @Test
    fun `a stream that ends after one header byte throws IOException`() {
        assertThrows(IOException::class.java) {
            StreamMessageFraming.readMessage(ByteArrayInputStream(byteArrayOf(0x00)))
        }
    }

    @Test
    fun `writing 65536 bytes writes nothing before it throws`() {
        val out = ByteArrayOutputStream()

        assertThrows(MessageTooLargeException::class.java) {
            StreamMessageFraming.writeMessage(out, ByteArray(StreamMessageFraming.MAX_MESSAGE_SIZE + 1))
        }

        assertEquals("no header and no partial frame", 0, out.size())
    }

    /** Returns one of [chunks] per read call, however much the caller asks for. */
    private class ChunkedInputStream(chunks: List<ByteArray>) : InputStream() {
        private val pending = ArrayDeque(chunks.map { it.toMutableList() })

        override fun read(): Int {
            val chunk = pending.firstOrNull() ?: return -1
            val b = chunk.removeAt(0).toInt() and 0xFF
            if (chunk.isEmpty()) pending.removeFirst()
            return b
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (len == 0) return 0
            val chunk = pending.firstOrNull() ?: return -1
            var n = 0
            while (n < len && chunk.isNotEmpty()) b[off + n++] = chunk.removeAt(0)
            if (chunk.isEmpty()) pending.removeFirst()
            return n
        }
    }
}
