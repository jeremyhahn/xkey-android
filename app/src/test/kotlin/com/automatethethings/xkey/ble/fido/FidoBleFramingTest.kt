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

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * FIDO BLE framing (CTAP 2.1, "Bluetooth Smart / Bluetooth Low Energy
 * Technology", framing): a CMD frame `CMD | HLEN | LLEN | DATA` followed by
 * CONT frames `SEQ | DATA`, SEQ counting from 0.
 */
class FidoBleFramingTest {

    private fun message(size: Int) = ByteArray(size) { (it * 7 + 3).toByte() }

    @Test
    fun `a message that fits one frame is a single CMD frame`() {
        val frames = FidoBle.fragment(FidoBle.CMD_MSG, byteArrayOf(1, 2, 3), maxFrameSize = 20)

        assertEquals(1, frames.size)
        assertArrayEquals(byteArrayOf(0x83.toByte(), 0, 3, 1, 2, 3), frames[0])
    }

    @Test
    fun `a long message is a CMD frame and CONT frames with rising sequence numbers`() {
        val data = message(50)
        val frames = FidoBle.fragment(FidoBle.CMD_MSG, data, maxFrameSize = 20)

        // CMD carries 17 bytes, each CONT 19: 17 + 19 + 14.
        assertEquals(3, frames.size)
        assertEquals(20, frames[0].size)
        assertEquals(0x83.toByte(), frames[0][0])
        assertEquals(0.toByte(), frames[0][1])
        assertEquals(50.toByte(), frames[0][2])
        assertEquals(0.toByte(), frames[1][0])
        assertEquals(20, frames[1].size)
        assertEquals(1.toByte(), frames[2][0])
        assertEquals(15, frames[2].size)
    }

    @Test
    fun `an empty message is a CMD frame with zero length`() {
        val frames = FidoBle.fragment(FidoBle.CMD_PING, ByteArray(0), maxFrameSize = 20)

        assertEquals(1, frames.size)
        assertArrayEquals(byteArrayOf(0x81.toByte(), 0, 0), frames[0])
    }

    @Test
    fun `fragments reassemble into the original message`() {
        val data = message(300)
        val reassembler = FidoBleReassembler()
        val frames = FidoBle.fragment(FidoBle.CMD_MSG, data, maxFrameSize = 23)

        frames.dropLast(1).forEach {
            assertEquals(FidoBleReassembler.Result.Incomplete, reassembler.accept(it))
        }
        val done = reassembler.accept(frames.last()) as FidoBleReassembler.Result.Complete

        assertEquals(FidoBle.CMD_MSG, done.command)
        assertArrayEquals(data, done.data)
    }

    @Test
    fun `the sequence number wraps from 0x7F to 0`() {
        // A CMD frame with one data byte, then 129 CONT frames of three:
        // SEQ runs 0..0x7F, then 0.
        val data = message(1 + 3 * 129)
        val frames = FidoBle.fragment(FidoBle.CMD_MSG, data, maxFrameSize = 4)
        assertEquals(130, frames.size)
        assertEquals(0x7F.toByte(), frames[128][0])
        assertEquals(0.toByte(), frames[129][0])

        val reassembler = FidoBleReassembler(maxMessageSize = 1024)
        var result: FidoBleReassembler.Result = FidoBleReassembler.Result.Incomplete
        frames.forEach { result = reassembler.accept(it) }
        assertArrayEquals(data, (result as FidoBleReassembler.Result.Complete).data)
    }

    @Test
    fun `a declared length over the maximum is refused with ERR_INVALID_LEN`() {
        val reassembler = FidoBleReassembler(maxMessageSize = 100)

        val result = reassembler.accept(byteArrayOf(0x83.toByte(), 0, 101, 1, 2))

        assertEquals(FidoBleReassembler.Result.Error(FidoBle.ERR_INVALID_LEN), result)
    }

    @Test
    fun `a CMD frame shorter than its header is refused with ERR_INVALID_LEN`() {
        val result = FidoBleReassembler().accept(byteArrayOf(0x83.toByte(), 0))

        assertEquals(FidoBleReassembler.Result.Error(FidoBle.ERR_INVALID_LEN), result)
    }

    @Test
    fun `a CMD frame carrying more data than it declares is refused with ERR_INVALID_LEN`() {
        val result = FidoBleReassembler().accept(byteArrayOf(0x83.toByte(), 0, 1, 1, 2))

        assertEquals(FidoBleReassembler.Result.Error(FidoBle.ERR_INVALID_LEN), result)
    }

    @Test
    fun `a CONT frame out of sequence is refused with ERR_INVALID_SEQ and the message dropped`() {
        val reassembler = FidoBleReassembler()
        val frames = FidoBle.fragment(FidoBle.CMD_MSG, message(60), maxFrameSize = 20)

        reassembler.accept(frames[0])
        val result = reassembler.accept(frames[2])

        assertEquals(FidoBleReassembler.Result.Error(FidoBle.ERR_INVALID_SEQ), result)
        // The partial message is gone: its next CONT frame has no CMD frame.
        assertEquals(
            FidoBleReassembler.Result.Error(FidoBle.ERR_INVALID_SEQ),
            reassembler.accept(frames[1])
        )
    }

    @Test
    fun `a CONT frame with no CMD frame before it is refused with ERR_INVALID_SEQ`() {
        val result = FidoBleReassembler().accept(byteArrayOf(0, 1, 2))

        assertEquals(FidoBleReassembler.Result.Error(FidoBle.ERR_INVALID_SEQ), result)
    }

    @Test
    fun `a new CMD frame in the middle of a message is refused with ERR_INVALID_SEQ`() {
        val reassembler = FidoBleReassembler()
        val frames = FidoBle.fragment(FidoBle.CMD_MSG, message(60), maxFrameSize = 20)

        reassembler.accept(frames[0])
        val result = reassembler.accept(frames[0])

        assertEquals(FidoBleReassembler.Result.Error(FidoBle.ERR_INVALID_SEQ), result)
    }

    @Test
    fun `a CANCEL frame completes at once with no data`() {
        val result = FidoBleReassembler().accept(byteArrayOf(0xBE.toByte(), 0, 0))

        assertEquals(FidoBle.CMD_CANCEL, (result as FidoBleReassembler.Result.Complete).command)
        assertEquals(0, result.data.size)
    }

    @Test
    fun `an empty frame is refused with ERR_INVALID_LEN`() {
        val result = FidoBleReassembler().accept(ByteArray(0))

        assertEquals(FidoBleReassembler.Result.Error(FidoBle.ERR_INVALID_LEN), result)
    }

    @Test
    fun `error and keepalive frames carry one status byte`() {
        assertArrayEquals(
            byteArrayOf(0xBF.toByte(), 0, 1, FidoBle.ERR_INVALID_SEQ.toByte()),
            FidoBle.errorFrame(FidoBle.ERR_INVALID_SEQ)
        )
        assertArrayEquals(
            byteArrayOf(0x82.toByte(), 0, 1, FidoBle.KEEPALIVE_UP_NEEDED.toByte()),
            FidoBle.keepaliveFrame(FidoBle.KEEPALIVE_UP_NEEDED)
        )
    }

    @Test
    fun `the service revision bitfield offers FIDO2 only`() {
        assertEquals(0x20.toByte(), FidoBle.SERVICE_REVISION_FIDO2)
        assertTrue(FidoBle.MAX_MESSAGE_SIZE >= 1024)
    }
}
