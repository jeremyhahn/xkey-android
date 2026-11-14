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
package com.automatethethings.xkey.media

import java.io.EOFException
import java.io.InputStream
import java.io.OutputStream
import java.io.RandomAccessFile

/**
 * Reads at positions in media of a known [length], so one header walk serves
 * a byte array, a file and a stream. A walk only ever reads at or after the
 * start of its previous read, which a forward-only stream can serve.
 */
internal interface ByteSource {
    val length: Long

    /** Exactly [count] bytes at [position]; [EOFException] past the end. */
    fun readAt(position: Long, count: Int): ByteArray
}

internal class ArrayByteSource(private val data: ByteArray) : ByteSource {
    override val length: Long get() = data.size.toLong()

    override fun readAt(position: Long, count: Int): ByteArray {
        if (position < 0 || count < 0 || position + count > data.size) throw EOFException("read past the end")
        return data.copyOfRange(position.toInt(), position.toInt() + count)
    }
}

internal class FileByteSource(private val raf: RandomAccessFile) : ByteSource {
    override val length: Long = raf.length()

    override fun readAt(position: Long, count: Int): ByteArray {
        val bytes = ByteArray(count)
        raf.seek(position)
        raf.readFully(bytes)
        return bytes
    }
}

/**
 * A forward-only [ByteSource] over [input], which holds [length] bytes. Each
 * read starts at or after the start of the previous one; the bytes of the
 * last read are kept, so overlapping reads are served without seeking back.
 */
internal class StreamByteSource(private val input: InputStream, override val length: Long) : ByteSource {
    private var windowStart = 0L
    private var window = ByteArray(0)

    override fun readAt(position: Long, count: Int): ByteArray {
        require(position >= windowStart) { "a stream is read forward only" }
        if (position + count > length) throw EOFException("read past the end")
        val windowEnd = windowStart + window.size
        val offset = position - windowStart
        if (position + count <= windowEnd) return window.copyOfRange(offset.toInt(), offset.toInt() + count)
        val out = ByteArray(count)
        var have = 0
        if (position < windowEnd) {
            have = (windowEnd - position).toInt()
            window.copyInto(out, 0, offset.toInt(), window.size)
        } else {
            skipFully(input, position - windowEnd)
        }
        readFully(input, out, have, count - have)
        windowStart = position
        window = out
        return out
    }
}

/**
 * One piece of the bytes a canonical hash covers: a range of the media or
 * bytes the canonical form puts in its place. A plan lists them in file
 * order, so it is applied in one forward pass.
 */
internal sealed interface Piece {
    class Range(val start: Long, val end: Long) : Piece
    class Literal(val bytes: ByteArray) : Piece
}

internal object Pieces {
    /** [plan] applied to [data]. */
    fun bytes(plan: List<Piece>, data: ByteArray): ByteArray {
        val out = java.io.ByteArrayOutputStream(data.size)
        write(plan, data.inputStream(), out)
        return out.toByteArray()
    }

    /** [plan] applied to [input], read once from its start, written to [output]. */
    fun write(plan: List<Piece>, input: InputStream, output: OutputStream) {
        val buffer = ByteArray(64 * 1024)
        var position = 0L
        for (piece in plan) {
            when (piece) {
                is Piece.Literal -> output.write(piece.bytes)
                is Piece.Range -> {
                    require(piece.start >= position) { "a plan is applied forward only" }
                    skipFully(input, piece.start - position)
                    var left = piece.end - piece.start
                    while (left > 0) {
                        val n = input.read(buffer, 0, minOf(buffer.size.toLong(), left).toInt())
                        if (n < 0) throw EOFException("media shrank while it was hashed")
                        output.write(buffer, 0, n)
                        left -= n
                    }
                    position = piece.end
                }
            }
        }
    }
}

private fun readFully(input: InputStream, into: ByteArray, offset: Int, count: Int) {
    var read = 0
    while (read < count) {
        val n = input.read(into, offset + read, count - read)
        if (n < 0) throw EOFException("media shrank while it was read")
        read += n
    }
}

private fun skipFully(input: InputStream, count: Long) {
    var left = count
    while (left > 0) {
        val skipped = input.skip(left)
        if (skipped > 0) {
            left -= skipped
        } else {
            if (input.read() < 0) throw EOFException("media shrank while it was read")
            left--
        }
    }
}
