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
package com.automatethethings.xkey.media

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue

/**
 * Fill-byte JPEG fixtures for the #47 device regressions in
 * `XmpMetadataHelperInstrumentedTest` and `FileOperationFlowTest`.
 *
 * A marker may be preceded by any number of `0xFF` fill bytes (ITU T.81
 * B.1.1.2). These helpers add them to a real encoder's output, so the file
 * still decodes, and walk the result to prove where they are. The JVM suite
 * `XmpMetadataHelperExifFillByteTest` carries its own copy of the walker,
 * because the two source sets share no code.
 */
object JpegFillBytes {

    /** A marker segment: where its fill-byte run starts, the run's length, its code and its end. */
    data class Segment(val start: Int, val fill: Int, val marker: Int, val end: Int)

    const val APP1 = 0xE1
    const val DQT = 0xDB
    const val SOF0 = 0xC0
    const val DHT = 0xC4
    private const val SOS = 0xDA
    private const val EOI = 0xD9

    private fun bytes(vararg values: Int) = ByteArray(values.size) { values[it].toByte() }
    private fun u(data: ByteArray, i: Int) = data[i].toInt() and 0xFF

    /** `Exif\0\0`, a big-endian TIFF header and an empty IFD0, as a camera may leave it. */
    private val emptyExifApp1 = bytes(
        0xFF, APP1, 0x00, 0x16,
        0x45, 0x78, 0x69, 0x66, 0, 0, 0x4D, 0x4D, 0x00, 0x2A, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0
    )

    /** [jpeg] with an EXIF APP1 segment straight after SOI. */
    fun withExifApp1(jpeg: ByteArray): ByteArray =
        jpeg.copyOfRange(0, 2) + emptyExifApp1 + jpeg.copyOfRange(2, jpeg.size)

    /**
     * Walks [data]'s marker segments from SOI to SOS (or EOI), fill bytes
     * included, and asserts the chain is unbroken: every segment starts with a
     * marker and its length stays inside the file.
     */
    fun segments(data: ByteArray): List<Segment> {
        assertTrue("SOI", data.size >= 4 && u(data, 0) == 0xFF && u(data, 1) == 0xD8)
        val out = mutableListOf<Segment>()
        var i = 2
        while (true) {
            assertTrue("a marker must start at $i", i + 1 < data.size && u(data, i) == 0xFF)
            val start = i
            while (i + 1 < data.size && u(data, i + 1) == 0xFF) i++
            assertTrue("fill bytes must end in a marker", i + 1 < data.size)
            val marker = u(data, i + 1)
            if (marker == EOI) return out + Segment(start, i - start, marker, i + 2)
            assertTrue("segment length at $i", i + 3 < data.size)
            val end = i + 2 + ((u(data, i + 2) shl 8) or u(data, i + 3))
            assertTrue("segment at $i must fit the file", end in i + 4..data.size)
            out += Segment(start, i - start, marker, end)
            if (marker == SOS) return out
            i = end
        }
    }

    /** The markers in [data] that are preceded by at least one fill byte. */
    fun filled(data: ByteArray): List<Int> = segments(data).filter { it.fill > 0 }.map { it.marker }

    /**
     * [base] with [count] fill bytes before its first [marker] segment, or
     * before the first segment after SOI when [marker] is null.
     */
    fun withFill(base: ByteArray, marker: Int?, count: Int): ByteArray {
        val all = segments(base)
        val at = (if (marker == null) all.first() else all.first { it.marker == marker }).start
        return base.copyOfRange(0, at) + ByteArray(count) { 0xFF.toByte() } + base.copyOfRange(at, base.size)
    }

    /**
     * [jpeg], which must hold no fill bytes, with two before [first] (null:
     * the first marker after SOI) and three before the kept table [retained].
     * Asserts the result holds them there and nowhere else.
     */
    fun fixture(jpeg: ByteArray, first: Int?, retained: Int): ByteArray {
        assertEquals("the encoder output must hold no fill bytes", emptyList<Int>(), filled(jpeg))
        val result = withFill(withFill(jpeg, retained, 3), first, 2)
        val expectedFirst = first ?: segments(jpeg).first().marker
        assertEquals("the fixture must hold fill bytes where intended", listOf(expectedFirst, retained), filled(result))
        return result
    }

    /** Asserts [data] keeps its tables, reaches its scan through an unbroken chain and ends in EOI. */
    fun assertWellFormed(data: ByteArray) {
        val markers = segments(data).map { it.marker }
        assertEquals("the scan must follow the tables", SOS, markers.last())
        assertTrue("the tables must survive", markers.containsAll(listOf(DQT, SOF0, DHT)))
        assertEquals("EOI", listOf(0xFF, EOI), listOf(u(data, data.size - 2), u(data, data.size - 1)))
    }
}
