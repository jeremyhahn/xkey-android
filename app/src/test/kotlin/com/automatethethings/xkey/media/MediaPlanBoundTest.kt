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

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File
import java.io.IOException

/**
 * Every media format parser plans the canonical hash through
 * [MediaPlan.Builder], which coalesces adjacent ranges and refuses a file
 * past [MediaPlan.MAX_PIECES] pieces with [MediaTooFragmentedException]: a
 * shared JPEG of millions of tiny markers hashes in bounded memory or is
 * refused, never planned into millions of objects.
 */
class MediaPlanBoundTest {

    private val jpeg = "image/jpeg"

    /** SOI, [count] copies of [marker], EOI. */
    private fun jpegOf(marker: ByteArray, count: Int): ByteArray {
        val out = ByteArray(2 + marker.size * count + 2)
        out[0] = 0xFF.toByte(); out[1] = 0xD8.toByte()
        for (k in 0 until count) marker.copyInto(out, 2 + k * marker.size)
        out[out.size - 2] = 0xFF.toByte(); out[out.size - 1] = 0xD9.toByte()
        return out
    }

    private val tem = byteArrayOf(0xFF.toByte(), 0x01)

    @Test
    fun `a JPEG of millions of adjacent tiny markers hashes as one piece`() {
        val data = jpegOf(tem, 2_000_000)
        // Every byte is kept, so the canonical hash is the plain one.
        assertEquals(MediaHasher.hashBytes(data), MediaHasher.hashCanonical(data, jpeg))
        val streamed = MediaHasher.hashStreamed({ data.inputStream() }, jpeg)
        assertEquals(MediaHasher.hashBytes(data), streamed.canonical)
    }

    @Test
    fun `a JPEG of tiny markers split by fill bytes is refused with a typed error`() {
        // Each fill byte is left out, so no two markers are adjacent.
        val data = jpegOf(byteArrayOf(0xFF.toByte(), 0xFF.toByte(), 0x01), MediaPlan.MAX_PIECES + 10)
        for (hash in listOf<() -> Unit>(
            { MediaHasher.hashCanonical(data, jpeg) },
            { MediaHasher.hashStreamed({ data.inputStream() }, jpeg) },
            { MediaHasher.contentHashMatches("0".repeat(64), data, jpeg, MediaHasher.SignatureSource.IN_BAND) }
        )) {
            try {
                hash()
                fail("a plan past the cap was built")
            } catch (e: MediaTooFragmentedException) {
                assertEquals(MediaPlan.MAX_PIECES, e.maxPieces)
                assertTrue("an IOException the screens report", e is IOException && !e.message.isNullOrBlank())
            }
        }
    }

    @Test
    fun `a JPEG just under the cap still hashes`() {
        val data = jpegOf(byteArrayOf(0xFF.toByte(), 0xFF.toByte(), 0x01), MediaPlan.MAX_PIECES - 10)
        assertEquals(64, MediaHasher.hashCanonical(data, jpeg).length)
    }

    @Test
    fun `the builder coalesces adjacent ranges and keeps literals apart`() {
        val plan = MediaPlan.Builder()
            .range(0, 2).range(2, 4).range(4, 4).range(6, 8)
            .literal(byteArrayOf(1)).range(8, 9).range(9, 10)
            .build()
        val shape = plan.pieces.map {
            when (it) {
                is Piece.Range -> "${it.start}-${it.end}"
                is Piece.Literal -> "L${it.bytes.size}"
            }
        }
        assertEquals(listOf("0-4", "6-8", "L1", "8-10"), shape)
    }

    @Test
    fun `the builder refuses past its cap and never goes backward`() {
        val builder = MediaPlan.Builder(maxPieces = 3)
        builder.range(0, 1).range(2, 3).range(4, 5)
        builder.range(5, 6) // coalesces: still three pieces
        try {
            builder.range(7, 8)
            fail("a fourth piece was added")
        } catch (e: MediaTooFragmentedException) {
            assertEquals(3, e.maxPieces)
        }
        try {
            MediaPlan.Builder().range(4, 6).range(2, 3)
            fail("a range before the last was added")
        } catch (e: IllegalArgumentException) {
            // expected
        }
    }

    // -------------------------------------------------------------------------
    // Bypass: no parser plans outside the builder
    // -------------------------------------------------------------------------

    private fun mediaSources(): Map<String, String> {
        val rel = "src/main/kotlin/com/automatethethings/xkey/media"
        val dir = listOf(File(rel), File("app/$rel")).firstOrNull { it.isDirectory }
            ?: error("$rel not found from ${File(".").absolutePath}")
        return dir.listFiles { f -> f.name.endsWith(".kt") }!!.associate { it.name to it.readText() }
    }

    @Test
    fun `no media parser makes a piece or a plan outside the builder`() {
        val sources = mediaSources()
        assertTrue("the parsers are gone; is the scan stale?", "MediaHasher.kt" in sources && "XmpContainers.kt" in sources)
        val offenders = mutableListOf<String>()
        for ((name, source) in sources) {
            val builder = if (name == "ByteSource.kt") builderBody(source) else IntRange.EMPTY
            Regex("""\b(Piece\.)?(Range|Literal)\(|\bMediaPlan\((?!\s*private)""").findAll(source).forEach { m ->
                val construct = m.value.startsWith("Piece.") || m.value.startsWith("MediaPlan(") ||
                    // a bare Range( / Literal( inside the file that declares them
                    (name == "ByteSource.kt" && m.range.first !in builder && !isDeclaration(source, m.range.first))
                if (construct && m.range.first !in builder) {
                    offenders += "$name:${lineOf(source, m.range.first)}: '${m.value}' outside MediaPlan.Builder"
                }
            }
            // A plan is a MediaPlan, never a bare list of pieces.
            Regex("""(List|ArrayList|Array|Sequence)<Piece>""").findAll(source).forEach { m ->
                if (m.range.first !in builder) offenders += "$name:${lineOf(source, m.range.first)}: '${m.value}' plan outside the builder"
            }
        }
        if (offenders.isNotEmpty()) fail("a media parser bypasses MediaPlan.Builder:\n" + offenders.joinToString("\n"))
    }

    @Test
    fun `every canonical plan a parser returns is a built MediaPlan`() {
        val sources = mediaSources()
        val planners = sources.flatMap { (name, source) ->
            Regex("""fun (\w*[Pp]lan)\([^)]*\)\s*:\s*([\w<>?]+)""").findAll(source).map { Triple(name, it.groupValues[1], it.groupValues[2]) }.toList()
        }
        val names = planners.map { it.second }.toSet()
        assertTrue("expected jpegPlan, canonicalPlan and stripPlan; is the scan stale?", names.containsAll(listOf("jpegPlan", "canonicalPlan", "stripPlan")))
        val offenders = planners.filter { it.third != "MediaPlan?" && it.third != "MediaPlan" }
            .map { "${it.first}: ${it.second} returns ${it.third}" }
        if (offenders.isNotEmpty()) fail(offenders.joinToString("\n"))
    }

    private fun isDeclaration(source: String, offset: Int): Boolean =
        source.substring(maxOf(0, offset - 6), offset).endsWith("class ")

    /**
     * Offsets in ByteSource.kt from MediaPlan's private constructor (the
     * pieces it holds) to the end of `class Builder`'s body.
     */
    private fun builderBody(source: String): IntRange {
        val plan = source.indexOf("class MediaPlan private constructor(")
        val start = source.indexOf("class Builder(")
        assertTrue("MediaPlan.Builder is gone; is the scan stale?", plan >= 0 && start > plan)
        val brace = source.indexOf('{', source.indexOf(')', start))
        var depth = 0
        for (i in brace until source.length) {
            when (source[i]) {
                '{' -> depth++
                '}' -> if (--depth == 0) return plan..i
            }
        }
        error("unbalanced Builder body")
    }

    private fun lineOf(source: String, offset: Int): Int = source.substring(0, offset).count { it == '\n' } + 1
}
