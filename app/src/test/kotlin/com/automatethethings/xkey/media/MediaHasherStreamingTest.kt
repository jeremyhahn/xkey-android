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

import android.content.ContentResolver
import android.net.Uri
import com.automatethethings.xkey.media.MediaHasher.SignatureSource
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.InputStream

/**
 * Canonical hashing of streamed media ([MediaHasher.hashStreamed]), which
 * both verify screens and the manual signer use through a URI: it gives what
 * the in-memory hash gives, and it hashes a video larger than the heap.
 */
class MediaHasherStreamingTest {

    private fun bytes(vararg values: Int) = ByteArray(values.size) { values[it].toByte() }

    private fun be64(value: Long) = XmpFixtures.be32(value ushr 32) + XmpFixtures.be32(value and 0xFFFFFFFFL)

    /** [head], then [zeros] zero bytes, then [tail], generated as read and never held. */
    private class SyntheticStream(
        private val head: ByteArray,
        private val zeros: Long,
        private val tail: ByteArray
    ) : InputStream() {
        private val total = head.size + zeros + tail.size
        private var position = 0L

        override fun read(): Int {
            val one = ByteArray(1)
            return if (read(one, 0, 1) < 0) -1 else one[0].toInt() and 0xFF
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (len == 0) return 0
            if (position >= total) return -1
            val zerosEnd = head.size + zeros
            val n = when {
                position < head.size -> {
                    val n = minOf(len, head.size - position.toInt())
                    head.copyInto(b, off, position.toInt(), position.toInt() + n)
                    n
                }
                position < zerosEnd -> {
                    val n = minOf(len.toLong(), zerosEnd - position).toInt()
                    b.fill(0, off, off + n)
                    n
                }
                else -> {
                    val from = (position - zerosEnd).toInt()
                    val n = minOf(len, tail.size - from)
                    tail.copyInto(b, off, from, from + n)
                    n
                }
            }
            position += n
            return n
        }

        override fun skip(n: Long): Long {
            val skipped = minOf(maxOf(n, 0), total - position)
            position += skipped
            return skipped
        }
    }

    /** A context whose resolver serves [open] at a URI, typed [mime]. */
    private fun resolverFor(mime: String, open: () -> InputStream): Pair<android.content.Context, Uri> {
        val uri = mockk<Uri>()
        val resolver = mockk<ContentResolver>()
        every { resolver.openInputStream(uri) } answers { open() }
        every { resolver.getType(uri) } returns mime
        val context = mockk<android.content.Context>()
        every { context.contentResolver } returns resolver
        // The original is read only once no granted write of it is pending recovery.
        every { context.filesDir } returns kotlin.io.path.createTempDirectory("files").toFile()
        return context to uri
    }

    @Test
    fun `a signed video larger than the heap verifies against its canonical hash`() {
        val ftyp = XmpFixtures.be32(16) + "ftyp".toByteArray() + "isom".toByteArray() + XmpFixtures.be32(0)
        // More than the heap holds and more than any byte array can.
        val mdatPayload = maxOf(Runtime.getRuntime().maxMemory(), Int.MAX_VALUE.toLong()) + (1L shl 20)
        val head = ftyp + XmpFixtures.be32(1) + "mdat".toByteArray() + be64(16 + mdatPayload)
        val small = XmpFixtures.mp4()
        val ours = XmpContainers.embed(small, XmpContainers.Format.ISO_BMFF, XmpFixtures.json())!!
            .let { it.copyOfRange(small.size, it.size) }
        val expected = MediaHasher.hashStream(SyntheticStream(head, mdatPayload, ByteArray(0)))

        val (resolver, uri) = resolverFor("video/mp4") { SyntheticStream(head, mdatPayload, ours) }

        assertEquals(
            MediaHasher.ContentHashCheck.MATCHES,
            MediaHasher.checkContentHashUri(resolver, uri, expected, SignatureSource.IN_BAND)
        )
        assertEquals(
            MediaHasher.ContentHashCheck.MISMATCH,
            MediaHasher.checkContentHashUri(resolver, uri, "0".repeat(64), SignatureSource.IN_BAND)
        )
    }

    @Test
    fun `the manual signer hashes a video larger than the heap canonically`() {
        val ftyp = XmpFixtures.be32(16) + "ftyp".toByteArray() + "isom".toByteArray() + XmpFixtures.be32(0)
        val mdatPayload = maxOf(Runtime.getRuntime().maxMemory(), Int.MAX_VALUE.toLong()) + (1L shl 20)
        val head = ftyp + XmpFixtures.be32(1) + "mdat".toByteArray() + be64(16 + mdatPayload)
        val expected = MediaHasher.hashStream(SyntheticStream(head, mdatPayload, ByteArray(0)))

        val (resolver, uri) = resolverFor("video/mp4") { SyntheticStream(head, mdatPayload, ByteArray(0)) }

        assertEquals(expected, MediaHasher.hashCanonicalUri(resolver, uri))
    }

    /** Media of every handled type, signed and not, well formed and not. */
    private fun cases(): List<Pair<String, ByteArray>> {
        val json = XmpFixtures.json()
        val containers = XmpFixtures.all.flatMap { (mime, raw) ->
            val format = XmpContainers.formatOf(mime)!!
            val signed = XmpContainers.embed(raw, format, json)!!
            listOf(mime to raw, mime to signed, mime to signed.copyOf(signed.size - 1))
        }
        val soi = bytes(0xFF, 0xD8)
        val app1 = bytes(0xFF, 0xE1, 0x00, 0x08) + "Exif\u0000\u0000".toByteArray(Charsets.ISO_8859_1)
        val dqt = bytes(0xFF, 0xDB, 0x00, 0x04, 0x01, 0x02)
        val sos = bytes(0xFF, 0xDA, 0x00, 0x04, 0x03, 0x04)
        val scan = bytes(0x11, 0x22, 0xFF, 0x00, 0x33)
        val eoi = bytes(0xFF, 0xD9)
        val jpegs = listOf(
            soi + app1 + dqt + sos + scan + eoi,
            soi + bytes(0xFF, 0xFF, 0xFF) + app1 + bytes(0xFF, 0xD0) + dqt + sos + scan + eoi,
            soi + app1 + dqt + bytes(0x00),
            soi + app1 + dqt + eoi,
            bytes(0x00, 0x01, 0x02, 0x03)
        ).map { "image/jpeg" to it }
        return containers + jpegs + listOf("image/heic" to bytes(1, 2, 3))
    }

    @Test
    fun `streamed hashes equal the in-memory hashes for every type`() {
        for ((mime, data) in cases()) {
            val streamed = MediaHasher.hashStreamed({ data.inputStream() }, mime)
            assertEquals(mime, MediaHasher.hashCanonical(data, mime), streamed.canonical)
            assertEquals(mime, MediaHasher.hashBytes(data), streamed.whole)
        }
    }

    @Test
    fun `a signed container's streamed canonical hash is the hash of the file before signing`() {
        for ((mime, raw) in XmpFixtures.all) {
            val signed = XmpContainers.embed(raw, XmpContainers.formatOf(mime)!!, XmpFixtures.json())!!
            val streamed = MediaHasher.hashStreamed({ signed.inputStream() }, mime)
            assertEquals(mime, MediaHasher.hashBytes(raw), streamed.canonical)
        }
    }
}
