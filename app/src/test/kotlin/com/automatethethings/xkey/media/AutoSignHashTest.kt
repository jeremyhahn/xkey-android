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

import android.content.ContentResolver
import android.net.Uri
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.InputStream

/**
 * The automatic signer hashes every capture, videos included, so the hash
 * must never need the whole file in the app heap.
 */
class AutoSignHashTest {

    /** [size] zero bytes, produced on demand so nothing holds them. */
    private class ZeroStream(private val size: Long) : InputStream() {
        private var position = 0L

        override fun read(): Int = if (position < size) { position++; 0 } else -1

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (position >= size) return -1
            val n = minOf(len.toLong(), size - position).toInt()
            java.util.Arrays.fill(b, off, off + n, 0)
            position += n
            return n
        }
    }

    private fun resolverFor(mimeType: String, size: Long): Pair<ContentResolver, Uri> {
        val resolver = mockk<ContentResolver>()
        val uri = mockk<Uri>()
        every { resolver.getType(uri) } returns mimeType
        every { resolver.openInputStream(uri) } answers { ZeroStream(size) }
        return resolver to uri
    }

    @Test
    fun `a video larger than any byte array is hashed by streaming the whole file`() {
        // One byte more than a ByteArray can hold: reading it whole cannot work.
        val size = Int.MAX_VALUE.toLong() + 1
        val (resolver, uri) = resolverFor("video/mp4", size)

        assertEquals(
            MediaHasher.hashStream(ZeroStream(size)),
            AutoSignHash.contentHashUri(resolver, uri)
        )
    }

    @Test
    fun `a JPEG above the bound is refused, never read whole`() {
        val (resolver, uri) = resolverFor("image/jpeg", 1025)

        val refused = assertThrows(AutoSignHash.TooLargeException::class.java) {
            AutoSignHash.contentHashUri(resolver, uri, limit = 1024)
        }
        assertEquals(1024, refused.limit)
    }

    @Test
    fun `a JPEG at the bound gets the canonical hash`() {
        val (resolver, uri) = resolverFor("image/jpeg", 1024)

        assertEquals(
            MediaHasher.hashCanonical(ByteArray(1024), "image/jpeg"),
            AutoSignHash.contentHashUri(resolver, uri, limit = 1024)
        )
    }

    @Test
    fun `the default bound is 32 MiB`() {
        assertEquals(32 * 1024 * 1024, AutoSignHash.MAX_CANONICAL_JPEG_BYTES)
    }
}
