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
import io.mockk.every
import io.mockk.mockk
import io.mockk.unmockkAll
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream

/**
 * Unit tests for [MediaHasher.hashUri] and the stream-lifecycle guarantees of
 * [MediaHasher.hashStream], driven by a mocked `ContentResolver`.
 *
 * `MediaHasherInstrumentedTest` proves `hashUri` against a real resolver on a
 * device. The branches it cannot reach are the ones a device will not produce on
 * demand: a resolver that hands back `null` (the URI vanished between the
 * MediaStore notification and the read, which is routine when a camera app
 * rewrites a capture), and a stream that fails part-way through. Both must not
 * be mistaken for a successful hash — a signature is taken over this value.
 *
 * The suite also pins that the input stream is always closed. The auto-signing
 * service hashes on every MediaStore change, so a leaked descriptor per capture
 * would exhaust the process.
 */
class MediaHasherUriTest {

    @After
    fun tearDown() {
        unmockkAll()
    }

    /** A stream that records whether the hasher closed it. */
    private class ClosingStream(data: ByteArray) : ByteArrayInputStream(data) {
        var closed = false
            private set

        override fun close() {
            closed = true
            super.close()
        }
    }

    /** A stream that fails once reading starts, modelling a truncated capture. */
    private class FailingStream : InputStream() {
        var closed = false
            private set

        override fun read(): Int = throw IOException("media went away mid-read")

        override fun read(b: ByteArray, off: Int, len: Int): Int =
            throw IOException("media went away mid-read")

        override fun close() {
            closed = true
        }
    }

    private fun resolverReturning(stream: InputStream?): ContentResolver {
        val resolver = mockk<ContentResolver>()
        every { resolver.openInputStream(any()) } returns stream
        return resolver
    }

    // -------------------------------------------------------------------------
    // hashUri
    // -------------------------------------------------------------------------

    @Test
    fun `hashUri closes the resolver's stream on success`() {
        val stream = ClosingStream("hello world".toByteArray())

        MediaHasher.hashUri(resolverReturning(stream), mockk<Uri>(relaxed = true))

        assertTrue("the resolver's stream must not be leaked", stream.closed)
    }

    @Test
    fun `hashUri rejects a URI the resolver cannot open`() {
        val e = assertThrows(IllegalArgumentException::class.java) {
            MediaHasher.hashUri(resolverReturning(null), mockk<Uri>(relaxed = true))
        }

        assertTrue(e.message!!, e.message!!.startsWith("Cannot open URI:"))
    }

    @Test
    fun `hashUri propagates a read failure instead of returning a partial hash`() {
        val stream = FailingStream()

        assertThrows(IOException::class.java) {
            MediaHasher.hashUri(resolverReturning(stream), mockk<Uri>(relaxed = true))
        }

        assertTrue("a failed read must still close the stream", stream.closed)
    }

    @Test
    fun `hashUri and hashBytes agree for the same content`() {
        val data = ByteArray(20_000) { (it % 97).toByte() }

        val fromUri = MediaHasher.hashUri(
            resolverReturning(ByteArrayInputStream(data)),
            mockk<Uri>(relaxed = true)
        )

        assertEquals(MediaHasher.hashBytes(data), fromUri)
    }
}
