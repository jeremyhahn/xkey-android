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
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.InputStream

/**
 * Every canonicalisation pass of a hash reads the same bytes: the media is
 * read once, into a private snapshot, and every later pass reads that
 * snapshot. Media that changes between reads (trailing bytes appended, a
 * scan byte rewritten, a signature dropped) is hashed as the one read saw
 * it, never as a mix of two versions.
 */
class MediaHasherSnapshotTest {

    private fun bytes(vararg values: Int) = ByteArray(values.size) { values[it].toByte() }

    private val jpeg = "image/jpeg"

    /** A JPEG with an EXIF segment, which the canonical hash leaves out. */
    private val original: ByteArray = run {
        val soi = bytes(0xFF, 0xD8)
        val app1 = bytes(0xFF, 0xE1, 0x00, 0x08) + "Exif\u0000\u0000".toByteArray(Charsets.ISO_8859_1)
        val dqt = bytes(0xFF, 0xDB, 0x00, 0x04, 0x01, 0x02)
        val sos = bytes(0xFF, 0xDA, 0x00, 0x04, 0x03, 0x04)
        val scan = bytes(0x11, 0x22, 0xFF, 0x00, 0x33)
        val eoi = bytes(0xFF, 0xD9)
        soi + app1 + dqt + sos + scan + eoi
    }

    /** The same JPEG with bytes appended after its end. */
    private val appended = original + bytes(0x44, 0x55, 0x66, 0x77)

    /** The same JPEG with one scan byte changed. */
    private val rescanned = original.copyOf().also { it[it.size - 3] = 0x34 }

    /** An `open` that returns [first] on its first call and [later] on every other, counting the calls. */
    private class ChangingSource(private val first: ByteArray, private val later: ByteArray) {
        var calls = 0
            private set

        fun open(): InputStream = (if (calls++ == 0) first else later).inputStream()
    }

    private fun assertHashedFromOneRead(changed: ByteArray) {
        val source = ChangingSource(original, changed)

        val hashes = MediaHasher.hashStreamed(source::open, jpeg)

        assertEquals("the media is read once", 1, source.calls)
        assertEquals(MediaHasher.hashCanonical(original, jpeg), hashes.canonical)
        assertEquals(MediaHasher.hashBytes(original), hashes.whole)
        // A hash stored for the original no longer matches the changed media.
        val stored = hashes.canonical
        val changedHashes = MediaHasher.hashStreamed({ changed.inputStream() }, jpeg)
        assertNotEquals(stored, changedHashes.canonical)
        assertNotEquals(stored, changedHashes.whole)
    }

    @Test
    fun `a JPEG that gains trailing bytes between reads is hashed from the one read`() {
        assertHashedFromOneRead(appended)
    }

    @Test
    fun `a JPEG whose scan changes between reads is hashed from the one read`() {
        assertHashedFromOneRead(rescanned)
    }

    private fun resolverFor(mimeType: String, source: ChangingSource): Pair<ContentResolver, Uri> {
        val resolver = mockk<ContentResolver>()
        val uri = mockk<Uri>()
        every { resolver.getType(uri) } returns mimeType
        every { resolver.openInputStream(uri) } answers { source.open() }
        return resolver to uri
    }

    @Test
    fun `the signer's size check and hash read the same bytes`() {
        val source = ChangingSource(original, rescanned)
        val (resolver, uri) = resolverFor(jpeg, source)

        val hash = AutoSignHash.contentHashUri(resolver, uri)

        assertEquals("the capture is read once", 1, source.calls)
        assertEquals(MediaHasher.hashCanonical(original, jpeg), hash)
    }

    @Test
    fun `the signer's carried-signature check and hash read the same bytes`() {
        val png = "image/png"
        val raw = XmpFixtures.png()
        val signed = XmpContainers.embed(raw, XmpContainers.Format.PNG, XmpFixtures.json())!!
        // Read signed, then unsigned: the check must not pass on the second read.
        val source = ChangingSource(signed, raw)
        val (resolver, uri) = resolverFor(png, source)

        assertThrows(AutoSignHash.TooLargeException::class.java) {
            AutoSignHash.contentHashUri(resolver, uri, embedLimit = 1)
        }
        assertEquals("the capture is read once", 1, source.calls)
    }
}
