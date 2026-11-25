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

import android.app.Application
import android.content.Context
import android.net.Uri
import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * A provider may hand out a shared document as a bounded asset descriptor:
 * a window (start offset, declared length) of a larger file. Every
 * cancellable read of it (sign, verify, hash) reads exactly that window.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class BoundedDescriptorReadTest {

    @get:Rule
    val folder = TemporaryFolder()

    private lateinit var context: Context
    private val document = XmpFixtures.png(ByteArray(300) { (it * 7).toByte() })
    private val bounded = Uri.parse("content://com.example.bounded/shared.png")
    private val whole = Uri.parse("content://com.example.whole/shared.png")

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        val prefix = ByteArray(37) { 0xAA.toByte() }
        val suffix = ByteArray(53) { 0x55.toByte() }
        Robolectric.setupContentProvider(FakeMediaProvider::class.java, "com.example.bounded").apply {
            media = folder.newFile("container.bin").apply { writeBytes(prefix + document + suffix) }
            window = prefix.size.toLong() to document.size.toLong()
        }
        Robolectric.setupContentProvider(FakeMediaProvider::class.java, "com.example.whole").apply {
            media = folder.newFile("shared.png").apply { writeBytes(document) }
        }
    }

    @After
    fun tearDown() {
        MediaPublisher.recoveryDirectory(context).deleteRecursively()
    }

    @Test
    fun `a cancellable read of a bounded descriptor reads exactly its declared bytes`() {
        val read = runBlocking { MediaPublisher.openOriginalCancellable(context, bounded) }.use { it.readBytes() }

        assertArrayEquals(document, read)
    }

    @Test
    fun `signing hashes a bounded descriptor as the document alone`() {
        val expected = MediaHasher.hashCanonicalUri(context, whole)

        val hash = runBlocking { MediaPublisher.readCancellable { MediaHasher.hashCanonicalUri(context, bounded, it) } }

        assertEquals(expected, hash)
    }

    @Test
    fun `verifying a bounded descriptor reads it without error`() {
        val check = runBlocking { MediaPublisher.readCancellable { MediaHasher.checkInBandUri(context, bounded, "image/png", it) } }
        val signature = runBlocking { XmpMetadataHelper.readOriginalSignature(context, bounded, "image/png") }

        assertNull("an unsigned document has no in-band signature", check)
        assertNull("an unsigned document has no signature", signature)
    }
}
