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

import android.content.Context
import android.net.Uri
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * Instrumented tests for [MediaHasher.hashUri].
 *
 * `MediaHasherTest` covers the byte and stream overloads in the JVM. The URI
 * overload is the one the auto-signing service actually calls, and it needs a
 * real `ContentResolver`, so it can only be proved here. The hash it produces
 * has to match the byte overload exactly -- a signature is taken over this
 * value, so a divergence would make every auto-signed photo unverifiable.
 */
@RunWith(AndroidJUnit4::class)
class MediaHasherInstrumentedTest {

    private lateinit var context: Context
    private lateinit var file: File

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        file = File(context.cacheDir, "media-hasher-${System.nanoTime()}.bin")
    }

    @After
    fun tearDown() {
        file.delete()
    }

    @Test
    fun hashUri_matchesTheByteOverload() {
        val content = ByteArray(64 * 1024) { (it % 251).toByte() }
        file.writeBytes(content)

        val fromUri = MediaHasher.hashUri(context.contentResolver, Uri.fromFile(file))

        assertEquals(MediaHasher.hashBytes(content), fromUri)
    }

    @Test
    fun hashUri_handlesAnEmptyFile() {
        file.writeBytes(ByteArray(0))

        val fromUri = MediaHasher.hashUri(context.contentResolver, Uri.fromFile(file))

        assertEquals(MediaHasher.hashBytes(ByteArray(0)), fromUri)
        assertEquals(64, fromUri.length)
    }

    @Test
    fun hashUri_isStableAcrossReads() {
        file.writeBytes("stable content".toByteArray())
        val uri = Uri.fromFile(file)

        val first = MediaHasher.hashUri(context.contentResolver, uri)
        val second = MediaHasher.hashUri(context.contentResolver, uri)

        assertEquals(first, second)
    }

    @Test
    fun hashUri_changesWhenTheContentChanges() {
        file.writeBytes("before".toByteArray())
        val uri = Uri.fromFile(file)
        val before = MediaHasher.hashUri(context.contentResolver, uri)

        file.writeBytes("after".toByteArray())

        assertNotEquals(before, MediaHasher.hashUri(context.contentResolver, uri))
    }

    @Test
    fun hashUri_failsForAUriItCannotOpen() {
        val missing = Uri.fromFile(File(context.cacheDir, "absent-${System.nanoTime()}.bin"))

        assertThrows(Exception::class.java) {
            MediaHasher.hashUri(context.contentResolver, missing)
        }
    }
}
