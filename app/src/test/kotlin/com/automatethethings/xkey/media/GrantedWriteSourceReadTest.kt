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

import android.Manifest
import android.app.Application
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.test.core.app.ApplicationProvider
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import java.io.File

/**
 * A source read of a capture ([MediaPublisher.openOriginal]) and a granted
 * write of it agree on what they read and write: every MediaStore spelling
 * of one item (its images, video or audio URI, its Files URI, its media
 * document) finds the same interrupted-write record, and a read never sees
 * a granted write's bytes part-way.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class GrantedWriteSourceReadTest {

    @get:Rule
    val folder = TemporaryFolder()

    private lateinit var context: Context
    private val previousStore = MediaPublisher.mediaStore

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        shadowOf(context as Application).grantPermissions(Manifest.permission.ACCESS_MEDIA_LOCATION)
        MediaPublisher.mediaStore = object : MediaPublisher.MediaStoreAccess {
            override fun ownerPackage(context: Context, uri: Uri): String? = "com.example.camera"
            override fun hasWriteGrant(context: Context, uri: Uri): Boolean = true
            override fun createWriteRequest(context: Context, uris: List<Uri>): PendingIntent =
                PendingIntent.getActivity(context, 0, Intent(), PendingIntent.FLAG_IMMUTABLE)
        }
    }

    @After
    fun tearDown() {
        MediaPublisher.mediaStore = previousStore
        MediaPublisher.recoveryDirectory(context).deleteRecursively()
    }

    private fun record(uri: Uri) {
        val directory = MediaPublisher.recoveryDirectory(context)
        val whole = File(directory, "whole").apply { writeBytes(byteArrayOf(1, 2, 3)) }
        val staged = File(directory, "staged").apply { writeBytes(byteArrayOf(4, 5, 6)) }
        MediaPublisher.GrantedWriteJournal.of(directory, uri).commit(whole, staged)
        staged.delete()
    }

    @Test
    fun `an interrupted write through one spelling of an item holds every source read of it`() {
        record(Uri.parse("content://media/external/images/media/7"))
        val aliases = listOf(
            "content://media/external/file/7",
            "content://media/external_primary/file/7",
            "content://media/external/images/media/7?requireOriginal=1",
            "content://com.android.providers.media.documents/document/image%3A7"
        ).map(Uri::parse)

        aliases.forEach { alias ->
            assertTrue("$alias names the interrupted item", MediaPublisher.recoveryPending(context, alias))
            assertThrows("$alias is not read part-written", MediaPublisher.RecoveryPendingException::class.java) {
                MediaPublisher.openOriginal(context, alias).close()
            }
        }
        assertFalse(MediaPublisher.recoveryPending(context, Uri.parse("content://media/external/file/8")))
        assertFalse(MediaPublisher.recoveryPending(context, Uri.parse("content://media/internal/file/7")))
    }

    @Test
    fun `a write recorded through the Files spelling holds a read through the media spelling`() {
        record(Uri.parse("content://media/external/file/9"))

        assertTrue(MediaPublisher.recoveryPending(context, Uri.parse("content://media/external/video/media/9")))
    }

    @Test
    fun `a source read open across a granted write reads the capture whole, never mixed`() {
        val before = XmpFixtures.png(ByteArray(256) { it.toByte() })
        val after = XmpFixtures.png(ByteArray(256) { (255 - it).toByte() })
        val media = folder.newFile("capture.png").apply { writeBytes(before) }
        Robolectric.setupContentProvider(FakeMediaProvider::class.java, "media").apply {
            this.media = media
            mimeType = "image/png"
        }
        val uri = Uri.parse("content://media/external/images/media/31")
        val snapshot = folder.newFile("snapshot.png").apply { writeBytes(before) }
        val source = MediaPublisher.StagedSource.of(snapshot, "image/png", AutoSignHash.contentHashFile(snapshot, "image/png"))
        val staged = folder.newFile("staged.png").apply { writeBytes(after) }

        val read = MediaPublisher.openOriginal(context, uri).use { input ->
            val head = ByteArray(16).also { input.read(it) }
            MediaPublisher.writeGranted(context, uri, staged, source)
            head + input.readBytes()
        }

        assertArrayEquals("the granted write went through", after, media.readBytes())
        assertArrayEquals("the read is the capture as it was, whole", before, read)
    }
}
