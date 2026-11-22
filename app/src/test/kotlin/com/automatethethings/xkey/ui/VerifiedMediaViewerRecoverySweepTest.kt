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
package com.automatethethings.xkey.ui

import android.Manifest
import android.app.Activity
import android.app.Application
import android.content.Intent
import android.net.Uri
import android.os.Environment
import android.os.Looper
import com.automatethethings.xkey.media.FakeMediaProvider
import com.automatethethings.xkey.media.MediaPublisher
import com.automatethethings.xkey.media.MediaSaveRuns
import com.automatethethings.xkey.media.XmpFixtures
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.android.controller.ActivityController
import org.robolectric.annotation.Config
import java.io.File

/**
 * Verifying a capture reads its original into snapshots in the recovery
 * directory. A process killed during verification leaves them behind: the
 * viewer removes them when it opens, so a user who only views media does not
 * collect video-sized files.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class VerifiedMediaViewerRecoverySweepTest {

    private lateinit var db: TestDatabase
    private val capture = Uri.parse("content://media/external/images/media/7")
    private val created = mutableListOf<File>()
    private val screens = mutableListOf<ActivityController<out Activity>>()

    @Before
    fun setUp() {
        db = TestDatabase()
        shadowOf(RuntimeEnvironment.getApplication()).grantPermissions(Manifest.permission.ACCESS_MEDIA_LOCATION)
    }

    @After
    fun tearDown() {
        screens.forEach { runCatching { it.pause().stop().destroy() } }
        created.reversed().forEach { it.delete() }
        db.close()
    }

    private fun idleUntil(condition: () -> Boolean) {
        val deadline = System.currentTimeMillis() + 10_000
        while (!condition()) {
            assertTrue("timed out", System.currentTimeMillis() < deadline)
            shadowOf(Looper.getMainLooper()).idle()
            Thread.sleep(10)
        }
    }

    /** Two snapshots an earlier process left, and one of this process. */
    private fun leftovers(): Triple<File, File, File> {
        val dir = MediaPublisher.recoveryDirectory(RuntimeEnvironment.getApplication())
        dir.mkdirs()
        val read = File(dir, "${MediaSaveRuns.WORK_PREFIX}0123456789abcdef-1.read").apply { writeBytes(ByteArray(64)) }
        val hash = File(dir, "${MediaSaveRuns.WORK_PREFIX}0123456789abcdef-2.hash").apply { writeBytes(ByteArray(64)) }
        val own = MediaSaveRuns.work(dir, ".read").apply { writeBytes(ByteArray(64)) }
        created += listOf(read, hash, own)
        return Triple(read, hash, own)
    }

    @Test
    fun `the viewer removes snapshots an earlier process left when it opens`() {
        @Suppress("DEPRECATION")
        val root = Environment.getExternalStorageDirectory()
        val media = File(root, "DCIM/Camera/IMG_0201.gif").apply {
            parentFile!!.mkdirs()
            writeBytes(XmpFixtures.png())
            created += this
        }
        Robolectric.setupContentProvider(FakeMediaProvider::class.java, "media").apply {
            this.media = media
            mimeType = "image/gif"
            dataPath = media.path
        }
        val (read, hash, own) = leftovers()

        val intent = Intent(Intent.ACTION_VIEW).setDataAndType(capture, "image/gif")
        screens += Robolectric.buildActivity(VerifiedMediaViewerActivity::class.java, intent).setup()

        idleUntil { !read.exists() && !hash.exists() }
        assertTrue("this process's snapshot stays", own.exists())
    }

    @Test
    fun `the viewer sweeps when it opens even with no media to read`() {
        val (read, hash, own) = leftovers()

        val intent = Intent(Intent.ACTION_VIEW)
        screens += Robolectric.buildActivity(VerifiedMediaViewerActivity::class.java, intent).setup()

        idleUntil { !read.exists() && !hash.exists() }
        assertTrue("this process's snapshot stays", own.exists())
    }
}
