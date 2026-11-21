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
import android.app.Application
import android.content.Intent
import android.net.Uri
import android.os.Environment
import android.os.Looper
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import com.automatethethings.xkey.R
import com.automatethethings.xkey.media.AutoSignHash
import com.automatethethings.xkey.media.FakeMediaProvider
import com.automatethethings.xkey.media.XmpFixtures
import com.automatethethings.xkey.media.XmpMetadataHelper
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import java.io.File

/**
 * The verified-media viewer finds a signature where the signer put it. A
 * capture another app owns, in a format with no in-band signature, has its
 * sidecar in a file xKey owns under Documents/xKey/, never beside it: the
 * viewer reads that one ([XmpMetadataHelper.ownedSidecarLocation]).
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class VerifiedMediaViewerOwnedSidecarTest {

    private lateinit var db: TestDatabase
    private lateinit var provider: FakeMediaProvider
    private val capture = Uri.parse("content://media/external/images/media/7")
    private val created = mutableListOf<File>()

    @Before
    fun setUp() {
        db = TestDatabase()
        shadowOf(RuntimeEnvironment.getApplication()).grantPermissions(Manifest.permission.ACCESS_MEDIA_LOCATION)
    }

    @After
    fun tearDown() {
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

    @Test
    fun `the viewer reads the sidecar xKey owns for a capture another app owns`() {
        @Suppress("DEPRECATION")
        val root = Environment.getExternalStorageDirectory()
        val media = File(root, "DCIM/Camera/IMG_0101.gif").apply {
            parentFile!!.mkdirs()
            writeBytes(XmpFixtures.png())
            created += this
        }
        provider = Robolectric.setupContentProvider(FakeMediaProvider::class.java, "media").apply {
            this.media = media
            mimeType = "image/gif"
            dataPath = media.path
        }
        // Only the owned sidecar exists: none beside the capture.
        val (relativePath, name) = XmpMetadataHelper.ownedSidecarLocation(media.path, capture)
        assertEquals("Documents/xKey/DCIM/Camera/", relativePath)
        File(File(root, relativePath), name).apply {
            parentFile!!.mkdirs()
            writeText(XmpFixtures.json(AutoSignHash.contentHash(media.readBytes(), "image/gif")))
            created += this
        }
        assertFalse(File(media.path + ".xkeysig").exists())

        val intent = Intent(Intent.ACTION_VIEW).setDataAndType(capture, "image/gif")
        val activity = Robolectric.buildActivity(VerifiedMediaViewerActivity::class.java, intent).setup().get()

        val signers = activity.findViewById<ViewGroup>(R.id.signerListContainer)
        val none = activity.findViewById<TextView>(R.id.textNoSignatures)
        idleUntil { signers.childCount > 0 || none.visibility == View.VISIBLE }
        assertTrue("the owned sidecar's signers are shown, not 'no signatures'", signers.childCount > 0)
    }

    @Test
    fun `the viewer reads the owned sidecar of a capture opened through its media document URI`() {
        @Suppress("DEPRECATION")
        val root = Environment.getExternalStorageDirectory()
        val media = File(root, "DCIM/Camera/IMG_0102.gif").apply {
            parentFile!!.mkdirs()
            writeBytes(XmpFixtures.png())
            created += this
        }
        // MediaStore names the capture's file; the media documents provider names none.
        provider = Robolectric.setupContentProvider(FakeMediaProvider::class.java, "media").apply {
            this.media = media
            mimeType = "image/gif"
            dataPath = media.path
        }
        Robolectric.setupContentProvider(FakeMediaProvider::class.java, "com.android.providers.media.documents").apply {
            this.media = media
            mimeType = "image/gif"
        }
        // Where the signer put it: the owned sidecar of the MediaStore item.
        val (relativePath, name) = XmpMetadataHelper.ownedSidecarLocation(media.path, capture)
        File(File(root, relativePath), name).apply {
            parentFile!!.mkdirs()
            writeText(XmpFixtures.json(AutoSignHash.contentHash(media.readBytes(), "image/gif")))
            created += this
        }
        val document = Uri.parse("content://com.android.providers.media.documents/document/image%3A7")

        val intent = Intent(Intent.ACTION_VIEW).setDataAndType(document, "image/gif")
        val activity = Robolectric.buildActivity(VerifiedMediaViewerActivity::class.java, intent).setup().get()

        val signers = activity.findViewById<ViewGroup>(R.id.signerListContainer)
        val none = activity.findViewById<TextView>(R.id.textNoSignatures)
        idleUntil { signers.childCount > 0 || none.visibility == View.VISIBLE }
        assertTrue("the owned sidecar's signers are shown, not 'no signatures'", signers.childCount > 0)
    }
}
