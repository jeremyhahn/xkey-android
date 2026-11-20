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

import android.Manifest
import android.app.Application
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
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
 * A capture the automatic signer fails on (a busy keystore, a provider that
 * fails a read, memory running out) is queued unsigned for a retry, never
 * dropped: the auto-signer does not offer it again.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class AutoSignRetryTest {

    @get:Rule
    val folder = TemporaryFolder()

    private lateinit var context: Context
    private val uri: Uri = Uri.parse("content://media/external/video/media/4545")
    private val previousStore = MediaPublisher.mediaStore
    private val previousSign = AutoSigner.sign

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        val media = folder.newFile("VID_0002.mp4").apply {
            writeBytes(
                with(XmpFixtures) {
                    box("ftyp", ascii("isom") + be32(0x200) + ascii("isommp42")) +
                        box("moov", box("mvhd", ByteArray(12) { 1 })) +
                        box("mdat", bytes(0x10, 0x20, 0x30, 0x40))
                }
            )
        }
        val provider = Robolectric.setupContentProvider(FakeMediaProvider::class.java, "media")
        provider.media = media
        provider.mimeType = "video/mp4"
        MediaPublisher.mediaStore = object : MediaPublisher.MediaStoreAccess {
            override fun ownerPackage(context: Context, uri: Uri): String? = "com.example.camera"
            override fun hasWriteGrant(context: Context, uri: Uri): Boolean = false
            override fun createWriteRequest(context: Context, uris: List<Uri>): PendingIntent =
                PendingIntent.getActivity(context, 0, Intent(), PendingIntent.FLAG_IMMUTABLE)
        }
        MediaWriteAuthorizations.clear(context)
        shadowOf(context as Application).grantPermissions(Manifest.permission.ACCESS_MEDIA_LOCATION)
    }

    @After
    fun tearDown() {
        MediaPublisher.mediaStore = previousStore
        AutoSigner.sign = previousSign
        MediaWriteAuthorizations.clear(context)
    }

    private fun assertQueuedUnsigned() {
        val queued = MediaWriteAuthorizations.pending(context).single()
        assertEquals(uri.toString(), queued.uri)
        assertEquals("key-1", queued.keyId)
        assertNull("it waits unsigned, to be hashed and signed again", queued.data)
    }

    @Test
    fun `a capture whose signing fails is queued for a retry`() = runBlocking<Unit> {
        AutoSigner.sign = { _, _, _ -> throw IllegalStateException("keystore busy") }

        val outcome = AutoSigner.signCapture(context, uri, null, "key-1", "Key")

        assertEquals(AutoSigner.Outcome.QueuedForRetry, outcome)
        assertQueuedUnsigned()
    }

    @Test
    fun `a capture that runs out of memory is queued for a retry`() = runBlocking<Unit> {
        AutoSigner.sign = { _, _, _ -> throw OutOfMemoryError("test") }

        val outcome = AutoSigner.signCapture(context, uri, null, "key-1", "Key")

        assertEquals(AutoSigner.Outcome.QueuedForRetry, outcome)
        assertQueuedUnsigned()
    }
}
