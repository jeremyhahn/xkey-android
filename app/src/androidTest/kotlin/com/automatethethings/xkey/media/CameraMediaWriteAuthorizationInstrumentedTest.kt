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
import android.content.ContentUris
import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.ParcelFileDescriptor
import android.provider.MediaStore
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Media another app created (here the shell, as a camera would) is not
 * xKey's to write: signing it asks for write access through the real
 * MediaStore.createWriteRequest and leaves the media as it was.
 */
@RunWith(AndroidJUnit4::class)
class CameraMediaWriteAuthorizationInstrumentedTest {

    private lateinit var context: Context
    private val name = "xkey-foreign-${System.nanoTime()}.png"
    private var uri: Uri? = null

    private fun shell(command: String): String {
        val pfd = InstrumentationRegistry.getInstrumentation().uiAutomation.executeShellCommand(command)
        return ParcelFileDescriptor.AutoCloseInputStream(pfd).use { it.readBytes().toString(Charsets.UTF_8) }
    }

    @Before
    fun setUp() {
        assumeTrue("write requests exist from Android 11", Build.VERSION.SDK_INT >= Build.VERSION_CODES.R)
        context = ApplicationProvider.getApplicationContext()
        val read = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            Manifest.permission.READ_MEDIA_IMAGES
        } else {
            Manifest.permission.READ_EXTERNAL_STORAGE
        }
        InstrumentationRegistry.getInstrumentation().uiAutomation.grantRuntimePermission(context.packageName, read)
        shell(
            "content insert --uri content://media/external/images/media" +
                " --bind _display_name:s:$name --bind mime_type:s:image/png --bind relative_path:s:Pictures/"
        )
        uri = context.contentResolver.query(
            MediaStore.Images.Media.EXTERNAL_CONTENT_URI,
            arrayOf(MediaStore.MediaColumns._ID),
            "${MediaStore.MediaColumns.DISPLAY_NAME} = ?",
            arrayOf(name),
            null
        )?.use { cursor ->
            if (cursor.moveToFirst()) ContentUris.withAppendedId(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, cursor.getLong(0)) else null
        }
        assumeTrue("the shell inserted the media", uri != null)
    }

    @After
    fun tearDown() {
        uri?.let { shell("content delete --uri $it") }
    }

    @Test
    fun mediaAnotherAppCreated_asksForWriteAccess() {
        val target = uri!!
        assertEquals("com.android.shell", MediaPublisher.mediaStore.ownerPackage(context, target))
        assertEquals(MediaPublisher.MediaWriteAccess.NEEDS_GRANT, MediaPublisher.writeAccess(context, target))

        val data = ContentAuthenticityData(
            contentHash = "a".repeat(64),
            signatures = listOf(
                SignatureEntry(
                    keyFingerprint = "b".repeat(64),
                    signerName = "Test Signer",
                    algorithm = "ES256",
                    value = "c2lnbmF0dXJl",
                    timestamp = "2026-01-01T00:00:00Z",
                    role = SignerRole.CREATOR
                )
            )
        )
        assertEquals(
            XmpMetadataHelper.MediaSignResult.NeedsWriteAuthorization,
            XmpMetadataHelper.signMedia(context, target, null, data)
        )
        assertNotNull(MediaPublisher.writeRequest(context, listOf(target)))
    }
}
