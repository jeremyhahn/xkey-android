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
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * The sidecar xKey owns for media another app owns is one per capture:
 * captures that share a name in different directories or volumes get
 * different sidecars, every spelling of one capture's URI gets the same, and
 * an update of an existing sidecar that fails keeps the signature it held.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class OwnedSidecarIdentityTest {

    @get:Rule
    val folder = TemporaryFolder()

    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun `captures sharing a name on secondary storage get different sidecars`() {
        val locations = listOf(
            "/storage/1a2b-3c4d/DCIM/clip.mkv",
            "/storage/1a2b-3c4d/Movies/clip.mkv",
            "/storage/5e6f-7a8b/DCIM/clip.mkv"
        ).map { XmpMetadataHelper.ownedSidecarLocation(it, null) }

        assertEquals("one sidecar per capture: $locations", locations.size, locations.toSet().size)
    }

    @Test
    fun `every spelling of a capture with no file gets the same sidecar`() {
        val plain = XmpMetadataHelper.ownedSidecarLocation(null, Uri.parse("content://media/external/video/media/12"))
        val document = XmpMetadataHelper.ownedSidecarLocation(
            null, Uri.parse("content://com.android.providers.media.documents/document/video%3A12")
        )
        val other = XmpMetadataHelper.ownedSidecarLocation(null, Uri.parse("content://media/external/video/media/13"))

        assertEquals(plain, document)
        assertNotEquals(plain, other)
    }

    @Test
    fun `a failed update of an existing owned sidecar keeps its signature`() {
        val old = XmpFixtures.json("a".repeat(64))
        val sidecar = folder.newFile("clip.mkv.xkeysig").apply { writeText(old) }
        Robolectric.setupContentProvider(FakeMediaProvider::class.java, "media").apply {
            media = sidecar
            mimeType = "application/octet-stream"
            failWrites = true
        }
        val target = Uri.parse("content://media/external_primary/file/99")

        assertThrows(Exception::class.java) {
            MediaPublisher.writeOwned(context, target, XmpFixtures.json("b".repeat(64)).toByteArray())
        }

        assertEquals("the earlier signature stays", old, sidecar.readText())
    }

    @Test
    fun `an existing owned sidecar whose backup cannot be read is not updated`() {
        val old = XmpFixtures.json("a".repeat(64))
        val sidecar = folder.newFile("clip.mkv.xkeysig").apply { writeText(old) }
        Robolectric.setupContentProvider(FakeMediaProvider::class.java, "media").apply {
            media = sidecar
            mimeType = "application/octet-stream"
            onOpen = { mode -> if ('w' !in mode) throw java.io.FileNotFoundException("the sidecar cannot be read") }
        }
        val target = Uri.parse("content://media/external_primary/file/99")

        assertThrows(Exception::class.java) {
            MediaPublisher.writeOwned(context, target, XmpFixtures.json("b".repeat(64)).toByteArray())
        }

        assertEquals("the earlier signature stays", old, sidecar.readText())
        assertFalse("no backup was recorded", MediaPublisher.recoveryPending(context, target))
    }

    @Test
    fun `an update of an existing owned sidecar replaces it whole`() {
        val sidecar = folder.newFile("clip.mkv.xkeysig").apply { writeText(XmpFixtures.json("a".repeat(64)) + " ".repeat(64)) }
        Robolectric.setupContentProvider(FakeMediaProvider::class.java, "media").apply {
            media = sidecar
            mimeType = "application/octet-stream"
        }
        val updated = XmpFixtures.json("b".repeat(64))

        MediaPublisher.writeOwned(context, Uri.parse("content://media/external_primary/file/99"), updated.toByteArray())

        assertEquals(updated, sidecar.readText())
    }
}
