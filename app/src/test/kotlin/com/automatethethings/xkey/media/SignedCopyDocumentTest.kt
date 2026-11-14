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

import android.app.Activity
import android.app.Application
import android.content.Intent
import android.net.Uri
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * A signed or co-signed copy is created as its source's own type, named
 * after the source with its media suffix, even when the source is an
 * opaque document id such as "image:123".
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class SignedCopyDocumentTest {

    @Test
    fun `a named source keeps its suffix and type`() {
        assertEquals(SignedCopyDocument("clip-signed.mp4", "video/mp4"), SignedCopyDocument.named("clip.mp4", "video/mp4", "signed"))
        assertEquals(SignedCopyDocument("IMG-cosigned.png", "image/png"), SignedCopyDocument.named("IMG.png", "image/png", "cosigned"))
    }

    @Test
    fun `an opaque document id gets the suffix of its type`() {
        // getFileName falls back to the Uri's last segment, "image:123".
        assertEquals(SignedCopyDocument("123-signed.jpg", "image/jpeg"), SignedCopyDocument.named("image:123", "image/jpeg", "signed"))
        assertEquals(SignedCopyDocument("456-signed.mov", "video/quicktime"), SignedCopyDocument.named("video:456", "video/quicktime", "signed"))
        assertEquals(SignedCopyDocument("7-signed.webp", "image/webp"), SignedCopyDocument.named("7", "image/webp", "signed"))
    }

    @Test
    fun `an unnamed, untyped source is still a named document`() {
        assertEquals(SignedCopyDocument("media-signed", "application/octet-stream"), SignedCopyDocument.named(null, null, "signed"))
    }

    @Test
    fun `an unqueryable document is named by its last segment`() {
        val resolver = ApplicationProvider.getApplicationContext<Application>().contentResolver
        val copy = SignedCopyDocument.of(resolver, Uri.parse("content://xkey.test.none/document/image%3A123"), "cosigned")
        assertEquals("123-cosigned", copy.name)
        assertEquals("application/octet-stream", copy.mimeType)
    }

    @Test
    fun `the picker is typed per launch and titled with the name`() {
        val contract = SignedCopyDocument.Create()
        val intent = contract.createIntent(ApplicationProvider.getApplicationContext(), SignedCopyDocument("123-signed.png", "image/png"))
        assertEquals(Intent.ACTION_CREATE_DOCUMENT, intent.action)
        assertEquals("image/png", intent.type)
        assertEquals("123-signed.png", intent.getStringExtra(Intent.EXTRA_TITLE))
        assertEquals(setOf(Intent.CATEGORY_OPENABLE), intent.categories)

        val picked = Uri.parse("content://xkey.test/doc")
        assertEquals(picked, contract.parseResult(Activity.RESULT_OK, Intent().setData(picked)))
        assertNull(contract.parseResult(Activity.RESULT_CANCELED, Intent().setData(picked)))
    }
}
