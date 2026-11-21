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
import android.provider.MediaStore
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File

/**
 * A granted write is journalled under the capture's one media identity: any
 * spelling of the same MediaStore item (its media-document URI, another
 * volume name, a require-original URI) finds the journal, so nothing reads
 * or signs bytes the write may have left part-written.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class GrantedWriteJournalIdentityTest {

    private val context: Context = ApplicationProvider.getApplicationContext()
    private val capture = Uri.parse("content://media/external/images/media/7")
    private lateinit var recovery: File

    @Before
    fun setUp() {
        recovery = MediaPublisher.recoveryDirectory(context)
        val whole = File(recovery, "whole").apply { writeBytes(byteArrayOf(1, 2, 3)) }
        val staged = File(recovery, "staged").apply { writeBytes(byteArrayOf(4, 5, 6)) }
        MediaPublisher.GrantedWriteJournal.of(recovery, capture).commit(whole, staged)
        staged.delete()
    }

    private val sameItem = listOf(
        Uri.parse("content://com.android.providers.media.documents/document/image%3A7"),
        Uri.parse("content://media/external_primary/images/media/7"),
        Uri.parse("content://media/1a2b-3c4d/images/media/7"),
        MediaStore.setRequireOriginal(capture)
    )

    @Test
    fun `every spelling of the journalled capture is recovery pending`() {
        for (uri in sameItem) {
            assertTrue("$uri is the journalled capture", MediaPublisher.recoveryPending(context, uri))
        }
    }

    @Test
    fun `every spelling of the journalled capture refuses openOriginal`() {
        for (uri in sameItem) {
            assertThrows("$uri is the journalled capture", MediaPublisher.RecoveryPendingException::class.java) {
                MediaPublisher.openOriginal(context, uri).close()
            }
        }
    }

    @Test
    fun `another item is not the journalled capture`() {
        assertFalse(MediaPublisher.recoveryPending(context, Uri.parse("content://media/external/images/media/8")))
        assertFalse(MediaPublisher.recoveryPending(context, Uri.parse("content://media/internal/images/media/7")))
        assertFalse(
            MediaPublisher.recoveryPending(
                context, Uri.parse("content://com.android.providers.media.documents/document/image%3A8")
            )
        )
    }

    @Test
    fun `a reloaded record keeps the URI the write was made through`() {
        assertEquals(listOf(capture), MediaPublisher.GrantedWriteJournal.all(recovery).map { it.target() })
    }
}
