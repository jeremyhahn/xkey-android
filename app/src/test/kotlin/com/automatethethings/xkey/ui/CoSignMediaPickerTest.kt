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

import android.app.Application
import android.content.Intent
import android.os.Looper
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.automatethethings.xkey.R
import com.automatethethings.xkey.media.MediaHasher
import com.automatethethings.xkey.media.XmpContainers
import com.automatethethings.xkey.media.XmpMetadataHelper
import com.automatethethings.xkey.storage.XKeyDatabase
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import java.util.concurrent.atomic.AtomicReference

/** An in-memory [XKeyDatabase] as the app's instance, and the software AndroidKeyStore, for activity tests. */
internal class TestDatabase {
    val database: XKeyDatabase =
        Room.inMemoryDatabaseBuilder(ApplicationProvider.getApplicationContext(), XKeyDatabase::class.java)
            .allowMainThreadQueries()
            .build()

    init {
        FakeAndroidKeyStore.install()
        instanceRef().set(database)
    }

    fun close() {
        instanceRef().set(null)
        database.close()
    }

    @Suppress("UNCHECKED_CAST")
    private fun instanceRef(): AtomicReference<XKeyDatabase?> =
        XKeyDatabase::class.java.getDeclaredField("instanceRef").apply { isAccessible = true }
            .get(null) as AtomicReference<XKeyDatabase?>
}

/** The [Button] showing [text] under [view], or null. */
internal fun findButton(view: View, text: String): Button? {
    if (view is Button && view.text.toString() == text) return view
    if (view is ViewGroup) {
        for (i in 0 until view.childCount) findButton(view.getChildAt(i), text)?.let { return it }
    }
    return null
}

/**
 * Co-signing writes the co-signature into a copy of the media it picked, in
 * EXIF or XMP, so its picker offers every type that carries an embedded
 * signature, not JPEG alone.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class CoSignMediaPickerTest {

    private lateinit var db: TestDatabase

    @Before
    fun setUp() {
        db = TestDatabase()
    }

    @After
    fun tearDown() {
        db.close()
    }

    @Test
    fun `the co-sign media picker offers every type with an embedded signature`() {
        val activity = Robolectric.buildActivity(CoSignActivity::class.java).setup().get()
        shadowOf(Looper.getMainLooper()).idle()

        val select = findButton(activity.window.decorView, activity.getString(R.string.cosign_select_media))
        assertNotNull("the select-media button", select)
        select!!.performClick()

        val started = shadowOf(activity).nextStartedActivityForResult
        assertNotNull("the picker was launched", started)
        assertEquals(Intent.ACTION_OPEN_DOCUMENT, started.intent.action)
        val offered = started.intent.getStringArrayExtra(Intent.EXTRA_MIME_TYPES)!!.toSet()
        assertEquals(
            setOf("image/jpeg", "image/png", "image/webp", "video/mp4", "video/quicktime"),
            offered
        )
    }

    @Test
    fun `every offered type has its own embedded container`() {
        for (type in XmpMetadataHelper.EMBEDDED_MIME_TYPES) {
            assertTrue(type, MediaHasher.isJpeg(type) || XmpContainers.formatOf(type) != null)
            assertTrue(type, XmpMetadataHelper.stagingSuffix(type) !in setOf(".bin", ".mkv"))
        }
    }
}
