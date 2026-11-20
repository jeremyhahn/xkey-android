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
import android.app.Activity
import android.app.Application
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Looper
import androidx.test.core.app.ApplicationProvider
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.android.controller.ActivityController
import org.robolectric.annotation.Config
import java.util.concurrent.TimeUnit

/**
 * One MediaStore write request carries its URIs in one Binder transaction,
 * whose size is limited: a backlog is asked for in bounded batches, the rest
 * stays queued, and the next batch follows each answer. A request the
 * platform refuses to build loses nothing and is never retried forever.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class MediaWriteRequestBatchTest {

    private lateinit var context: Context
    private val previousStore = MediaPublisher.mediaStore

    /** The URIs each write request was built for. */
    private val requests = mutableListOf<List<Uri>>()

    /** Above this many URIs, building a write request fails, as an oversized transaction does. */
    private var transactionLimit = Int.MAX_VALUE

    /** URIs whose write request never builds. */
    private val unbuildable = mutableSetOf<Uri>()

    private val batch = MediaWriteAuthorizations.MAX_WRITE_REQUEST_URIS

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        MediaPublisher.mediaStore = object : MediaPublisher.MediaStoreAccess {
            override fun ownerPackage(context: Context, uri: Uri): String? = "com.example.camera"
            override fun hasWriteGrant(context: Context, uri: Uri): Boolean = false
            override fun createWriteRequest(context: Context, uris: List<Uri>): PendingIntent {
                requests += uris
                if (uris.size > transactionLimit) throw RuntimeException("transaction too large: ${uris.size}")
                if (uris.any { it in unbuildable }) throw IllegalArgumentException("cannot ask for ${uris.size}")
                return PendingIntent.getActivity(context, 0, Intent(), PendingIntent.FLAG_IMMUTABLE)
            }
        }
        MediaWriteAuthorizations.clear(context)
        shadowOf(context as Application).grantPermissions(Manifest.permission.ACCESS_MEDIA_LOCATION)
    }

    @After
    fun tearDown() {
        MediaPublisher.mediaStore = previousStore
        MediaWriteAuthorizations.clear(context)
    }

    private fun uri(i: Int): Uri = Uri.parse("content://media/external/images/media/${1000 + i}")

    private fun queue(count: Int): List<String> = (0 until count).map { i ->
        uri(i).toString().also { MediaWriteAuthorizations.add(context, PendingMediaWrite(it, null, "key-1", "Key", null)) }
    }

    @Test
    fun `a backlog larger than one batch drains in successive bounded requests`() {
        val queued = queue(2 * batch + 5)
        val asked = mutableSetOf<String>()

        while (true) {
            val request = MediaWriteAuthorizations.request(context, asked) ?: break
            if (request.requested.isEmpty()) break
            assertTrue("a batch of ${request.requested.size}", request.requested.size <= batch)
            asked += request.requested
            MediaWriteAuthorizations.deny(context, request.requested)
        }

        assertEquals(listOf(batch, batch, 5), requests.map { it.size })
        assertEquals(queued.toSet(), asked)
        assertTrue(MediaWriteAuthorizations.pending(context).isEmpty())
    }

    @Test
    fun `a request too large to build is asked for in smaller batches and loses nothing`() {
        val queued = queue(batch)
        transactionLimit = 7

        val request = MediaWriteAuthorizations.request(context)!!

        assertTrue("asked for ${request.requested.size}", request.requested.size in 1..7)
        assertTrue("every built request fits", requests.last().size <= 7)
        assertEquals("nothing leaves the queue", queued, MediaWriteAuthorizations.pending(context).map { it.uri })
    }

    @Test
    fun `a capture whose request never builds stays queued and is skipped, not asked for forever`() {
        val queued = queue(3)
        unbuildable += uri(1)

        val asked = mutableSetOf<String>()
        val skipped = mutableSetOf<String>()
        var rounds = 0

        while (rounds++ < 10) {
            val request = MediaWriteAuthorizations.request(context, asked + skipped) ?: break
            skipped += request.skipped
            if (request.requested.isEmpty()) break
            asked += request.requested
        }

        assertTrue("the requests end", rounds < 10)
        assertEquals(setOf(uri(0).toString(), uri(2).toString()), asked)
        assertEquals(setOf(uri(1).toString()), skipped)
        assertEquals("nothing leaves the queue", queued, MediaWriteAuthorizations.pending(context).map { it.uri })
    }

    private fun answer(controller: ActivityController<MediaWriteRequestActivity>, resultCode: Int) {
        val shadow = shadowOf(controller.get())
        val request = shadow.lastIntentSenderRequest ?: error("no write request was launched")
        shadow.callOnActivityResult(request.requestCode, resultCode, Intent())
    }

    private fun awaitMain(done: () -> Boolean): Boolean {
        val end = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
        while (System.nanoTime() < end) {
            shadowOf(Looper.getMainLooper()).idle()
            if (done()) return true
            Thread.sleep(20)
        }
        return done()
    }

    @Test
    fun `the screen asks for the next batch after each answer until the backlog is answered`() {
        queue(batch + 5)
        val controller = Robolectric.buildActivity(MediaWriteRequestActivity::class.java).setup()

        answer(controller, Activity.RESULT_CANCELED)
        assertTrue("the next batch is asked for", awaitMain { requests.size == 2 })
        assertEquals(listOf(batch, 5), requests.map { it.size })
        assertTrue(!controller.get().isFinishing)

        answer(controller, Activity.RESULT_CANCELED)
        assertTrue("it finishes once every batch is answered", awaitMain { controller.get().isFinishing })
        assertEquals(2, requests.size)
        assertTrue(MediaWriteAuthorizations.pending(context).isEmpty())
    }

    @Test
    fun `the screen recreated between batches asks for the next one, never the answered one again`() {
        queue(batch + 5)
        val controller = Robolectric.buildActivity(MediaWriteRequestActivity::class.java).setup()

        answer(controller, Activity.RESULT_CANCELED)
        assertTrue(awaitMain { requests.size == 2 })
        controller.recreate()
        answer(controller, Activity.RESULT_CANCELED)

        assertTrue(awaitMain { controller.get().isFinishing })
        assertEquals(listOf(batch, 5), requests.map { it.size })
        assertTrue(MediaWriteAuthorizations.pending(context).isEmpty())
    }
}
