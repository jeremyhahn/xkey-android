/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
 *
 * This file is part of xkey-android.
 *
 * xkey-android is dual-licensed:
 *
 * 1. GNU Affero General Public License v3.0 (AGPL-3.0)
 *    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
 *
 * 2. Commercial License
 *    Contact licensing@automatethethings.com for commercial licensing options.
 */

package com.automatethethings.xkey.media

import android.app.Application
import android.app.NotificationManager
import android.app.Service
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.media.MediaSigningServiceFixture.Capture
import com.automatethethings.xkey.media.MediaSigningServiceFixture.Companion.IMAGES
import com.automatethethings.xkey.media.MediaSigningServiceFixture.Companion.VIDEOS
import com.automatethethings.xkey.storage.XKeyDatabase
import io.mockk.verify
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowPowerManager

/**
 * When [MediaSigningService] signs at all: the settings gates, read at each
 * event, and the observer, foreground and wake-lock lifecycle of the service.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class, sdk = [34])
class MediaSigningServiceGateTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    private lateinit var fixture: MediaSigningServiceFixture

    @Before
    fun setUp() {
        fixture = MediaSigningServiceFixture(tempFolder.newFolder("media"))
        fixture.setUp()
        fixture.start()
    }

    @After
    fun tearDown() = fixture.tearDown()

    private var seed = 0

    private fun photo(): Capture =
        fixture.addCapture(IMAGES, "IMG_${++seed}.png", MediaSigningServiceFixture.png(seed), "image/png")

    private fun video(): Capture =
        fixture.addCapture(VIDEOS, "VID_${++seed}.mp4", MediaSigningServiceFixture.video(seed), "video/mp4")

    private fun assertSigned(capture: Capture) {
        assertTrue("${capture.file.name} must be signed", capture.sidecar.isFile)
        verify(exactly = 1) { AuditLogger.logMediaAutoSigned(any(), any(), capture.uri.toString()) }
    }

    private fun assertNotSigned(vararg captures: Capture) {
        captures.forEach {
            fixture.assertUnsigned(it)
            verify(exactly = 0) { AuditLogger.logMediaAutoSigned(any(), any(), it.uri.toString()) }
        }
    }

    private fun assertKeyStoreUntouched() {
        verify(exactly = 0) { anyConstructed<KeystoreManager>().publicKeyDERAt(any()) }
        assertTrue("nothing may be signed", fixture.signCalls.isEmpty())
    }

    // -------------------------------------------------------------------------
    // Settings gates
    // -------------------------------------------------------------------------

    @Test
    fun `auto-sign off signs nothing and never reaches the key store or the database`() {
        fixture.settings = fixture.settings.copy(autoSignEnabled = false)
        val photo = photo()
        val video = video()

        fixture.deliver(photo.uri)
        fixture.deliver(video.uri)

        assertNotSigned(photo, video)
        assertKeyStoreUntouched()
        verify(exactly = 0) { XKeyDatabase.getInstance(any()) }
    }

    @Test
    fun `photo signing off skips a photo while a video still signs`() {
        fixture.settings = fixture.settings.copy(signPhotos = false)
        val photo = photo()
        val video = video()

        fixture.deliver(photo.uri)
        fixture.deliver(video.uri)

        assertNotSigned(photo)
        assertSigned(video)
        assertEquals(1, fixture.signCalls.size)
    }

    @Test
    fun `video signing off skips a video while a photo still signs`() {
        fixture.settings = fixture.settings.copy(signVideos = false)
        val photo = photo()
        val video = video()

        fixture.deliver(video.uri)
        fixture.deliver(photo.uri)

        assertNotSigned(video)
        assertSigned(photo)
        assertEquals(1, fixture.signCalls.size)
    }

    @Test
    fun `no signing key id signs nothing and never calls the key store`() {
        fixture.settings = fixture.settings.copy(signingKeyId = null)
        val photo = photo()
        val video = video()

        fixture.deliver(photo.uri)
        fixture.deliver(video.uri)

        assertNotSigned(photo, video)
        assertKeyStoreUntouched()
    }

    @Test
    fun `a signing key id missing from the database signs nothing and never calls the key store`() {
        fixture.settings = fixture.settings.copy(signingKeyId = "deleted-key")
        val photo = photo()
        val video = video()

        fixture.deliver(photo.uri)
        fixture.deliver(video.uri)

        assertNotSigned(photo, video)
        assertKeyStoreUntouched()
    }

    @Test
    fun `settings changed after start are read at event time`() {
        fixture.settings = fixture.settings.copy(autoSignEnabled = false)
        val first = photo()
        fixture.deliver(first.uri)
        assertNotSigned(first)

        fixture.settings = fixture.settings.copy(autoSignEnabled = true)
        val second = photo()
        fixture.deliver(second.uri)
        fixture.deliver(first.uri)

        assertSigned(second)
        assertSigned(first)

        fixture.settings = fixture.settings.copy(signPhotos = false)
        val third = photo()
        fixture.deliver(third.uri)
        assertNotSigned(third)
    }

    // -------------------------------------------------------------------------
    // Lifecycle
    // -------------------------------------------------------------------------

    @Test
    fun `a start posts the foreground notification and registers one observer per collection`() {
        val shadow = shadowOf(fixture.service)
        val notification = shadow.lastForegroundNotification
        assertNotNull("the service must run in the foreground", notification)
        assertEquals("media_signing_channel", notification.channelId)
        assertEquals(2002, shadow.lastForegroundNotificationId)
        val manager = fixture.service.getSystemService(NotificationManager::class.java)
        assertNotNull("the channel must exist", manager.getNotificationChannel("media_signing_channel"))

        assertEquals(1, fixture.observers(IMAGES).size)
        assertEquals(1, fixture.observers(VIDEOS).size)
    }

    @Test
    fun `onStartCommand returns START_STICKY and a second start keeps one observer per collection`() {
        assertEquals(Service.START_STICKY, fixture.service.onStartCommand(null, 0, 41))
        fixture.start()

        assertEquals(1, fixture.observers(IMAGES).size)
        assertEquals(1, fixture.observers(VIDEOS).size)

        val photo = photo()
        fixture.deliver(photo.uri)
        assertSigned(photo)
        assertEquals("one event must sign once", 1, fixture.signCalls.size)
    }

    @Test
    fun `onDestroy leaves no observers and releases the wake lock`() {
        val wakeLock = ShadowPowerManager.getLatestWakeLock()
        assertNotNull("a start must take the wake lock", wakeLock)
        assertTrue(wakeLock!!.isHeld)

        fixture.destroy()

        assertTrue(fixture.observers(IMAGES).isEmpty())
        assertTrue(fixture.observers(VIDEOS).isEmpty())
        assertFalse("onDestroy must release the wake lock", wakeLock.isHeld)
    }
}
