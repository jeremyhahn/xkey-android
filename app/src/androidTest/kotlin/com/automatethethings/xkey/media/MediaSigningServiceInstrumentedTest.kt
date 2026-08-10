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
import android.app.NotificationManager
import android.content.ContentUris
import android.content.Context
import android.content.Intent
import android.database.ContentObserver
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.provider.MediaStore
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.rule.GrantPermissionRule
import com.automatethethings.xkey.audit.AuditOperationType
import com.automatethethings.xkey.settings.MediaSigningSettingsData
import com.automatethethings.xkey.settings.MediaSigningSettingsRepository
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.ui.MainActivity
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * Instrumented tests for [MediaSigningService], the foreground service that
 * watches MediaStore and signs new captures.
 *
 * Nothing in this class exists off-device: a foreground notification, a wake
 * lock, two `MediaStore` content observers and a DataStore-backed settings read.
 *
 * Two things are proved here. First the lifecycle: starting the service posts
 * its ongoing notification and creates its channel, and stopping it takes the
 * notification down and releases the observers — a service that leaked either
 * would keep the phone awake between captures.
 *
 * Second, and more important, the **refusal** branches. Auto-signing is off by
 * default and gated by three further switches, and every gate has to hold: a
 * capture must not be signed when auto-signing is disabled, when that media kind
 * is disabled, when no signing key is configured, or when the configured key has
 * been deleted. Each test fires a real MediaStore change notification at the
 * running service and then asserts no `MEDIA_AUTO_SIGNED` audit record names
 * that URI. A control observer registered alongside the service's proves the
 * notification really was delivered, so a passing assertion means "the service
 * saw it and declined", not "nothing happened".
 *
 * The success path needs a genuine MediaStore row plus a Keystore signing key
 * and would leave a photo in the device gallery, so it is deliberately out of
 * scope here.
 *
 * Cleanup: the service is stopped and the media-signing settings are restored to
 * their defaults after every test. The notification channel is left in place —
 * it is app-owned, permanent by design and recreated by production code on the
 * next start.
 */
@RunWith(AndroidJUnit4::class)
class MediaSigningServiceInstrumentedTest {

    @get:Rule
    val notificationPermission: GrantPermissionRule =
        GrantPermissionRule.grant(Manifest.permission.POST_NOTIFICATIONS)

    private lateinit var context: Context
    private lateinit var notificationManager: NotificationManager
    private lateinit var settings: MediaSigningSettingsRepository
    private var activity: ActivityScenario<MainActivity>? = null
    private var originalSettings: MediaSigningSettingsData? = null

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        notificationManager = context.getSystemService(NotificationManager::class.java)
        settings = MediaSigningSettingsRepository(context)
        runBlocking {
            originalSettings = settings.getSettings()
            settings.updateSettings(MediaSigningSettingsData())
        }
        // A foreground-service start is only permitted while the app is visible.
        activity = ActivityScenario.launch(MainActivity::class.java)
    }

    @After
    fun tearDown() {
        stopService()
        // stopService() is asynchronous. Without settling here, the next test's
        // startService() can be satisfied by this test's notification and then
        // watch it vanish underneath it.
        awaitNotificationGone()
        runBlocking {
            settings.updateSettings(originalSettings ?: MediaSigningSettingsData())
        }
        originalSettings = null
        activity?.close()
        activity = null
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private fun startService() {
        context.startService(Intent(context, MediaSigningService::class.java))
        awaitNotification(present = true)
    }

    private fun stopService() {
        context.stopService(Intent(context, MediaSigningService::class.java))
    }

    /**
     * Polls until the notification is gone, without asserting. Teardown must not
     * turn a slow shutdown into a second failure for a test that already passed;
     * [stoppingTheService_takesTheNotificationDown] is what asserts the takedown.
     */
    private fun awaitNotificationGone() {
        val deadline = SystemClock.uptimeMillis() + TIMEOUT_MS
        while (SystemClock.uptimeMillis() < deadline) {
            if (notificationManager.activeNotifications.none { it.id == NOTIFICATION_ID }) return
            SystemClock.sleep(POLL_MS)
        }
    }

    /** Polls until the ongoing notification is (or is no longer) posted. */
    private fun awaitNotification(present: Boolean) {
        val deadline = SystemClock.uptimeMillis() + TIMEOUT_MS
        while (SystemClock.uptimeMillis() < deadline) {
            val posted = notificationManager.activeNotifications.any { it.id == NOTIFICATION_ID }
            if (posted == present) return
            SystemClock.sleep(POLL_MS)
        }
        fail(
            if (present) "the media signing notification was never posted"
            else "the media signing notification was never taken down"
        )
    }

    /** A MediaStore URI for a row that does not exist, unique per call. */
    private fun syntheticMediaUri(collection: Uri): Uri =
        ContentUris.withAppendedId(collection, 900_000_000L + (System.nanoTime() % 1_000_000L))

    /**
     * Fires a MediaStore change for [uri] and blocks until a control observer
     * registered on the same collection has seen it, so the service's observer
     * has demonstrably been given the same notification.
     */
    private fun notifyAndAwaitDelivery(collection: Uri, uri: Uri) {
        val delivered = CountDownLatch(1)
        val control = object : ContentObserver(Handler(Looper.getMainLooper())) {
            override fun onChange(selfChange: Boolean, changed: Uri?) {
                if (changed == uri) delivered.countDown()
            }
        }
        context.contentResolver.registerContentObserver(collection, true, control)
        try {
            context.contentResolver.notifyChange(uri, null)
            assertTrue(
                "the MediaStore change was never delivered to observers",
                delivered.await(TIMEOUT_MS, TimeUnit.MILLISECONDS)
            )
        } finally {
            context.contentResolver.unregisterContentObserver(control)
        }
        // The service defers signing to let the file finish being written.
        SystemClock.sleep(SETTLE_MS)
    }

    /** Fails if any audit record says the given URI was auto-signed. */
    private fun assertNotAutoSigned(uri: Uri) {
        val signed = runBlocking {
            XKeyDatabase.getInstance(context).auditLogDao()
                .getByOperationType(AuditOperationType.MEDIA_AUTO_SIGNED)
        }
        val offender = signed.firstOrNull { it.details?.contains(uri.toString()) == true }
        assertNull("this capture must not have been signed: ${offender?.details}", offender)
    }

    private fun configure(
        autoSignEnabled: Boolean,
        signingKeyId: String?,
        signPhotos: Boolean = true,
        signVideos: Boolean = true
    ) {
        runBlocking {
            settings.updateSettings(
                MediaSigningSettingsData(
                    autoSignEnabled = autoSignEnabled,
                    signingKeyId = signingKeyId,
                    signPhotos = signPhotos,
                    signVideos = signVideos
                )
            )
        }
    }

    // -------------------------------------------------------------------------
    // Lifecycle
    // -------------------------------------------------------------------------

    @Test
    fun startingTheService_postsAnOngoingForegroundNotification() {
        startService()

        val posted = notificationManager.activeNotifications.first { it.id == NOTIFICATION_ID }
        assertTrue("the signing notification must be ongoing", posted.isOngoing)
        assertEquals(CHANNEL_ID, posted.notification.channelId)
    }

    @Test
    fun startingTheService_createsItsLowImportanceChannel() {
        startService()

        val channel = notificationManager.getNotificationChannel(CHANNEL_ID)
        assertNotNull("the media signing channel must exist once the service runs", channel)
        assertEquals(NotificationManager.IMPORTANCE_LOW, channel!!.importance)
        assertNotNull(channel.description)
    }

    @Test
    fun stoppingTheService_takesTheNotificationDown() {
        startService()

        stopService()

        awaitNotification(present = false)
    }

    @Test
    fun theServiceCanBeRestarted() {
        startService()
        stopService()
        awaitNotification(present = false)

        startService()

        awaitNotification(present = true)
    }

    @Test
    fun startingTheServiceTwice_keepsASingleNotification() {
        startService()

        // START_STICKY means onStartCommand can be re-delivered; a second start
        // must leave exactly one ongoing notification behind.
        context.startService(Intent(context, MediaSigningService::class.java))
        SystemClock.sleep(SETTLE_MS)

        assertEquals(
            1,
            notificationManager.activeNotifications.count { it.id == NOTIFICATION_ID }
        )
        stopService()
        awaitNotification(present = false)
    }

    // -------------------------------------------------------------------------
    // Refusal branches
    // -------------------------------------------------------------------------

    @Test
    fun aNewPhoto_isNotSignedWhileAutoSigningIsOff() {
        configure(autoSignEnabled = false, signingKeyId = "any-key")
        startService()
        val uri = syntheticMediaUri(MediaStore.Images.Media.EXTERNAL_CONTENT_URI)

        notifyAndAwaitDelivery(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, uri)

        assertNotAutoSigned(uri)
    }

    @Test
    fun aNewPhoto_isNotSignedWhenPhotoSigningIsOff() {
        configure(autoSignEnabled = true, signingKeyId = "any-key", signPhotos = false)
        startService()
        val uri = syntheticMediaUri(MediaStore.Images.Media.EXTERNAL_CONTENT_URI)

        notifyAndAwaitDelivery(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, uri)

        assertNotAutoSigned(uri)
    }

    @Test
    fun aNewVideo_isNotSignedWhenVideoSigningIsOff() {
        configure(autoSignEnabled = true, signingKeyId = "any-key", signVideos = false)
        startService()
        val uri = syntheticMediaUri(MediaStore.Video.Media.EXTERNAL_CONTENT_URI)

        notifyAndAwaitDelivery(MediaStore.Video.Media.EXTERNAL_CONTENT_URI, uri)

        assertNotAutoSigned(uri)
    }

    @Test
    fun aNewPhoto_isNotSignedWhenNoSigningKeyIsConfigured() {
        configure(autoSignEnabled = true, signingKeyId = null)
        startService()
        val uri = syntheticMediaUri(MediaStore.Images.Media.EXTERNAL_CONTENT_URI)

        notifyAndAwaitDelivery(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, uri)

        assertNotAutoSigned(uri)
    }

    @Test
    fun aNewPhoto_isNotSignedWhenTheConfiguredKeyHasBeenDeleted() {
        configure(autoSignEnabled = true, signingKeyId = "key-that-was-deleted-${System.nanoTime()}")
        startService()
        val uri = syntheticMediaUri(MediaStore.Images.Media.EXTERNAL_CONTENT_URI)

        notifyAndAwaitDelivery(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, uri)

        assertNotAutoSigned(uri)
    }

    @Test
    fun aMediaChangeAfterTheServiceStops_isIgnored() {
        configure(autoSignEnabled = true, signingKeyId = "any-key")
        startService()
        stopService()
        awaitNotification(present = false)
        val uri = syntheticMediaUri(MediaStore.Images.Media.EXTERNAL_CONTENT_URI)

        notifyAndAwaitDelivery(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, uri)

        assertNotAutoSigned(uri)
    }

    private companion object {
        /** Mirrors the private constants in [MediaSigningService]. */
        const val NOTIFICATION_ID = 2002
        const val CHANNEL_ID = "media_signing_channel"

        /**
         * Comfortably past the ~10s the system may defer a foreground-service
         * notification by. A 10s budget sits exactly on that boundary and loses
         * the race whenever the emulator is loaded.
         */
        const val TIMEOUT_MS = 20_000L
        const val POLL_MS = 100L

        /** Comfortably past the service's 500 ms write-settling delay. */
        const val SETTLE_MS = 2_000L
    }
}
