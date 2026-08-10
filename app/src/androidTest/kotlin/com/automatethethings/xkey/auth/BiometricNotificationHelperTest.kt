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
package com.automatethethings.xkey.auth

import android.Manifest
import android.app.Notification
import android.app.NotificationManager
import android.content.Context
import android.service.notification.StatusBarNotification
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.rule.GrantPermissionRule
import com.automatethethings.xkey.R
import com.automatethethings.xkey.XKeyApplication
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * Instrumented tests for [BiometricNotificationHelper].
 *
 * The helper exists to wake a locked phone when a paired desktop asks for a
 * signature, so it is nothing but calls into `NotificationManager`,
 * `PendingIntent` and a main-looper `Handler` -- none of which exist off-device.
 *
 * Assertions read `NotificationManager.getActiveNotifications`, which reports
 * only this app's own notifications, rather than trusting that `notify` was
 * called. Every test cancels what it posted, and teardown cancels again in case
 * an assertion failed midway.
 */
@RunWith(AndroidJUnit4::class)
class BiometricNotificationHelperTest {

    @get:Rule
    val notificationPermission: GrantPermissionRule =
        GrantPermissionRule.grant(Manifest.permission.POST_NOTIFICATIONS)

    private val notificationId = 2001

    private lateinit var context: Context
    private lateinit var notificationManager: NotificationManager
    private lateinit var helper: BiometricNotificationHelper

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        notificationManager = context.getSystemService(NotificationManager::class.java)
        helper = BiometricNotificationHelper(context)
        notificationManager.cancel(notificationId)
    }

    @After
    fun tearDown() {
        helper.cancelNotification()
        notificationManager.cancel(notificationId)
    }

    private fun posted(): StatusBarNotification? =
        notificationManager.activeNotifications.firstOrNull { it.id == notificationId }

    private fun awaitPosted(timeoutMs: Long = 5_000L): StatusBarNotification {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            posted()?.let { return it }
            Thread.sleep(25)
        }
        throw AssertionError("no notification with id $notificationId was posted")
    }

    private fun awaitGone(timeoutMs: Long = 5_000L) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (posted() == null) return
            Thread.sleep(25)
        }
        throw AssertionError("notification $notificationId was still showing")
    }

    @Test
    fun biometricChannelExists() {
        val channel = notificationManager.getNotificationChannel(
            XKeyApplication.BIOMETRIC_CHANNEL_ID
        )

        assertNotNull(
            "the application must create ${XKeyApplication.BIOMETRIC_CHANNEL_ID} at startup",
            channel
        )
        assertEquals(XKeyApplication.BIOMETRIC_CHANNEL_ID, channel!!.id)
        // A full-screen intent is only honoured from a channel at default
        // importance or above, which is the whole reason this channel exists.
        assertTrue(
            "importance was ${channel.importance}",
            channel.importance >= NotificationManager.IMPORTANCE_DEFAULT
        )
    }

    @Test
    fun showBiometricRequiredNotification_postsOnTheBiometricChannel() {
        helper.showBiometricRequiredNotification(
            operationType = "sign",
            rpName = "Example Corp",
            requestId = "request-${System.nanoTime()}"
        )

        val notification = awaitPosted().notification
        assertEquals(XKeyApplication.BIOMETRIC_CHANNEL_ID, notification.channelId)
        assertEquals(Notification.CATEGORY_CALL, notification.category)
        assertNotNull(notification.contentIntent)
        // `fullScreenIntent` is deliberately not asserted: from Android 14 the
        // platform strips it when USE_FULL_SCREEN_INTENT has not been granted,
        // which is the default for an app that is not a dialler or alarm clock.
        // The helper still sets it, and the demoted notification still posts.
    }

    @Test
    fun showBiometricRequiredNotification_namesTheRelyingParty() {
        helper.showBiometricRequiredNotification(
            operationType = "sign",
            rpName = "Example Corp",
            requestId = "request-${System.nanoTime()}"
        )

        val text = awaitPosted().notification.extras
            .getCharSequence(Notification.EXTRA_TEXT)?.toString()
        assertNotNull(text)
        assertTrue(text!!, text.contains("Example Corp"))
        assertEquals(
            context.getString(R.string.biometric_notification_title),
            awaitPosted().notification.extras
                .getCharSequence(Notification.EXTRA_TITLE)?.toString()
        )
    }

    @Test
    fun showBiometricRequiredNotification_fallsBackToTheAppNameWithoutARelyingParty() {
        helper.showBiometricRequiredNotification(
            operationType = "decrypt",
            rpName = null,
            requestId = "request-${System.nanoTime()}"
        )

        val text = awaitPosted().notification.extras
            .getCharSequence(Notification.EXTRA_TEXT)?.toString()
        assertNotNull(text)
        assertTrue(text!!, text.contains(context.getString(R.string.app_name)))
    }

    @Test
    fun cancelNotification_removesIt() {
        helper.showBiometricRequiredNotification(
            operationType = "sign",
            rpName = "Example Corp",
            requestId = "request-${System.nanoTime()}"
        )
        awaitPosted()

        helper.cancelNotification()

        awaitGone()
    }

    @Test
    fun cancelNotification_isSafeWhenNothingIsShowing() {
        helper.cancelNotification()
        helper.cancelNotification()

        assertNull(posted())
    }

    @Test
    fun theTimeoutCallbackFiresAndTakesTheNotificationWithIt() {
        val timedOut = CountDownLatch(1)

        helper.showBiometricRequiredNotification(
            operationType = "sign",
            rpName = "Example Corp",
            requestId = "request-${System.nanoTime()}",
            timeoutMs = 400L,
            onTimeout = { timedOut.countDown() }
        )

        assertTrue(
            "the timeout callback never ran",
            timedOut.await(10, TimeUnit.SECONDS)
        )
        awaitGone()
    }

    @Test
    fun cancellingBeforeTheTimeoutSuppressesTheCallback() {
        val timedOut = CountDownLatch(1)

        helper.showBiometricRequiredNotification(
            operationType = "sign",
            rpName = "Example Corp",
            requestId = "request-${System.nanoTime()}",
            timeoutMs = 1_500L,
            onTimeout = { timedOut.countDown() }
        )
        awaitPosted()

        helper.cancelNotification()

        assertFalse(
            "the timeout callback ran after the request was cancelled",
            timedOut.await(3, TimeUnit.SECONDS)
        )
    }

    @Test
    fun aSecondRequestReplacesThePendingTimeout() {
        val firstTimedOut = CountDownLatch(1)
        val secondTimedOut = CountDownLatch(1)

        helper.showBiometricRequiredNotification(
            operationType = "sign",
            rpName = "First",
            requestId = "request-a-${System.nanoTime()}",
            timeoutMs = 600L,
            onTimeout = { firstTimedOut.countDown() }
        )
        helper.showBiometricRequiredNotification(
            operationType = "sign",
            rpName = "Second",
            requestId = "request-b-${System.nanoTime()}",
            timeoutMs = 600L,
            onTimeout = { secondTimedOut.countDown() }
        )

        assertTrue(
            "the surviving request's callback never ran",
            secondTimedOut.await(10, TimeUnit.SECONDS)
        )
        assertEquals(
            "the superseded request's callback should have been removed",
            1L,
            firstTimedOut.count
        )
    }
}
