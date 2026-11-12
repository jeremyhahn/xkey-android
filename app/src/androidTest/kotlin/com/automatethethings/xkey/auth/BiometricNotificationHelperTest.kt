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
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Handler
import android.os.Looper
import android.service.notification.StatusBarNotification
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.rule.GrantPermissionRule
import com.automatethethings.xkey.R
import com.automatethethings.xkey.XKeyApplication
import com.automatethethings.xkey.ui.TransparentBiometricActivity
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
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

    /** The key each test posts under, and tearDown takes down. */
    private val requestId = "request-${System.nanoTime()}"

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        notificationManager = context.getSystemService(NotificationManager::class.java)
        helper = BiometricNotificationHelper(context)
        notificationManager.cancel(notificationId)
    }

    @After
    fun tearDown() {
        helper.cancelNotification(requestId)
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
            requestId = requestId
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
            requestId = requestId
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
            requestId = requestId
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
            requestId = requestId
        )
        awaitPosted()

        helper.cancelNotification(requestId)

        awaitGone()
    }

    @Test
    fun theTimeoutCallbackFiresAndTakesTheNotificationWithIt() {
        val timedOut = CountDownLatch(1)

        helper.showBiometricRequiredNotification(
            operationType = "sign",
            rpName = "Example Corp",
            requestId = requestId,
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
            requestId = requestId,
            timeoutMs = 1_500L,
            onTimeout = { timedOut.countDown() }
        )
        awaitPosted()

        helper.cancelNotification(requestId)

        // The helper's timeout sits on the main looper. A marker posted there now
        // with the same delay runs after the timeout's deadline, so by the time it
        // runs a timeout that survived the cancel would already have fired.
        val pastTheDeadline = CountDownLatch(1)
        Handler(Looper.getMainLooper()).postDelayed({ pastTheDeadline.countDown() }, 1_500L)
        assertTrue(
            "the main looper never reached the timeout's deadline",
            pastTheDeadline.await(10, TimeUnit.SECONDS)
        )
        assertEquals(
            "the timeout callback ran after the request was cancelled",
            1L,
            timedOut.count
        )
    }

    /** The notification posted under [key], or null when none is up. */
    private fun postedUnder(key: String): StatusBarNotification? =
        notificationManager.activeNotifications.firstOrNull { it.id == notificationId && it.tag == key }

    private fun awaitGoneUnder(key: String, timeoutMs: Long = 5_000L) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (postedUnder(key) == null) return
            Thread.sleep(25)
        }
        throw AssertionError("the notification under $key was still showing")
    }

    /** Waits [delayMs] on the main looper, where the helper's timeouts run. */
    private fun passOnTheMainLooper(delayMs: Long) {
        val passed = CountDownLatch(1)
        Handler(Looper.getMainLooper()).postDelayed({ passed.countDown() }, delayMs)
        assertTrue("the main looper never got that far", passed.await(10, TimeUnit.SECONDS))
    }

    private fun show(key: String, timeoutMs: Long, timedOut: CountDownLatch) =
        helper.showBiometricRequiredNotification(
            operationType = "sign",
            rpName = key,
            requestId = key,
            timeoutMs = timeoutMs,
            onTimeout = { timedOut.countDown() }
        )

    @Test
    fun differentRequestsExpireAndCancelIndependently() {
        val first = "$requestId-a"
        val second = "$requestId-b"
        val third = "$requestId-c"
        val firstTimedOut = CountDownLatch(1)
        val secondTimedOut = CountDownLatch(1)
        val thirdTimedOut = CountDownLatch(1)
        try {
            show(first, 600L, firstTimedOut)
            show(second, 600L, secondTimedOut)
            show(third, 1_500L, thirdTimedOut)

            assertTrue("the first request's callback never ran", firstTimedOut.await(10, TimeUnit.SECONDS))
            assertTrue("the second request's callback never ran", secondTimedOut.await(10, TimeUnit.SECONDS))
            awaitGoneUnder(first)
            awaitGoneUnder(second)
            assertNotNull("the others' expiry left the third request's notification up", postedUnder(third))

            helper.cancelNotification(third)
            passOnTheMainLooper(1_500L)

            assertEquals("the third request's callback ran after its cancel", 1L, thirdTimedOut.count)
            awaitGoneUnder(third)
        } finally {
            listOf(first, second, third).forEach(helper::cancelNotification)
        }
    }

    @Test
    fun twoKeysWithEqualHashCodesNeverShareOrRewriteAPendingIntent() {
        // Process-safe approval ids are large; these two hash alike, so a
        // request code drawn from hashCode() alone cannot tell them apart.
        val older = "approval-3363295394234823610"
        val newer = "approval-2315463952855601407"
        assertEquals("the keys must collide for this test to mean anything", older.hashCode(), newer.hashCode())
        val unused = CountDownLatch(1)
        try {
            show(older, 30_000L, unused)
            val olderIntent = awaitPostedUnder(older).notification.contentIntent
            assertNotNull(olderIntent)

            show(newer, 30_000L, unused)
            val newerIntent = awaitPostedUnder(newer).notification.contentIntent
            assertNotNull(newerIntent)

            assertNotEquals(
                "the newer request's notification took over the older one's pending intent",
                olderIntent,
                newerIntent
            )
            assertEquals(
                "posting the newer request replaced the older notification's pending intent",
                olderIntent,
                postedUnder(older)!!.notification.contentIntent
            )
            // Each key has a pending intent of its own: a plain intent that
            // differs only in extras, as both did before, matches neither.
            assertNull(
                "an intent without the key's data still matches a notification's pending intent",
                PendingIntent.getActivity(
                    context,
                    older.hashCode(),
                    Intent(context, TransparentBiometricActivity::class.java),
                    PendingIntent.FLAG_NO_CREATE or PendingIntent.FLAG_IMMUTABLE
                )
            )
        } finally {
            helper.cancelNotification(older)
            helper.cancelNotification(newer)
        }
    }

    private fun awaitPostedUnder(key: String, timeoutMs: Long = 5_000L): StatusBarNotification {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            postedUnder(key)?.let { return it }
            Thread.sleep(25)
        }
        throw AssertionError("no notification was posted under $key")
    }

    @Test
    fun repostingTheSameRequestReplacesItsTimeout() {
        val replacedTimedOut = CountDownLatch(1)
        val currentTimedOut = CountDownLatch(1)

        show(requestId, 600L, replacedTimedOut)
        show(requestId, 2_000L, currentTimedOut)
        passOnTheMainLooper(900L)

        assertEquals("the replaced timeout's callback ran", 1L, replacedTimedOut.count)
        assertNotNull("the replaced timeout took the notification down", postedUnder(requestId))
        assertTrue("the current timeout's callback never ran", currentTimedOut.await(10, TimeUnit.SECONDS))
        awaitGoneUnder(requestId)
    }
}
