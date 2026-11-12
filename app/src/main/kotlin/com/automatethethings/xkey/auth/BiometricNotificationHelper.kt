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
package com.automatethethings.xkey.auth

import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Handler
import android.os.Looper
import android.util.Log
import androidx.core.app.NotificationCompat
import com.automatethethings.xkey.XKeyApplication
import com.automatethethings.xkey.R
import com.automatethethings.xkey.ui.TransparentBiometricActivity
import java.util.concurrent.ConcurrentHashMap

/**
 * Helper class for showing high-priority biometric request notifications.
 *
 * This class is responsible for creating full-screen intent notifications that
 * can wake the screen and display over the lock screen when biometric
 * authentication is required while the phone is locked.
 *
 * Features:
 * - Full-screen intent for immediate display on lock screen
 * - High-priority notification channel for visibility
 * - Auto-dismiss after timeout with callback
 * - Cancellation support
 *
 * Each notification belongs to the request it was posted for: it is posted
 * under that request id as its tag, and [cancelNotification] with the id
 * takes down only that one. Requests take turns on screen, and one that is
 * withdrawn while it waits for its turn has posted nothing, so it must take
 * nothing down: the notification up is the route to another request's prompt.
 *
 * Usage:
 * ```kotlin
 * val helper = BiometricNotificationHelper(context)
 * helper.showBiometricRequiredNotification(
 *     operationType = "sign",
 *     rpName = "Example Corp",
 *     requestId = "unique-request-id",
 *     onTimeout = { /* handle timeout */ }
 * )
 * ```
 */
class BiometricNotificationHelper(private val context: Context) {

    companion object {
        private const val TAG = "BiometricNotifyHelper"
        private const val NOTIFICATION_ID = 2001
        private const val DEFAULT_TIMEOUT_MS = 30_000L
    }

    private val handler = Handler(Looper.getMainLooper())

    /** The pending timeout of each notification this helper has up, by request id. */
    private val timeouts = ConcurrentHashMap<String, Runnable>()

    /**
     * Shows a high-priority notification indicating biometric authentication is required.
     *
     * This notification uses a full-screen intent that will:
     * - Turn on the screen if it's off
     * - Display over the lock screen
     * - Launch the biometric prompt activity directly
     *
     * @param operationType The type of operation requiring authentication
     *                      (e.g., "sign", "decrypt", "attestKey")
     * @param rpName The relying party name for context, or null if unavailable
     * @param requestId A unique identifier for the biometric request; the
     *   notification is posted under it, and replaces only an earlier one for
     *   the same request
     * @param timeoutMs Timeout in milliseconds before auto-dismissing (default 30s)
     * @param onTimeout Callback invoked when the notification times out without user action
     * @param promptIntent The prompt a [BiometricActivityLauncher] request opened
     *   for [requestId] (see its `onLaunch`). Opening that same intent lets an
     *   approval or a cancel on the lock screen complete the waiting request;
     *   without one, the notification opens a generic prompt that answers no
     *   launcher request.
     */
    fun showBiometricRequiredNotification(
        operationType: String,
        rpName: String?,
        requestId: String,
        timeoutMs: Long = DEFAULT_TIMEOUT_MS,
        onTimeout: () -> Unit = {},
        promptIntent: Intent? = null
    ) {
        Log.d(TAG, "Showing biometric notification: operation=$operationType, rpName=$rpName")

        // The full-screen intent: the launcher's own prompt when there is one,
        // else a generic TransparentBiometricActivity.
        // The launcher has already started its prompt, so the copy carries no
        // CLEAR_TOP: that would destroy the live prompt and recreate it,
        // answering the request as closed. A repeat delivery of the copy is
        // refused by the prompt that owns the request (for signing,
        // CryptoSigningCancellations; TransparentBiometricActivity is
        // singleTop and on top while it prompts).
        val fullScreenIntent = promptIntent?.let { Intent(it) }?.apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        } ?: Intent(context, TransparentBiometricActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra(TransparentBiometricActivity.EXTRA_REQUEST_ID, requestId)
            putExtra(TransparentBiometricActivity.EXTRA_TITLE, context.getString(R.string.biometric_prompt_title))
            putExtra(TransparentBiometricActivity.EXTRA_SUBTITLE, rpName ?: operationType)
            putExtra(TransparentBiometricActivity.EXTRA_SHOW_ON_LOCK_SCREEN, true)
        }

        val fullScreenPendingIntent = PendingIntent.getActivity(
            context,
            requestId.hashCode(),
            fullScreenIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        // Create the notification content
        val displayName = rpName ?: context.getString(R.string.app_name)
        val notification = NotificationCompat.Builder(context, XKeyApplication.BIOMETRIC_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_fingerprint)
            .setContentTitle(context.getString(R.string.biometric_notification_title))
            .setContentText(context.getString(R.string.biometric_notification_text, displayName))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_CALL)
            .setFullScreenIntent(fullScreenPendingIntent, true)
            .setContentIntent(fullScreenPendingIntent)
            .setAutoCancel(true)
            .setOngoing(true)
            .setTimeoutAfter(timeoutMs)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .build()

        val notificationManager = context.getSystemService(NotificationManager::class.java)
        notificationManager.notify(requestId, NOTIFICATION_ID, notification)

        // Schedule this request's timeout callback
        val timeout = object : Runnable {
            override fun run() {
                // Only while this is still the request's notification.
                if (!timeouts.remove(requestId, this)) return
                Log.d(TAG, "Biometric notification timed out")
                notificationManager.cancel(requestId, NOTIFICATION_ID)
                onTimeout()
            }
        }
        timeouts.put(requestId, timeout)?.let(handler::removeCallbacks)
        handler.postDelayed(timeout, timeoutMs)

        Log.i(TAG, "Biometric notification shown, will timeout in ${timeoutMs}ms")
    }

    /**
     * Cancels the notification posted for [requestId], and its pending
     * timeout callback, leaving every other request's notification up.
     */
    fun cancelNotification(requestId: String) {
        Log.d(TAG, "Cancelling biometric notification")

        timeouts.remove(requestId)?.let(handler::removeCallbacks)

        val notificationManager = context.getSystemService(NotificationManager::class.java)
        notificationManager.cancel(requestId, NOTIFICATION_ID)
    }

    /**
     * Cancels every notification this helper has up, and their timeout
     * callbacks. For a caller that cannot name its request; one that can
     * cancels by its id instead, so it never takes down another request's.
     */
    fun cancelNotification() {
        for (requestId in timeouts.keys.toList()) {
            cancelNotification(requestId)
        }
    }
}
