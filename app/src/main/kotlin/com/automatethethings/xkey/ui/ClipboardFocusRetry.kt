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
package com.automatethethings.xkey.ui

import android.app.Activity
import android.app.Application
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.view.ViewTreeObserver
import java.util.WeakHashMap

/**
 * The one place a pending clipboard clear is retried: whenever any window of
 * the app gains focus, on every screen. From Android 10 on that is when the
 * app can read the clipboard again, so [SensitiveClipboard.retryPendingClears]
 * can finish a clear an unreadable clipboard held back.
 *
 * Registered once in the Application's onCreate. The focus listener goes on
 * an activity's decor view when it first resumes (by then its content is
 * set) and comes off when the activity is destroyed.
 */
internal object ClipboardFocusRetry : Application.ActivityLifecycleCallbacks {

    private val listeners = WeakHashMap<Activity, ViewTreeObserver.OnWindowFocusChangeListener>()

    override fun onActivityResumed(activity: Activity) {
        val context = activity.applicationContext
        if (activity !in listeners) {
            // The listener holds only the application context, never the activity.
            val listener = ViewTreeObserver.OnWindowFocusChangeListener { hasFocus ->
                if (hasFocus) retry(context)
            }
            activity.window.decorView.viewTreeObserver.addOnWindowFocusChangeListener(listener)
            listeners[activity] = listener
        }
        // Harmless while the clipboard is still unreadable: nothing is cleared.
        retry(context)
    }

    override fun onActivityDestroyed(activity: Activity) {
        val listener = listeners.remove(activity) ?: return
        val observer = activity.window.decorView.viewTreeObserver
        if (observer.isAlive) observer.removeOnWindowFocusChangeListener(listener)
    }

    private fun retry(context: Context) {
        val clipboard = context.getSystemService(ClipboardManager::class.java) ?: return
        SensitiveClipboard.retryPendingClears(clipboard)
    }

    override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {}

    override fun onActivityStarted(activity: Activity) {}

    override fun onActivityPaused(activity: Activity) {}

    override fun onActivityStopped(activity: Activity) {}

    override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) {}
}
