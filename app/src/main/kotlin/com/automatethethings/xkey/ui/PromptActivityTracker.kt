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

package com.automatethethings.xkey.ui

import android.app.Activity
import android.app.Application
import android.os.Bundle
import androidx.annotation.VisibleForTesting
import androidx.fragment.app.FragmentActivity
import java.lang.ref.WeakReference

/**
 * Where a prompt (the pairing confirmation, a biometric prompt) is raised:
 * the activity in front, or none.
 */
fun interface PromptHost {
    /** The resumed activity that may host a prompt, or null to refuse. */
    fun current(): FragmentActivity?
}

/**
 * The app's one record of the resumed [FragmentActivity], whichever screen
 * it is. [com.automatethethings.xkey.XKeyApplication] registers it for every
 * activity, so no screen has to register itself.
 *
 * An activity going away (paused or destroyed) clears the record only when it
 * is the one held: an old instance finishing after a newer one resumed must
 * not take the newer one's place away (#320).
 *
 * With no resumed activity [current] is null, and callers refuse: a prompt is
 * never raised from the background.
 */
object PromptActivityTracker : Application.ActivityLifecycleCallbacks, PromptHost {

    @Volatile
    private var resumed: WeakReference<FragmentActivity>? = null

    override fun current(): FragmentActivity? {
        val activity = resumed?.get() ?: return null
        if (activity.isFinishing || activity.isDestroyed) return null
        return activity
    }

    @Synchronized
    override fun onActivityResumed(activity: Activity) {
        if (activity is FragmentActivity) resumed = WeakReference(activity)
    }

    override fun onActivityPaused(activity: Activity) = clearIfHeld(activity)

    override fun onActivityDestroyed(activity: Activity) = clearIfHeld(activity)

    override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) = Unit

    override fun onActivityStarted(activity: Activity) = Unit

    override fun onActivityStopped(activity: Activity) = Unit

    override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) = Unit

    @VisibleForTesting
    fun reset() {
        resumed = null
    }

    @Synchronized
    private fun clearIfHeld(activity: Activity) {
        if (resumed?.get() === activity) resumed = null
    }
}
