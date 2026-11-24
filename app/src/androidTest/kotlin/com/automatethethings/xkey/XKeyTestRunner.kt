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
package com.automatethethings.xkey

import android.app.Activity
import android.app.Application
import android.os.Bundle
import android.os.ParcelFileDescriptor
import android.util.Log
import android.view.WindowManager
import androidx.test.runner.AndroidJUnitRunner

/**
 * The instrumentation runner for the whole androidTest suite.
 *
 * The suite runs on emulators and on real, owner-used phones. A real phone left
 * alone for a long run sleeps after its screen-off timeout, locks behind its
 * keyguard and animates every window and dialog transition; Espresso then fails
 * with `NoActivityResumedException`, `RootViewWithoutFocusException` or an
 * "animations are enabled" `PerformException`, none of which says anything about
 * the app. This runner puts the device into a testable state before the first
 * test and puts it back after the last one:
 *
 * - the three animation scales are set to 0;
 * - the screen is woken, kept on while the device is powered
 *   (`stay_on_while_plugged_in`) and its screen-off timeout is raised;
 * - every activity of the app process shows over the keyguard, turns the screen
 *   on and keeps it on ([ShowOverKeyguard]). The keyguard itself is never
 *   dismissed or weakened.
 *
 * Every value it changes is read first and written back in [finish]. The
 * originals are also parked in `Settings.Global` under [SAVED_PREFIX] keys
 * until they are restored, so a run killed before [finish] (a crashed test
 * process, a pulled cable) is repaired by the next run instead of having its
 * zeroed values taken as the device's own.
 */
class XKeyTestRunner : AndroidJUnitRunner() {

    private var restored = false

    override fun onStart() {
        runCatching { prepareDevice() }
            .onFailure { Log.w(TAG, "could not prepare the device; tests run as it is", it) }
        (targetContext.applicationContext as? Application)
            ?.registerActivityLifecycleCallbacks(ShowOverKeyguard)
        super.onStart()
    }

    override fun finish(resultCode: Int, results: Bundle?) {
        restoreDevice()
        super.finish(resultCode, results)
    }

    override fun onDestroy() {
        restoreDevice()
        super.onDestroy()
    }

    private fun prepareDevice() {
        TESTING_VALUES.forEach { (setting, value) ->
            val saved = shell("settings get global $SAVED_PREFIX${setting.name}")
            if (isUnset(saved)) {
                // No earlier run left a value behind: the current one is the owner's.
                val current = shell("settings get ${setting.table} ${setting.name}")
                shell("settings put global $SAVED_PREFIX${setting.name} ${encode(current)}")
            }
            shell("settings put ${setting.table} ${setting.name} $value")
        }
        shell("input keyevent KEYCODE_WAKEUP")
        shell("wm dismiss-keyguard") // only clears a swipe keyguard; a secure one stays
    }

    @Synchronized
    private fun restoreDevice() {
        if (restored) return
        restored = true
        TESTING_VALUES.keys.forEach { setting ->
            runCatching {
                val saved = shell("settings get global $SAVED_PREFIX${setting.name}")
                if (isUnset(saved)) return@runCatching
                val original = saved.trim()
                if (original == UNSET_MARKER) {
                    shell("settings delete ${setting.table} ${setting.name}")
                } else {
                    shell("settings put ${setting.table} ${setting.name} $original")
                }
                shell("settings delete global $SAVED_PREFIX${setting.name}")
            }.onFailure { Log.w(TAG, "could not restore ${setting.name}", it) }
        }
    }

    /** Runs [command] as the shell user and returns its standard output. */
    private fun shell(command: String): String {
        val pfd = uiAutomation.executeShellCommand(command)
        return ParcelFileDescriptor.AutoCloseInputStream(pfd).use { stream ->
            stream.readBytes().toString(Charsets.UTF_8)
        }
    }

    private data class Setting(val table: String, val name: String)

    /**
     * Shows every activity of the app process over the keyguard, turns the
     * screen on for it and keeps the screen on while it is in front. These
     * flags are set from the test process only; the release app never sees
     * them.
     */
    private object ShowOverKeyguard : Application.ActivityLifecycleCallbacks {
        override fun onActivityPreCreated(activity: Activity, savedInstanceState: Bundle?) {
            activity.setShowWhenLocked(true)
            activity.setTurnScreenOn(true)
            activity.window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        }

        override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {
            // Activities created before the callback existed still get the flags.
            onActivityPreCreated(activity, savedInstanceState)
        }

        override fun onActivityStarted(activity: Activity) = Unit
        override fun onActivityResumed(activity: Activity) = Unit
        override fun onActivityPaused(activity: Activity) = Unit
        override fun onActivityStopped(activity: Activity) = Unit
        override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) = Unit
        override fun onActivityDestroyed(activity: Activity) = Unit
    }

    companion object {
        private const val TAG = "XKeyTestRunner"

        /** Prefix of the `Settings.Global` keys holding the owner's values mid-run. */
        const val SAVED_PREFIX = "xkey_test_saved_"

        /** Stored for a setting that had no value, so restore deletes it again. */
        private const val UNSET_MARKER = "__unset__"

        /** Thirty minutes: long enough that the stay-on setting never races it. */
        private const val SCREEN_OFF_TIMEOUT_MS = 30 * 60 * 1000

        /** `BatteryManager.BATTERY_PLUGGED_AC | USB | WIRELESS | DOCK`. */
        private const val STAY_ON_ANY_POWER = 1 or 2 or 4 or 8

        private val TESTING_VALUES: Map<Setting, String> = linkedMapOf(
            Setting("global", "window_animation_scale") to "0",
            Setting("global", "transition_animation_scale") to "0",
            Setting("global", "animator_duration_scale") to "0",
            Setting("global", "stay_on_while_plugged_in") to STAY_ON_ANY_POWER.toString(),
            Setting("system", "screen_off_timeout") to SCREEN_OFF_TIMEOUT_MS.toString(),
        )

        /** `settings get` prints `null` for a setting that has no value. */
        internal fun isUnset(output: String): Boolean {
            val value = output.trim()
            return value.isEmpty() || value == "null"
        }

        internal fun encode(current: String): String =
            if (isUnset(current)) UNSET_MARKER else current.trim()
    }
}
