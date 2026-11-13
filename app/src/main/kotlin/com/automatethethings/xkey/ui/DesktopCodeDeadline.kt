// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under AGPL-3.0 (see LICENSE) or a commercial license.
// Contact licensing@automatethethings.com for commercial licensing options.

package com.automatethethings.xkey.ui

import android.os.SystemClock

/**
 * Milliseconds on a clock that never goes back (not wall time) and keeps
 * counting in deep sleep, as an OTP's or approval's validity does. This is
 * the one clock for user-visible expiry: never System.nanoTime() or
 * SystemClock.uptimeMillis(), which stop while the device sleeps.
 */
fun interface MonotonicClock {
    fun nowMillis(): Long

    companion object {
        val SYSTEM = MonotonicClock { SystemClock.elapsedRealtimeNanos() / 1_000_000 }
    }
}

/**
 * The one way a desktop OATH code reaches the screen. The deadline is fixed
 * when the reply arrives, [expiresInSeconds] after [clock]'s now; [view]
 * returns the code only before it, and drops the code once it has passed.
 * A null [expiresInSeconds] (HOTP) has no deadline.
 */
class DesktopCodeDeadline(
    code: String,
    expiresInSeconds: Int?,
    private val clock: MonotonicClock
) {
    sealed interface View {
        data class Live(val code: String, val remainingSeconds: Int) : View
        data class NoExpiry(val code: String) : View
        data object Expired : View
    }

    private var code: String? = code
    private val deadlineMillis: Long? = expiresInSeconds?.let { clock.nowMillis() + it * 1_000L }

    /** What the dialog shows now. */
    fun view(): View {
        val shown = code ?: return View.Expired
        val deadline = deadlineMillis ?: return View.NoExpiry(shown)
        val left = deadline - clock.nowMillis()
        if (left <= 0) {
            code = null
            return View.Expired
        }
        return View.Live(shown, ((left + 999) / 1_000).toInt())
    }

    /** Milliseconds until [view] next changes; null when it never will. */
    fun millisUntilChange(): Long? {
        if (view() !is View.Live) return null
        val left = deadlineMillis!! - clock.nowMillis()
        return (left - 1) % 1_000 + 1
    }

    override fun toString(): String = "DesktopCodeDeadline(${if (code == null) "expired" else "live"})"
}
