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

package com.automatethethings.xkey.testing

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.LockSupport

/**
 * Waits for an event on another thread. Real time is only a hang guard,
 * sized well past a loaded CI runner: a wait returns as soon as its event
 * has happened, and fails only when it never does.
 */
object ThreadWait {
    const val HANG_GUARD_MILLIS = 30_000L

    private val PARK_NANOS = TimeUnit.MILLISECONDS.toNanos(1)

    /** Waits until [done] holds; fails with [what] if it never did within [HANG_GUARD_MILLIS]. */
    fun until(what: String, done: () -> Boolean) {
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(HANG_GUARD_MILLIS)
        while (!done()) {
            if (System.nanoTime() - deadline > 0) throw AssertionError("$what: not within $HANG_GUARD_MILLIS ms")
            LockSupport.parkNanos(PARK_NANOS)
        }
    }

    /** Waits until [thread] is blocked entering a monitor another thread holds. */
    fun untilBlocked(thread: Thread, what: String = "${thread.name} waits on a lock") =
        until(what) { thread.state == Thread.State.BLOCKED }

    /** Waits until [latch] is counted down; fails with [what] if it never is. */
    fun await(latch: CountDownLatch, what: String) {
        if (!latch.await(HANG_GUARD_MILLIS, TimeUnit.MILLISECONDS)) {
            throw AssertionError("$what: not within $HANG_GUARD_MILLIS ms")
        }
    }
}
