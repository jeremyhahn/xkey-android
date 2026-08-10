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
package com.automatethethings.xkey.ui

import android.app.Activity
import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.fail

/** How long to wait for an activity to reach DESTROYED after a back press. */
private const val DESTROY_TIMEOUT_MS = 5_000L
private const val POLL_INTERVAL_MS = 50L

/**
 * Asserts that [scenario]'s activity reaches [Lifecycle.State.DESTROYED].
 *
 * Back-press handling is asynchronous, so reading `scenario.state` immediately
 * after `pressBackUnconditionally()` races the teardown. This polls until the
 * activity is destroyed or [DESTROY_TIMEOUT_MS] elapses.
 */
fun <A : Activity> assertActivityDestroyed(scenario: ActivityScenario<A>) {
    InstrumentationRegistry.getInstrumentation().waitForIdleSync()

    val deadline = System.currentTimeMillis() + DESTROY_TIMEOUT_MS
    while (System.currentTimeMillis() < deadline) {
        if (scenario.state == Lifecycle.State.DESTROYED) return
        Thread.sleep(POLL_INTERVAL_MS)
    }
    fail("Activity should be finished after pressing back, but was ${scenario.state}")
}
