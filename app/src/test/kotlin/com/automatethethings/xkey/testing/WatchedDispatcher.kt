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

import java.util.concurrent.atomic.AtomicInteger
import kotlin.coroutines.CoroutineContext
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Runnable

/**
 * Runs its tasks on [target] and counts those queued or running. At zero,
 * everything the code under test was handed has run to its next suspension
 * or to its end: a wait for that is a wait for the work itself, not for a
 * time it is hoped to fit in.
 */
class WatchedDispatcher(
    private val target: CoroutineDispatcher = Dispatchers.Default
) : CoroutineDispatcher() {
    private val pending = AtomicInteger()

    override fun dispatch(context: CoroutineContext, block: Runnable) {
        pending.incrementAndGet()
        try {
            target.dispatch(context, Runnable {
                try {
                    block.run()
                } finally {
                    pending.decrementAndGet()
                }
            })
        } catch (e: Throwable) {
            pending.decrementAndGet()
            throw e
        }
    }

    /** Waits until no task is queued or running; fails with [what] if that never happens. */
    fun awaitIdle(what: String) = ThreadWait.until(what) { pending.get() == 0 }
}
