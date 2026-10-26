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

package com.automatethethings.xkey.ble

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull

/**
 * Waits until every coroutine [owner] started on its scope has finished. A
 * test calls it after the owner's `destroy()` and before it unmocks.
 *
 * `destroy()` cancels the scope but does not wait for it. A coroutine still
 * running then (a connection's event consumer settling its disconnect, a
 * request worker, the teardown a disconnect launched) runs on to its end on
 * its own thread. If the test has unmocked `Log` by then, its next `Log`
 * call throws, and kotlinx-coroutines-test reports that exception in
 * whichever `runTest` comes next, as `UncaughtExceptionsBeforeTest` (#63).
 */
internal fun awaitScopeFinished(owner: Any, timeoutMs: Long = 5_000L) {
    val scope = try {
        owner.javaClass.getDeclaredField("scope").apply { isAccessible = true }.get(owner) as CoroutineScope
    } catch (e: NoSuchFieldException) {
        throw AssertionError("${owner.javaClass.simpleName}.scope is a seam these BLE tests drive", e)
    }
    val job = scope.coroutineContext[Job]
        ?: throw AssertionError("${owner.javaClass.simpleName}.scope has no job")
    if (!job.isCancelled) throw AssertionError("destroy() cancels ${owner.javaClass.simpleName}.scope")
    runBlocking { withTimeoutOrNull(timeoutMs) { job.join() } }
        ?: throw AssertionError(
            "${owner.javaClass.simpleName}'s coroutines still run $timeoutMs ms after destroy(): " +
                job.children.toList()
        )
}
