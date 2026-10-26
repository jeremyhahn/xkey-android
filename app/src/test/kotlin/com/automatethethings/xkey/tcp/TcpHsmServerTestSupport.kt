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

package com.automatethethings.xkey.tcp

import com.automatethethings.xkey.transport.DesktopPeer
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.job
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull

/**
 * Closes [desktop] and waits for the server to finish with it (#64): the
 * connection's last log comes before the server is back to listening, so no
 * connection is mid-serve, still logging, when the test unmocks `Log`.
 */
internal suspend fun TcpHsmServer.closeAndAwaitListening(desktop: DesktopPeer, timeoutMs: Long = 10_000L) {
    desktop.close()
    withTimeout(timeoutMs) { state.first { it is TcpHsmState.Listening } }
}

/**
 * Stops the server and waits until its accept loop has finished (#69). A
 * test calls it in tearDown, before it unmocks.
 *
 * `stop()` cancels the server's scope but does not wait for it. A connection
 * still being served when the test ends -- a test that failed mid-handshake --
 * unwinds on its own thread and logs through `Log`. If the test has unmocked
 * `Log` by then, that call throws, the accept loop's `Log.e` throws again,
 * and kotlinx-coroutines-test reports it in whichever `runTest` comes next,
 * as `UncaughtExceptionsBeforeTest`.
 */
internal fun TcpHsmServer.stopAndAwaitStopped(timeoutMs: Long = 10_000L) {
    // stop() clears serverScope, so it is read before.
    val scope = javaClass.getDeclaredField("serverScope").apply { isAccessible = true }.get(this) as CoroutineScope?
    stop()
    val job = scope?.coroutineContext?.job ?: return
    runBlocking { withTimeoutOrNull(timeoutMs) { job.join() } }
        ?: throw AssertionError("TcpHsmServer's accept loop still runs $timeoutMs ms after stop(): ${job.children.toList()}")
}
