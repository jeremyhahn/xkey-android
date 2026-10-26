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

package com.automatethethings.xkey.transport

import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.job
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout

/**
 * The phone's side of the connections a test serves, and the scope `serve`
 * runs in. [end] closes every accepted socket, so a `serve` blocked on a read
 * returns, and waits for the scope's coroutines to finish (#64): nothing is
 * mid-serve, still logging, when the test unmocks `Log`.
 */
internal class ServedConnections(private val timeoutMs: Long = 10_000L) {
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val accepted = CopyOnWriteArrayList<Socket>()

    /** Records [socket] so [end] closes it. */
    fun track(socket: Socket): Socket = socket.also { accepted += it }

    fun end() {
        accepted.forEach { runCatching { it.close() } }
        runBlocking { withTimeout(timeoutMs) { scope.coroutineContext.job.cancelAndJoin() } }
    }
}
