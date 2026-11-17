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
package com.automatethethings.xkey.remote

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext

/**
 * The one place a transport keeps the [SessionSender] it hands out for a
 * connection, owned by that connection's lifecycle.
 *
 * Repeated lookups on one live connection get the same sender, so share
 * sessions taken on an unchanged connection compare equal. The entry lives
 * only as long as its connection: [retire] drops it when the connection ends,
 * so the cache never keeps an ended connection's Noise session reachable, and
 * then zeroes that connection's keys through [zeroKeys], which waits for any
 * send still in flight on it.
 *
 * A transport with a bound sender holds exactly one of these and caches its
 * senders nowhere else.
 *
 * @param C the connection, compared by identity
 * @param zeroKeys zeroes a retired connection's session keys once its pending
 *   sends have drained; called once per [retire], and must tolerate a repeat
 */
class ConnectionSenders<C : Any>(private val zeroKeys: suspend (C) -> Unit) {

    private val lock = Any()

    /** The connection [sender] is bound to. Guarded by [lock]. */
    private var connection: C? = null

    /** The sender handed out for [connection]. Guarded by [lock]. */
    private var sender: SessionSender? = null

    /**
     * The sender bound to [connection], made by [newSender] on the first
     * lookup and the same object on every later one, or null when [live]
     * says the connection has ended. [live] is read under the cache's lock: a
     * transport marks a connection ended before it [retire]s it, so a lookup
     * racing the end either sees it ended or has its entry dropped by
     * [retire].
     */
    fun senderFor(connection: C, live: (C) -> Boolean, newSender: (C) -> SessionSender): SessionSender? =
        synchronized(lock) {
            if (!live(connection)) return null
            sender?.takeIf { this.connection === connection }
                ?: newSender(connection).also {
                    this.connection = connection
                    sender = it
                }
        }

    /**
     * [connection] has ended: its entry is dropped now, and its keys are
     * zeroed in [scope] once its pending sends drain, through [launchCleanup],
     * so they are zeroed even if [scope] is cancelled before the job runs.
     * Returns the zeroing job.
     */
    fun retire(connection: C, scope: CoroutineScope): Job {
        drop(connection)
        return scope.launchCleanup { zeroKeys(connection) }
    }

    /** [connection] has ended: drops its entry, then zeroes its keys once its pending sends drain. */
    suspend fun retire(connection: C) {
        drop(connection)
        withContext(NonCancellable) { zeroKeys(connection) }
    }

    private fun drop(connection: C) = synchronized(lock) {
        if (this.connection === connection) {
            this.connection = null
            sender = null
        }
    }

    /** Whether a sender is cached for any connection. */
    val isEmpty: Boolean get() = synchronized(lock) { sender == null }

    /** Whether a sender is cached for [connection]. */
    fun holds(connection: C): Boolean = synchronized(lock) { sender != null && this.connection === connection }
}
