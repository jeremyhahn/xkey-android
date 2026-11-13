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
package com.automatethethings.xkey.protocol

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Process-wide claims on key ids, shared by every connection's handler.
 *
 * Approval prompts take turns, so a request's checks can run long before it
 * acts, and another request for the same key can act in between. A key
 * creation reserves its id from its existence check until it ends, so a
 * second creation of that id is refused instead of reaching a generator that
 * replaces the first key. Work that must see the state the previous request
 * left (the creation's recheck, a passkey's signature counter) runs under
 * the key's lock.
 *
 * Ids are namespaced by the caller (`key:`, `credential:`), since the
 * Keystore aliases behind them differ.
 */
internal class KeyIdReservations {

    private class Lock {
        val mutex = Mutex()
        var users = 0
    }

    private val reserved = HashSet<String>()
    private val locks = HashMap<String, Lock>()

    /** Reserves [id]; false when another request holds it. */
    fun tryReserve(id: String): Boolean = synchronized(this) { reserved.add(id) }

    fun release(id: String) {
        synchronized(this) { reserved.remove(id) }
    }

    /** Runs [block] holding [id]'s lock; one block per id at a time, in arrival order. */
    suspend fun <T> withKeyLock(id: String, block: suspend () -> T): T {
        val lock = synchronized(this) { locks.getOrPut(id) { Lock() }.also { it.users++ } }
        try {
            return lock.mutex.withLock { block() }
        } finally {
            synchronized(this) {
                if (--lock.users == 0) locks.remove(id)
            }
        }
    }

    companion object {
        /** The one instance every handler in the process shares. */
        val process = KeyIdReservations()
    }
}
