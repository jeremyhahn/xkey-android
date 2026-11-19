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
package com.automatethethings.xkey.credential

import androidx.annotation.VisibleForTesting
import com.automatethethings.xkey.storage.dao.CredentialMetadataDao
import com.automatethethings.xkey.storage.dao.KeyDao
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * The one WebAuthn signature counter of a passkey.
 *
 * A passkey is served by two paths: the credential provider
 * (credential_metadata) and the phone backend (keys). Each store holds a
 * sign_count, and the relying party must see a counter that rises on every
 * assertion whichever path served it. Both paths take the value to sign from
 * [next] before they build authenticator data, and neither writes sign_count
 * itself.
 *
 * The counter advances before anything is signed. A signature that fails
 * afterwards leaves a gap, which a relying party accepts because the next
 * value is still larger; a value is never handed out twice.
 */
class PasskeySignCounter(
    private val credentialDao: CredentialMetadataDao,
    private val keyDao: KeyDao
) {

    /**
     * Advance the counter of [credentialId] and return the value to sign.
     *
     * The value is max(metadata counter, key counter) + 1, so stores that
     * already disagree continue from the larger. It is written to both stores
     * before it is returned; a store without a row for the passkey is left
     * alone. If a write fails the error propagates and the caller must not
     * sign.
     */
    suspend fun next(credentialId: String): Long = withCounterLock(credentialId) {
        val metadataCount = credentialDao.getByCredentialId(credentialId)?.signCount ?: 0
        val keyCount = keyDao.getByKeyId(credentialId)?.signCount ?: 0
        val next = maxOf(metadataCount, keyCount) + 1
        credentialDao.updateSignCount(credentialId, next)
        keyDao.updateSignCount(credentialId, next)
        next
    }

    internal companion object {
        /**
         * One lock per credential id, shared by every instance in the
         * process: the provider service and the protocol handler each build
         * their own counter. An entry lives only while a caller holds or
         * waits for its lock, so credentials that come and go leave nothing
         * behind. Guarded by itself.
         */
        private val locks = HashMap<String, CounterLock>()

        /** A credential's lock and the callers holding or awaiting it. */
        private class CounterLock {
            val mutex = Mutex()
            var users = 0
        }

        /** The number of credential ids the registry holds a lock for. */
        @VisibleForTesting
        internal fun lockCount(): Int = synchronized(locks) { locks.size }

        /**
         * Runs [block] under [credentialId]'s lock, dropping the registry
         * entry when its last user leaves, whether [block] returns, throws
         * or is cancelled, and whether the caller held the lock or was still
         * waiting for it.
         */
        private suspend fun <T> withCounterLock(credentialId: String, block: suspend () -> T): T {
            val lock = synchronized(locks) {
                locks.getOrPut(credentialId) { CounterLock() }.also { it.users++ }
            }
            try {
                return lock.mutex.withLock { block() }
            } finally {
                synchronized(locks) {
                    if (--lock.users == 0) locks.remove(credentialId)
                }
            }
        }
    }
}
