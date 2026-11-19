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

import com.automatethethings.xkey.storage.dao.CredentialMetadataDao
import com.automatethethings.xkey.storage.dao.KeyDao
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.concurrent.ConcurrentHashMap

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
    suspend fun next(credentialId: String): Long = lockFor(credentialId).withLock {
        val metadataCount = credentialDao.getByCredentialId(credentialId)?.signCount ?: 0
        val keyCount = keyDao.getByKeyId(credentialId)?.signCount ?: 0
        val next = maxOf(metadataCount, keyCount) + 1
        credentialDao.updateSignCount(credentialId, next)
        keyDao.updateSignCount(credentialId, next)
        next
    }

    private companion object {
        /**
         * One lock per credential id, shared by every instance in the
         * process: the provider service and the protocol handler each build
         * their own counter.
         */
        val locks = ConcurrentHashMap<String, Mutex>()

        fun lockFor(credentialId: String): Mutex = locks.computeIfAbsent(credentialId) { Mutex() }
    }
}
