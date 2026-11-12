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
package com.automatethethings.xkey.ui

import com.automatethethings.xkey.settings.PairedDeviceData
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.storage.dao.KeySharingPolicyDao
import com.automatethethings.xkey.storage.entity.KeySharingPolicy
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/**
 * The peer list of [KeySharingBottomSheet] for one key: every paired device,
 * whether it holds a grant, and whether the user may change that.
 *
 * Read from the `key_sharing_policies` rows and the paired-device store
 * themselves, so a change made elsewhere (a grant cleanup, another screen, a
 * device pairing while the sheet is open) reaches the sheet.
 *
 * A peer whose grant revocation is still pending (#174: unpaired, then
 * paired again before the cleanup finished) is shown unselected and not
 * selectable, whatever rows it still has, and a grant for it is refused:
 * the cleanup would delete it. The list updates when the revocation
 * completes. A grant is bound to the pairing it was checked against
 * ([PairedDeviceRepository.writeGrant]): one that lands after that pairing
 * ended authorizes nothing and is deleted.
 *
 * The grant protocol commits prefs synchronously, so it runs on
 * [ioDispatcher], never on the sheet's Main caller. Grants, withdrawals and
 * key-wide policy changes ([setKeyPolicy]) take one lock, which is FIFO,
 * before that switch, so they land in the order the user made them: a later
 * withdrawal or clear always follows an earlier grant. A grant carries the
 * pairing generation read when the user acted, before that wait.
 */
class KeySharingPeers(
    private val keyId: String,
    private val policyDao: KeySharingPolicyDao,
    private val repository: PairedDeviceRepository,
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO
) {

    /** One row of the list. [selectable] is false while the row must not be changed. */
    data class Peer(
        val device: PairedDeviceData,
        val allowed: Boolean,
        val selectable: Boolean
    )

    /** The list, again on every change to this key's policy rows, the paired devices or the pending revocations. */
    fun peers(): Flow<List<Peer>> =
        combine(policyDao.getPoliciesForKey(keyId), PairedDeviceRepository.storeChanges) { policies, _ ->
            val pending = repository.pendingRevocations()
            val allowed = policies.filter { it.allowed }.map { it.peerPublicKeyHex }.toSet()
            repository.getAllDevices().map { device ->
                val revoking = device.publicKeyHex in pending
                Peer(
                    device,
                    allowed = !revoking && device.publicKeyHex in allowed,
                    selectable = !revoking
                )
            }
        }

    /**
     * Grants or withdraws [peerPublicKeyHex]'s access to the key. Returns
     * false if a grant does not stand: refused before anything was written
     * (the peer is not paired, or its revocation is pending), or written for
     * a pairing that ended meanwhile, which the grant cleanup then deletes.
     * Withdrawing is always allowed.
     */
    suspend fun setAllowed(peerPublicKeyHex: String, allowed: Boolean): Boolean {
        if (allowed) {
            // The pairing the user approved, read before any wait: a grant
            // still queued when that pairing ends is refused, never written
            // for a later pairing of the same key.
            val pairing = repository.pairingOf(peerPublicKeyHex) ?: return false
            return edits.withLock {
                withContext(ioDispatcher) {
                    repository.writeGrant(peerPublicKeyHex, pairing) {
                        policyDao.setPolicy(KeySharingPolicy(keyId = keyId, peerPublicKeyHex = peerPublicKeyHex, allowed = true))
                    }
                }
            }
        }
        edits.withLock { policyDao.removePolicy(keyId, peerPublicKeyHex) }
        return true
    }

    /**
     * Stores the key's sharing [policy] through [persist], in the same order
     * as grants and withdrawals. Leaving [SharingPolicyType.SELECTED_PEERS]
     * clears every per-peer row under that order too, so a grant the user
     * made earlier lands first and is cleared, never after the clear.
     */
    suspend fun setKeyPolicy(policy: SharingPolicyType, persist: suspend () -> Unit) {
        edits.withLock {
            persist()
            if (policy != SharingPolicyType.SELECTED_PEERS) {
                policyDao.clearPoliciesForKey(keyId)
            }
        }
    }

    private companion object {
        /** Orders every grant and withdrawal, across all sheets. */
        val edits = Mutex()
    }
}
