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
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
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
 * Every edit of the key's peer rows made here (a grant, a withdrawal, the
 * key-wide clear on leaving SELECTED_PEERS) runs through one queue per key,
 * shared by every instance for that key, in the order the calls were made
 * (#193), on [ioDispatcher]. A call takes its place in the queue before it
 * first suspends, so a caller that starts it undispatched queues it in the
 * order of the user's actions. Once queued, an edit completes even if its
 * caller is cancelled: a withdrawal must not be dropped behind a grant.
 */
class KeySharingPeers(
    private val keyId: String,
    private val policyDao: KeySharingPolicyDao,
    private val repository: PairedDeviceRepository,
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO
) {

    private companion object {
        /** The edit queue of each key id. Fair: waiters are served in arrival order. */
        val queues = ConcurrentHashMap<String, Mutex>()
    }

    private val queue: Mutex = queues.computeIfAbsent(keyId) { Mutex() }

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
     *
     * [pairing] is the peer's [PairedDeviceRepository.pairingGeneration] read
     * when the user acted: a grant is refused if the peer was not paired then,
     * or that pairing ended before the grant's turn came.
     */
    suspend fun setAllowed(peerPublicKeyHex: String, allowed: Boolean, pairing: Long?): Boolean = inOrder {
        if (!allowed) {
            policyDao.removePolicy(keyId, peerPublicKeyHex)
            true
        } else if (pairing == null) {
            false
        } else {
            repository.writeGrant(peerPublicKeyHex, pairing) {
                policyDao.setPolicy(KeySharingPolicy(keyId = keyId, peerPublicKeyHex = peerPublicKeyHex, allowed = true))
            }
        }
    }

    /**
     * Sets the key's sharing policy: runs [store], which writes the key's
     * policy column, then, unless [selectedPeers], deletes every peer row of
     * the key, so selecting peers again starts from nothing. Queued with the
     * grants and withdrawals, so an earlier grant cannot land after the clear.
     */
    suspend fun setSharingPolicy(selectedPeers: Boolean, store: suspend () -> Unit) = inOrder {
        store()
        if (!selectedPeers) policyDao.clearPoliciesForKey(keyId)
    }

    private suspend fun <T> inOrder(change: suspend () -> T): T =
        withContext(NonCancellable) {
            queue.withLock { withContext(ioDispatcher) { change() } }
        }
}
