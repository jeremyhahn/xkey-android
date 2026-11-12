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
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.combine

/**
 * The peer list of [KeySharingBottomSheet] for one key: every paired device,
 * whether it holds a grant, and whether the user may change that.
 *
 * Read from the `key_sharing_policies` rows themselves, so a change made
 * elsewhere (a grant cleanup, another screen) reaches the sheet.
 *
 * A peer whose grant revocation is still pending (#174: unpaired, then
 * paired again before the cleanup finished) is shown unselected and not
 * selectable, whatever rows it still has, and a grant for it is refused:
 * the cleanup would delete it. The list updates when the revocation
 * completes.
 */
class KeySharingPeers(
    private val keyId: String,
    private val policyDao: KeySharingPolicyDao,
    private val repository: PairedDeviceRepository
) {

    /** One row of the list. [selectable] is false while the row must not be changed. */
    data class Peer(
        val device: PairedDeviceData,
        val allowed: Boolean,
        val selectable: Boolean
    )

    /** The list, again on every change to this key's policy rows or to the pending revocations. */
    fun peers(): Flow<List<Peer>> =
        combine(policyDao.getPoliciesForKey(keyId), PairedDeviceRepository.revocationChanges) { policies, _ ->
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
     * false if the change was refused and nothing was written: a grant to a
     * peer whose revocation is still pending. Withdrawing is always allowed.
     */
    suspend fun setAllowed(peerPublicKeyHex: String, allowed: Boolean): Boolean {
        if (allowed) {
            if (repository.isRevocationPending(peerPublicKeyHex)) return false
            policyDao.setPolicy(KeySharingPolicy(keyId = keyId, peerPublicKeyHex = peerPublicKeyHex, allowed = true))
        } else {
            policyDao.removePolicy(keyId, peerPublicKeyHex)
        }
        return true
    }
}
