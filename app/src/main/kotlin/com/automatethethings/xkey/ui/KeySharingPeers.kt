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
import kotlinx.coroutines.flow.map

/**
 * The peer list of [KeySharingBottomSheet] for one key: every paired device,
 * whether it holds a grant, and whether the user may change that.
 *
 * Read from the `key_sharing_policies` rows themselves, so a change made
 * elsewhere (a grant cleanup, another screen) reaches the sheet.
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

    /** The list, again on every change to this key's policy rows. */
    fun peers(): Flow<List<Peer>> =
        policyDao.getPoliciesForKey(keyId).map { policies ->
            val allowed = policies.filter { it.allowed }.map { it.peerPublicKeyHex }.toSet()
            repository.getAllDevices().map { device ->
                Peer(device, allowed = device.publicKeyHex in allowed, selectable = true)
            }
        }

    /**
     * Grants or withdraws [peerPublicKeyHex]'s access to the key. Returns
     * false if the change was refused and nothing was written.
     */
    suspend fun setAllowed(peerPublicKeyHex: String, allowed: Boolean): Boolean {
        if (allowed) {
            policyDao.setPolicy(KeySharingPolicy(keyId = keyId, peerPublicKeyHex = peerPublicKeyHex, allowed = true))
        } else {
            policyDao.removePolicy(keyId, peerPublicKeyHex)
        }
        return true
    }
}
