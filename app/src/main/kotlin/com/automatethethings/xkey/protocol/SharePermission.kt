package com.automatethethings.xkey.protocol

import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.storage.dao.KeySharingPolicyDao
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.storage.entity.SharingPolicyType

/**
 * The one decision on whether a key may be shared with a peer. Every share
 * path calls it: the inbound `local.*` handlers (protocol/Handler.kt) and every
 * outbound share to a desktop (remote/DesktopShareGate, which the key-sharing
 * sheet and DesktopKeyShare go through). No other code reads a peer grant to
 * decide a share.
 *
 *  - PRIVATE: never.
 *  - ALL_PEERS: always.
 *  - SELECTED_PEERS: only a known peer whose grant revocation is not pending
 *    and whose `key_sharing_policies` row allows it. A peer unpaired and
 *    re-paired with the same static key keeps its old rows until the grant
 *    cleanup deletes them; while that revocation is pending those rows must
 *    not authorize it (fail closed, #174).
 */
class SharePermission(
    private val grants: KeySharingPolicyDao,
    private val pairedDevices: PairedDeviceRepository?
) {

    suspend fun canShare(entity: KeyEntity, peerPublicKeyHex: String?): Boolean =
        when (entity.sharingPolicy) {
            SharingPolicyType.PRIVATE -> false
            SharingPolicyType.ALL_PEERS -> true
            SharingPolicyType.SELECTED_PEERS -> when {
                peerPublicKeyHex.isNullOrEmpty() -> false
                else -> grants.isKeySharedWithPeer(entity.keyId, peerPublicKeyHex)
            }
        }
}
