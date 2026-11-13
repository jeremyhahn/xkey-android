package com.automatethethings.xkey.protocol

import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.storage.dao.KeySharingPolicyDao
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import com.automatethethings.xkey.ui.KeySharingPeers

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
 *
 * A sharing edit the sheet or local.setKeyPolicy accepted but has not yet
 * stored is enforced over the stored state (#174): a pending withdrawal or
 * Private denies at once, and a pending Selected Peers over a stored All
 * Peers admits only the peers its grant rows name.
 */
class SharePermission(
    private val grants: KeySharingPolicyDao,
    private val pairedDevices: PairedDeviceRepository?
) {

    suspend fun canShare(entity: KeyEntity, peerPublicKeyHex: String?): Boolean {
        if (KeySharingPeers.isWithdrawalPending(entity.keyId, peerPublicKeyHex)) return false
        val enforced = KeySharingPeers.enforcedPolicy(entity.keyId) ?: entity.sharingPolicy
        return when (enforced) {
            SharingPolicyType.PRIVATE -> false
            SharingPolicyType.ALL_PEERS -> true
            SharingPolicyType.SELECTED_PEERS -> when {
                peerPublicKeyHex.isNullOrEmpty() -> false
                pairedDevices?.isRevocationPending(peerPublicKeyHex) == true -> false
                // The stored policy agrees: the stored-policy query decides.
                entity.sharingPolicy == SharingPolicyType.SELECTED_PEERS ->
                    grants.isKeySharedWithPeer(entity.keyId, peerPublicKeyHex)
                // A pending Selected Peers over another stored policy: the
                // grant row alone, as the stored All Peers would admit anyone.
                else -> grants.isPeerGranted(entity.keyId, peerPublicKeyHex)
            }
        }
    }
}
