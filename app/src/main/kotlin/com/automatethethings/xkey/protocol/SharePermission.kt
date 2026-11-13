package com.automatethethings.xkey.protocol

import com.automatethethings.xkey.storage.KeyPolicyStore
import com.automatethethings.xkey.ui.KeySharingPeers
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
 *
 * With a [KeyPolicyStore] (#193), the policy decided on is the one the store
 * enforces: a narrowing whose write failed stays denied, a restart included.
 * A peer whose withdrawal is still being retried is refused, and a
 * SELECTED_PEERS grant is read from its row alone, never from the stored
 * policy, which may still be All Peers while a Selected Peers change is
 * pending (#174).
 */
class SharePermission(
    private val grants: KeySharingPolicyDao,
    private val pairedDevices: PairedDeviceRepository?,
    private val policies: KeyPolicyStore? = null
) {

    suspend fun canShare(entity: KeyEntity, peerPublicKeyHex: String?): Boolean {
        if (KeySharingPeers.isWithdrawalPending(entity.keyId, entity.id, peerPublicKeyHex)) return false
        val policy = policies?.enforcedPolicy(entity) ?: entity.sharingPolicy
        return when (policy) {
            SharingPolicyType.PRIVATE -> false
            SharingPolicyType.ALL_PEERS -> true
            SharingPolicyType.SELECTED_PEERS -> when {
                peerPublicKeyHex.isNullOrEmpty() -> false
                pairedDevices?.isRevocationPending(peerPublicKeyHex) == true -> false
                policies != null -> grants.isPeerGranted(entity.keyId, peerPublicKeyHex)
                else -> grants.isKeySharedWithPeer(entity.keyId, peerPublicKeyHex)
            }
        }
    }
}
