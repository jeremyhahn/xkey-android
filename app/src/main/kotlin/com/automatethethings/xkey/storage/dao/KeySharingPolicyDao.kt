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
package com.automatethethings.xkey.storage.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.storage.entity.KeySharingPolicy
import kotlinx.coroutines.flow.Flow

/**
 * Data Access Object for per-key sharing policy operations.
 *
 * Provides CRUD operations for managing fine-grained key sharing permissions
 * with specific peer devices. This DAO works in conjunction with the
 * [SharingPolicyType] field in [KeyEntity] to determine overall sharing behavior.
 *
 * Policy Resolution:
 * When a peer requests to use a key, the resolution order is:
 * 1. Check [KeyEntity.sharingPolicy]:
 *    - PRIVATE: Deny immediately
 *    - ALL_PEERS: Allow immediately
 *    - SELECTED_PEERS: Query this table
 * 2. For SELECTED_PEERS, check if a policy exists for the (keyId, peerPublicKeyHex) pair
 * 3. If policy exists and [KeySharingPolicy.allowed] is true, permit access
 *
 * All mutating operations are suspend functions for coroutine compatibility.
 * Observation queries return [Flow] for reactive UI updates.
 */
@Dao
interface KeySharingPolicyDao {

    // -------------------------------------------------------------------------
    // Query operations
    // -------------------------------------------------------------------------

    /**
     * Observe all sharing policies for a specific key.
     *
     * Returns a reactive Flow that emits whenever policies for this key change.
     * Useful for UI components that display the list of peers with access.
     *
     * @param keyId The unique key identifier.
     * @return Flow emitting the list of policies whenever changes occur.
     */
    @Query("SELECT * FROM key_sharing_policies WHERE key_id = :keyId ORDER BY created_at DESC")
    fun getPoliciesForKey(keyId: String): Flow<List<KeySharingPolicy>>

    /**
     * Get all sharing policies for a specific key (non-reactive).
     *
     * @param keyId The unique key identifier.
     * @return List of all policies for the key.
     */
    @Query("SELECT * FROM key_sharing_policies WHERE key_id = :keyId ORDER BY created_at DESC")
    suspend fun getPoliciesForKeySync(keyId: String): List<KeySharingPolicy>

    /**
     * Get the sharing policy for a specific key and peer combination.
     *
     * @param keyId The unique key identifier.
     * @param peerPublicKeyHex Hex-encoded public key of the peer device.
     * @return The policy if it exists, null otherwise.
     */
    @Query("SELECT * FROM key_sharing_policies WHERE key_id = :keyId AND peer_public_key_hex = :peerPublicKeyHex LIMIT 1")
    suspend fun getPolicy(keyId: String, peerPublicKeyHex: String): KeySharingPolicy?

    /**
     * Get all FIDO2 keys that are shareable with a specific peer.
     *
     * This query performs a join between the keys table and sharing policies
     * to find FIDO2 keys where either:
     * - The key's sharing_policy is 'ALL_PEERS', OR
     * - The key's sharing_policy is 'SELECTED_PEERS' AND a policy exists for this peer
     *
     * Note: Keys with sharing_policy = 'PRIVATE' are excluded.
     *
     * @param peerPublicKeyHex Hex-encoded public key of the peer device.
     * @return List of FIDO2 keys the peer can use.
     */
    @Query(
        """
        SELECT k.* FROM keys k
        WHERE k.key_type = 'fido2'
        AND (
            k.sharing_policy = 'ALL_PEERS'
            OR (
                k.sharing_policy = 'SELECTED_PEERS'
                AND EXISTS (
                    SELECT 1 FROM key_sharing_policies p
                    WHERE p.key_id = k.key_id
                    AND p.peer_public_key_hex = :peerPublicKeyHex
                    AND p.allowed = 1
                )
            )
        )
        ORDER BY k.last_used_at DESC
        """
    )
    suspend fun getShareableFido2ForPeer(peerPublicKeyHex: String): List<KeyEntity>

    /**
     * Get all keys (any type) that are shareable with a specific peer.
     *
     * Similar to [getShareableFido2ForPeer] but not limited to FIDO2 keys.
     *
     * @param peerPublicKeyHex Hex-encoded public key of the peer device.
     * @return List of all keys the peer can use.
     */
    @Query(
        """
        SELECT k.* FROM keys k
        WHERE (
            k.sharing_policy = 'ALL_PEERS'
            OR (
                k.sharing_policy = 'SELECTED_PEERS'
                AND EXISTS (
                    SELECT 1 FROM key_sharing_policies p
                    WHERE p.key_id = k.key_id
                    AND p.peer_public_key_hex = :peerPublicKeyHex
                    AND p.allowed = 1
                )
            )
        )
        ORDER BY k.last_used_at DESC
        """
    )
    suspend fun getAllShareableForPeer(peerPublicKeyHex: String): List<KeyEntity>

    /**
     * Check if a specific key is shared with a specific peer.
     *
     * This is the primary access control check used during key operations.
     * It considers the key's overall sharing policy and any specific peer policies.
     *
     * Resolution logic:
     * 1. If key's sharing_policy is 'ALL_PEERS' -> true
     * 2. If key's sharing_policy is 'PRIVATE' -> false
     * 3. If key's sharing_policy is 'SELECTED_PEERS' -> check policy table
     *
     * An unknown key is not shared. The policy is resolved with a scalar
     * subquery rather than `FROM keys`, because that form returns NO ROW for an
     * unknown key id — and Room then hands a null back to a non-null `Boolean`,
     * so the access-control gate threw a NullPointerException instead of
     * refusing. This form always returns exactly one row.
     *
     * @param keyId The unique key identifier.
     * @param peerPublicKeyHex Hex-encoded public key of the peer device.
     * @return True if the peer is allowed to use this key.
     */
    @Query(
        """
        SELECT CASE (SELECT k.sharing_policy FROM keys k WHERE k.key_id = :keyId)
            WHEN 'ALL_PEERS' THEN 1
            WHEN 'SELECTED_PEERS' THEN
                COALESCE(
                    (SELECT p.allowed FROM key_sharing_policies p
                     WHERE p.key_id = :keyId AND p.peer_public_key_hex = :peerPublicKeyHex),
                    0
                )
            ELSE 0
        END
        """
    )
    suspend fun isKeySharedWithPeer(keyId: String, peerPublicKeyHex: String): Boolean

    /**
     * Check whether [peerPublicKeyHex] holds an explicit grant row for [keyId],
     * whatever the key's stored sharing policy says.
     *
     * The check for a Selected Peers policy that is enforced but not yet
     * stored (#174): [isKeySharedWithPeer] answers from the stored policy, so
     * a key still stored as All Peers would authorize every peer.
     *
     * @param keyId The unique key identifier.
     * @param peerPublicKeyHex Hex-encoded public key of the peer device.
     * @return True if an allowed policy row exists for this key and peer.
     */
    @Query(
        """
        SELECT EXISTS (
            SELECT 1 FROM key_sharing_policies
            WHERE key_id = :keyId AND peer_public_key_hex = :peerPublicKeyHex AND allowed = 1
        )
        """
    )
    suspend fun isPeerGranted(keyId: String, peerPublicKeyHex: String): Boolean

    /**
     * The `keys` row id of [keyId], or null when no such key is stored.
     *
     * Identifies the key instance a sharing edit was accepted for (#193): a
     * key deleted and generated again under the same id gets a new row id,
     * so an older edit's retry can tell it is no longer its key.
     */
    @Query("SELECT id FROM keys WHERE key_id = :keyId")
    suspend fun keyInstance(keyId: String): Long?

    /**
     * Get all peers that have access to a specific key.
     *
     * @param keyId The unique key identifier.
     * @return List of peer public key hex strings with allowed=true policies.
     */
    @Query("SELECT peer_public_key_hex FROM key_sharing_policies WHERE key_id = :keyId AND allowed = 1")
    suspend fun getAllowedPeersForKey(keyId: String): List<String>

    /**
     * Count the number of keys shared with a specific peer.
     *
     * @param peerPublicKeyHex Hex-encoded public key of the peer device.
     * @return Number of keys the peer can access.
     */
    @Query(
        """
        SELECT COUNT(*) FROM keys k
        WHERE (
            k.sharing_policy = 'ALL_PEERS'
            OR (
                k.sharing_policy = 'SELECTED_PEERS'
                AND EXISTS (
                    SELECT 1 FROM key_sharing_policies p
                    WHERE p.key_id = k.key_id
                    AND p.peer_public_key_hex = :peerPublicKeyHex
                    AND p.allowed = 1
                )
            )
        )
        """
    )
    suspend fun countKeysSharedWithPeer(peerPublicKeyHex: String): Int

    // -------------------------------------------------------------------------
    // Mutation operations
    // -------------------------------------------------------------------------

    /**
     * Insert or update a sharing policy.
     *
     * If a policy already exists for the (keyId, peerPublicKeyHex) pair,
     * it will be replaced with the new policy.
     *
     * @param policy The sharing policy to insert or update.
     */
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun setPolicy(policy: KeySharingPolicy)

    /**
     * Insert or update multiple sharing policies.
     *
     * @param policies The list of sharing policies to insert or update.
     */
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun setPolicies(policies: List<KeySharingPolicy>)

    /**
     * Remove all sharing policies for a specific key.
     *
     * Note: This is typically called when changing a key's sharing policy
     * from SELECTED_PEERS to PRIVATE or ALL_PEERS.
     *
     * @param keyId The unique key identifier.
     * @return Number of policies deleted.
     */
    @Query("DELETE FROM key_sharing_policies WHERE key_id = :keyId")
    suspend fun clearPoliciesForKey(keyId: String): Int

    /**
     * Remove a specific sharing policy.
     *
     * @param keyId The unique key identifier.
     * @param peerPublicKeyHex Hex-encoded public key of the peer device.
     * @return Number of policies deleted (0 or 1).
     */
    @Query("DELETE FROM key_sharing_policies WHERE key_id = :keyId AND peer_public_key_hex = :peerPublicKeyHex")
    suspend fun removePolicy(keyId: String, peerPublicKeyHex: String): Int

    /**
     * Remove all policies for a specific peer across all keys.
     *
     * Useful when a peer device is unpaired or its access is revoked globally.
     *
     * @param peerPublicKeyHex Hex-encoded public key of the peer device.
     * @return Number of policies deleted.
     */
    @Query("DELETE FROM key_sharing_policies WHERE peer_public_key_hex = :peerPublicKeyHex")
    suspend fun clearPoliciesForPeer(peerPublicKeyHex: String): Int

    /**
     * Revoke access for a peer to a specific key without deleting the policy.
     *
     * Sets allowed=false instead of deleting, which preserves the audit trail
     * and makes it easy to re-enable access later.
     *
     * @param keyId The unique key identifier.
     * @param peerPublicKeyHex Hex-encoded public key of the peer device.
     */
    @Query("UPDATE key_sharing_policies SET allowed = 0 WHERE key_id = :keyId AND peer_public_key_hex = :peerPublicKeyHex")
    suspend fun revokePolicy(keyId: String, peerPublicKeyHex: String)

    /**
     * Grant access for a peer to a specific key.
     *
     * Sets allowed=true for an existing policy.
     *
     * @param keyId The unique key identifier.
     * @param peerPublicKeyHex Hex-encoded public key of the peer device.
     */
    @Query("UPDATE key_sharing_policies SET allowed = 1 WHERE key_id = :keyId AND peer_public_key_hex = :peerPublicKeyHex")
    suspend fun grantPolicy(keyId: String, peerPublicKeyHex: String)

    // -------------------------------------------------------------------------
    // Deletion
    // -------------------------------------------------------------------------

    /**
     * Delete all sharing policies.
     *
     * Use with caution - this removes all peer access permissions.
     */
    @Query("DELETE FROM key_sharing_policies")
    suspend fun deleteAll()
}
