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
import com.automatethethings.xkey.storage.entity.KeyDeletionEntity
import com.automatethethings.xkey.storage.entity.KeyPolicyEntity
import com.automatethethings.xkey.storage.entity.KeySharingPolicy
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import kotlinx.coroutines.flow.Flow

/**
 * The single-statement reads and writes `KeyPolicyStore` composes into its
 * transactions (#193). Nothing else writes a key's policy row or its grant
 * rows through this DAO: call the store.
 */
@Dao
interface KeyPolicyDao {

    /** `keys.id` of [keyId]'s key row, or null if there is none. */
    @Query("SELECT id FROM keys WHERE key_id = :keyId")
    suspend fun keyInstance(keyId: String): Long?

    @Query("SELECT * FROM key_policies WHERE key_id = :keyId")
    suspend fun policyRow(keyId: String): KeyPolicyEntity?

    @Query("SELECT * FROM key_policies WHERE key_id = :keyId")
    fun observePolicyRow(keyId: String): Flow<KeyPolicyEntity?>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun putPolicyRow(row: KeyPolicyEntity)

    /** Sets the key row's policy, and `shareable` from it as [KeyDao.updateSharingPolicy] does. */
    @Query(
        """
        UPDATE keys SET
            sharing_policy = :policy,
            shareable = CASE WHEN :policy = 'PRIVATE' THEN 0 ELSE 1 END
        WHERE key_id = :keyId
        """
    )
    suspend fun setKeyPolicy(keyId: String, policy: SharingPolicyType): Int

    @Query("SELECT * FROM key_sharing_policies WHERE key_id = :keyId")
    fun observeGrants(keyId: String): Flow<List<KeySharingPolicy>>

    @Query("SELECT * FROM key_sharing_policies WHERE key_id = :keyId")
    suspend fun grants(keyId: String): List<KeySharingPolicy>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun putGrant(grant: KeySharingPolicy)

    @Query("DELETE FROM key_sharing_policies WHERE key_id = :keyId AND peer_public_key_hex = :peerPublicKeyHex")
    suspend fun deleteGrant(keyId: String, peerPublicKeyHex: String): Int

    @Query("DELETE FROM key_sharing_policies WHERE key_id = :keyId")
    suspend fun deleteGrants(keyId: String): Int

    /** Inserts [key], replacing a row with its key_id as [KeyDao.insert] does. */
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertKey(key: KeyEntity): Long

    @Query("DELETE FROM keys WHERE key_id = :keyId")
    suspend fun deleteKey(keyId: String): Int

    /** [keyInstance], observed: null while [keyId] has no key row. */
    @Query("SELECT id FROM keys WHERE key_id = :keyId")
    fun observeKeyInstance(keyId: String): Flow<Long?>

    @Query("SELECT source FROM keys WHERE key_id = :keyId")
    suspend fun keySource(keyId: String): String?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun putDeletion(row: KeyDeletionEntity)

    @Query("SELECT * FROM key_deletions WHERE key_id = :keyId")
    suspend fun deletion(keyId: String): KeyDeletionEntity?

    @Query("SELECT * FROM key_deletions")
    suspend fun deletions(): List<KeyDeletionEntity>

    /** Drops [keyId]'s tombstone only if it is still the one for [instance]. */
    @Query("DELETE FROM key_deletions WHERE key_id = :keyId AND key_instance = :instance")
    suspend fun dropDeletion(keyId: String, instance: Long): Int
}
