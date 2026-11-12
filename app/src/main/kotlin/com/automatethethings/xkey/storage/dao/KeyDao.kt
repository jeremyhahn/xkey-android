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
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import com.automatethethings.xkey.remote.SharePermissionLedger
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import kotlinx.coroutines.flow.Flow

/**
 * Data Access Object for unified key storage operations.
 *
 * Provides CRUD operations, type-filtered queries, FIDO2-specific lookups,
 * usage tracking, and sharing policy management for all key types stored
 * in the unified `keys` table.
 *
 * All mutating operations are suspend functions for coroutine compatibility.
 * Observation queries return [Flow] for reactive UI updates.
 */
/**
 * Marks the raw Room writes behind [KeyDao]'s row writes. Only [KeyDao]'s own
 * wrappers opt in: every other caller goes through a wrapper, which commits
 * the write as a [SharePermissionLedger] revoke of the key.
 */
@RequiresOptIn(
    message = "A raw key-row write bypasses SharePermissionLedger; call the KeyDao wrapper instead.",
    level = RequiresOptIn.Level.ERROR
)
@Retention(AnnotationRetention.BINARY)
@Target(AnnotationTarget.FUNCTION)
annotation class RawKeyRowWrite

/**
 * Data Access Object for unified key storage operations.
 *
 * Every write that replaces, changes the sharing permission of, or deletes a
 * key row is a [SharePermissionLedger] revoke of that key, at this one choke
 * point: a desktop share of the key waiting at a transport's admission is
 * refused. The raw Room writes are [RawKeyRowWrite] and called only by the
 * wrappers here. [recordUsage] and [updateSignCount] change counters only,
 * not what a key may be shared with, and are not revokes.
 */
@Dao
@OptIn(RawKeyRowWrite::class)
interface KeyDao {

    /**
     * Insert a key entry, as a revoke of its `key_id`: if a row with the
     * same `key_id` already exists, it is replaced.
     *
     * @param key The key entity to insert.
     * @return The row ID of the inserted entry.
     */
    suspend fun insert(key: KeyEntity): Long =
        SharePermissionLedger.revoking(key.keyId) { insertRow(key) }

    /** Raw insert-or-replace; call [insert]. */
    @RawKeyRowWrite
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertRow(key: KeyEntity): Long

    /**
     * Update an existing key entry, as a revoke of its `key_id`.
     *
     * @param key The key entity to update.
     */
    suspend fun update(key: KeyEntity) =
        SharePermissionLedger.revoking(key.keyId) { updateRow(key) }

    /** Raw update; call [update]. */
    @RawKeyRowWrite
    @Update
    suspend fun updateRow(key: KeyEntity)

    /**
     * Delete a key entry, as a revoke of its `key_id`.
     *
     * @param key The key entity to delete.
     */
    suspend fun delete(key: KeyEntity) =
        SharePermissionLedger.revoking(key.keyId) { deleteRow(key) }

    /** Raw delete; call [delete]. */
    @RawKeyRowWrite
    @Delete
    suspend fun deleteRow(key: KeyEntity)

    /**
     * Observe all keys ordered by creation time (newest first).
     *
     * @return Flow emitting the list of all keys whenever changes occur.
     */
    @Query("SELECT * FROM keys ORDER BY created_at DESC")
    fun observeAll(): Flow<List<KeyEntity>>

    /**
     * Get all keys ordered by creation time (newest first).
     *
     * @return List of all key entities.
     */
    @Query("SELECT * FROM keys ORDER BY created_at DESC")
    suspend fun getAll(): List<KeyEntity>

    /**
     * Get a key by its unique key identifier.
     *
     * @param keyId The unique key identifier.
     * @return The key entity, or null if not found.
     */
    @Query("SELECT * FROM keys WHERE key_id = :keyId LIMIT 1")
    suspend fun getByKeyId(keyId: String): KeyEntity?

    /**
     * Get all keys of a specific type.
     *
     * @param keyType The key type (e.g., "fido2", "ssh", "tls").
     * @return List of keys matching the type.
     */
    @Query("SELECT * FROM keys WHERE key_type = :keyType ORDER BY created_at DESC")
    suspend fun getByType(keyType: String): List<KeyEntity>

    /**
     * Observe all keys of a specific type.
     *
     * @param keyType The key type to observe.
     * @return Flow emitting keys of the given type whenever changes occur.
     */
    @Query("SELECT * FROM keys WHERE key_type = :keyType ORDER BY created_at DESC")
    fun observeByType(keyType: String): Flow<List<KeyEntity>>

    /**
     * Observe a single key, emitting again whenever its row changes.
     *
     * A detail screen that reads once cannot notice a change made from a dialog
     * or bottom sheet, because those never stop the host activity and so never
     * trigger `onResume`.
     *
     * @param keyId The unique key identifier.
     * @return A Flow of the key, or null once it is deleted.
     */
    @Query("SELECT * FROM keys WHERE key_id = :keyId LIMIT 1")
    fun observeByKeyId(keyId: String): Flow<KeyEntity?>

    /**
     * Get all keys from a specific source.
     *
     * @param source The origin source (e.g., "local", "remote_ble", "xkmsd").
     * @return List of keys from the specified source.
     */
    @Query("SELECT * FROM keys WHERE source = :source ORDER BY created_at DESC")
    suspend fun getBySource(source: String): List<KeyEntity>

    // -------------------------------------------------------------------------
    // FIDO2-specific queries
    // -------------------------------------------------------------------------

    /**
     * Get all FIDO2 keys for a relying party, ordered by most recently used.
     *
     * @param rpId The relying party identifier.
     * @return List of FIDO2 keys for the relying party.
     */
    @Query("SELECT * FROM keys WHERE key_type = 'fido2' AND rp_id = :rpId ORDER BY last_used_at DESC")
    suspend fun getFido2ByRpId(rpId: String): List<KeyEntity>

    /**
     * Get shareable FIDO2 keys for a relying party.
     *
     * Returns keys that can be used by the paired laptop via BLE/USB.
     *
     * @param rpId The relying party identifier.
     * @return List of shareable FIDO2 keys for the relying party.
     */
    @Query("SELECT * FROM keys WHERE key_type = 'fido2' AND rp_id = :rpId AND shareable = 1 ORDER BY last_used_at DESC")
    suspend fun getShareableFido2ByRpId(rpId: String): List<KeyEntity>

    /**
     * Get discoverable (resident) FIDO2 keys for a relying party.
     *
     * @param rpId The relying party identifier.
     * @return List of discoverable FIDO2 keys for the relying party.
     */
    @Query("SELECT * FROM keys WHERE key_type = 'fido2' AND rp_id = :rpId AND is_discoverable = 1 ORDER BY last_used_at DESC")
    suspend fun getDiscoverableFido2ByRpId(rpId: String): List<KeyEntity>

    /**
     * Get a FIDO2 key by user ID and relying party.
     *
     * @param userId The user handle (Base64-encoded).
     * @param rpId The relying party identifier.
     * @return The matching FIDO2 key, or null if not found.
     */
    @Query("SELECT * FROM keys WHERE key_type = 'fido2' AND user_id = :userId AND rp_id = :rpId LIMIT 1")
    suspend fun getFido2ByUserIdAndRpId(userId: String, rpId: String): KeyEntity?

    // -------------------------------------------------------------------------
    // Usage tracking
    // -------------------------------------------------------------------------

    /**
     * Record a key usage by incrementing the use count and updating the timestamp.
     *
     * @param keyId The unique key identifier.
     * @param timestamp The usage timestamp (defaults to current time).
     */
    @Query("UPDATE keys SET use_count = use_count + 1, last_used_at = :timestamp WHERE key_id = :keyId")
    suspend fun recordUsage(keyId: String, timestamp: Long = System.currentTimeMillis())

    /**
     * Update the FIDO2 signature counter for a key.
     *
     * @param keyId The unique key identifier.
     * @param signCount The new signature counter value.
     * @param timestamp The usage timestamp (defaults to current time).
     */
    @Query("UPDATE keys SET sign_count = :signCount, last_used_at = :timestamp WHERE key_id = :keyId")
    suspend fun updateSignCount(keyId: String, signCount: Long, timestamp: Long = System.currentTimeMillis())

    // -------------------------------------------------------------------------
    // Sharing policy
    // -------------------------------------------------------------------------

    /**
     * Update the sharing policy for a key.
     *
     * This also updates the legacy [shareable] field for backward compatibility:
     * - PRIVATE -> shareable = false
     * - ALL_PEERS -> shareable = true
     * - SELECTED_PEERS -> shareable = true
     *
     * @param keyId The unique key identifier.
     * @param policy The new sharing policy type.
     */
    suspend fun updateSharingPolicy(keyId: String, policy: SharingPolicyType) =
        SharePermissionLedger.revoking(keyId) { updateSharingPolicyRow(keyId, policy) }

    /** Raw policy update; call [updateSharingPolicy]. */
    @RawKeyRowWrite
    @Query(
        """
        UPDATE keys SET
            sharing_policy = :policy,
            shareable = CASE WHEN :policy = 'PRIVATE' THEN 0 ELSE 1 END
        WHERE key_id = :keyId
        """
    )
    suspend fun updateSharingPolicyRow(keyId: String, policy: SharingPolicyType)

    /**
     * Get all keys with a specific sharing policy.
     *
     * @param policy The sharing policy type to filter by.
     * @return List of keys with the specified sharing policy.
     */
    @Query("SELECT * FROM keys WHERE sharing_policy = :policy ORDER BY created_at DESC")
    suspend fun getBySharePolicy(policy: SharingPolicyType): List<KeyEntity>

    /**
     * Observe all keys with a specific sharing policy.
     *
     * @param policy The sharing policy type to filter by.
     * @return Flow emitting keys with the specified policy whenever changes occur.
     */
    @Query("SELECT * FROM keys WHERE sharing_policy = :policy ORDER BY created_at DESC")
    fun observeBySharePolicy(policy: SharingPolicyType): Flow<List<KeyEntity>>

    /**
     * Get all FIDO2 keys with a specific sharing policy.
     *
     * @param policy The sharing policy type to filter by.
     * @return List of FIDO2 keys with the specified sharing policy.
     */
    @Query("SELECT * FROM keys WHERE key_type = 'fido2' AND sharing_policy = :policy ORDER BY created_at DESC")
    suspend fun getFido2BySharePolicy(policy: SharingPolicyType): List<KeyEntity>

    /**
     * Get all non-private keys (ALL_PEERS or SELECTED_PEERS).
     *
     * @return List of keys that can potentially be shared.
     */
    @Query("SELECT * FROM keys WHERE sharing_policy != 'PRIVATE' ORDER BY created_at DESC")
    suspend fun getSharedKeys(): List<KeyEntity>

    /**
     * Count keys by sharing policy type.
     *
     * @param policy The sharing policy type to count.
     * @return Number of keys with the specified policy.
     */
    @Query("SELECT COUNT(*) FROM keys WHERE sharing_policy = :policy")
    suspend fun countBySharePolicy(policy: SharingPolicyType): Int

    // -------------------------------------------------------------------------
    // Deletion
    // -------------------------------------------------------------------------

    /**
     * Delete a key by its unique key identifier, as a revoke of that key.
     *
     * @param keyId The unique key identifier.
     * @return Number of rows deleted.
     */
    suspend fun deleteByKeyId(keyId: String): Int =
        SharePermissionLedger.revoking(keyId) { deleteRowByKeyId(keyId) }

    /** Raw delete by key ID; call [deleteByKeyId]. */
    @RawKeyRowWrite
    @Query("DELETE FROM keys WHERE key_id = :keyId")
    suspend fun deleteRowByKeyId(keyId: String): Int

    /**
     * Delete all FIDO2 keys for a relying party, each as a revoke of its key.
     *
     * @param rpId The relying party identifier.
     * @return Number of rows deleted.
     */
    suspend fun deleteFido2ByRpId(rpId: String): Int =
        getFido2ByRpId(rpId).sumOf { deleteByKeyId(it.keyId) }

    /**
     * Delete all keys, each as a revoke of its key.
     */
    suspend fun deleteAll() {
        getAll().forEach { deleteByKeyId(it.keyId) }
    }

    // -------------------------------------------------------------------------
    // Counting and existence checks
    // -------------------------------------------------------------------------

    /**
     * Get the total count of all keys.
     *
     * @return Total number of keys.
     */
    @Query("SELECT COUNT(*) FROM keys")
    suspend fun countAll(): Int

    /**
     * Get the count of keys of a specific type.
     *
     * @param keyType The key type to count.
     * @return Number of keys of the given type.
     */
    @Query("SELECT COUNT(*) FROM keys WHERE key_type = :keyType")
    suspend fun countByType(keyType: String): Int

    /**
     * Check if a key exists by its unique key identifier.
     *
     * @param keyId The unique key identifier.
     * @return True if the key exists.
     */
    @Query("SELECT EXISTS(SELECT 1 FROM keys WHERE key_id = :keyId)")
    suspend fun exists(keyId: String): Boolean

    // -------------------------------------------------------------------------
    // Metadata queries
    // -------------------------------------------------------------------------

    /**
     * Get all distinct key types present in the table.
     *
     * @return List of distinct key type strings.
     */
    @Query("SELECT DISTINCT key_type FROM keys ORDER BY key_type")
    suspend fun getKeyTypes(): List<String>

    /**
     * Get all distinct FIDO2 relying party IDs.
     *
     * @return List of distinct relying party identifiers.
     */
    @Query("SELECT DISTINCT rp_id FROM keys WHERE key_type = 'fido2' AND rp_id IS NOT NULL ORDER BY rp_id")
    suspend fun getFido2RpIds(): List<String>
}
