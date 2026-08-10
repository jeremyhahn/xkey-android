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
import com.automatethethings.xkey.storage.entity.CredentialMetadataEntity
import kotlinx.coroutines.flow.Flow

/**
 * Data Access Object for credential metadata operations.
 *
 * Provides CRUD operations for passkey credential metadata stored in Room.
 * All operations are suspend functions for coroutine compatibility.
 */
@Dao
interface CredentialMetadataDao {

    /**
     * Insert a new credential metadata entry.
     *
     * @param credential The credential metadata to insert.
     * @return The row ID of the inserted entry.
     */
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(credential: CredentialMetadataEntity): Long

    /**
     * Update an existing credential metadata entry.
     *
     * @param credential The credential metadata to update.
     */
    @Update
    suspend fun update(credential: CredentialMetadataEntity)

    /**
     * Delete a credential metadata entry.
     *
     * @param credential The credential metadata to delete.
     */
    @Delete
    suspend fun delete(credential: CredentialMetadataEntity)

    /**
     * Delete a credential by its credential ID.
     *
     * @param credentialId The credential ID to delete.
     * @return Number of rows deleted.
     */
    @Query("DELETE FROM credential_metadata WHERE credential_id = :credentialId")
    suspend fun deleteByCredentialId(credentialId: String): Int

    /**
     * Get a credential by its credential ID.
     *
     * @param credentialId The credential ID to look up.
     * @return The credential metadata, or null if not found.
     */
    @Query("SELECT * FROM credential_metadata WHERE credential_id = :credentialId LIMIT 1")
    suspend fun getByCredentialId(credentialId: String): CredentialMetadataEntity?

    /**
     * Get all credentials for a relying party.
     *
     * @param rpId The relying party identifier.
     * @return List of credentials for the relying party.
     */
    @Query("SELECT * FROM credential_metadata WHERE rp_id = :rpId ORDER BY last_used_at DESC")
    suspend fun getByRpId(rpId: String): List<CredentialMetadataEntity>

    /**
     * Get all discoverable credentials for a relying party.
     *
     * @param rpId The relying party identifier.
     * @return List of discoverable credentials for the relying party.
     */
    @Query("SELECT * FROM credential_metadata WHERE rp_id = :rpId AND is_discoverable = 1 ORDER BY last_used_at DESC")
    suspend fun getDiscoverableByRpId(rpId: String): List<CredentialMetadataEntity>

    /**
     * Get a credential by user ID and relying party.
     *
     * @param userId The user ID.
     * @param rpId The relying party identifier.
     * @return The credential metadata, or null if not found.
     */
    @Query("SELECT * FROM credential_metadata WHERE user_id = :userId AND rp_id = :rpId LIMIT 1")
    suspend fun getByUserIdAndRpId(userId: String, rpId: String): CredentialMetadataEntity?

    /**
     * Get all credentials.
     *
     * @return List of all credential metadata entries.
     */
    @Query("SELECT * FROM credential_metadata ORDER BY last_used_at DESC")
    suspend fun getAll(): List<CredentialMetadataEntity>

    /**
     * Observe all credentials as a Flow.
     *
     * @return Flow emitting list of all credentials whenever changes occur.
     */
    @Query("SELECT * FROM credential_metadata ORDER BY last_used_at DESC")
    fun observeAll(): Flow<List<CredentialMetadataEntity>>

    /**
     * Observe credentials for a specific relying party.
     *
     * @param rpId The relying party identifier.
     * @return Flow emitting credentials for the relying party.
     */
    @Query("SELECT * FROM credential_metadata WHERE rp_id = :rpId ORDER BY last_used_at DESC")
    fun observeByRpId(rpId: String): Flow<List<CredentialMetadataEntity>>

    /**
     * Update the sign count for a credential.
     *
     * @param credentialId The credential ID.
     * @param signCount The new sign count.
     */
    @Query("UPDATE credential_metadata SET sign_count = :signCount, last_used_at = :lastUsedAt WHERE credential_id = :credentialId")
    suspend fun updateSignCount(credentialId: String, signCount: Long, lastUsedAt: Long = System.currentTimeMillis())

    /**
     * Get the count of credentials for a relying party.
     *
     * @param rpId The relying party identifier.
     * @return Number of credentials for the relying party.
     */
    @Query("SELECT COUNT(*) FROM credential_metadata WHERE rp_id = :rpId")
    suspend fun countByRpId(rpId: String): Int

    /**
     * Get the total count of all credentials.
     *
     * @return Total number of credentials.
     */
    @Query("SELECT COUNT(*) FROM credential_metadata")
    suspend fun countAll(): Int

    /**
     * Check if a credential exists.
     *
     * @param credentialId The credential ID to check.
     * @return True if the credential exists.
     */
    @Query("SELECT EXISTS(SELECT 1 FROM credential_metadata WHERE credential_id = :credentialId)")
    suspend fun exists(credentialId: String): Boolean

    /**
     * Get all unique relying party IDs.
     *
     * @return List of distinct relying party IDs.
     */
    @Query("SELECT DISTINCT rp_id FROM credential_metadata ORDER BY rp_id")
    suspend fun getAllRpIds(): List<String>

    /**
     * Delete all credentials for a relying party.
     *
     * @param rpId The relying party identifier.
     * @return Number of rows deleted.
     */
    @Query("DELETE FROM credential_metadata WHERE rp_id = :rpId")
    suspend fun deleteByRpId(rpId: String): Int

    /**
     * Delete all credentials.
     */
    @Query("DELETE FROM credential_metadata")
    suspend fun deleteAll()
}
