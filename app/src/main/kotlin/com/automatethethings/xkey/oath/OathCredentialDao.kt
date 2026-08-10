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
package com.automatethethings.xkey.oath

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

/**
 * Data Access Object for OATH credential operations.
 *
 * Provides query and management capabilities for TOTP/HOTP credentials:
 * - Insert and replace credentials
 * - Query all credentials or filter by issuer / OATH ID
 * - Track usage statistics (last used timestamp, use count)
 * - Update HOTP counter values
 * - Observe credential list and count reactively via [Flow]
 *
 * All mutation operations are suspend functions for coroutine compatibility.
 * Observation queries return [Flow] for reactive UI updates.
 */
@Dao
interface OathCredentialDao {

    // -------------------------------------------------------------------------
    // Insert Operations
    // -------------------------------------------------------------------------

    /**
     * Insert or replace an OATH credential.
     *
     * Uses [OnConflictStrategy.REPLACE] so that re-importing a credential
     * with the same unique [OathCredentialEntity.oathId] overwrites the
     * existing row rather than throwing a constraint violation.
     *
     * @param credential The OATH credential entity to insert or replace.
     * @return The row ID of the inserted (or replaced) entry.
     */
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(credential: OathCredentialEntity): Long

    // -------------------------------------------------------------------------
    // Query Operations
    // -------------------------------------------------------------------------

    /**
     * Observe all OATH credentials ordered by issuer and account name.
     *
     * @return Flow emitting the full credential list whenever changes occur.
     */
    @Query("SELECT * FROM oath_credentials ORDER BY issuer, account_name")
    fun observeAll(): Flow<List<OathCredentialEntity>>

    /**
     * Get all OATH credentials ordered by issuer and account name.
     *
     * @return List of all OATH credential entities.
     */
    @Query("SELECT * FROM oath_credentials ORDER BY issuer, account_name")
    suspend fun getAll(): List<OathCredentialEntity>

    /**
     * Get a single OATH credential by its unique OATH ID.
     *
     * @param oathId The unique OATH identifier (e.g. "issuer:account").
     * @return The matching credential, or null if not found.
     */
    @Query("SELECT * FROM oath_credentials WHERE oath_id = :oathId")
    suspend fun getByOathId(oathId: String): OathCredentialEntity?

    /**
     * Get all OATH credentials for a specific issuer.
     *
     * @param issuer The issuer name to filter by.
     * @return List of credentials from the given issuer.
     */
    @Query("SELECT * FROM oath_credentials WHERE issuer = :issuer")
    suspend fun getByIssuer(issuer: String): List<OathCredentialEntity>

    // -------------------------------------------------------------------------
    // Update Operations
    // -------------------------------------------------------------------------

    /**
     * Record a usage event for an OATH credential.
     *
     * Increments the use count and updates the last-used timestamp atomically.
     *
     * @param oathId The unique OATH identifier of the credential.
     * @param timestamp The usage timestamp in Unix milliseconds (defaults to now).
     */
    @Query("UPDATE oath_credentials SET last_used_at = :timestamp, use_count = use_count + 1 WHERE oath_id = :oathId")
    suspend fun recordUsage(oathId: String, timestamp: Long = System.currentTimeMillis())

    /**
     * Update the HOTP counter for a credential.
     *
     * Should be called after each successful HOTP code generation to advance
     * the counter and keep the credential in sync with the verifying server.
     *
     * @param oathId The unique OATH identifier of the HOTP credential.
     * @param counter The new counter value.
     */
    @Query("UPDATE oath_credentials SET counter = :counter WHERE oath_id = :oathId")
    suspend fun updateCounter(oathId: String, counter: Long)

    // -------------------------------------------------------------------------
    // Delete Operations
    // -------------------------------------------------------------------------

    /**
     * Get all OATH credentials from a specific source.
     *
     * @param source The source to filter by ("local" or "remote").
     * @return List of credentials from the given source.
     */
    @Query("SELECT * FROM oath_credentials WHERE source = :source")
    suspend fun getBySource(source: String): List<OathCredentialEntity>

    /**
     * Delete an OATH credential by its unique OATH ID.
     *
     * @param oathId The unique OATH identifier of the credential to delete.
     */
    @Query("DELETE FROM oath_credentials WHERE oath_id = :oathId")
    suspend fun deleteByOathId(oathId: String)

    // -------------------------------------------------------------------------
    // Aggregate Queries
    // -------------------------------------------------------------------------

    /**
     * Get the total count of OATH credentials.
     *
     * @return Number of stored credentials.
     */
    @Query("SELECT COUNT(*) FROM oath_credentials")
    suspend fun count(): Int

    /**
     * Observe the total count of OATH credentials.
     *
     * @return Flow emitting the credential count whenever it changes.
     */
    @Query("SELECT COUNT(*) FROM oath_credentials")
    fun observeCount(): Flow<Int>
}
