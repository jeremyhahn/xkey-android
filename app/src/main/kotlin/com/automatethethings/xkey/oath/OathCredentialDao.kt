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
import androidx.room.Transaction
import kotlinx.coroutines.flow.Flow

/**
 * Data Access Object for OATH credential operations.
 *
 * Provides query and management capabilities for TOTP/HOTP credentials:
 * - Insert and replace credentials
 * - Query all credentials or filter by issuer / OATH ID
 * - Track usage statistics (last used timestamp, use count)
 * - Advance HOTP counter values (compare-and-set)
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

    /**
     * Insert an OATH credential only while no row has its
     * [OathCredentialEntity.oathId]; an existing row is left untouched.
     *
     * @return The new row ID, or -1 if a row with that OATH ID already exists.
     */
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertIfAbsent(credential: OathCredentialEntity): Long

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
     * Advance the HOTP counter of a credential from [expected] to [next],
     * only while the stored counter is still [expected]: the one statement
     * both checks and writes, so a counter a sync raised meanwhile
     * ([updateSynced]) or another code took is never rewound.
     *
     * @param oathId The unique OATH identifier of the HOTP credential.
     * @param expected The counter the caller read and generated a code for.
     * @param next The counter to store.
     * @return The number of rows updated: 0 if the counter moved since it was
     *         read (or no row has [oathId]), and the code for [expected] must
     *         not be used.
     */
    @Query("UPDATE oath_credentials SET counter = :next WHERE oath_id = :oathId AND counter = :expected")
    suspend fun advanceCounter(oathId: String, expected: Long, next: Long): Int

    /**
     * Update a synced credential in place: only its label and HOTP counter.
     * The row keeps its primary key, creation time, usage statistics,
     * source, remote device and key material (secret, type, algorithm,
     * digits, period): the sync wire item carries no timestamp, so a stale
     * peer could otherwise revert a re-keyed credential. The counter only
     * moves forward (`MAX(counter, :counter)`), so a peer that has generated
     * fewer codes never rewinds it.
     *
     * @return The number of rows updated: 0 if no row has [oathId].
     */
    @Query(
        "UPDATE oath_credentials SET counter = MAX(counter, :counter), issuer = :issuer, " +
            "account_name = :accountName WHERE oath_id = :oathId"
    )
    suspend fun updateSynced(
        oathId: String,
        counter: Long,
        issuer: String?,
        accountName: String
    ): Int

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

    /**
     * Record that [oathId] was deleted on the phone at [deletedAt], so a
     * sync never adds it back. A later deletion of the same id replaces the
     * earlier record.
     */
    @Query("INSERT OR REPLACE INTO oath_deletions (oath_id, deleted_at) VALUES (:oathId, :deletedAt)")
    suspend fun recordDeletion(oathId: String, deletedAt: Long)

    /**
     * @return true if [oathId] has a delete record ([recordDeletion]).
     */
    @Query("SELECT EXISTS(SELECT 1 FROM oath_deletions WHERE oath_id = :oathId)")
    suspend fun isDeleted(oathId: String): Boolean

    /**
     * Delete the credential with [oathId] and record its deletion at
     * [deletedAt] ([recordDeletion]), in one transaction: no sync merge,
     * gather or interruption sees the record without the delete or the
     * delete without the record. The id is recorded even when no row has it.
     */
    @Transaction
    suspend fun deleteAndRecordDeletion(oathId: String, deletedAt: Long) {
        recordDeletion(oathId, deletedAt)
        deleteByOathId(oathId)
    }

    /**
     * If [oathId] has a deletion record, delete any row still stored under
     * it, in one transaction with the check: a row an earlier, interrupted
     * merge left beside its record never stays usable. Synced ids are never
     * reused by local adds (those get random UUIDs), so such a row is always
     * a leftover.
     *
     * @return true if [oathId] has a deletion record.
     */
    @Transaction
    suspend fun removeIfDeleted(oathId: String): Boolean {
        if (!isDeleted(oathId)) return false
        deleteByOathId(oathId)
        return true
    }

    /**
     * Add a synced [credential] while no row has its oath id, unless the
     * phone deleted that id ([recordDeletion]), in one transaction: the
     * deletion check and the insert see the same state, so a delete cannot
     * land between them, and no interruption leaves the row stored beside
     * its record. A row already there for a deleted id is removed
     * ([removeIfDeleted]).
     *
     * @return [OATH_KEPT_DELETED] (-2) when the id is deleted, otherwise
     *         what [insertIfAbsent] returns (-1 when a row has the id).
     */
    @Transaction
    suspend fun insertIfAbsentUnlessDeleted(credential: OathCredentialEntity): Long {
        if (removeIfDeleted(credential.oathId)) return OATH_KEPT_DELETED
        return insertIfAbsent(credential)
    }

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

/** [OathCredentialDao.insertIfAbsentUnlessDeleted]: the id was deleted on the phone and stays deleted. */
const val OATH_KEPT_DELETED = -2L
