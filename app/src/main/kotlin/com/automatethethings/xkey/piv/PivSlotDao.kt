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
package com.automatethethings.xkey.piv

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

/**
 * Data Access Object for PIV smart card key slot operations.
 *
 * Provides CRUD and observation capabilities for the PIV slots stored in the
 * `piv_slots` table. Supports:
 * - Querying individual slots by hex ID or listing all slots
 * - Upserting slot metadata (insert or replace on conflict)
 * - Deleting slot entries when keys are destroyed
 * - Observing populated slots reactively via [Flow] for UI updates
 * - Tracking usage statistics (last used timestamp, use count)
 *
 * All query operations are suspend functions for coroutine compatibility.
 * Observation queries return [Flow] for reactive UI updates via Room's
 * invalidation tracker.
 */
@Dao
interface PivSlotDao {

    // -------------------------------------------------------------------------
    // Query Operations
    // -------------------------------------------------------------------------

    /**
     * Get all PIV slot entries ordered by slot ID.
     *
     * @return List of all PIV slot entities.
     */
    @Query("SELECT * FROM piv_slots ORDER BY slot_id ASC")
    suspend fun getAll(): List<PivSlotEntity>

    /**
     * Get a single PIV slot entry by its hex slot ID.
     *
     * @param slotId The PIV slot hex identifier (e.g., "9A").
     * @return The PIV slot entity, or null if the slot has no entry.
     */
    @Query("SELECT * FROM piv_slots WHERE slot_id = :slotId LIMIT 1")
    suspend fun getBySlotId(slotId: String): PivSlotEntity?

    // -------------------------------------------------------------------------
    // Insert / Update Operations
    // -------------------------------------------------------------------------

    /**
     * Insert or replace a PIV slot entry.
     *
     * Uses [OnConflictStrategy.REPLACE] so that re-generating a key in an
     * existing slot overwrites the previous metadata.
     *
     * @param entity The PIV slot entity to upsert.
     * @return The row ID of the inserted or replaced entry.
     */
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(entity: PivSlotEntity): Long

    // -------------------------------------------------------------------------
    // Delete Operations
    // -------------------------------------------------------------------------

    /**
     * Delete a PIV slot entry by its hex slot ID.
     *
     * Called when a key is destroyed and its metadata should be removed.
     *
     * @param slotId The PIV slot hex identifier (e.g., "9A").
     * @return The number of rows deleted (0 or 1).
     */
    @Query("DELETE FROM piv_slots WHERE slot_id = :slotId")
    suspend fun deleteBySlotId(slotId: String): Int

    // -------------------------------------------------------------------------
    // Observation Queries
    // -------------------------------------------------------------------------

    /**
     * Observe all PIV slot entries that contain a generated key.
     *
     * Emits a new list whenever the `piv_slots` table is modified.
     *
     * @return Flow emitting the list of populated slot entries.
     */
    @Query("SELECT * FROM piv_slots WHERE has_key = 1 ORDER BY slot_id ASC")
    fun observePopulatedSlots(): Flow<List<PivSlotEntity>>

    /**
     * Observe all PIV slot entries ordered by slot ID.
     *
     * Emits a new list whenever the `piv_slots` table is modified.
     *
     * @return Flow emitting the list of all slot entries.
     */
    @Query("SELECT * FROM piv_slots ORDER BY slot_id ASC")
    fun observeAll(): Flow<List<PivSlotEntity>>

    // -------------------------------------------------------------------------
    // Aggregate Queries
    // -------------------------------------------------------------------------

    /**
     * Get the count of PIV slots that contain a generated key.
     *
     * @return Number of populated slots.
     */
    @Query("SELECT COUNT(*) FROM piv_slots WHERE has_key = 1")
    suspend fun countPopulated(): Int

    /**
     * Observe the count of PIV slots that contain a generated key.
     *
     * Emits a new count whenever the `piv_slots` table is modified.
     *
     * @return Flow emitting the populated slot count.
     */
    @Query("SELECT COUNT(*) FROM piv_slots WHERE has_key = 1")
    fun observePopulatedCount(): Flow<Int>

    // -------------------------------------------------------------------------
    // Usage Tracking
    // -------------------------------------------------------------------------

    /**
     * Record a usage event for a PIV slot.
     *
     * Atomically updates the last-used timestamp and increments the use count.
     *
     * @param slotId The PIV slot hex identifier (e.g., "9A").
     * @param timestamp The timestamp of the usage event in milliseconds (defaults to now).
     */
    @Query("UPDATE piv_slots SET last_used_at = :timestamp, use_count = use_count + 1 WHERE slot_id = :slotId")
    suspend fun recordUsage(slotId: String, timestamp: Long = System.currentTimeMillis())
}
