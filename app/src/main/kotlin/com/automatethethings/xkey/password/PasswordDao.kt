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
package com.automatethethings.xkey.password

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

/**
 * Data Access Object for stored password entries.
 *
 * All mutations are suspend functions; observation queries return [Flow] for
 * reactive UI updates.
 */
@Dao
interface PasswordDao {

    /**
     * Insert or replace a password entry, keyed by the unique
     * [PasswordEntity.passwordId].
     */
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(password: PasswordEntity): Long

    /** Observe all password entries ordered by name then username. */
    @Query("SELECT * FROM passwords ORDER BY name, username")
    fun observeAll(): Flow<List<PasswordEntity>>

    /** Get all password entries ordered by name then username. */
    @Query("SELECT * FROM passwords ORDER BY name, username")
    suspend fun getAll(): List<PasswordEntity>

    /** Get a single password entry by its unique password ID, or null. */
    @Query("SELECT * FROM passwords WHERE password_id = :passwordId")
    suspend fun getByPasswordId(passwordId: String): PasswordEntity?

    /** Get all password entries from a given source ("local" or "remote"). */
    @Query("SELECT * FROM passwords WHERE source = :source")
    suspend fun getBySource(source: String): List<PasswordEntity>

    /** Delete a password entry by its unique password ID. */
    @Query("DELETE FROM passwords WHERE password_id = :passwordId")
    suspend fun deleteByPasswordId(passwordId: String)

    /** Total number of stored password entries. */
    @Query("SELECT COUNT(*) FROM passwords")
    suspend fun count(): Int

    /** Observe the total number of stored password entries. */
    @Query("SELECT COUNT(*) FROM passwords")
    fun observeCount(): Flow<Int>
}
