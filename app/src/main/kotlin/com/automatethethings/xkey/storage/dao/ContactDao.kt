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
import com.automatethethings.xkey.storage.entity.ContactEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface ContactDao {

    @Insert(onConflict = OnConflictStrategy.ABORT)
    suspend fun insert(contact: ContactEntity): Long

    @Query("SELECT * FROM contacts ORDER BY name ASC")
    suspend fun getAll(): List<ContactEntity>

    @Query("SELECT * FROM contacts ORDER BY name ASC")
    fun observeAll(): Flow<List<ContactEntity>>

    @Query("SELECT * FROM contacts WHERE public_key_fingerprint = :fingerprint LIMIT 1")
    suspend fun getByFingerprint(fingerprint: String): ContactEntity?

    @Query("SELECT * FROM contacts WHERE name LIKE '%' || :query || '%' COLLATE NOCASE ORDER BY name ASC")
    suspend fun searchByName(query: String): List<ContactEntity>

    @Query("DELETE FROM contacts WHERE public_key_fingerprint = :fingerprint")
    suspend fun deleteByFingerprint(fingerprint: String): Int

    @Query("DELETE FROM contacts WHERE id = :id")
    suspend fun deleteById(id: Long): Int

    @Query("SELECT COUNT(*) FROM contacts")
    suspend fun countAll(): Long

    @Query("SELECT COUNT(*) FROM contacts")
    fun observeCount(): Flow<Long>
}
