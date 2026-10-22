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
import androidx.room.Update
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

    /**
     * Insert a new entry only if no entry has its [PasswordEntity.passwordId]
     * yet (`INSERT OR IGNORE`): the one statement both checks and writes, so
     * an entry another writer added or changed meanwhile is never replaced.
     * Returns the new row id, or -1 if an entry with that id was already there
     * and nothing was written.
     */
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertIfAbsent(password: PasswordEntity): Long

    /**
     * Update an existing entry in place, matched by its primary key
     * [PasswordEntity.id]. Never inserts: returns the number of rows changed,
     * 0 if the entry was deleted since it was read.
     */
    @Update
    suspend fun update(password: PasswordEntity): Int

    /**
     * Overwrite an entry's editable fields, matched by its primary key [id],
     * only while every stored column is still the `expected` value read: the
     * one statement both finds the row and writes it, so no other write can
     * land in between. Leaves `password_id`, `created_at`, `shared` and
     * `tenant_id` alone and never inserts.
     *
     * A row replaced (every insert stores a fresh AES-GCM ciphertext), patched
     * by another update, or deleted since it was read matches nothing and this
     * returns 0. `IS` compares the nullable columns, so NULL matches NULL.
     */
    @Query(
        "UPDATE passwords SET name = :name, title = :title, username = :username, " +
            "password_encrypted = :passwordEncrypted, url = :url, notes = :notes, " +
            "folder_path = :folderPath, source = :source, expires_at = :expiresAt, updated_at = :updatedAt " +
            "WHERE id = :id AND password_encrypted = :expectedPasswordEncrypted " +
            "AND name = :expectedName AND title IS :expectedTitle AND username IS :expectedUsername " +
            "AND url IS :expectedUrl AND notes IS :expectedNotes AND folder_path IS :expectedFolderPath " +
            "AND source = :expectedSource AND created_at = :expectedCreatedAt AND updated_at = :expectedUpdatedAt " +
            "AND expires_at IS :expectedExpiresAt AND shared = :expectedShared AND tenant_id = :expectedTenantId"
    )
    suspend fun updateFieldsIfUnchanged(
        id: Long,
        expectedPasswordEncrypted: ByteArray,
        expectedName: String,
        expectedTitle: String?,
        expectedUsername: String?,
        expectedUrl: String?,
        expectedNotes: String?,
        expectedFolderPath: String?,
        expectedSource: String,
        expectedCreatedAt: Long,
        expectedUpdatedAt: Long,
        expectedExpiresAt: String?,
        expectedShared: Boolean,
        expectedTenantId: String,
        name: String,
        title: String?,
        username: String?,
        passwordEncrypted: ByteArray,
        url: String?,
        notes: String?,
        folderPath: String?,
        source: String,
        expiresAt: String?,
        updatedAt: Long
    ): Int

    /** Observe all password entries ordered by name then username. */
    @Query("SELECT * FROM passwords ORDER BY name, username")
    fun observeAll(): Flow<List<PasswordEntity>>

    /** Get all password entries ordered by name then username. */
    @Query("SELECT * FROM passwords ORDER BY name, username")
    suspend fun getAll(): List<PasswordEntity>

    /** Get a single password entry by its unique password ID, in any tenant, or null. */
    @Query("SELECT * FROM passwords WHERE password_id = :passwordId")
    suspend fun getByPasswordId(passwordId: String): PasswordEntity?

    /**
     * Get a single password entry by its unique password ID, or null if no
     * entry has it or the one that does belongs to another tenant than
     * [tenantId].
     */
    @Query("SELECT * FROM passwords WHERE password_id = :passwordId AND tenant_id = :tenantId")
    suspend fun getByPasswordIdInTenant(passwordId: String, tenantId: String): PasswordEntity?

    /**
     * The entries of [tenantId] ordered by name then username: only the
     * shared ones when [shared] is true, only the personal ones when false,
     * both when null; and only those in [folderPath] unless it is null.
     */
    @Query(
        "SELECT * FROM passwords WHERE tenant_id = :tenantId " +
            "AND (:shared IS NULL OR shared = :shared) " +
            "AND (:folderPath IS NULL OR folder_path = :folderPath) " +
            "ORDER BY name, username"
    )
    suspend fun getForListing(tenantId: String, shared: Boolean?, folderPath: String?): List<PasswordEntity>

    /** Get all password entries from a given source ("local" or "remote"). */
    @Query("SELECT * FROM passwords WHERE source = :source")
    suspend fun getBySource(source: String): List<PasswordEntity>

    /** Delete a password entry by its unique password ID, in any tenant. Returns the rows deleted. */
    @Query("DELETE FROM passwords WHERE password_id = :passwordId")
    suspend fun deleteByPasswordId(passwordId: String): Int

    /**
     * Delete the entry with [passwordId] if it belongs to [tenantId]. Returns
     * the rows deleted: 0 for an unknown id or another tenant's entry.
     */
    @Query("DELETE FROM passwords WHERE password_id = :passwordId AND tenant_id = :tenantId")
    suspend fun deleteByPasswordIdInTenant(passwordId: String, tenantId: String): Int

    /** Total number of stored password entries. */
    @Query("SELECT COUNT(*) FROM passwords")
    suspend fun count(): Int

    /** Observe the total number of stored password entries. */
    @Query("SELECT COUNT(*) FROM passwords")
    fun observeCount(): Flow<Int>
}
