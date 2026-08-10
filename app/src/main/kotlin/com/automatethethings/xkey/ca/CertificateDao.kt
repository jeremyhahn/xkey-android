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
package com.automatethethings.xkey.ca

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

/**
 * Room DAO for [CertificateEntity] operations.
 *
 * Provides CRUD operations and queries for certificate lifecycle management
 * including observation via Flow for reactive UI updates, profile-based
 * filtering, revocation tracking, and expiration monitoring.
 */
@Dao
interface CertificateDao {

    // -------------------------------------------------------------------------
    // Insert / Update
    // -------------------------------------------------------------------------

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(certificate: CertificateEntity): Long

    // -------------------------------------------------------------------------
    // Observation (Flow)
    // -------------------------------------------------------------------------

    @Query("SELECT * FROM certificates ORDER BY created_at DESC")
    fun observeAll(): Flow<List<CertificateEntity>>

    @Query("SELECT * FROM certificates WHERE profile = :profile ORDER BY created_at DESC")
    fun observeByProfile(profile: String): Flow<List<CertificateEntity>>

    @Query("SELECT * FROM certificates WHERE revoked = 1 ORDER BY revoked_at DESC")
    fun observeRevoked(): Flow<List<CertificateEntity>>

    @Query("SELECT * FROM certificates WHERE is_ca = 1 ORDER BY created_at DESC")
    fun observeCA(): Flow<List<CertificateEntity>>

    // -------------------------------------------------------------------------
    // Queries
    // -------------------------------------------------------------------------

    @Query("SELECT * FROM certificates ORDER BY created_at DESC")
    suspend fun getAll(): List<CertificateEntity>

    @Query("SELECT * FROM certificates WHERE serial_number = :serialNumber")
    suspend fun getBySerial(serialNumber: String): CertificateEntity?

    @Query("SELECT * FROM certificates WHERE profile = :profile ORDER BY created_at DESC")
    suspend fun getByProfile(profile: String): List<CertificateEntity>

    @Query("SELECT * FROM certificates WHERE revoked = 1 ORDER BY revoked_at DESC")
    suspend fun getRevoked(): List<CertificateEntity>

    @Query("SELECT * FROM certificates WHERE not_after < :now AND revoked = 0 ORDER BY not_after ASC")
    suspend fun getExpired(now: Long = System.currentTimeMillis()): List<CertificateEntity>

    @Query("SELECT * FROM certificates WHERE not_after BETWEEN :now AND :threshold AND revoked = 0 ORDER BY not_after ASC")
    suspend fun getExpiringSoon(
        now: Long = System.currentTimeMillis(),
        threshold: Long = System.currentTimeMillis() + 30L * 24 * 60 * 60 * 1000
    ): List<CertificateEntity>

    @Query("SELECT * FROM certificates WHERE is_ca = 1 ORDER BY created_at DESC")
    suspend fun getCACertificates(): List<CertificateEntity>

    @Query("SELECT * FROM certificates WHERE key_id = :keyId ORDER BY created_at DESC")
    suspend fun getByKeyId(keyId: String): List<CertificateEntity>

    // -------------------------------------------------------------------------
    // Counts
    // -------------------------------------------------------------------------

    @Query("SELECT COUNT(*) FROM certificates")
    suspend fun countAll(): Int

    @Query("SELECT COUNT(*) FROM certificates WHERE not_after < :now AND revoked = 0")
    suspend fun countExpired(now: Long = System.currentTimeMillis()): Int

    @Query("SELECT COUNT(*) FROM certificates WHERE not_after BETWEEN :now AND :threshold AND revoked = 0")
    suspend fun countExpiringSoon(
        now: Long = System.currentTimeMillis(),
        threshold: Long = System.currentTimeMillis() + 30L * 24 * 60 * 60 * 1000
    ): Int

    @Query("SELECT COUNT(*) FROM certificates WHERE revoked = 1")
    suspend fun countRevoked(): Int

    // -------------------------------------------------------------------------
    // Revocation
    // -------------------------------------------------------------------------

    @Query("UPDATE certificates SET revoked = 1, revoked_at = :revokedAt, revoked_reason = :reason WHERE serial_number = :serialNumber")
    suspend fun revoke(serialNumber: String, revokedAt: Long = System.currentTimeMillis(), reason: Int = 0)

    @Query("SELECT revoked FROM certificates WHERE serial_number = :serialNumber")
    suspend fun isRevoked(serialNumber: String): Boolean?

    // -------------------------------------------------------------------------
    // Search
    // -------------------------------------------------------------------------

    @Query("SELECT * FROM certificates WHERE subject_dn LIKE '%' || :query || '%' ORDER BY created_at DESC")
    suspend fun searchBySubject(query: String): List<CertificateEntity>

    // -------------------------------------------------------------------------
    // Delete
    // -------------------------------------------------------------------------

    @Query("DELETE FROM certificates WHERE serial_number = :serialNumber")
    suspend fun deleteBySerial(serialNumber: String)

    @Query("DELETE FROM certificates WHERE fingerprint = :fingerprint")
    suspend fun deleteByFingerprint(fingerprint: String)

    @Query("DELETE FROM certificates WHERE id = :id")
    suspend fun deleteById(id: Long)
}
