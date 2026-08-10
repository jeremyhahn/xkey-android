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
package com.automatethethings.xkey.audit

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

/**
 * Data Access Object for audit log operations.
 *
 * Provides comprehensive query and management capabilities for the audit log system:
 * - Insert new audit entries
 * - Query by various criteria (key, operation type, date range, etc.)
 * - Search by key label
 * - Retention management (delete old entries)
 * - Aggregate statistics
 *
 * All query operations are suspend functions for coroutine compatibility.
 * Observation queries return [Flow] for reactive UI updates.
 */
@Dao
interface AuditLogDao {

    // -------------------------------------------------------------------------
    // Insert Operations
    // -------------------------------------------------------------------------

    /**
     * Insert a new audit log entry.
     *
     * @param entry The audit log entry to insert.
     * @return The row ID of the inserted entry.
     */
    @Insert
    suspend fun insert(entry: AuditLogEntity): Long

    /**
     * Insert multiple audit log entries in a single transaction.
     *
     * @param entries The list of audit log entries to insert.
     * @return List of row IDs for the inserted entries.
     */
    @Insert
    suspend fun insertAll(entries: List<AuditLogEntity>): List<Long>

    // -------------------------------------------------------------------------
    // Query Operations
    // -------------------------------------------------------------------------

    /**
     * Get all audit log entries ordered by timestamp (newest first).
     *
     * @return List of all audit log entries.
     */
    @Query("SELECT * FROM audit_logs ORDER BY timestamp DESC")
    suspend fun getAll(): List<AuditLogEntity>

    /**
     * Observe all audit log entries ordered by timestamp (newest first).
     *
     * @return Flow emitting the list of all entries whenever changes occur.
     */
    @Query("SELECT * FROM audit_logs ORDER BY timestamp DESC")
    fun observeAll(): Flow<List<AuditLogEntity>>

    /**
     * Get audit log entries with pagination.
     *
     * @param limit Maximum number of entries to return.
     * @param offset Number of entries to skip.
     * @return List of audit log entries.
     */
    @Query("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT :limit OFFSET :offset")
    suspend fun getPaginated(limit: Int, offset: Int): List<AuditLogEntity>

    /**
     * Get a single audit log entry by ID.
     *
     * @param id The entry ID.
     * @return The audit log entry, or null if not found.
     */
    @Query("SELECT * FROM audit_logs WHERE id = :id LIMIT 1")
    suspend fun getById(id: Long): AuditLogEntity?

    /**
     * Get all audit log entries for a specific key.
     *
     * @param keyId The unique key identifier.
     * @return List of audit log entries for the key.
     */
    @Query("SELECT * FROM audit_logs WHERE key_id = :keyId ORDER BY timestamp DESC")
    suspend fun getByKeyId(keyId: String): List<AuditLogEntity>

    /**
     * Observe audit log entries for a specific key.
     *
     * @param keyId The unique key identifier.
     * @return Flow emitting entries for the key whenever changes occur.
     */
    @Query("SELECT * FROM audit_logs WHERE key_id = :keyId ORDER BY timestamp DESC")
    fun observeByKeyId(keyId: String): Flow<List<AuditLogEntity>>

    /**
     * Get all audit log entries for a specific key type.
     *
     * @param keyType The key type (e.g., "fido2", "signing", "secret").
     * @return List of audit log entries for keys of the given type.
     */
    @Query("SELECT * FROM audit_logs WHERE key_type = :keyType ORDER BY timestamp DESC")
    suspend fun getByKeyType(keyType: String): List<AuditLogEntity>

    /**
     * Observe audit log entries for a specific key type.
     *
     * @param keyType The key type.
     * @return Flow emitting entries for the key type whenever changes occur.
     */
    @Query("SELECT * FROM audit_logs WHERE key_type = :keyType ORDER BY timestamp DESC")
    fun observeByKeyType(keyType: String): Flow<List<AuditLogEntity>>

    /**
     * Get all audit log entries for a specific operation type.
     *
     * @param operationType The operation type to filter by.
     * @return List of audit log entries for the operation type.
     */
    @Query("SELECT * FROM audit_logs WHERE operation_type = :operationType ORDER BY timestamp DESC")
    suspend fun getByOperationType(operationType: AuditOperationType): List<AuditLogEntity>

    /**
     * Observe audit log entries for a specific operation type.
     *
     * @param operationType The operation type to filter by.
     * @return Flow emitting entries for the operation type whenever changes occur.
     */
    @Query("SELECT * FROM audit_logs WHERE operation_type = :operationType ORDER BY timestamp DESC")
    fun observeByOperationType(operationType: AuditOperationType): Flow<List<AuditLogEntity>>

    /**
     * Get all audit log entries within a date range.
     *
     * @param startTimestamp The start of the range (inclusive), in milliseconds.
     * @param endTimestamp The end of the range (inclusive), in milliseconds.
     * @return List of audit log entries within the date range.
     */
    @Query(
        """
        SELECT * FROM audit_logs
        WHERE timestamp >= :startTimestamp AND timestamp <= :endTimestamp
        ORDER BY timestamp DESC
        """
    )
    suspend fun getByDateRange(startTimestamp: Long, endTimestamp: Long): List<AuditLogEntity>

    /**
     * Observe audit log entries within a date range.
     *
     * @param startTimestamp The start of the range (inclusive), in milliseconds.
     * @param endTimestamp The end of the range (inclusive), in milliseconds.
     * @return Flow emitting entries within the date range whenever changes occur.
     */
    @Query(
        """
        SELECT * FROM audit_logs
        WHERE timestamp >= :startTimestamp AND timestamp <= :endTimestamp
        ORDER BY timestamp DESC
        """
    )
    fun observeByDateRange(startTimestamp: Long, endTimestamp: Long): Flow<List<AuditLogEntity>>

    /**
     * Get all audit log entries for a specific device.
     *
     * @param deviceId The device identifier.
     * @return List of audit log entries for the device.
     */
    @Query("SELECT * FROM audit_logs WHERE device_id = :deviceId ORDER BY timestamp DESC")
    suspend fun getByDeviceId(deviceId: String): List<AuditLogEntity>

    /**
     * Get all successful or failed audit log entries.
     *
     * @param success True for successful operations, false for failed.
     * @return List of audit log entries matching the success status.
     */
    @Query("SELECT * FROM audit_logs WHERE success = :success ORDER BY timestamp DESC")
    suspend fun getBySuccess(success: Boolean): List<AuditLogEntity>

    /**
     * Search audit log entries by key label.
     *
     * Performs a case-insensitive partial match on the key label.
     *
     * @param query The search query string.
     * @return List of audit log entries with matching key labels.
     */
    @Query(
        """
        SELECT * FROM audit_logs
        WHERE key_label LIKE '%' || :query || '%' COLLATE NOCASE
        ORDER BY timestamp DESC
        """
    )
    suspend fun searchByKeyLabel(query: String): List<AuditLogEntity>

    /**
     * Observe audit log entries matching a key label search.
     *
     * @param query The search query string.
     * @return Flow emitting matching entries whenever changes occur.
     */
    @Query(
        """
        SELECT * FROM audit_logs
        WHERE key_label LIKE '%' || :query || '%' COLLATE NOCASE
        ORDER BY timestamp DESC
        """
    )
    fun observeSearchByKeyLabel(query: String): Flow<List<AuditLogEntity>>

    /**
     * Get audit log entries with combined filters.
     *
     * Supports filtering by operation type, key type, success status, and date range
     * simultaneously. Pass null for any filter to ignore it.
     *
     * @param operationType The operation type filter (null to ignore).
     * @param keyType The key type filter (null to ignore).
     * @param success The success status filter (null to ignore).
     * @param startTimestamp The start of date range (null to ignore).
     * @param endTimestamp The end of date range (null to ignore).
     * @return List of audit log entries matching all specified filters.
     */
    @Query(
        """
        SELECT * FROM audit_logs
        WHERE (:operationType IS NULL OR operation_type = :operationType)
          AND (:keyType IS NULL OR key_type = :keyType)
          AND (:success IS NULL OR success = :success)
          AND (:startTimestamp IS NULL OR timestamp >= :startTimestamp)
          AND (:endTimestamp IS NULL OR timestamp <= :endTimestamp)
        ORDER BY timestamp DESC
        """
    )
    suspend fun getFiltered(
        operationType: AuditOperationType?,
        keyType: String?,
        success: Boolean?,
        startTimestamp: Long?,
        endTimestamp: Long?
    ): List<AuditLogEntity>

    // -------------------------------------------------------------------------
    // Aggregate Queries
    // -------------------------------------------------------------------------

    /**
     * Get the total count of all audit log entries.
     *
     * @return Total number of entries.
     */
    @Query("SELECT COUNT(*) FROM audit_logs")
    suspend fun getCount(): Long

    /**
     * Observe the total count of audit log entries.
     *
     * @return Flow emitting the count whenever it changes.
     */
    @Query("SELECT COUNT(*) FROM audit_logs")
    fun observeCount(): Flow<Long>

    /**
     * Get the count of entries by operation type.
     *
     * @param operationType The operation type to count.
     * @return Number of entries of the given operation type.
     */
    @Query("SELECT COUNT(*) FROM audit_logs WHERE operation_type = :operationType")
    suspend fun countByOperationType(operationType: AuditOperationType): Long

    /**
     * Get the count of entries by key type.
     *
     * @param keyType The key type to count.
     * @return Number of entries for the given key type.
     */
    @Query("SELECT COUNT(*) FROM audit_logs WHERE key_type = :keyType")
    suspend fun countByKeyType(keyType: String): Long

    /**
     * Get the count of successful operations.
     *
     * @return Number of successful operations.
     */
    @Query("SELECT COUNT(*) FROM audit_logs WHERE success = 1")
    suspend fun countSuccessful(): Long

    /**
     * Get the count of failed operations.
     *
     * @return Number of failed operations.
     */
    @Query("SELECT COUNT(*) FROM audit_logs WHERE success = 0")
    suspend fun countFailed(): Long

    /**
     * Get the most recent N entries.
     *
     * @param limit Maximum number of entries to return.
     * @return List of the most recent entries.
     */
    @Query("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT :limit")
    suspend fun getRecent(limit: Int): List<AuditLogEntity>

    /**
     * Observe the most recent N entries.
     *
     * @param limit Maximum number of entries to observe.
     * @return Flow emitting the most recent entries whenever changes occur.
     */
    @Query("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT :limit")
    fun observeRecent(limit: Int): Flow<List<AuditLogEntity>>

    /**
     * Get all distinct key types that have audit entries.
     *
     * @return List of key types with audit entries.
     */
    @Query("SELECT DISTINCT key_type FROM audit_logs WHERE key_type IS NOT NULL ORDER BY key_type")
    suspend fun getDistinctKeyTypes(): List<String>

    /**
     * Get all distinct operation types that have audit entries.
     *
     * @return List of operation types with audit entries.
     */
    @Query("SELECT DISTINCT operation_type FROM audit_logs ORDER BY operation_type")
    suspend fun getDistinctOperationTypes(): List<AuditOperationType>

    // -------------------------------------------------------------------------
    // Retention Management
    // -------------------------------------------------------------------------

    /**
     * Delete audit log entries older than a specified timestamp.
     *
     * Used for retention policy enforcement to prevent unbounded log growth.
     *
     * @param olderThan Timestamp threshold; entries before this will be deleted.
     * @return Number of entries deleted.
     */
    @Query("DELETE FROM audit_logs WHERE timestamp < :olderThan")
    suspend fun deleteOlderThan(olderThan: Long): Int

    /**
     * Delete all audit log entries for a specific key.
     *
     * Useful when a key is deleted and its audit history should be removed.
     *
     * @param keyId The unique key identifier.
     * @return Number of entries deleted.
     */
    @Query("DELETE FROM audit_logs WHERE key_id = :keyId")
    suspend fun deleteByKeyId(keyId: String): Int

    /**
     * Delete all audit log entries.
     *
     * Use with caution - this removes all audit history.
     *
     * @return Number of entries deleted.
     */
    @Query("DELETE FROM audit_logs")
    suspend fun deleteAll(): Int

    /**
     * Delete entries exceeding a maximum count, keeping the most recent.
     *
     * Useful for maintaining a maximum log size while preserving recent history.
     *
     * @param maxCount Maximum number of entries to keep.
     * @return Number of entries deleted.
     */
    @Query(
        """
        DELETE FROM audit_logs
        WHERE id NOT IN (
            SELECT id FROM audit_logs ORDER BY timestamp DESC LIMIT :maxCount
        )
        """
    )
    suspend fun deleteExceedingCount(maxCount: Int): Int
}
