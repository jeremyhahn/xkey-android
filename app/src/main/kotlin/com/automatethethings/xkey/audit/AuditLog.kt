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

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/**
 * Represents the type of operation recorded in the audit log.
 *
 * Operations are grouped by category for easier filtering and analysis:
 * - Key lifecycle: CREATE, DELETE, ATTEST
 * - Key usage: SIGN, ENCRYPT, DECRYPT, DERIVE
 * - Connection: PAIRING, CONNECTION
 * - Configuration: SETTINGS
 */
enum class AuditOperationType {
    // Key lifecycle operations
    /** A new cryptographic key was created. */
    KEY_CREATED,
    /** A cryptographic key was deleted. */
    KEY_DELETED,
    /** A key was used for any cryptographic operation. */
    KEY_USED,
    /** A key attestation was requested and performed. */
    KEY_ATTESTED,
    /** A key's sharing policy was modified. */
    KEY_SHARING_CHANGED,
    /** A key was exported (public key only). */
    KEY_EXPORTED,

    // Cryptographic operations
    /** A signing operation was requested. */
    SIGNING_REQUEST,
    /** An encryption operation was requested. */
    ENCRYPTION_REQUEST,
    /** A decryption operation was requested. */
    DECRYPTION_REQUEST,
    /** A key derivation operation was performed. */
    KEY_DERIVATION_REQUEST,
    /** An HMAC operation was performed. */
    HMAC_REQUEST,

    // FIDO2/WebAuthn operations
    /** A FIDO2 credential was registered. */
    FIDO2_REGISTRATION,
    /** A FIDO2 authentication was performed. */
    FIDO2_AUTHENTICATION,

    // Pairing and connection operations
    /** A device pairing request was approved. */
    PAIRING_APPROVED,
    /** A device pairing request was denied. */
    PAIRING_DENIED,
    /** A device was unpaired/removed. */
    DEVICE_UNPAIRED,
    /** A secure connection was established. */
    CONNECTION_ESTABLISHED,
    /** A secure connection was closed. */
    CONNECTION_CLOSED,
    /** Device attestation was verified. */
    DEVICE_ATTESTED,
    /**
     * This device was issued a credential by an external CA.
     *
     * The mirror of [DEVICE_ATTESTED], which records this device judging
     * someone else. Here this device is the subject, so the operator can see
     * which authority it answers to and when that standing lapses.
     */
    DEVICE_ENROLLED,

    // Configuration operations
    /** Application settings were changed. */
    SETTINGS_CHANGED,
    /** A CA certificate was imported to the trust store. */
    TRUST_STORE_IMPORT,
    /** A CA certificate was removed from the trust store. */
    TRUST_STORE_DELETE,

    // Security events
    /** Biometric authentication succeeded. */
    BIOMETRIC_SUCCESS,
    /** Biometric authentication failed. */
    BIOMETRIC_FAILURE,
    /** An operation was denied due to policy. */
    POLICY_DENIED,

    // Service events
    /** The xKey service was started. */
    SERVICE_STARTED,
    /** The xKey service was stopped. */
    SERVICE_STOPPED,

    // Certificate operations
    /** A certificate was issued by the local CA. */
    CERTIFICATE_ISSUED,
    /** A certificate was revoked. */
    CERTIFICATE_REVOKED,
    /** A CSR was signed by the local CA. */
    CSR_SIGNED,
    /** A CRL was generated. */
    CRL_GENERATED,
    /** A certificate was exported. */
    CERTIFICATE_EXPORTED,

    // File and media operations
    /** A file was signed. */
    FILE_SIGNED,
    /** A file signature was verified. */
    FILE_VERIFIED,
    /** A file was encrypted. */
    FILE_ENCRYPTED,
    /** A file was decrypted. */
    FILE_DECRYPTED,
    /** Media was auto-signed by MediaSigningService. */
    MEDIA_AUTO_SIGNED,

    // Contact operations
    /** A contact public key was imported. */
    CONTACT_IMPORTED,
    /** A contact was deleted. */
    CONTACT_DELETED,

    // OATH/TOTP operations
    /** An OATH credential was created. */
    OATH_CREDENTIAL_CREATED,
    /** An OATH credential was deleted. */
    OATH_CREDENTIAL_DELETED,
    /** An OATH code was generated. */
    OATH_CODE_GENERATED,
    /** OATH credentials were synced with a paired device. */
    OATH_SYNC_PERFORMED,

    // Co-signing operations
    /** A co-sign request was initiated. */
    COSIGN_INITIATED,
    /** A co-sign response was received. */
    COSIGN_RECEIVED,

    // PIN operations
    /** SO PIN was set for the first time. */
    PIN_SO_SET,
    /** SO PIN was changed. */
    PIN_SO_CHANGED,
    /** User PIN was set. */
    PIN_USER_SET,
    /** User PIN was changed. */
    PIN_USER_CHANGED,
    /** PIN verification succeeded. */
    PIN_VERIFICATION_SUCCESS,
    /** PIN verification failed. */
    PIN_VERIFICATION_FAILED,
    /** PIN lockout was triggered after too many failures. */
    PIN_LOCKOUT_TRIGGERED,
    /** PIN lockout was reset by SO PIN. */
    PIN_LOCKOUT_RESET,

    // PIV operations
    /** A PIV key was generated in a slot. */
    PIV_KEY_GENERATED,
    /** A certificate was imported into a PIV slot. */
    PIV_CERT_IMPORTED,
    /** A PIV signing request was processed. */
    PIV_SIGN_REQUEST,
    /** A PIV key was deleted from a slot. */
    PIV_KEY_DELETED,

    // Desktop backups (local.createBackup / local.restoreBackup)
    /** A paired desktop stored an encrypted backup on the phone. */
    BACKUP_CREATED,
    /** A paired desktop fetched a stored backup from the phone. */
    BACKUP_RESTORED
}

/**
 * Room entity representing a single audit log entry.
 *
 * Audit logs provide a comprehensive record of all security-relevant operations
 * performed by xKey. Each entry captures:
 * - What operation occurred
 * - When it occurred
 * - Which key was involved (if applicable)
 * - Which device was involved (if applicable)
 * - Whether the operation succeeded
 * - Additional context as JSON
 * - Operation duration for performance monitoring
 *
 * Audit logs support compliance requirements, security forensics, and
 * operational troubleshooting.
 *
 * @property id Auto-generated primary key.
 * @property timestamp Unix timestamp in milliseconds when the event occurred.
 * @property operationType The type of operation that was logged.
 * @property keyId The unique identifier of the key involved (null if not key-related).
 * @property keyLabel Human-readable label of the key involved.
 * @property keyType The type of key involved (e.g., "fido2", "signing", "secret").
 * @property deviceId Identifier of the remote device involved (null if local operation).
 * @property deviceName Human-readable name of the remote device.
 * @property success Whether the operation completed successfully.
 * @property errorMessage Error message if the operation failed.
 * @property details Additional context as a JSON string.
 * @property durationMs Duration of the operation in milliseconds.
 */
@Entity(
    tableName = "audit_logs",
    indices = [
        Index(value = ["timestamp"]),
        Index(value = ["operation_type"]),
        Index(value = ["key_id"]),
        Index(value = ["key_type"]),
        Index(value = ["device_id"]),
        Index(value = ["success"])
    ]
)
data class AuditLogEntity(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,

    /** Unix timestamp in milliseconds when the event occurred. */
    @ColumnInfo(name = "timestamp")
    val timestamp: Long = System.currentTimeMillis(),

    /** The type of operation that was logged. */
    @ColumnInfo(name = "operation_type")
    val operationType: AuditOperationType,

    /** The unique identifier of the key involved (null if not key-related). */
    @ColumnInfo(name = "key_id")
    val keyId: String? = null,

    /** Human-readable label of the key involved. */
    @ColumnInfo(name = "key_label")
    val keyLabel: String? = null,

    /** The type of key involved (e.g., "fido2", "signing", "secret"). */
    @ColumnInfo(name = "key_type")
    val keyType: String? = null,

    /** Identifier of the remote device involved (null if local operation). */
    @ColumnInfo(name = "device_id")
    val deviceId: String? = null,

    /** Human-readable name of the remote device. */
    @ColumnInfo(name = "device_name")
    val deviceName: String? = null,

    /** Whether the operation completed successfully. */
    @ColumnInfo(name = "success")
    val success: Boolean = true,

    /** Error message if the operation failed (null if successful). */
    @ColumnInfo(name = "error_message")
    val errorMessage: String? = null,

    /** Additional context as a JSON string (e.g., algorithm, RP ID, etc.). */
    @ColumnInfo(name = "details")
    val details: String? = null,

    /** Duration of the operation in milliseconds (null if not measured). */
    @ColumnInfo(name = "duration_ms")
    val durationMs: Long? = null
)

/**
 * Summary statistics for audit logs.
 *
 * Used for dashboard displays and quick overviews.
 */
data class AuditLogSummary(
    val totalCount: Long,
    val successCount: Long,
    val failureCount: Long,
    val operationCounts: Map<AuditOperationType, Long>,
    val keyTypeCounts: Map<String, Long>,
    val recentActivity: List<AuditLogEntity>
)
