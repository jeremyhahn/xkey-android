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

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/**
 * Room entity representing an X.509 certificate managed by the local CA.
 *
 * Stores certificate metadata and PEM-encoded certificate data for the
 * certificate lifecycle management system. Supports querying by profile,
 * revocation status, expiration, and subject.
 *
 * @property id Auto-generated primary key.
 * @property serialNumber Hex-encoded certificate serial number (unique).
 * @property subjectDN The certificate subject distinguished name.
 * @property issuerDN The certificate issuer distinguished name.
 * @property notBefore Certificate validity start time (Unix millis).
 * @property notAfter Certificate validity end time (Unix millis).
 * @property profile Certificate profile name (e.g., "tls-server", "code-signing").
 * @property fingerprint SHA-256 fingerprint of the certificate (hex-encoded).
 * @property certificatePEM PEM-encoded certificate.
 * @property chainPEM PEM-encoded certificate chain (null if not available).
 * @property keyId Associated key ID in the keys table (null if external).
 * @property deviceId Associated device ID (null if local).
 * @property revoked Whether the certificate has been revoked.
 * @property revokedAt Revocation timestamp (Unix millis, null if not revoked).
 * @property revokedReason RFC 5280 CRLReason code (null if not revoked).
 * @property isCA Whether this is a CA certificate.
 * @property createdAt Creation timestamp (Unix millis).
 */
@Entity(
    tableName = "certificates",
    indices = [
        Index(value = ["serial_number"], unique = true),
        Index(value = ["profile"]),
        Index(value = ["key_id"]),
        Index(value = ["revoked"]),
        Index(value = ["not_after"]),
        Index(value = ["is_ca"]),
        Index(value = ["fingerprint"])
    ]
)
data class CertificateEntity(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,

    @ColumnInfo(name = "serial_number")
    val serialNumber: String,

    @ColumnInfo(name = "subject_dn")
    val subjectDN: String,

    @ColumnInfo(name = "issuer_dn")
    val issuerDN: String,

    @ColumnInfo(name = "not_before")
    val notBefore: Long,

    @ColumnInfo(name = "not_after")
    val notAfter: Long,

    @ColumnInfo(name = "profile")
    val profile: String,

    @ColumnInfo(name = "fingerprint")
    val fingerprint: String,

    @ColumnInfo(name = "certificate_pem")
    val certificatePEM: String,

    @ColumnInfo(name = "chain_pem")
    val chainPEM: String? = null,

    @ColumnInfo(name = "key_id")
    val keyId: String? = null,

    @ColumnInfo(name = "device_id")
    val deviceId: String? = null,

    @ColumnInfo(name = "revoked")
    val revoked: Boolean = false,

    @ColumnInfo(name = "revoked_at")
    val revokedAt: Long? = null,

    @ColumnInfo(name = "revoked_reason")
    val revokedReason: Int? = null,

    @ColumnInfo(name = "is_ca")
    val isCA: Boolean = false,

    @ColumnInfo(name = "created_at")
    val createdAt: Long = System.currentTimeMillis()
)
