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

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/**
 * Room entity representing an OATH credential (TOTP or HOTP).
 *
 * Stores the encrypted secret and metadata required for OTP code generation.
 * Supports both locally-created credentials and those synchronized from remote
 * devices. The [secretEncrypted] field holds the shared secret encrypted with
 * the Android Keystore, never stored in plaintext.
 *
 * @property id Auto-generated primary key.
 * @property oathId Unique identifier for the credential (URI-style, e.g. "issuer:account").
 * @property oathType OTP type: "TOTP" (time-based) or "HOTP" (counter-based).
 * @property algorithm HMAC algorithm: "SHA1", "SHA256", or "SHA512".
 * @property digits Number of digits in the generated code (typically 6 or 8).
 * @property periodSeconds Time step in seconds for TOTP (default 30, ignored for HOTP).
 * @property counter Current counter value for HOTP (ignored for TOTP).
 * @property issuer Credential issuer name (e.g. "GitHub", "Google").
 * @property accountName User account name or email address.
 * @property secretEncrypted OATH shared secret encrypted with Android Keystore.
 * @property source Origin of the credential: "local" or "remote".
 * @property remoteDeviceId Device ID if the credential was synced from a remote device.
 * @property createdAt Creation timestamp (Unix millis).
 * @property lastUsedAt Timestamp of last OTP generation (Unix millis, null if never used).
 * @property useCount Number of times an OTP has been generated from this credential.
 */
@Entity(
    tableName = "oath_credentials",
    indices = [
        Index(value = ["oath_id"], unique = true),
        Index(value = ["issuer"]),
        Index(value = ["source"])
    ]
)
data class OathCredentialEntity(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,

    @ColumnInfo(name = "oath_id")
    val oathId: String,

    @ColumnInfo(name = "oath_type")
    val oathType: String,

    @ColumnInfo(name = "algorithm")
    val algorithm: String,

    @ColumnInfo(name = "digits")
    val digits: Int = 6,

    @ColumnInfo(name = "period_seconds")
    val periodSeconds: Int = 30,

    @ColumnInfo(name = "counter")
    val counter: Long = 0,

    @ColumnInfo(name = "issuer")
    val issuer: String?,

    @ColumnInfo(name = "account_name")
    val accountName: String,

    @ColumnInfo(name = "secret_encrypted")
    val secretEncrypted: ByteArray,

    @ColumnInfo(name = "source")
    val source: String = "local",

    @ColumnInfo(name = "remote_device_id")
    val remoteDeviceId: String? = null,

    @ColumnInfo(name = "created_at")
    val createdAt: Long,

    @ColumnInfo(name = "last_used_at")
    val lastUsedAt: Long? = null,

    @ColumnInfo(name = "use_count")
    val useCount: Int = 0
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is OathCredentialEntity) return false
        return id == other.id &&
            oathId == other.oathId &&
            oathType == other.oathType &&
            algorithm == other.algorithm &&
            digits == other.digits &&
            periodSeconds == other.periodSeconds &&
            counter == other.counter &&
            issuer == other.issuer &&
            accountName == other.accountName &&
            secretEncrypted.contentEquals(other.secretEncrypted) &&
            source == other.source &&
            remoteDeviceId == other.remoteDeviceId &&
            createdAt == other.createdAt &&
            lastUsedAt == other.lastUsedAt &&
            useCount == other.useCount
    }

    override fun hashCode(): Int {
        var result = id.hashCode()
        result = 31 * result + oathId.hashCode()
        result = 31 * result + oathType.hashCode()
        result = 31 * result + algorithm.hashCode()
        result = 31 * result + digits
        result = 31 * result + periodSeconds
        result = 31 * result + counter.hashCode()
        result = 31 * result + (issuer?.hashCode() ?: 0)
        result = 31 * result + accountName.hashCode()
        result = 31 * result + secretEncrypted.contentHashCode()
        result = 31 * result + source.hashCode()
        result = 31 * result + (remoteDeviceId?.hashCode() ?: 0)
        result = 31 * result + createdAt.hashCode()
        result = 31 * result + (lastUsedAt?.hashCode() ?: 0)
        result = 31 * result + useCount
        return result
    }
}
