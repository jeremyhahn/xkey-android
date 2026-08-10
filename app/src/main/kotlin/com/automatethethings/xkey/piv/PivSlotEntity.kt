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

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/**
 * Room entity representing a PIV smart card key slot and its metadata.
 *
 * Stores the metadata for keys generated in PIV slots, including the algorithm,
 * DER-encoded public key, DER-encoded certificate, and usage statistics. The
 * actual private keys are stored securely in Android Keystore using the alias
 * convention `xkey_piv_{slotHex}`.
 *
 * This entity maps to the `piv_slots` table with indices on [slotId] (unique)
 * and [hasKey] for efficient querying of populated slots.
 *
 * @property id Auto-generated primary key.
 * @property slotId The PIV slot hex identifier (e.g., "9A", "9C").
 * @property algorithm The algorithm used for key generation (e.g., "ES256", "RS2048").
 * @property publicKeyDer DER-encoded public key bytes (SubjectPublicKeyInfo format).
 * @property certificateDer DER-encoded X.509 certificate bytes.
 * @property hasKey Whether this slot contains a generated key.
 * @property createdAt Unix timestamp in milliseconds when the key was generated.
 * @property lastUsedAt Unix timestamp in milliseconds when the key was last used.
 * @property useCount Number of times the key has been used for cryptographic operations.
 */
@Entity(
    tableName = "piv_slots",
    indices = [
        Index(value = ["slot_id"], unique = true),
        Index(value = ["has_key"])
    ]
)
data class PivSlotEntity(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,

    /** The PIV slot hex identifier (e.g., "9A", "9C"). */
    @ColumnInfo(name = "slot_id")
    val slotId: String,

    /** The algorithm used for key generation (e.g., "ES256", "RS2048"), or null if no key. */
    @ColumnInfo(name = "algorithm")
    val algorithm: String? = null,

    /** DER-encoded public key bytes (SubjectPublicKeyInfo format), or null if no key. */
    @ColumnInfo(name = "public_key_der")
    val publicKeyDer: ByteArray? = null,

    /** DER-encoded X.509 certificate bytes, or null if no certificate imported. */
    @ColumnInfo(name = "certificate_der")
    val certificateDer: ByteArray? = null,

    /** Whether this slot contains a generated key. */
    @ColumnInfo(name = "has_key")
    val hasKey: Boolean = false,

    /** Unix timestamp in milliseconds when the key was generated. */
    @ColumnInfo(name = "created_at")
    val createdAt: Long = System.currentTimeMillis(),

    /** Unix timestamp in milliseconds when the key was last used, or null if never used. */
    @ColumnInfo(name = "last_used_at")
    val lastUsedAt: Long? = null,

    /** Number of times the key has been used for cryptographic operations. */
    @ColumnInfo(name = "use_count")
    val useCount: Int = 0
) {
    /**
     * Custom equals implementation that correctly compares [ByteArray] fields
     * by content rather than by reference.
     */
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PivSlotEntity) return false

        return id == other.id &&
            slotId == other.slotId &&
            algorithm == other.algorithm &&
            byteArrayContentEquals(publicKeyDer, other.publicKeyDer) &&
            byteArrayContentEquals(certificateDer, other.certificateDer) &&
            hasKey == other.hasKey &&
            createdAt == other.createdAt &&
            lastUsedAt == other.lastUsedAt &&
            useCount == other.useCount
    }

    /**
     * Custom hashCode implementation that correctly hashes [ByteArray] fields
     * by content rather than by reference.
     */
    override fun hashCode(): Int {
        var result = id.hashCode()
        result = 31 * result + slotId.hashCode()
        result = 31 * result + (algorithm?.hashCode() ?: 0)
        result = 31 * result + (publicKeyDer?.let { it.contentHashCode() } ?: 0)
        result = 31 * result + (certificateDer?.let { it.contentHashCode() } ?: 0)
        result = 31 * result + hasKey.hashCode()
        result = 31 * result + createdAt.hashCode()
        result = 31 * result + (lastUsedAt?.hashCode() ?: 0)
        result = 31 * result + useCount
        return result
    }
}

/**
 * Check if two nullable [ByteArray]s have equal contents.
 */
private fun byteArrayContentEquals(a: ByteArray?, b: ByteArray?): Boolean {
    if (a === b) return true
    if (a == null || b == null) return false
    return a.contentEquals(b)
}
