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
package com.automatethethings.xkey.storage.entity

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/**
 * Room entity representing credential metadata for passkeys.
 *
 * This entity stores metadata about passkey credentials, while the actual
 * cryptographic keys are stored securely in Android Keystore. The separation
 * allows for efficient querying of credentials by relying party while
 * maintaining key security.
 *
 * @property id Auto-generated primary key.
 * @property credentialId Base64-encoded credential ID (matches Keystore alias).
 * @property rpId Relying party identifier (e.g., "example.com").
 * @property rpName Human-readable relying party name.
 * @property userId Base64-encoded user handle from the relying party.
 * @property userName User's account name (e.g., email).
 * @property userDisplayName User's display name for UI.
 * @property publicKeyCose COSE-encoded public key bytes for attestation.
 * @property signCount Signature counter for clone detection.
 * @property createdAt Timestamp when the credential was created.
 * @property lastUsedAt Timestamp when the credential was last used.
 * @property isDiscoverable Whether this is a discoverable (resident) credential.
 */
@Entity(
    tableName = "credential_metadata",
    indices = [
        Index(value = ["credential_id"], unique = true),
        Index(value = ["rp_id"]),
        Index(value = ["user_id", "rp_id"])
    ]
)
data class CredentialMetadataEntity(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,

    @ColumnInfo(name = "credential_id")
    val credentialId: String,

    @ColumnInfo(name = "rp_id")
    val rpId: String,

    @ColumnInfo(name = "rp_name")
    val rpName: String,

    @ColumnInfo(name = "user_id")
    val userId: String,

    @ColumnInfo(name = "user_name")
    val userName: String,

    @ColumnInfo(name = "user_display_name")
    val userDisplayName: String,

    @ColumnInfo(name = "public_key_cose", typeAffinity = ColumnInfo.BLOB)
    val publicKeyCose: ByteArray,

    @ColumnInfo(name = "sign_count")
    val signCount: Long = 0,

    @ColumnInfo(name = "created_at")
    val createdAt: Long = System.currentTimeMillis(),

    @ColumnInfo(name = "last_used_at")
    val lastUsedAt: Long = System.currentTimeMillis(),

    @ColumnInfo(name = "is_discoverable")
    val isDiscoverable: Boolean = true
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as CredentialMetadataEntity

        if (id != other.id) return false
        if (credentialId != other.credentialId) return false
        if (rpId != other.rpId) return false
        if (rpName != other.rpName) return false
        if (userId != other.userId) return false
        if (userName != other.userName) return false
        if (userDisplayName != other.userDisplayName) return false
        if (!publicKeyCose.contentEquals(other.publicKeyCose)) return false
        if (signCount != other.signCount) return false
        if (createdAt != other.createdAt) return false
        if (lastUsedAt != other.lastUsedAt) return false
        if (isDiscoverable != other.isDiscoverable) return false

        return true
    }

    override fun hashCode(): Int {
        var result = id.hashCode()
        result = 31 * result + credentialId.hashCode()
        result = 31 * result + rpId.hashCode()
        result = 31 * result + rpName.hashCode()
        result = 31 * result + userId.hashCode()
        result = 31 * result + userName.hashCode()
        result = 31 * result + userDisplayName.hashCode()
        result = 31 * result + publicKeyCose.contentHashCode()
        result = 31 * result + signCount.hashCode()
        result = 31 * result + createdAt.hashCode()
        result = 31 * result + lastUsedAt.hashCode()
        result = 31 * result + isDiscoverable.hashCode()
        return result
    }
}
