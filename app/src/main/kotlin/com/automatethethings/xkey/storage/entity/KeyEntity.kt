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
 * Defines how a key can be shared with peer devices.
 *
 * This enum controls the overall sharing behavior for a key. When set to
 * [SELECTED_PEERS], the [KeySharingPolicy] table determines which specific
 * peers have access.
 */
enum class SharingPolicyType {
    /**
     * Key is never shared with any peer device.
     * This is the most secure default for sensitive keys.
     */
    PRIVATE,

    /**
     * Key is shared with all trusted/paired peer devices.
     * Useful for keys that should be universally accessible across devices.
     */
    ALL_PEERS,

    /**
     * Key is only shared with specific peers listed in the key_sharing_policies table.
     * Provides fine-grained control over which devices can use the key.
     */
    SELECTED_PEERS
}

/**
 * Room entity for unified key storage.
 *
 * Stores metadata for ALL key types managed by xKey:
 * - FIDO2 credentials (created by CredentialProvider or BLE/USB)
 * - TLS client certificates
 * - General signing/encryption keys
 * - Secret keys (AES-GCM symmetric encryption)
 * - HMAC keys
 * - CA keys (certificate authority)
 * - Attestation keys
 *
 * Actual cryptographic key material remains in Android Keystore.
 * This table stores metadata, usage tracking, and sharing policies.
 *
 * Keys can originate from:
 * - "local": Created locally via CredentialProvider
 * - "remote_ble": Created remotely via BLE protocol
 * - "remote_usb": Created remotely via USB protocol
 * - "xkmsd": Reference to a key on the laptop's xkmsd (phone is client)
 *
 * @property id Auto-generated primary key.
 * @property keyId Unique key identifier (matches Android Keystore alias suffix).
 * @property keyType Key type: "fido2", "tls", "signing", "encryption", "secret", "hmac", "ca", "attestation".
 * @property algorithm Algorithm identifier (e.g., "ES256", "AES256", "HMAC-SHA256").
 * @property label Human-readable label for the key.
 * @property publicKeyDer DER-encoded public key bytes (null for symmetric/HMAC keys).
 * @property publicKeyCose COSE-encoded public key bytes (for FIDO2 keys).
 * @property keySizeBits Key size in bits.
 * @property strongBoxBacked Whether the key is backed by StrongBox hardware.
 * @property biometricRequired Whether biometric authentication is required for operations.
 * @property authDurationSeconds Seconds the key remains unlocked after authentication.
 * @property exportable Whether the public key can be exported.
 * @property shareable Whether this key can be used by the paired laptop (legacy, use sharingPolicy).
 * @property sharingPolicy Fine-grained sharing policy: PRIVATE, ALL_PEERS, or SELECTED_PEERS.
 * @property source Origin: "local", "remote_ble", "remote_usb", "xkmsd".
 * @property remoteBackend For xkmsd keys: backend holding the key ("tpm2", "pkcs11", "software").
 * @property useCount Number of times the key has been used.
 * @property createdAt Timestamp when the key was created.
 * @property lastUsedAt Timestamp when the key was last used.
 * @property rpId Relying party identifier for FIDO2 keys (e.g., "example.com").
 * @property rpName Relying party display name.
 * @property userId Base64-encoded user handle for FIDO2 keys.
 * @property userName User's account name for FIDO2 keys.
 * @property userDisplayName User's display name for FIDO2 keys.
 * @property isDiscoverable Whether this is a discoverable (resident) FIDO2 credential.
 * @property signCount FIDO2 signature counter.
 * @property isSystemKey Whether this is a system/framework key (e.g., AndroidX Security master key).
 */
@Entity(
    tableName = "keys",
    indices = [
        Index(value = ["key_id"], unique = true),
        Index(value = ["key_type"]),
        Index(value = ["algorithm"]),
        Index(value = ["source"]),
        Index(value = ["rp_id"])
    ]
)
data class KeyEntity(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,

    /** Unique key identifier (matches Android Keystore alias suffix). */
    @ColumnInfo(name = "key_id")
    val keyId: String,

    /** Key type: "fido2", "tls", "signing", "encryption", "secret", "hmac", "ca", "attestation". */
    @ColumnInfo(name = "key_type")
    val keyType: String,

    /** Algorithm: "ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "AES128", "AES256", "HMAC-SHA256", "HMAC-SHA512". */
    @ColumnInfo(name = "algorithm")
    val algorithm: String,

    /** Human-readable label for the key. */
    @ColumnInfo(name = "label")
    val label: String,

    /** DER-encoded public key bytes (null for symmetric/HMAC keys). */
    @ColumnInfo(name = "public_key_der", typeAffinity = ColumnInfo.BLOB)
    val publicKeyDer: ByteArray? = null,

    /** COSE-encoded public key bytes (for FIDO2 keys). */
    @ColumnInfo(name = "public_key_cose", typeAffinity = ColumnInfo.BLOB)
    val publicKeyCose: ByteArray? = null,

    /** Key size in bits. */
    @ColumnInfo(name = "key_size_bits")
    val keySizeBits: Int,

    /** Whether the key is backed by StrongBox hardware. */
    @ColumnInfo(name = "strongbox_backed")
    val strongBoxBacked: Boolean = false,

    /** Whether biometric authentication is required for operations. */
    @ColumnInfo(name = "biometric_required")
    val biometricRequired: Boolean = true,

    /** Seconds the key remains unlocked after authentication. */
    @ColumnInfo(name = "auth_duration_seconds")
    val authDurationSeconds: Int = 5,

    /** Whether the public key can be exported. */
    @ColumnInfo(name = "exportable")
    val exportable: Boolean = false,

    /**
     * Whether this key can be used by the paired laptop.
     *
     * @deprecated Use [sharingPolicy] for fine-grained control. This field is
     * retained for backward compatibility during migration. When sharingPolicy
     * is PRIVATE, shareable should be false. When sharingPolicy is ALL_PEERS
     * or SELECTED_PEERS, shareable should be true.
     */
    @ColumnInfo(name = "shareable")
    val shareable: Boolean = false,

    /**
     * Fine-grained sharing policy for this key.
     *
     * Controls how this key can be shared with peer devices:
     * - PRIVATE: Never shared (default)
     * - ALL_PEERS: Shared with all trusted peers
     * - SELECTED_PEERS: Only shared with peers in key_sharing_policies table
     *
     * When set to SELECTED_PEERS, query [KeySharingPolicyDao] to determine
     * which peers have access.
     */
    @ColumnInfo(name = "sharing_policy")
    val sharingPolicy: SharingPolicyType = SharingPolicyType.PRIVATE,

    /** Origin: "local", "remote_ble", "remote_usb", "xkmsd". */
    @ColumnInfo(name = "source")
    val source: String,

    /** For xkmsd keys: which backend holds the key ("tpm2", "pkcs11", "software"). */
    @ColumnInfo(name = "remote_backend")
    val remoteBackend: String? = null,

    /** Number of times the key has been used. */
    @ColumnInfo(name = "use_count")
    val useCount: Long = 0,

    /** Timestamp when the key was created. */
    @ColumnInfo(name = "created_at")
    val createdAt: Long = System.currentTimeMillis(),

    /** Timestamp when the key was last used. */
    @ColumnInfo(name = "last_used_at")
    val lastUsedAt: Long = 0,

    // FIDO2-specific metadata (null for non-FIDO2 keys)

    /** Relying party identifier (e.g., "example.com"). */
    @ColumnInfo(name = "rp_id")
    val rpId: String? = null,

    /** Relying party display name. */
    @ColumnInfo(name = "rp_name")
    val rpName: String? = null,

    /** Base64-encoded user handle. */
    @ColumnInfo(name = "user_id")
    val userId: String? = null,

    /** User's account name. */
    @ColumnInfo(name = "user_name")
    val userName: String? = null,

    /** User's display name. */
    @ColumnInfo(name = "user_display_name")
    val userDisplayName: String? = null,

    /** Whether this is a discoverable (resident) FIDO2 credential. */
    @ColumnInfo(name = "is_discoverable")
    val isDiscoverable: Boolean = false,

    /** FIDO2 signature counter. */
    @ColumnInfo(name = "sign_count")
    val signCount: Long = 0,

    /** Whether this is a system/framework key that must not be deleted. */
    @ColumnInfo(name = "is_system_key")
    val isSystemKey: Boolean = false
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as KeyEntity

        if (id != other.id) return false
        if (keyId != other.keyId) return false
        if (keyType != other.keyType) return false
        if (algorithm != other.algorithm) return false
        if (label != other.label) return false
        if (publicKeyDer != null) {
            if (other.publicKeyDer == null) return false
            if (!publicKeyDer.contentEquals(other.publicKeyDer)) return false
        } else if (other.publicKeyDer != null) return false
        if (publicKeyCose != null) {
            if (other.publicKeyCose == null) return false
            if (!publicKeyCose.contentEquals(other.publicKeyCose)) return false
        } else if (other.publicKeyCose != null) return false
        if (keySizeBits != other.keySizeBits) return false
        if (strongBoxBacked != other.strongBoxBacked) return false
        if (biometricRequired != other.biometricRequired) return false
        if (authDurationSeconds != other.authDurationSeconds) return false
        if (exportable != other.exportable) return false
        if (shareable != other.shareable) return false
        if (sharingPolicy != other.sharingPolicy) return false
        if (source != other.source) return false
        if (remoteBackend != other.remoteBackend) return false
        if (useCount != other.useCount) return false
        if (createdAt != other.createdAt) return false
        if (lastUsedAt != other.lastUsedAt) return false
        if (rpId != other.rpId) return false
        if (rpName != other.rpName) return false
        if (userId != other.userId) return false
        if (userName != other.userName) return false
        if (userDisplayName != other.userDisplayName) return false
        if (isDiscoverable != other.isDiscoverable) return false
        if (signCount != other.signCount) return false
        if (isSystemKey != other.isSystemKey) return false

        return true
    }

    override fun hashCode(): Int {
        var result = id.hashCode()
        result = 31 * result + keyId.hashCode()
        result = 31 * result + keyType.hashCode()
        result = 31 * result + algorithm.hashCode()
        result = 31 * result + label.hashCode()
        result = 31 * result + (publicKeyDer?.contentHashCode() ?: 0)
        result = 31 * result + (publicKeyCose?.contentHashCode() ?: 0)
        result = 31 * result + keySizeBits
        result = 31 * result + strongBoxBacked.hashCode()
        result = 31 * result + biometricRequired.hashCode()
        result = 31 * result + authDurationSeconds
        result = 31 * result + exportable.hashCode()
        result = 31 * result + shareable.hashCode()
        result = 31 * result + sharingPolicy.hashCode()
        result = 31 * result + source.hashCode()
        result = 31 * result + (remoteBackend?.hashCode() ?: 0)
        result = 31 * result + useCount.hashCode()
        result = 31 * result + createdAt.hashCode()
        result = 31 * result + lastUsedAt.hashCode()
        result = 31 * result + (rpId?.hashCode() ?: 0)
        result = 31 * result + (rpName?.hashCode() ?: 0)
        result = 31 * result + (userId?.hashCode() ?: 0)
        result = 31 * result + (userName?.hashCode() ?: 0)
        result = 31 * result + (userDisplayName?.hashCode() ?: 0)
        result = 31 * result + isDiscoverable.hashCode()
        result = 31 * result + signCount.hashCode()
        result = 31 * result + isSystemKey.hashCode()
        return result
    }
}
