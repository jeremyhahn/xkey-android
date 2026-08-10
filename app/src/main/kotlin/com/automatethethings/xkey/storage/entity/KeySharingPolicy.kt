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
import androidx.room.ForeignKey
import androidx.room.Index

/**
 * Room entity for per-key sharing policies with specific peers.
 *
 * This entity enables fine-grained control over which keys can be used by
 * which paired devices. Each policy entry represents permission for a specific
 * peer (identified by their public key) to use a specific key.
 *
 * The sharing system works as follows:
 * 1. A key's [SharingPolicyType] in [KeyEntity] determines the overall sharing mode:
 *    - PRIVATE: Key is never shared, no policies checked
 *    - ALL_PEERS: Key is shared with all trusted peers, no policies checked
 *    - SELECTED_PEERS: Only peers with explicit [KeySharingPolicy] entries can use the key
 *
 * 2. When [SharingPolicyType.SELECTED_PEERS] is set, this table is queried to
 *    determine if the requesting peer has permission.
 *
 * The foreign key relationship ensures policies are automatically deleted
 * when the associated key is removed (CASCADE delete).
 *
 * Usage:
 * ```kotlin
 * // Allow peer to use a specific key
 * val policy = KeySharingPolicy(
 *     keyId = "credential-abc123",
 *     peerPublicKeyHex = "04a1b2c3...",  // Peer's ECDH public key
 *     allowed = true
 * )
 * keySharingPolicyDao.setPolicy(policy)
 *
 * // Check if peer can use key
 * val canUse = keySharingPolicyDao.isKeySharedWithPeer(keyId, peerPublicKeyHex)
 * ```
 *
 * @property keyId The unique key identifier from the [KeyEntity] table.
 * @property peerPublicKeyHex Hex-encoded public key of the peer device (ECDH P-256).
 * @property allowed Whether the peer is allowed to use this key. Setting to false
 *                   explicitly denies access (useful for revocation without deletion).
 * @property createdAt Timestamp when this policy was created.
 */
@Entity(
    tableName = "key_sharing_policies",
    primaryKeys = ["key_id", "peer_public_key_hex"],
    foreignKeys = [
        ForeignKey(
            entity = KeyEntity::class,
            parentColumns = ["key_id"],
            childColumns = ["key_id"],
            onDelete = ForeignKey.CASCADE
        )
    ],
    indices = [
        Index("key_id"),
        Index("peer_public_key_hex")
    ]
)
data class KeySharingPolicy(
    /** The unique key identifier from the keys table. */
    @ColumnInfo(name = "key_id")
    val keyId: String,

    /** Hex-encoded public key of the peer device (ECDH P-256, uncompressed). */
    @ColumnInfo(name = "peer_public_key_hex")
    val peerPublicKeyHex: String,

    /** Whether the peer is allowed to use this key. */
    @ColumnInfo(name = "allowed")
    val allowed: Boolean = true,

    /** Timestamp when this policy was created. */
    @ColumnInfo(name = "created_at")
    val createdAt: Long = System.currentTimeMillis()
)
