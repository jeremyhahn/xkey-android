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
import androidx.room.PrimaryKey

/**
 * A key's sharing policy state, in one row (#193). Written only by
 * `KeyPolicyStore`, in the same transaction as the key row and its grant
 * rows, so the policy, a denial left by a failed narrowing and an owed
 * grant clear never disagree, a restart included.
 *
 * The row belongs to one key row: [keyInstance] is `keys.id`, and deleting
 * that row deletes this one. A key deleted and recreated under the same
 * [keyId] gets a new instance, so an edit bound to the old one is refused.
 */
@Entity(
    tableName = "key_policies",
    foreignKeys = [
        ForeignKey(
            entity = KeyEntity::class,
            parentColumns = ["id"],
            childColumns = ["key_instance"],
            onDelete = ForeignKey.CASCADE
        )
    ],
    indices = [Index(value = ["key_instance"], unique = true)]
)
data class KeyPolicyEntity(
    @PrimaryKey
    @ColumnInfo(name = "key_id")
    val keyId: String,

    /** `keys.id` of the key row this state belongs to. */
    @ColumnInfo(name = "key_instance")
    val keyInstance: Long,

    /** The stored policy, kept equal to `keys.sharing_policy`. */
    @ColumnInfo(name = "sharing_policy")
    val sharingPolicy: SharingPolicyType,

    /** A narrowing that was refused because its write failed, or null. */
    @ColumnInfo(name = "pending_policy")
    val pendingPolicy: SharingPolicyType? = null,

    /**
     * Enforced over [sharingPolicy] until a policy write lands: PRIVATE
     * denies every peer, SELECTED_PEERS every peer without a grant row.
     */
    @ColumnInfo(name = "denial")
    val denial: SharingPolicyType? = null,

    /** The key's grant rows must be deleted before any grant counts again. */
    @ColumnInfo(name = "clear_grants")
    val clearGrants: Boolean = false
) {
    /** The policy authorization enforces. */
    val enforced: SharingPolicyType
        get() = if (clearGrants) SharingPolicyType.PRIVATE else denial ?: sharingPolicy
}
