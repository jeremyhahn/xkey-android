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
import androidx.room.PrimaryKey

/**
 * A key whose rows are deleted but whose material delete has not yet
 * succeeded (#193). Written by `KeyPolicyStore` in the transaction that
 * deletes the key row, and dropped only once the material delete returns,
 * so material is never left with no record: a failed or interrupted delete
 * is replayed at start-up and before every key sync.
 *
 * [keyInstance] is the deleted `keys.id` (0 when the material had no row).
 * It outlives that row, so it has no foreign key. A key generated again
 * under [keyId] before the replay keeps its material.
 *
 * [generation] names the exact material the delete owes, read under the
 * key's material lock before the row delete (#193 r12): the replay deletes
 * that generation only, never whatever is stored under the id by then.
 */
@Entity(tableName = "key_deletions")
data class KeyDeletionEntity(
    @PrimaryKey
    @ColumnInfo(name = "key_id")
    val keyId: String,

    @ColumnInfo(name = "key_instance")
    val keyInstance: Long,

    /** The deleted row's `source`, which names where its material lives. */
    @ColumnInfo(name = "source")
    val source: String?,

    /**
     * The material generation the delete owes (the app's encoding is
     * `keyMaterialGeneration`'s); null only for a tombstone written before
     * it was recorded, which owes no material it can name.
     */
    @ColumnInfo(name = "generation")
    val generation: String? = null
)
