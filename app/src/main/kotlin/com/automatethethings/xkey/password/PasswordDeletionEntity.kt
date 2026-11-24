// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under AGPL-3.0 (see LICENSE) or a commercial license.
// Contact licensing@automatethethings.com for commercial licensing options.

package com.automatethethings.xkey.password

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * The record that the password entry [passwordId] was deleted on this phone
 * at [deletedAt] (epoch milliseconds).
 *
 * Password sync reads it so that a peer which still holds the entry does not
 * add it back: a synced copy of a deleted id is added again only if it was
 * changed after the delete. Records older than
 * [PasswordRepository.DELETION_RETENTION_MS] are dropped.
 */
@Entity(tableName = "password_deletions")
data class PasswordDeletionEntity(
    @PrimaryKey
    @ColumnInfo(name = "password_id")
    val passwordId: String,

    @ColumnInfo(name = "deleted_at")
    val deletedAt: Long
)
