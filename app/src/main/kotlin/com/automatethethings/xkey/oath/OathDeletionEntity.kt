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
import androidx.room.PrimaryKey

/**
 * A record that an OATH credential was deleted on the phone.
 *
 * The sync wire item carries no timestamp, so without this record the next
 * sync with a paired device that still holds the credential would add it
 * back. [OathRepository.upsertStructured] skips a synced item whose id has a
 * record. No secret or label is kept: only the id and when it was deleted.
 *
 * @property oathId The deleted credential's [OathCredentialEntity.oathId].
 * @property deletedAt When it was deleted on the phone (Unix millis).
 */
@Entity(tableName = "oath_deletions")
data class OathDeletionEntity(
    @PrimaryKey
    @ColumnInfo(name = "oath_id")
    val oathId: String,

    @ColumnInfo(name = "deleted_at")
    val deletedAt: Long
)
