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

@Entity(tableName = "contacts", indices = [
    Index(value = ["public_key_fingerprint"], unique = true),
    Index(value = ["name"]),
    Index(value = ["algorithm"])
])
data class ContactEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val name: String,
    @ColumnInfo(name = "public_key_der", typeAffinity = ColumnInfo.BLOB) val publicKeyDer: ByteArray,
    @ColumnInfo(name = "public_key_fingerprint") val publicKeyFingerprint: String,
    val algorithm: String,
    @ColumnInfo(name = "imported_at") val importedAt: Long = System.currentTimeMillis(),
    val source: String,
    val notes: String? = null
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ContactEntity) return false
        return id == other.id &&
                name == other.name &&
                publicKeyDer.contentEquals(other.publicKeyDer) &&
                publicKeyFingerprint == other.publicKeyFingerprint &&
                algorithm == other.algorithm &&
                importedAt == other.importedAt &&
                source == other.source &&
                notes == other.notes
    }

    override fun hashCode(): Int {
        var result = id.hashCode()
        result = 31 * result + name.hashCode()
        result = 31 * result + publicKeyDer.contentHashCode()
        result = 31 * result + publicKeyFingerprint.hashCode()
        result = 31 * result + algorithm.hashCode()
        result = 31 * result + importedAt.hashCode()
        result = 31 * result + source.hashCode()
        result = 31 * result + (notes?.hashCode() ?: 0)
        return result
    }
}
