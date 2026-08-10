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
package com.automatethethings.xkey.password

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/**
 * Room entity for a stored password entry.
 *
 * The password value is encrypted at rest with the Android Keystore (see
 * [com.automatethethings.xkey.crypto.KeystoreAeadCipher]); only [passwordEncrypted]
 * is persisted, never the plaintext. Field names mirror the go-xkms pairing
 * `SyncPassword` wire type so credentials sync cleanly with the desktop.
 *
 * @property id Auto-generated primary key.
 * @property passwordId Stable unique identifier (maps to SyncPassword.id).
 * @property name Display name / label (maps to SyncPassword.name).
 * @property title Optional title.
 * @property username Account username or email.
 * @property passwordEncrypted Password encrypted with the Android Keystore.
 * @property url Associated site/service URL.
 * @property notes Free-form notes.
 * @property folderPath Optional folder/grouping path.
 * @property source Origin: "local" or "remote".
 * @property createdAt Creation timestamp (Unix millis).
 * @property updatedAt Last-modified timestamp (Unix millis).
 */
@Entity(
    tableName = "passwords",
    indices = [
        Index(value = ["password_id"], unique = true),
        Index(value = ["name"]),
        Index(value = ["source"])
    ]
)
data class PasswordEntity(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,

    @ColumnInfo(name = "password_id")
    val passwordId: String,

    @ColumnInfo(name = "name")
    val name: String,

    @ColumnInfo(name = "title")
    val title: String? = null,

    @ColumnInfo(name = "username")
    val username: String? = null,

    @ColumnInfo(name = "password_encrypted")
    val passwordEncrypted: ByteArray,

    @ColumnInfo(name = "url")
    val url: String? = null,

    @ColumnInfo(name = "notes")
    val notes: String? = null,

    @ColumnInfo(name = "folder_path")
    val folderPath: String? = null,

    @ColumnInfo(name = "source")
    val source: String = "local",

    @ColumnInfo(name = "created_at")
    val createdAt: Long,

    @ColumnInfo(name = "updated_at")
    val updatedAt: Long
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PasswordEntity) return false
        return id == other.id &&
            passwordId == other.passwordId &&
            name == other.name &&
            title == other.title &&
            username == other.username &&
            passwordEncrypted.contentEquals(other.passwordEncrypted) &&
            url == other.url &&
            notes == other.notes &&
            folderPath == other.folderPath &&
            source == other.source &&
            createdAt == other.createdAt &&
            updatedAt == other.updatedAt
    }

    override fun hashCode(): Int {
        var result = id.hashCode()
        result = 31 * result + passwordId.hashCode()
        result = 31 * result + name.hashCode()
        result = 31 * result + (title?.hashCode() ?: 0)
        result = 31 * result + (username?.hashCode() ?: 0)
        result = 31 * result + passwordEncrypted.contentHashCode()
        result = 31 * result + (url?.hashCode() ?: 0)
        result = 31 * result + (notes?.hashCode() ?: 0)
        result = 31 * result + (folderPath?.hashCode() ?: 0)
        result = 31 * result + source.hashCode()
        result = 31 * result + createdAt.hashCode()
        result = 31 * result + updatedAt.hashCode()
        return result
    }
}
