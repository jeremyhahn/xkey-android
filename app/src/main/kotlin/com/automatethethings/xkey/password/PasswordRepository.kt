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

import com.automatethethings.xkey.crypto.KeystoreAeadCipher
import kotlinx.coroutines.flow.Flow

/**
 * Decrypted view of a password entry. The plaintext [password] exists only in
 * memory; the persisted form is encrypted (see [PasswordEntity]).
 */
data class PasswordRecord(
    val passwordId: String,
    val name: String,
    val title: String? = null,
    val username: String? = null,
    val password: String,
    val url: String? = null,
    val notes: String? = null,
    val folderPath: String? = null,
    val source: String = "local",
    val createdAt: Long = 0,
    val updatedAt: Long = 0
)

/**
 * Repository for the encrypted password store. Encrypts each password value with
 * the Android Keystore via [KeystoreAeadCipher] before persisting through
 * [PasswordDao], and decrypts on read.
 */
class PasswordRepository(
    private val dao: PasswordDao,
    private val cipher: KeystoreAeadCipher = KeystoreAeadCipher(KEY_ALIAS)
) {
    companion object {
        private const val KEY_ALIAS = "xkey_password_encryption_key"
    }

    /** List all stored passwords (decrypted). */
    suspend fun list(): List<PasswordRecord> = dao.getAll().map { it.toRecord() }

    /** List stored passwords from a given source ("local" or "remote"). */
    suspend fun listBySource(source: String): List<PasswordRecord> =
        dao.getBySource(source).map { it.toRecord() }

    /** Get a single password by ID (decrypted), or null. */
    suspend fun get(passwordId: String): PasswordRecord? = dao.getByPasswordId(passwordId)?.toRecord()

    /**
     * Insert or update a password, encrypting the value at rest.
     *
     * Preserves the original [PasswordEntity.createdAt] on update. Returns the
     * stable password ID.
     */
    suspend fun upsert(record: PasswordRecord): String {
        val existing = dao.getByPasswordId(record.passwordId)
        val now = System.currentTimeMillis()
        dao.insert(
            PasswordEntity(
                id = existing?.id ?: 0,
                passwordId = record.passwordId,
                name = record.name,
                title = record.title,
                username = record.username,
                passwordEncrypted = cipher.encrypt(record.password.toByteArray(Charsets.UTF_8)),
                url = record.url,
                notes = record.notes,
                folderPath = record.folderPath,
                source = record.source,
                createdAt = existing?.createdAt ?: if (record.createdAt > 0) record.createdAt else now,
                updatedAt = if (record.updatedAt > 0) record.updatedAt else now
            )
        )
        return record.passwordId
    }

    /** Delete a password by ID. */
    suspend fun delete(passwordId: String) = dao.deleteByPasswordId(passwordId)

    /** Number of stored passwords. */
    suspend fun count(): Int = dao.count()

    /** Observe stored password entities (encrypted) for reactive UI. */
    fun observeAll(): Flow<List<PasswordEntity>> = dao.observeAll()

    private fun PasswordEntity.toRecord(): PasswordRecord = PasswordRecord(
        passwordId = passwordId,
        name = name,
        title = title,
        username = username,
        password = String(cipher.decrypt(passwordEncrypted), Charsets.UTF_8),
        url = url,
        notes = notes,
        folderPath = folderPath,
        source = source,
        createdAt = createdAt,
        updatedAt = updatedAt
    )
}
