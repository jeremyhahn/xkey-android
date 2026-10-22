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
 *
 * [expiresAt] is an RFC 3339 instant in UTC or null, [shared] marks a shared
 * rather than a personal entry, and [tenantId] names the go-xkms tenant the
 * entry belongs to ([PasswordEntity.DEFAULT_TENANT] by default).
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
    val updatedAt: Long = 0,
    val expiresAt: String? = null,
    val shared: Boolean = false,
    val tenantId: String = PasswordEntity.DEFAULT_TENANT
)

/**
 * The fields a [PasswordRepository.updateFields] call sets, as a `*string`
 * update on the wire: a null property keeps the stored value, and an empty
 * [title], [username], [url], [notes], [folderPath] or [expiresAt] clears it.
 * A non-null [password] replaces the stored one, and a non-null [source]
 * re-labels the entry. [updatedAt] stamps the entry; 0 means now.
 *
 * An entry's tenant and sharing are not part of a patch: they are set when it
 * is added and an update keeps them.
 */
data class PasswordPatch(
    val name: String? = null,
    val title: String? = null,
    val username: String? = null,
    val password: String? = null,
    val url: String? = null,
    val notes: String? = null,
    val folderPath: String? = null,
    val expiresAt: String? = null,
    val source: String? = null,
    val updatedAt: Long = 0
) {
    /** [record] with this patch's fields set; its password is left as is. */
    internal fun applyTo(record: PasswordRecord): PasswordRecord = record.copy(
        name = name ?: record.name,
        title = clearable(title, record.title),
        username = clearable(username, record.username),
        url = clearable(url, record.url),
        notes = clearable(notes, record.notes),
        folderPath = clearable(folderPath, record.folderPath),
        expiresAt = clearable(expiresAt, record.expiresAt),
        source = source ?: record.source
    )

    private fun clearable(value: String?, current: String?): String? =
        if (value == null) current else value.ifEmpty { null }
}

/**
 * Which of a tenant's entries a listing returns: the [PERSONAL] ones (not
 * shared), the [SHARED] ones, or [ALL] of them. [shared] is the value the
 * `shared` column must hold, or null for no constraint.
 */
enum class PasswordScope(val wireName: String, val shared: Boolean?) {
    PERSONAL("personal", false),
    SHARED("shared", true),
    ALL("all", null);

    companion object {
        /** The scope named [wireName] on the wire, or null for an unknown name. */
        fun fromWire(wireName: String): PasswordScope? = entries.firstOrNull { it.wireName == wireName }
    }
}

/**
 * An update refused, nothing written, because another writer changed the
 * entry between each of [PasswordRepository.updateFields]'s reads and its
 * write. The message names no content.
 */
class PasswordUpdateConflictException :
    Exception("the entry changed while it was being updated; nothing was written")

/**
 * Repository for the encrypted password store. Encrypts each password value with
 * the Android Keystore via [KeystoreAeadCipher] before persisting through
 * [PasswordDao], and decrypts on read.
 *
 * Every write ([upsert], [updateFields]) is held to
 * [PasswordEntryLimit.MAX_ENTRY_SIZE] and refused with
 * [PasswordEntryTooLargeException] over it, so no writer can store an entry
 * go-xkms cannot read back.
 */
class PasswordRepository(
    private val dao: PasswordDao,
    private val cipher: KeystoreAeadCipher = KeystoreAeadCipher(KEY_ALIAS)
) {
    companion object {
        private const val KEY_ALIAS = "xkey_password_encryption_key"

        /** Reads of an entry [updateFields] makes before refusing one that keeps moving. */
        private const val UPDATE_ATTEMPTS = 2
    }

    /** List all stored passwords (decrypted). */
    suspend fun list(): List<PasswordRecord> = dao.getAll().map { it.toRecord() }

    /**
     * List all stored passwords without decrypting them: every record's
     * [PasswordRecord.password] is empty. Listings use this so that answering
     * one never puts every plaintext in memory at once.
     */
    suspend fun listWithoutSecrets(): List<PasswordRecord> =
        dao.getAll().map { it.toRecord(decrypt = false) }

    /**
     * List [tenantId]'s passwords in [scope], and in [folderPath] unless it is
     * null, ordered by name then username, without decrypting them: every
     * record's [PasswordRecord.password] is empty. The database applies every
     * filter, so a page cut from the result is a page of matching entries.
     */
    suspend fun listInTenant(
        tenantId: String,
        scope: PasswordScope = PasswordScope.ALL,
        folderPath: String? = null
    ): List<PasswordRecord> =
        dao.getForListing(tenantId, scope.shared, folderPath).map { it.toRecord(decrypt = false) }

    /** List stored passwords from a given source ("local" or "remote"). */
    suspend fun listBySource(source: String): List<PasswordRecord> =
        dao.getBySource(source).map { it.toRecord() }

    /**
     * Get a single password by ID (decrypted), or null. With a [tenantId],
     * another tenant's entry is null too.
     */
    suspend fun get(passwordId: String, tenantId: String? = null): PasswordRecord? =
        find(passwordId, tenantId)?.toRecord()

    /**
     * The entry with [passwordId], or null. A null [tenantId] finds it in any
     * tenant; otherwise an entry of another tenant is not found, exactly like
     * an unknown id.
     */
    private suspend fun find(passwordId: String, tenantId: String?): PasswordEntity? =
        if (tenantId == null) dao.getByPasswordId(passwordId) else dao.getByPasswordIdInTenant(passwordId, tenantId)

    /**
     * Insert or update a password, encrypting the value at rest.
     *
     * Preserves the original [PasswordEntity.createdAt] on update. Returns the
     * stable password ID.
     *
     * An entry deleted between the read and the write is written again, from
     * [record] alone: no stored value outlives the delete, as when the add
     * follows it.
     */
    suspend fun upsert(record: PasswordRecord): String {
        val existing = dao.getByPasswordId(record.passwordId)
        val now = System.currentTimeMillis()
        val createdAt = existing?.createdAt ?: if (record.createdAt > 0) record.createdAt else now
        val updatedAt = if (record.updatedAt > 0) record.updatedAt else now
        // Measured as PasswordGet answers it, with the timestamps it is stored under.
        PasswordEntryLimit.requireFits(record.copy(createdAt = createdAt, updatedAt = updatedAt))
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
                createdAt = createdAt,
                updatedAt = updatedAt,
                expiresAt = record.expiresAt,
                shared = record.shared,
                tenantId = record.tenantId
            )
        )
        return record.passwordId
    }

    /**
     * Add [record] as a new entry, encrypting the value at rest, only if no
     * entry has its [PasswordRecord.passwordId]. Returns whether it was added:
     * false means an entry with that id is there, perhaps added by another
     * writer since the caller looked, and it is left exactly as it is.
     *
     * Unlike [upsert], this never replaces a row, so it cannot undo a write
     * that lands between the caller's read and this one, such as a
     * `PasswordUpdate` setting the entry's expiry.
     */
    suspend fun insertIfAbsent(record: PasswordRecord): Boolean {
        val now = System.currentTimeMillis()
        val createdAt = if (record.createdAt > 0) record.createdAt else now
        val updatedAt = if (record.updatedAt > 0) record.updatedAt else now
        // Measured as PasswordGet answers it, with the timestamps it is stored under.
        PasswordEntryLimit.requireFits(record.copy(createdAt = createdAt, updatedAt = updatedAt))
        val rowId = dao.insertIfAbsent(
            PasswordEntity(
                passwordId = record.passwordId,
                name = record.name,
                title = record.title,
                username = record.username,
                passwordEncrypted = cipher.encrypt(record.password.toByteArray(Charsets.UTF_8)),
                url = record.url,
                notes = record.notes,
                folderPath = record.folderPath,
                source = record.source,
                createdAt = createdAt,
                updatedAt = updatedAt,
                expiresAt = record.expiresAt,
                shared = record.shared,
                tenantId = record.tenantId
            )
        )
        return rowId != -1L
    }

    /**
     * Get a single password by ID without decrypting it ([PasswordRecord.password]
     * is empty), or null. With a [tenantId], another tenant's entry is null too.
     */
    suspend fun getWithoutSecret(passwordId: String, tenantId: String? = null): PasswordRecord? =
        find(passwordId, tenantId)?.toRecord(decrypt = false)

    /**
     * Apply [patch] to the entry with [passwordId]. A patch without a password
     * keeps the stored ciphertext as is, and decrypts it only to measure an
     * entry near the size limit. Returns false if no entry has [passwordId],
     * or, with a [tenantId], if the one that has it belongs to another tenant.
     * The entry keeps its tenant and sharing; the patch sets its expiry.
     *
     * The read, the patch, the size check and the write are one unit: the
     * patch is applied to the row this call reads, and the write is an
     * in-place UPDATE guarded by every column of that row
     * ([PasswordDao.updateFieldsIfUnchanged]), so it never inserts and never
     * overwrites a field another writer changed after the read. An entry
     * changed or deleted between the read and the write is read, patched and
     * checked again, once: a deleted entry then returns false, a changed one
     * gets the patch on top of its current fields. An entry that changes again
     * before the second write is refused with [PasswordUpdateConflictException],
     * nothing written.
     */
    suspend fun updateFields(passwordId: String, patch: PasswordPatch, tenantId: String? = null): Boolean {
        val updatedAt = if (patch.updatedAt > 0) patch.updatedAt else System.currentTimeMillis()
        var newCiphertext: ByteArray? = null
        repeat(UPDATE_ATTEMPTS) {
            val existing = find(passwordId, tenantId) ?: return false
            val patched = patch.applyTo(existing.toRecord(decrypt = false)).copy(updatedAt = updatedAt)
            requireFits(patched, patch.password, existing.passwordEncrypted)
            val passwordEncrypted = when (val password = patch.password) {
                null -> existing.passwordEncrypted
                else -> newCiphertext ?: cipher.encrypt(password.toByteArray(Charsets.UTF_8))
                    .also { newCiphertext = it }
            }
            val changed = dao.updateFieldsIfUnchanged(
                id = existing.id,
                expectedPasswordEncrypted = existing.passwordEncrypted,
                expectedName = existing.name,
                expectedTitle = existing.title,
                expectedUsername = existing.username,
                expectedUrl = existing.url,
                expectedNotes = existing.notes,
                expectedFolderPath = existing.folderPath,
                expectedSource = existing.source,
                expectedCreatedAt = existing.createdAt,
                expectedUpdatedAt = existing.updatedAt,
                expectedExpiresAt = existing.expiresAt,
                expectedShared = existing.shared,
                expectedTenantId = existing.tenantId,
                name = patched.name,
                title = patched.title,
                username = patched.username,
                passwordEncrypted = passwordEncrypted,
                url = patched.url,
                notes = patched.notes,
                folderPath = patched.folderPath,
                source = patched.source,
                expiresAt = patched.expiresAt,
                updatedAt = updatedAt
            )
            if (changed > 0) return true
        }
        throw PasswordUpdateConflictException()
    }

    /**
     * Refuses [record] with [PasswordEntryTooLargeException] if it would not
     * fit with [newPassword] or, when null, the password stored as
     * [storedCiphertext]. The stored password is decrypted only when its
     * ciphertext length cannot rule an overflow out.
     */
    private fun requireFits(record: PasswordRecord, newPassword: String?, storedCiphertext: ByteArray) {
        if (newPassword != null) return PasswordEntryLimit.requireFits(record.copy(password = newPassword))
        if (PasswordEntryLimit.fitsWithStoredPassword(record, storedCiphertext.size)) return
        val plaintext = cipher.decrypt(storedCiphertext)
        try {
            PasswordEntryLimit.requireFits(record.copy(password = String(plaintext, Charsets.UTF_8)))
        } finally {
            plaintext.fill(0)
        }
    }

    /**
     * Delete a password by ID, in any tenant or, with a [tenantId], only if it
     * belongs to that tenant. Returns whether an entry was deleted.
     */
    suspend fun delete(passwordId: String, tenantId: String? = null): Boolean =
        if (tenantId == null) {
            dao.deleteByPasswordId(passwordId) > 0
        } else {
            dao.deleteByPasswordIdInTenant(passwordId, tenantId) > 0
        }

    /** Number of stored passwords. */
    suspend fun count(): Int = dao.count()

    /** Observe stored password entities (encrypted) for reactive UI. */
    fun observeAll(): Flow<List<PasswordEntity>> = dao.observeAll()

    private fun PasswordEntity.toRecord(decrypt: Boolean = true): PasswordRecord = PasswordRecord(
        passwordId = passwordId,
        name = name,
        title = title,
        username = username,
        password = if (decrypt) String(cipher.decrypt(passwordEncrypted), Charsets.UTF_8) else "",
        url = url,
        notes = notes,
        folderPath = folderPath,
        source = source,
        createdAt = createdAt,
        updatedAt = updatedAt,
        expiresAt = expiresAt,
        shared = shared,
        tenantId = tenantId
    )
}
