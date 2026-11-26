/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
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
package com.automatethethings.xkey.ble.fido

import com.automatethethings.xkey.crypto.UserKeyKind
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.util.Base64

/**
 * One Keystore key to delete: the key ID and the namespace its alias lives
 * in. A fido2 row's key is a credential when the phone registered it and a
 * general key when local.generateKey made it, so the namespace is recorded
 * with the ID: a retry deletes the very alias the row's key was under.
 *
 * A null [kind] is a record whose namespace is not known: one written before
 * namespaces were recorded, when a replaced passkey's key could be either.
 * Its deletion tries every namespace ([candidates]).
 */
data class PendingKey(val keyId: String, val kind: UserKeyKind?) {
    /** The namespaces whose key under [keyId] this record deletes. */
    val candidates: List<UserKeyKind> get() = kind?.let { listOf(it) } ?: UserKeyKind.entries
}

/**
 * The Keystore keys of passkeys whose rows are gone, or going, but whose
 * Keystore deletion has not yet succeeded. A key is recorded here before its
 * rows are deleted and forgotten once Keystore has deleted it, so a deletion
 * that fails, or a process that dies between the rows and the key, leaves a
 * record [AndroidFidoCredentialBackend] retries until the key is gone.
 *
 * It also records the registrations not yet complete: a new passkey is
 * recorded before its key or rows are made and forgotten once it is whole.
 * Until then it is never offered, and a retry removes its rows, if any, and
 * its key, a credential key.
 */
interface PendingKeyDeletions {
    /** Record [keys] as keys to delete. Throws when the record cannot be written. */
    fun add(keys: Collection<PendingKey>)

    /**
     * Record [keyId] as a registration not yet complete: its rows and its
     * credential key are to go unless it is [remove]d. Throws when the
     * record cannot be written.
     */
    fun addRegistration(keyId: String)

    /** Forget every record of [keyId], as a key to delete and as a registration: a row owns its key. */
    fun remove(keyId: String)

    /**
     * Forget [key], now deleted: its deletion, and the registration of its
     * ID when its deletion covered the credential key a registration makes
     * (a credential, or a key of either namespace). A key of the other
     * namespace under the same ID stays recorded.
     */
    fun remove(key: PendingKey)

    /** Every key recorded to delete and not yet forgotten. */
    fun all(): Set<PendingKey>

    /** Every registration recorded and not yet complete or cleaned up. */
    fun registrations(): Set<String>
}

/**
 * [PendingKeyDeletions] in one file, so the record survives a restart. Each
 * line is one key ID in base64, whatever characters the stored ID holds:
 * after "c " for a credential key to delete, after "g " for a general key to
 * delete, bare for a key to delete in either namespace (every record written
 * before namespaces were recorded), and after "r " for a registration not
 * yet complete. Every change writes a new
 * file, synced, and renames it over the old one, so the file is always
 * either the old record or the new one.
 */
class FilePendingKeyDeletions(private val file: File) : PendingKeyDeletions {

    override fun add(keys: Collection<PendingKey>) = synchronized(lock) {
        val now = read()
        val next = Record(now.deletions + keys, now.registrations)
        if (next != now) write(next)
    }

    override fun addRegistration(keyId: String) = synchronized(lock) {
        val now = read()
        val next = Record(now.deletions, now.registrations + keyId)
        if (next != now) write(next)
    }

    override fun remove(keyId: String) = synchronized(lock) {
        val now = read()
        val next = Record(now.deletions.filterNot { it.keyId == keyId }.toSet(), now.registrations - keyId)
        if (next != now) write(next)
    }

    override fun remove(key: PendingKey) = synchronized(lock) {
        val now = read()
        val registrations =
            if (UserKeyKind.CREDENTIAL in key.candidates) now.registrations - key.keyId else now.registrations
        val next = Record(now.deletions - key, registrations)
        if (next != now) write(next)
    }

    override fun all(): Set<PendingKey> = synchronized(lock) { read().deletions }

    override fun registrations(): Set<String> = synchronized(lock) { read().registrations }

    private data class Record(val deletions: Set<PendingKey>, val registrations: Set<String>)

    private fun read(): Record {
        if (!file.exists()) return Record(emptySet(), emptySet())
        val lines = file.readLines(Charsets.US_ASCII).map { it.trim() }.filter { it.isNotEmpty() }
        fun decode(line: String) = String(Base64.getDecoder().decode(line), Charsets.UTF_8)
        val deletions = mutableSetOf<PendingKey>()
        val registrations = mutableSetOf<String>()
        for (line in lines) {
            when {
                line.startsWith(REGISTRATION) -> registrations += decode(line.removePrefix(REGISTRATION))
                line.startsWith(GENERAL) -> deletions += PendingKey(decode(line.removePrefix(GENERAL)), UserKeyKind.GENERAL)
                line.startsWith(CREDENTIAL) -> deletions += PendingKey(decode(line.removePrefix(CREDENTIAL)), UserKeyKind.CREDENTIAL)
                // Written before namespaces were recorded: either namespace.
                else -> deletions += PendingKey(decode(line), null)
            }
        }
        return Record(deletions, registrations)
    }

    private fun write(record: Record) {
        file.parentFile?.mkdirs()
        fun encode(id: String) = Base64.getEncoder().encodeToString(id.toByteArray(Charsets.UTF_8))
        val text = record.deletions.joinToString("") {
            when (it.kind) {
                UserKeyKind.GENERAL -> GENERAL
                UserKeyKind.CREDENTIAL -> CREDENTIAL
                null -> ""
            } + encode(it.keyId) + "\n"
        } + record.registrations.joinToString("") { REGISTRATION + encode(it) + "\n" }
        val next = File(file.path + ".new")
        FileOutputStream(next).use { out ->
            out.write(text.toByteArray(Charsets.US_ASCII))
            out.fd.sync()
        }
        if (!next.renameTo(file)) throw IOException("Could not replace ${file.name}")
    }

    private companion object {
        /** One lock for every instance: two backends in one process share the file. */
        val lock = Any()

        /**
         * A registration's line starts with this; a key to delete in either
         * namespace is bare base64, which never holds a space, as records
         * written before namespaces were recorded are.
         */
        const val REGISTRATION = "r "

        /** A general key to delete: its line starts with this. */
        const val GENERAL = "g "

        /** A credential key to delete: its line starts with this. */
        const val CREDENTIAL = "c "
    }
}
