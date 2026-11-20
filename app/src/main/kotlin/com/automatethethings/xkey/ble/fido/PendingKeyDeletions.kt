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

import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.util.Base64

/**
 * The Keystore keys of passkeys whose rows are gone, or going, but whose
 * Keystore deletion has not yet succeeded. A key is recorded here before its
 * rows are deleted and forgotten once Keystore has deleted it, so a deletion
 * that throws, or a process that dies between the rows and the key, leaves a
 * record [AndroidFidoCredentialBackend] retries until the key is gone.
 *
 * It also records the registrations not yet complete: a new passkey is
 * recorded before its key or rows are made and forgotten once it is whole.
 * Until then it is never offered, and a retry removes its rows, if any, and
 * its key.
 */
interface PendingKeyDeletions {
    /** Record [keyIds] as keys to delete. Throws when the record cannot be written. */
    fun add(keyIds: Collection<String>)

    /**
     * Record [keyId] as a registration not yet complete: its rows and its key
     * are to go unless it is [remove]d. Throws when the record cannot be written.
     */
    fun addRegistration(keyId: String)

    /** Forget [keyId], as a key to delete and as a registration: its key is deleted, or a row owns it. */
    fun remove(keyId: String)

    /** Every key recorded to delete and not yet forgotten. */
    fun all(): Set<String>

    /** Every registration recorded and not yet complete or cleaned up. */
    fun registrations(): Set<String>
}

/**
 * [PendingKeyDeletions] in one file, so the record survives a restart. Each
 * line is one key ID in base64, whatever characters the stored ID holds,
 * after "r " for a registration not yet complete. Every change writes a new
 * file, synced, and renames it over the old one, so the file is always
 * either the old record or the new one.
 */
class FilePendingKeyDeletions(private val file: File) : PendingKeyDeletions {

    override fun add(keyIds: Collection<String>) = synchronized(lock) {
        val now = read()
        val next = Record(now.deletions + keyIds, now.registrations)
        if (next != now) write(next)
    }

    override fun addRegistration(keyId: String) = synchronized(lock) {
        val now = read()
        val next = Record(now.deletions, now.registrations + keyId)
        if (next != now) write(next)
    }

    override fun remove(keyId: String) = synchronized(lock) {
        val now = read()
        val next = Record(now.deletions - keyId, now.registrations - keyId)
        if (next != now) write(next)
    }

    override fun all(): Set<String> = synchronized(lock) { read().deletions }

    override fun registrations(): Set<String> = synchronized(lock) { read().registrations }

    private data class Record(val deletions: Set<String>, val registrations: Set<String>)

    private fun read(): Record {
        if (!file.exists()) return Record(emptySet(), emptySet())
        val lines = file.readLines(Charsets.US_ASCII).map { it.trim() }.filter { it.isNotEmpty() }
        fun decode(line: String) = String(Base64.getDecoder().decode(line), Charsets.UTF_8)
        return Record(
            deletions = lines.filterNot { it.startsWith(REGISTRATION) }.map(::decode).toSet(),
            registrations = lines.filter { it.startsWith(REGISTRATION) }
                .map { decode(it.removePrefix(REGISTRATION)) }.toSet()
        )
    }

    private fun write(record: Record) {
        file.parentFile?.mkdirs()
        fun encode(id: String) = Base64.getEncoder().encodeToString(id.toByteArray(Charsets.UTF_8))
        val text = record.deletions.joinToString("") { encode(it) + "\n" } +
            record.registrations.joinToString("") { REGISTRATION + encode(it) + "\n" }
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

        /** A registration's line starts with this; a key to delete is bare base64, which never holds a space. */
        const val REGISTRATION = "r "
    }
}
