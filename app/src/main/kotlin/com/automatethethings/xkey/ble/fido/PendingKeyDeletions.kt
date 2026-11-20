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
 */
interface PendingKeyDeletions {
    /** Record [keyIds] as keys to delete. Throws when the record cannot be written. */
    fun add(keyIds: Collection<String>)

    /** Forget [keyId]: its key is deleted, or a row still owns it. */
    fun remove(keyId: String)

    /** Every key recorded and not yet forgotten. */
    fun all(): Set<String>
}

/**
 * [PendingKeyDeletions] in one file, so the record survives a restart. Each
 * line is one key ID in base64, whatever characters the stored ID holds. Every
 * change writes a new file, synced, and renames it over the old one, so the
 * file is always either the old record or the new one.
 */
class FilePendingKeyDeletions(private val file: File) : PendingKeyDeletions {

    override fun add(keyIds: Collection<String>) = synchronized(lock) {
        val now = read()
        if (!now.containsAll(keyIds)) write(now + keyIds)
    }

    override fun remove(keyId: String) = synchronized(lock) {
        val now = read()
        if (keyId in now) write(now - keyId)
    }

    override fun all(): Set<String> = synchronized(lock) { read() }

    private fun read(): Set<String> {
        if (!file.exists()) return emptySet()
        return file.readLines(Charsets.US_ASCII)
            .filter { it.isNotBlank() }
            .map { String(Base64.getDecoder().decode(it.trim()), Charsets.UTF_8) }
            .toSet()
    }

    private fun write(keyIds: Set<String>) {
        file.parentFile?.mkdirs()
        val text = keyIds.joinToString("") { Base64.getEncoder().encodeToString(it.toByteArray(Charsets.UTF_8)) + "\n" }
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
    }
}
