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
package com.automatethethings.xkey.backup

import android.content.Context
import com.automatethethings.xkey.crypto.SyncCodec
import java.io.File
import java.nio.ByteBuffer

/**
 * Stores opaque, already-encrypted backup blobs created by a paired desktop
 * (`local.createBackup`) so they can be returned later (`local.restoreBackup`).
 *
 * The phone treats each blob as opaque — it never inspects or decrypts it.
 *
 * ## On-disk layout
 *
 * Each backup is one file under `filesDir/backups/` named
 * `<sha256-hex-of-id>.backup`. The digest is what makes the filename safe: it
 * cannot contain a path separator, cannot escape the directory, and — unlike
 * the character-replacing sanitiser this replaced — is injective, so two ids
 * that differ only in punctuation (`a/b` and `a\b`) can never land on the same
 * file and overwrite each other.
 *
 * A digest is one-way, so the id the peer actually sent is written into the
 * record itself:
 *
 * ```
 * "XKB1" | id length (4 bytes, big endian) | id (UTF-8) | blob
 * ```
 *
 * [latestId] therefore returns the peer's own id rather than a mangled
 * filename.
 *
 * ## Records written by older builds
 *
 * Earlier builds named files `sanitize(id)` and stored the bare blob. Such
 * files are migrated on first access: the filename is the best available
 * reconstruction of the id (for every id this app generated itself it *is* the
 * id, and it is exactly what the old [latestId] returned), so the file is
 * rewritten as a record under that id with its modification time preserved.
 */
class BackupStore(context: Context) {
    private val dir: File = File(context.filesDir, "backups").apply { mkdirs() }

    private var migrated = false

    /**
     * Store a backup blob. If [backupId] is blank a timestamp-based id is
     * generated. Returns the id under which the blob was stored.
     */
    fun store(backupId: String, data: ByteArray): String {
        migrateLegacyRecords()
        val id = backupId.ifBlank { "backup-${System.currentTimeMillis()}" }
        recordFile(id).writeBytes(encodeRecord(id, data))
        return id
    }

    /** Returns the stored blob for [backupId], or null if absent. */
    fun load(backupId: String): ByteArray? {
        migrateLegacyRecords()
        val file = recordFile(backupId)
        if (!file.exists()) return null
        return decodeRecord(file.readBytes())?.second
    }

    /** Id of the most-recently-stored backup, or null if none exist. */
    fun latestId(): String? {
        migrateLegacyRecords()
        return recordFiles()
            .sortedByDescending { it.lastModified() }
            .firstNotNullOfOrNull { decodeRecord(it.readBytes())?.first }
    }

    /** Creation (last-modified) time of [backupId] in Unix millis, or 0. */
    fun createdAtMillis(backupId: String): Long {
        migrateLegacyRecords()
        return recordFile(backupId).let { if (it.exists()) it.lastModified() else 0L }
    }

    // -------------------------------------------------------------------------
    // Record format
    // -------------------------------------------------------------------------

    private fun recordFile(id: String): File =
        File(dir, "${SyncCodec.sha256Hex(id.toByteArray(Charsets.UTF_8))}$RECORD_SUFFIX")

    private fun recordFiles(): List<File> =
        dir.listFiles()?.filter { RECORD_NAME.matches(it.name) } ?: emptyList()

    private fun encodeRecord(id: String, data: ByteArray): ByteArray {
        val idBytes = id.toByteArray(Charsets.UTF_8)
        return ByteBuffer.allocate(MAGIC.size + 4 + idBytes.size + data.size)
            .put(MAGIC)
            .putInt(idBytes.size)
            .put(idBytes)
            .put(data)
            .array()
    }

    /** Splits a record into (id, blob), or null if [bytes] is not a record. */
    private fun decodeRecord(bytes: ByteArray): Pair<String, ByteArray>? {
        val headerSize = MAGIC.size + 4
        if (bytes.size < headerSize) return null
        if (!MAGIC.contentEquals(bytes.copyOfRange(0, MAGIC.size))) return null
        val idLength = ByteBuffer.wrap(bytes, MAGIC.size, 4).int
        if (idLength < 0 || headerSize + idLength > bytes.size) return null
        val id = String(bytes, headerSize, idLength, Charsets.UTF_8)
        return id to bytes.copyOfRange(headerSize + idLength, bytes.size)
    }

    // -------------------------------------------------------------------------
    // Migration
    // -------------------------------------------------------------------------

    /**
     * Rewrites blobs left by older builds — bare bytes under a sanitised
     * filename — as records keyed by the digest of their id.
     */
    private fun migrateLegacyRecords() {
        if (migrated) return
        migrated = true
        val files = dir.listFiles() ?: return
        for (file in files) {
            if (RECORD_NAME.matches(file.name)) continue
            val id = file.name
            val target = recordFile(id)
            if (!target.exists()) {
                val modified = file.lastModified()
                target.writeBytes(encodeRecord(id, file.readBytes()))
                target.setLastModified(modified)
            }
            file.delete()
        }
    }

    private companion object {
        /** Record marker; distinguishes a record from a legacy bare blob. */
        val MAGIC = "XKB1".toByteArray(Charsets.US_ASCII)
        const val RECORD_SUFFIX = ".backup"
        val RECORD_NAME = Regex("[0-9a-f]{64}\\.backup")
    }
}
