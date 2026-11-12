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
import java.io.DataInputStream
import java.io.File
import java.io.IOException
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
 * record itself. Records written by this build are:
 *
 * ```
 * "XKB2" | sequence (8 bytes) | created-at millis (8 bytes)
 *        | id length (4 bytes) | id (UTF-8) | blob          (all big endian)
 * ```
 *
 * ## Ids
 *
 * A peer may name a backup; `local.createBackup` does not, so [store] then
 * generates `backup-<creation millis>-<sequence>`. The sequence is one more
 * than the highest sequence of any record in the directory, so two backups
 * stored in the same millisecond still get distinct ids and neither
 * overwrites the other.
 *
 * ## Latest backup
 *
 * [latestId] orders records by sequence, then by creation time. It never
 * depends on the file modification time of an `XKB2` record, whose
 * granularity can be a whole second.
 *
 * ## Records written by older builds
 *
 * `XKB1` records (`"XKB1" | id length | id | blob`) are still read as they
 * are: their sequence is 0, so every backup stored by this build sorts after
 * them, and their creation time is the file modification time.
 *
 * Earlier builds named files `sanitize(id)` and stored the bare blob. Such
 * files are migrated on first access: the filename is the best available
 * reconstruction of the id (for every id this app generated itself it *is* the
 * id), so the file is rewritten as an `XKB2` record with sequence 0 and its
 * modification time as the creation time.
 */
class BackupStore(context: Context) {
    private val dir: File = File(context.filesDir, "backups").apply { mkdirs() }

    private var migrated = false

    /**
     * Store a backup blob. If [backupId] is blank a unique id is generated.
     * Returns the id under which the blob was stored. Storing an existing id
     * again replaces it and makes it the latest backup.
     */
    fun store(backupId: String, data: ByteArray): String = synchronized(LOCK) {
        migrateLegacyRecords()
        var sequence = nextSequence()
        val now = System.currentTimeMillis()
        val id = if (backupId.isNotBlank()) {
            backupId
        } else {
            var generated = "backup-$now-$sequence"
            while (recordFile(generated).exists()) {
                sequence++
                generated = "backup-$now-$sequence"
            }
            generated
        }
        recordFile(id).writeBytes(encodeRecord(Header(sequence, now), id, data))
        id
    }

    /** Returns the stored blob for [backupId], or null if absent. */
    fun load(backupId: String): ByteArray? = synchronized(LOCK) {
        migrateLegacyRecords()
        val file = recordFile(backupId)
        if (!file.exists()) return null
        decodeRecord(file.readBytes())?.second
    }

    /** Id of the most-recently-stored backup, or null if none exist. */
    fun latestId(): String? = synchronized(LOCK) {
        migrateLegacyRecords()
        recordFiles()
            .mapNotNull { file -> readHeader(file)?.let { file to it } }
            .sortedWith(
                compareByDescending<Pair<File, Header>> { it.second.sequence }
                    .thenByDescending { it.second.createdAtMillis }
            )
            .firstNotNullOfOrNull { decodeRecord(it.first.readBytes())?.first }
    }

    /** Creation time of [backupId] in Unix millis, or 0. */
    fun createdAtMillis(backupId: String): Long = synchronized(LOCK) {
        migrateLegacyRecords()
        val file = recordFile(backupId)
        if (!file.exists()) return 0L
        readHeader(file)?.createdAtMillis ?: 0L
    }

    // -------------------------------------------------------------------------
    // Record format
    // -------------------------------------------------------------------------

    /** Order and creation time of a record. */
    private data class Header(val sequence: Long, val createdAtMillis: Long)

    private fun recordFile(id: String): File =
        File(dir, "${SyncCodec.sha256Hex(id.toByteArray(Charsets.UTF_8))}$RECORD_SUFFIX")

    private fun recordFiles(): List<File> =
        dir.listFiles()?.filter { RECORD_NAME.matches(it.name) } ?: emptyList()

    private fun nextSequence(): Long =
        (recordFiles().mapNotNull { readHeader(it)?.sequence }.maxOrNull() ?: 0L) + 1

    private fun encodeRecord(header: Header, id: String, data: ByteArray): ByteArray {
        val idBytes = id.toByteArray(Charsets.UTF_8)
        return ByteBuffer.allocate(V2_HEADER_SIZE + idBytes.size + data.size)
            .put(MAGIC_V2)
            .putLong(header.sequence)
            .putLong(header.createdAtMillis)
            .putInt(idBytes.size)
            .put(idBytes)
            .put(data)
            .array()
    }

    /**
     * Reads only the header of [file]: an `XKB2` record's sequence and
     * creation time, or sequence 0 and the modification time for an `XKB1`
     * record. Null if [file] is not a record.
     */
    private fun readHeader(file: File): Header? = try {
        DataInputStream(file.inputStream().buffered()).use { input ->
            val magic = ByteArray(MAGIC_V2.size)
            input.readFully(magic)
            when {
                MAGIC_V2.contentEquals(magic) -> Header(input.readLong(), input.readLong())
                MAGIC_V1.contentEquals(magic) -> Header(0L, file.lastModified())
                else -> null
            }
        }
    } catch (e: IOException) {
        null
    }

    /** Splits a record into (id, blob), or null if [bytes] is not a record. */
    private fun decodeRecord(bytes: ByteArray): Pair<String, ByteArray>? {
        if (bytes.size < MAGIC_V1.size) return null
        val magic = bytes.copyOfRange(0, MAGIC_V1.size)
        val headerSize = when {
            MAGIC_V2.contentEquals(magic) -> V2_HEADER_SIZE
            MAGIC_V1.contentEquals(magic) -> V1_HEADER_SIZE
            else -> return null
        }
        if (bytes.size < headerSize) return null
        val idLength = ByteBuffer.wrap(bytes, headerSize - 4, 4).int
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
                target.writeBytes(encodeRecord(Header(0L, modified), id, file.readBytes()))
                target.setLastModified(modified)
            }
            file.delete()
        }
    }

    private companion object {
        /** Guards the directory: [store] reads the highest sequence, then writes. */
        val LOCK = Any()

        /** Record markers; distinguish a record from a legacy bare blob. */
        val MAGIC_V1 = "XKB1".toByteArray(Charsets.US_ASCII)
        val MAGIC_V2 = "XKB2".toByteArray(Charsets.US_ASCII)

        /** Magic and id length. */
        const val V1_HEADER_SIZE = 4 + 4

        /** Magic, sequence, created-at and id length. */
        const val V2_HEADER_SIZE = 4 + 8 + 8 + 4

        const val RECORD_SUFFIX = ".backup"
        val RECORD_NAME = Regex("[0-9a-f]{64}\\.backup")
    }
}
