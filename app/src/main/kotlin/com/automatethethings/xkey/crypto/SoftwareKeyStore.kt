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
package com.automatethethings.xkey.crypto

import android.content.Context
import com.automatethethings.xkey.storage.filePresence
import org.json.JSONObject
import java.io.File

/**
 * A software-backed key whose raw material can leave the device (subject to its
 * sharing policy). Hardware-backed keys never live here — they stay in the
 * Android Keystore and are non-exportable by design. Software keys exist
 * precisely so that "shareable" private/symmetric material can be exported to a
 * paired desktop over the (Noise-encrypted) pairing channel.
 *
 * @property keyType "symmetric" or "private".
 */
data class SoftwareKey(
    val keyId: String,
    val algorithm: String,
    val keyType: String,
    val keySize: Int,
    val exportable: Boolean,
    val shareable: Boolean,
    val material: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SoftwareKey) return false
        return keyId == other.keyId && algorithm == other.algorithm && keyType == other.keyType &&
            keySize == other.keySize && exportable == other.exportable && shareable == other.shareable &&
            material.contentEquals(other.material)
    }

    override fun hashCode(): Int {
        var result = keyId.hashCode()
        result = 31 * result + algorithm.hashCode()
        result = 31 * result + keyType.hashCode()
        result = 31 * result + keySize
        result = 31 * result + exportable.hashCode()
        result = 31 * result + shareable.hashCode()
        result = 31 * result + material.contentHashCode()
        return result
    }
}

/**
 * File-backed store for [SoftwareKey]s. Raw key material is encrypted at rest
 * with the Android Keystore via [KeystoreAeadCipher]; non-sensitive metadata is
 * stored alongside as JSON. Files live under `filesDir/software_keys/`.
 *
 * ## File naming
 *
 * A key is stored as `<sha256-hex-of-keyId>.key` (material) plus
 * `<sha256-hex-of-keyId>.meta` (metadata, including the original id). Hashing
 * is what keeps distinct keys distinct: the character-replacing sanitiser this
 * replaced mapped `a/b` and `a:b` onto one filename, so storing one key could
 * silently destroy an unrelated key's material. A digest is injective, so a
 * collision needs a SHA-256 collision.
 *
 * ## Records written by older builds
 *
 * Files named by the old sanitiser are migrated on first access. The original
 * id is read back out of the `.meta` JSON, so the migration is exact. A `.key`
 * whose `.meta` is missing or carries no `keyId` cannot be attributed to an id
 * and is left untouched.
 */
class SoftwareKeyStore(
    context: Context,
    cipher: KeystoreAeadCipher? = null,
    /** Moves a file, true when it was moved: a test fails it as a failed rename would. */
    private val rename: (File, File) -> Boolean = { from, to -> from.renameTo(to) },
    /** Removes a file, true when it was removed: a test fails it as an I/O error would. */
    private val unlink: (File) -> Boolean = { it.delete() }
) {
    /**
     * Opened on the first read or write of material: [contains] and [delete]
     * touch only files, so an existence check needs no Keystore.
     */
    private val cipher: KeystoreAeadCipher by lazy { cipher ?: KeystoreAeadCipher(KEY_ALIAS) }

    private val dir: File = File(context.filesDir, "software_keys").apply { mkdirs() }

    private var migrated = false

    /** Writes and deletes of [dir] in this process, by every instance over it. */
    private val writes: java.util.concurrent.atomic.AtomicLong =
        WRITES.computeIfAbsent(dir.absolutePath) { java.util.concurrent.atomic.AtomicLong() }

    /** The kept metadata scan of [legacyIndex], valid while [writes] is at its version. */
    @Volatile
    private var index: LegacyIndex? = null

    /**
     * Every record's metadata as one scan read it: the stems whose metadata
     * cannot be read, the stems that hold material naming no id, and the
     * stems of each id a record's metadata names.
     */
    private class LegacyIndex(
        val version: Long,
        val unreadableMetadata: Set<String>,
        val unattributed: Set<String>,
        val named: Map<String, Set<String>>
    )

    /** Store (or replace) a software key, encrypting its material at rest. */
    fun put(key: SoftwareKey) {
        requireValidKeyId(key.keyId)
        migrateLegacyRecords()
        val id = fileId(key.keyId)
        try {
            File(dir, "$id.key").writeBytes(cipher.encrypt(key.material))
            File(dir, "$id.meta").writeText(
            JSONObject().apply {
                put("keyId", key.keyId)
                put("algorithm", key.algorithm)
                put("keyType", key.keyType)
                put("keySize", key.keySize)
                put("exportable", key.exportable)
                put("shareable", key.shareable)
            }.toString()
            )
        } finally {
            wrote()
        }
    }

    /** Retrieve a software key by id (material decrypted), or null. */
    fun get(keyId: String): SoftwareKey? {
        migrateLegacyRecords()
        val id = fileId(keyId)
        val keyFile = File(dir, "$id.key")
        val metaFile = File(dir, "$id.meta")
        // The one presence probe (#255 review r8): a file whose lookup fails
        // is unreadable, never a key that is not there; and material whose
        // metadata does not name [keyId] is unreadable (#255 verify r4).
        when (recordOf(keyId)) {
            KeyPresence.UNREADABLE -> throw KeyPresenceUnreadableException(keyId, null)
            // An older build's record this id could be (one that names no
            // id beside material, or one of this id left under its old
            // name) is never read as no key.
            KeyPresence.ABSENT -> if (legacyRecordOf(keyId) == KeyPresence.ABSENT) return null else
                throw KeyPresenceUnreadableException(keyId, null)
            KeyPresence.PRESENT -> {
                if (filePresence(keyFile) != KeyPresence.PRESENT) return null
                // Material whose metadata is gone (a put or an older build's
                // delete stopped short) is this id's, but cannot be read.
                if (filePresence(metaFile) != KeyPresence.PRESENT) throw KeyPresenceUnreadableException(keyId, null)
            }
        }
        val meta = readMetadata(metaFile, keyId)
        return SoftwareKey(
            keyId = keyId,
            algorithm = meta.optString("algorithm", ""),
            keyType = meta.optString("keyType", "symmetric"),
            keySize = meta.optInt("keySize", 0),
            exportable = meta.optBoolean("exportable", false),
            shareable = meta.optBoolean("shareable", false),
            material = cipher.decrypt(readRecordFile(keyFile, keyId))
        )
    }

    /**
     * Whether a software key with [keyId] exists.
     *
     * @throws KeyPresenceUnreadableException if the store cannot be read: never read as absent.
     */
    fun contains(keyId: String): Boolean = when (presence(keyId)) {
        KeyPresence.PRESENT -> true
        KeyPresence.ABSENT -> false
        KeyPresence.UNREADABLE -> throw KeyPresenceUnreadableException(keyId, null)
    }

    /**
     * What this store holds for [keyId], three-way (#255 review r6): either
     * file of the key, or an older build's record of it that could not be
     * migrated, is [KeyPresence.PRESENT]; a store directory that exists but
     * cannot be listed, or a file whose existence cannot be read, is
     * [KeyPresence.UNREADABLE], never [KeyPresence.ABSENT]. A store
     * directory that was never created holds no key. Every file is probed
     * with [filePresence] (#255 review r8), never File.exists(), which
     * answers false when a lookup fails: a directory that can be listed but
     * not searched is unreadable, not empty.
     */
    fun presence(keyId: String): KeyPresence =
        try {
            when (filePresence(dir)) {
                KeyPresence.ABSENT -> KeyPresence.ABSENT
                KeyPresence.UNREADABLE -> KeyPresence.UNREADABLE
                KeyPresence.PRESENT -> if (!dir.isDirectory || dir.listFiles() == null) {
                    KeyPresence.UNREADABLE
                } else {
                    migrateLegacyRecords()
                    when (val own = recordOf(keyId)) {
                        KeyPresence.ABSENT -> legacyRecordOf(keyId)
                        else -> own
                    }
                }
            }
        } catch (e: Exception) {
            KeyPresence.UNREADABLE
        }

    private fun legacyRecordOf(keyId: String): KeyPresence {
        val index = legacyIndex(keyId)
        // [keyId]'s own record is read by [recordOf].
        val own = fileId(keyId)
        return when {
            // Metadata that is listed but cannot be read could be any id's
            // (#255 verify r2z): it is unreadable for [keyId], never read
            // as its key, so no other key (an internal one under a raw
            // alias) is taken for a user key of [keyId].
            index.unreadableMetadata.any { it != own } -> KeyPresence.UNREADABLE
            index.named[keyId].orEmpty().any { it != own } -> KeyPresence.PRESENT
            index.unattributed.any { it != own } -> KeyPresence.UNREADABLE
            else -> KeyPresence.ABSENT
        }
    }

    /**
     * The one scan of every record's metadata, read by [legacyRecordOf]:
     * kept until a write or delete of this store's directory, through any
     * instance ([writes]), so repeated presence checks read the metadata
     * once (#255). A scan that a write overlaps carries the count from
     * before it, so the next check scans again.
     */
    private fun legacyIndex(keyId: String): LegacyIndex {
        val version = writes.get()
        index?.takeIf { it.version == version }?.let { return it }
        val unreadable = HashSet<String>()
        val unattributed = HashSet<String>()
        val named = HashMap<String, MutableSet<String>>()
        for (file in dir.listFiles() ?: throw KeyPresenceUnreadableException(keyId, null)) {
            val stem = file.name.substringBeforeLast('.')
            if (file.name.endsWith(".key")) {
                // Material with no metadata beside it names no id.
                if (filePresence(File(dir, "$stem.meta")) != KeyPresence.PRESENT) unattributed += stem
                continue
            }
            if (!file.name.endsWith(".meta")) continue
            val text = try {
                readMetadataText(file, stem)
            } catch (e: KeyPresenceUnreadableException) {
                unreadable += stem
                continue
            }
            // Every record is told by the id its metadata names, never by
            // its name's shape (#255 verify r5): an older build kept a
            // 64-hex id as its file name, which looks like a digest. A
            // record under the digest of the string its metadata names is
            // that string's, even one no write takes now (an empty id an
            // older build wrote): it is never an unknown id's (#255 verify
            // r6). One whose metadata names no id beside material could be
            // any id's (#255 verify r2y, r4).
            val id = namedId(text)
            when {
                id != null && isValidKeyId(id) -> named.getOrPut(id) { HashSet() } += stem
                id != null && stem == fileId(id) -> {}
                filePresence(File(dir, "$stem.key")) != KeyPresence.ABSENT -> unattributed += stem
            }
        }
        return LegacyIndex(version, unreadable, unattributed, named).also { index = it }
    }

    /** Counts a write or delete of this store's directory, invalidating every instance's [index]. */
    private fun wrote() {
        writes.incrementAndGet()
    }

    /**
     * What the record under [keyId]'s own file name holds of it (#255 verify
     * r4, r5): nothing, a metadata-only record (an older build's delete
     * stopped between its unlinks), material alone (a put stopped between
     * its writes, or an older build's delete), or material whose metadata
     * names [keyId]; each but nothing is [KeyPresence.PRESENT]. Material
     * with metadata that is unreadable or names any other id (or none) is
     * [KeyPresence.UNREADABLE]: it cannot be vouched for as [keyId]'s, and
     * is never read as absent.
     */
    private fun recordOf(keyId: String): KeyPresence {
        val id = fileId(keyId)
        val metaFile = File(dir, "$id.meta")
        val material = filePresence(File(dir, "$id.key"))
        val meta = filePresence(metaFile)
        return when {
            KeyPresence.UNREADABLE == material || KeyPresence.UNREADABLE == meta -> KeyPresence.UNREADABLE
            material == KeyPresence.ABSENT -> meta
            // Material alone under this id's digest name: only this id's
            // put or an older build's delete leaves it. It holds the id, so
            // no other key stands in, and its delete's replay can finish it
            // (#255 verify r5); [get] refuses to read it.
            meta == KeyPresence.ABSENT -> KeyPresence.PRESENT
            else -> {
                val text = try {
                    readMetadataText(metaFile, keyId)
                } catch (e: KeyPresenceUnreadableException) {
                    return KeyPresence.UNREADABLE
                }
                if (recordId(text) == keyId) KeyPresence.PRESENT else KeyPresence.UNREADABLE
            }
        }
    }

    /**
     * The id a record's metadata [text] names: its keyId when that is a
     * non-empty string, else null (unparseable JSON, no keyId, an empty one,
     * or one of another type). The one reading of a record's id, for the
     * presence probe, the key read and the migration alike.
     */
    private fun recordId(text: String): String? = namedId(text)?.takeIf(::isValidKeyId)

    /**
     * The string a record's metadata [text] names as its keyId, valid or
     * not, else null: read only by [recordId] and by [legacyRecordOf], which
     * attributes a record under the digest of that string to it (#255
     * verify r6).
     */
    private fun namedId(text: String): String? =
        try {
            JSONObject(text).opt("keyId") as? String
        } catch (e: org.json.JSONException) {
            null
        }

    /**
     * The one read of a record's file, material or metadata (#255 verify
     * r2z, ruling 554): a read that fails (an I/O error, a file that can be
     * stat'ed but not read, a denied read) is [KeyPresenceUnreadableException]
     * for [keyId], never a key that is there or not, and never an
     * IOException out of a caller. Every read of a record file in this
     * store goes through here (SoftwareKeyStoreReadBypassTest).
     */
    private fun readRecordFile(file: File, keyId: String): ByteArray =
        try {
            file.readBytes()
        } catch (e: java.io.IOException) {
            throw KeyPresenceUnreadableException(keyId, e)
        } catch (e: SecurityException) {
            throw KeyPresenceUnreadableException(keyId, e)
        }

    /** A record's metadata [file] as text, read by [readRecordFile]. */
    private fun readMetadataText(file: File, keyId: String): String =
        readRecordFile(file, keyId).toString(Charsets.UTF_8)

    /**
     * A record's metadata [file] as JSON, read by [readRecordFile]: metadata
     * that cannot be parsed is [KeyPresenceUnreadableException] too.
     */
    private fun readMetadata(file: File, keyId: String): JSONObject =
        try {
            JSONObject(readMetadataText(file, keyId))
        } catch (e: org.json.JSONException) {
            throw KeyPresenceUnreadableException(keyId, e)
        }

    /** Throws [IllegalArgumentException] for an id [isValidKeyId] rejects. */
    private fun requireValidKeyId(keyId: String) =
        require(isValidKeyId(keyId)) { "Invalid key id: a software key's id must be non-empty" }

    /**
     * Delete a software key by id: its record under its digest name, and
     * every older build's record naming it that could not be migrated
     * (#255 review r9), each through [deleteRecord].
     */
    fun delete(keyId: String) {
        migrateLegacyRecords()
        val own = fileId(keyId)
        val legacy = try {
            legacyIndex(keyId).named[keyId].orEmpty() - own
        } catch (e: KeyPresenceUnreadableException) {
            emptySet()
        }
        for (stem in listOf(own) + legacy.sorted()) deleteRecord(stem)
    }

    /**
     * The generation of the software key [keyId]: a digest of its encrypted
     * material, which [put] rewrites under a fresh IV, so a key stored again
     * under the same id has another generation. A metadata-only record (a
     * [delete] stopped between its two unlinks; [put] writes the material
     * first, so nothing else leaves one) has a [METADATA_ONLY] generation,
     * so a delete tracks it as well as the material (#255 verify r2y). Null
     * if no record of the id is stored.
     *
     * The one read of what a delete owes ([records], #255 review r9): an
     * older build's record of [keyId] that could not be moved onto its
     * digest name is the id's material too, so its digest is part of the
     * generation (comma-separated, sorted), and a store [presence] cannot
     * vouch for refuses here as it does there. A record's digest names its
     * content, never its file, so the record moved onto the digest name
     * later is still the generation a tombstone recorded.
     */
    fun generation(keyId: String): String? {
        migrateLegacyRecords()
        return records(keyId).values.distinct().sorted().takeIf { it.isNotEmpty() }?.joinToString(GENERATION_SEPARATOR)
    }

    /**
     * Every record of [keyId], by file stem, with its generation: the
     * record under its digest name and each older build's record whose
     * metadata names it. Refuses ([KeyPresenceUnreadableException]) exactly
     * where [presence] reads [KeyPresence.UNREADABLE], so the two never
     * disagree on whether the id holds material.
     */
    private fun records(keyId: String): Map<String, String> {
        val own = fileId(keyId)
        when (recordOf(keyId)) {
            KeyPresence.UNREADABLE -> throw KeyPresenceUnreadableException(keyId, null)
            KeyPresence.ABSENT -> if (legacyRecordOf(keyId) == KeyPresence.UNREADABLE) throw KeyPresenceUnreadableException(keyId, null)
            KeyPresence.PRESENT -> {}
        }
        val legacy = legacyIndex(keyId).named[keyId].orEmpty() - own
        val records = LinkedHashMap<String, String>()
        for (stem in listOf(own) + legacy.sorted()) recordGeneration(stem, keyId)?.let { records[stem] = it }
        return records
    }

    /** The generation of the record named [stem]: its material's digest, or its metadata's when it has none. */
    private fun recordGeneration(stem: String, keyId: String): String? {
        val keyFile = File(dir, "$stem.key")
        val metaFile = File(dir, "$stem.meta")
        val files = listOf(filePresence(keyFile), filePresence(metaFile))
        if (KeyPresence.UNREADABLE in files) throw KeyPresenceUnreadableException(keyId, null)
        return when {
            // A file that stats but cannot be read is unreadable, never an
            // IOException out of a delete (#255 verify r2z).
            files[0] == KeyPresence.PRESENT -> SyncCodec.sha256Hex(readRecordFile(keyFile, keyId))
            files[1] == KeyPresence.PRESENT -> METADATA_ONLY + SyncCodec.sha256Hex(readRecordFile(metaFile, keyId))
            else -> null
        }
    }

    /**
     * Unlinks the record named [stem]: the material first, and the metadata
     * only once it is gone (#255 verify r5), so a failed material unlink
     * leaves the record whole and the delete's replay reads it as this id's
     * key and retries.
     */
    private fun deleteRecord(stem: String) {
        val material = File(dir, "$stem.key")
        try {
            if (unlink(material) || filePresence(material) == KeyPresence.ABSENT) unlink(File(dir, "$stem.meta"))
        } finally {
            wrote()
        }
    }

    /**
     * Delete the software key [keyId] only if it is still at [generation];
     * a key stored again since is left. A metadata-only record holds no
     * material and is what an interrupted delete of some generation left, so
     * it is retired whatever [generation] names: the replay of a delete that
     * stopped between its unlinks completes it, never reserving the id for
     * good. Each record of the id ([records]) is told apart by its own
     * generation, so an older build's record that could not be migrated is
     * deleted with the key, and one moved onto the digest name since is
     * still the one [generation] recorded (#255 review r9). Returns true
     * when no record of [generation] and no metadata-only record remains.
     */
    fun deleteGeneration(keyId: String, generation: String): Boolean {
        migrateLegacyRecords()
        val owed = generation.split(GENERATION_SEPARATOR).toSet()
        val doomed = { tag: String -> tag in owed || tag.startsWith(METADATA_ONLY) }
        for ((stem, tag) in records(keyId)) if (doomed(tag)) deleteRecord(stem)
        return records(keyId).values.none(doomed)
    }

    /** Filename stem for [keyId]: a digest, so distinct ids stay distinct. */
    private fun fileId(keyId: String): String =
        SyncCodec.sha256Hex(keyId.toByteArray(Charsets.UTF_8))

    /**
     * Renames key/metadata pairs written by older builds under the old
     * sanitised filename onto their digest name, taking the true id from the
     * metadata.
     */
    private fun migrateLegacyRecords() {
        if (migrated) return
        migrated = true
        val files = dir.listFiles() ?: return
        for (meta in files) {
            if (!meta.name.endsWith(".meta")) continue
            val stem = meta.name.removeSuffix(".meta")
            // Migrated or not is told by the id the metadata names (its
            // digest is the record's name once migrated), never by the
            // name's shape: an older build kept a 64-hex id as its name
            // (#255 verify r5).
            val keyId = runCatching { recordId(readMetadataText(meta, stem)) }.getOrNull() ?: continue
            val target = fileId(keyId)
            // Never let an old record overwrite one already written under the
            // digest name — that record is the newer of the two.
            // A digest name whose lookup fails is taken as held, never free.
            if (!migratable(stem, keyId) || filePresence(File(dir, "$target.key")) != KeyPresence.ABSENT) continue
            // The metadata moves only once the material has: a record is
            // never split between two names.
            val material = File(dir, "$stem.key")
            // A move is a write of the store: every instance's scan is redone.
            wrote()
            if (rename(material, File(dir, "$target.key")) || filePresence(material) == KeyPresence.ABSENT) {
                rename(meta, File(dir, "$target.meta"))
            }
            wrote()
        }
    }

    /**
     * Whether the record named [stem] whose metadata names [id] is an older
     * build's record of [id], to move onto [id]'s digest name (#255 verify
     * r5). One already under that name is migrated. An older build named a
     * record by its sanitised id, which is 64 lowercase hex only when the id
     * is itself that hex (kept as is): a hex name that is neither [id] nor
     * its digest was written under another id's digest, so its metadata
     * contradicts its name. It stays where it is, unreadable for that id
     * ([recordOf]) and unread for [id], never moved out of the way.
     */
    private fun migratable(stem: String, id: String): Boolean =
        stem != fileId(id) && (stem == id || !HEX_64.matches(stem))

    companion object {
        private const val KEY_ALIAS = "xkey_software_key_store"

        /** Each store directory's write count, shared by every instance over it. */
        private val WRITES = java.util.concurrent.ConcurrentHashMap<String, java.util.concurrent.atomic.AtomicLong>()

        /** The shape of a digest name, read only by [migratable]. */
        private val HEX_64 = Regex("[0-9a-f]{64}")

        /**
         * Whether [keyId] is an id a software key may have: non-empty. The
         * one key-id check (#255 verify r6), for the record reader
         * ([recordId]) and every write ([put], local.generateKey's parse)
         * alike, so no write takes an id the reader rejects.
         */
        fun isValidKeyId(keyId: String): Boolean = keyId.isNotEmpty()

        /** Prefix of a metadata-only record's [generation]. */
        const val METADATA_ONLY = "meta-only:"

        /** Between the record generations of one [generation]: no digest or [METADATA_ONLY] tag holds it. */
        private const val GENERATION_SEPARATOR = ","
    }
}
