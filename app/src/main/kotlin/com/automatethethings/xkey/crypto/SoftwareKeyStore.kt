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
    private val cipher: KeystoreAeadCipher = KeystoreAeadCipher(KEY_ALIAS)
) {
    private val dir: File = File(context.filesDir, "software_keys").apply { mkdirs() }

    private var migrated = false

    /** Store (or replace) a software key, encrypting its material at rest. */
    fun put(key: SoftwareKey) {
        migrateLegacyRecords()
        val id = fileId(key.keyId)
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
    }

    /** Retrieve a software key by id (material decrypted), or null. */
    fun get(keyId: String): SoftwareKey? {
        migrateLegacyRecords()
        val id = fileId(keyId)
        val keyFile = File(dir, "$id.key")
        val metaFile = File(dir, "$id.meta")
        // The one presence probe (#255 review r8): a file whose lookup fails
        // is unreadable, never a key that is not there.
        val files = listOf(filePresence(keyFile), filePresence(metaFile))
        if (KeyPresence.UNREADABLE in files) throw KeyPresenceUnreadableException(keyId, null)
        if (KeyPresence.ABSENT in files) return null
        val meta = JSONObject(metaFile.readText())
        return SoftwareKey(
            keyId = meta.optString("keyId", keyId),
            algorithm = meta.optString("algorithm", ""),
            keyType = meta.optString("keyType", "symmetric"),
            keySize = meta.optInt("keySize", 0),
            exportable = meta.optBoolean("exportable", false),
            shareable = meta.optBoolean("shareable", false),
            material = cipher.decrypt(keyFile.readBytes())
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
                    val id = fileId(keyId)
                    val files = listOf(filePresence(File(dir, "$id.key")), filePresence(File(dir, "$id.meta")))
                    when {
                        KeyPresence.PRESENT in files -> KeyPresence.PRESENT
                        KeyPresence.UNREADABLE in files -> KeyPresence.UNREADABLE
                        else -> legacyRecordOf(keyId)
                    }
                }
            }
        } catch (e: Exception) {
            KeyPresence.UNREADABLE
        }

    /**
     * What an older build's records left under their old names (their
     * migration found the digest name taken, or could not rename) hold of
     * [keyId]. A record whose file cannot be read is taken as [keyId]'s, so
     * an unreadable record never reads as absent. A record whose metadata
     * cannot be parsed while its material is there (or cannot be probed)
     * could be any id's: it is [KeyPresence.UNREADABLE], never a record of
     * another id, so a caller refuses rather than fall back to another
     * credential under [keyId] (#255 verify r2y). One whose metadata parses
     * but names no id, or which holds no material, is attributable to none,
     * as the migration finds.
     */
    private fun legacyRecordOf(keyId: String): KeyPresence {
        var unreadable = false
        for (meta in dir.listFiles() ?: throw KeyPresenceUnreadableException(keyId, null)) {
            if (!meta.name.endsWith(".meta")) continue
            val stem = meta.name.removeSuffix(".meta")
            if (DIGEST_NAME.matches(stem)) continue
            val text = try {
                meta.readText()
            } catch (e: java.io.IOException) {
                return KeyPresence.PRESENT
            }
            val id = try {
                JSONObject(text).optString("keyId", "")
            } catch (e: org.json.JSONException) {
                if (filePresence(File(dir, "$stem.key")) != KeyPresence.ABSENT) unreadable = true
                continue
            }
            if (id == keyId) return KeyPresence.PRESENT
        }
        return if (unreadable) KeyPresence.UNREADABLE else KeyPresence.ABSENT
    }

    /** Delete a software key by id. */
    fun delete(keyId: String) {
        migrateLegacyRecords()
        val id = fileId(keyId)
        File(dir, "$id.key").delete()
        File(dir, "$id.meta").delete()
    }

    /**
     * The generation of the software key [keyId]: a digest of its encrypted
     * material, which [put] rewrites under a fresh IV, so a key stored again
     * under the same id has another generation. A metadata-only record (a
     * [delete] stopped between its two unlinks; [put] writes the material
     * first, so nothing else leaves one) has a [METADATA_ONLY] generation,
     * so a delete tracks it as well as the material (#255 verify r2y). Null
     * if neither file is stored.
     */
    fun generation(keyId: String): String? {
        migrateLegacyRecords()
        val id = fileId(keyId)
        val keyFile = File(dir, "$id.key")
        val metaFile = File(dir, "$id.meta")
        val files = listOf(filePresence(keyFile), filePresence(metaFile))
        if (KeyPresence.UNREADABLE in files) throw KeyPresenceUnreadableException(keyId, null)
        return when {
            files[0] == KeyPresence.PRESENT -> SyncCodec.sha256Hex(keyFile.readBytes())
            files[1] == KeyPresence.PRESENT -> METADATA_ONLY + SyncCodec.sha256Hex(metaFile.readBytes())
            else -> null
        }
    }

    /**
     * Delete the software key [keyId] only if it is still at [generation];
     * a key stored again since is left. A metadata-only record holds no
     * material and is what an interrupted delete of some generation left, so
     * it is retired whatever [generation] names: the replay of a delete that
     * stopped between its unlinks completes it, never reserving the id for
     * good. Returns true when no material of [generation] and no
     * metadata-only record remains.
     */
    fun deleteGeneration(keyId: String, generation: String): Boolean {
        val current = generation(keyId)
        if (current == generation || current?.startsWith(METADATA_ONLY) == true) delete(keyId)
        val left = generation(keyId)
        return left != generation && left?.startsWith(METADATA_ONLY) != true
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
            if (DIGEST_NAME.matches(stem)) continue
            val keyId = runCatching { JSONObject(meta.readText()).optString("keyId", "") }
                .getOrDefault("")
            if (keyId.isEmpty()) continue
            val target = fileId(keyId)
            // Never let an old record overwrite one already written under the
            // digest name — that record is the newer of the two.
            // A digest name whose lookup fails is taken as held, never free.
            if (target == stem || filePresence(File(dir, "$target.key")) != KeyPresence.ABSENT) continue
            File(dir, "$stem.key").renameTo(File(dir, "$target.key"))
            meta.renameTo(File(dir, "$target.meta"))
        }
    }

    companion object {
        private const val KEY_ALIAS = "xkey_software_key_store"

        /** A filename stem already produced by [fileId]. */
        private val DIGEST_NAME = Regex("[0-9a-f]{64}")

        /** Prefix of a metadata-only record's [generation]. */
        const val METADATA_ONLY = "meta-only:"
    }
}
