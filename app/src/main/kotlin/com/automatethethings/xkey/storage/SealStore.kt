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
package com.automatethethings.xkey.storage

import com.automatethethings.xkey.crypto.KeystoreAeadCipher
import com.automatethethings.xkey.crypto.SyncCodec
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.File
import java.io.IOException
import java.nio.file.DirectoryIteratorException
import java.nio.file.Files

/**
 * The store exists but cannot be enumerated, or a listed secret's name cannot
 * be read. Never taken for an empty store or a missing secret:
 * that would hide its secrets, so the RPC answers INTERNAL_ERROR.
 */
class SealStoreUnreadableException(cause: IOException) : IOException("seal store cannot be read", cause)

/**
 * The phone's sealed-secret store: named secrets go-xkms seals to this device
 * over USB (`SealStorePut`), each encrypted at rest under a Keystore AES-GCM
 * key that never leaves the TEE.
 *
 * Laid out like [com.automatethethings.xkey.crypto.SoftwareKeyStore]: a secret
 * is `<sha256-hex-of-name>.sealed` (ciphertext) plus `<sha256-hex-of-name>.name`
 * (the name itself, which is not secret), so distinct names never share a file.
 * Each file is written to a temporary file and renamed into place, the name
 * first, so a ciphertext on disk always has its name: a secret that can be read
 * is always listed.
 *
 * @param dir App-private directory the store owns.
 */
class SealStore(
    private val dir: File,
    private val cipher: KeystoreAeadCipher = KeystoreAeadCipher(KEY_ALIAS)
) {
    companion object {
        private const val KEY_ALIAS = "xkey_seal_store_key"

        /** `SealStoreStatusResponse.sealer_id`: what seals the secrets. */
        const val SEALER_ID = "android-keystore"

        private const val SEALED_SUFFIX = ".sealed"
        private const val NAME_SUFFIX = ".name"
    }

    private val mutex = Mutex()

    /** Seals [secret] under [name], replacing any secret of that name. */
    suspend fun put(name: String, secret: ByteArray) = mutex.withLock {
        withContext(Dispatchers.IO) { write(name, cipher.encrypt(secret)) }
    }

    /**
     * The unsealed secret named [name], or null if there is none.
     *
     * @throws IOException if the ciphertext cannot be looked up or read.
     */
    suspend fun get(name: String): ByteArray? = withContext(Dispatchers.IO) {
        readSealed(name)?.let { cipher.decrypt(it) }
    }

    /**
     * Deletes the secret named [name]. Returns false if there was none.
     *
     * Throws [IOException] if the ciphertext is there but cannot be removed,
     * and keeps its name, so the secret still lists. The name goes only once
     * the ciphertext is gone; if removing it fails, the secret is gone anyway
     * and [list] skips a name without ciphertext.
     */
    suspend fun delete(name: String): Boolean = mutex.withLock {
        withContext(Dispatchers.IO) {
            val id = fileId(name)
            val existed = Files.deleteIfExists(File(dir, id + SEALED_SUFFIX).toPath())
            try {
                Files.deleteIfExists(File(dir, id + NAME_SUFFIX).toPath())
            } catch (e: IOException) {
                // A name without ciphertext lists nothing and a later put rewrites it.
            }
            existed
        }
    }

    /**
     * Re-seals the secret named [name] under a fresh IV with the current
     * Keystore key. Returns false if there is no such secret. The plaintext is
     * held only between the decrypt and the encrypt, and wiped after.
     */
    suspend fun reseal(name: String): Boolean = mutex.withLock {
        withContext(Dispatchers.IO) {
            val sealed = readSealed(name) ?: return@withContext false
            val plaintext = cipher.decrypt(sealed)
            try {
                write(name, cipher.encrypt(plaintext))
            } finally {
                plaintext.fill(0)
            }
            true
        }
    }

    /**
     * Every secret's name, sorted. A store never written lists empty.
     *
     * @throws SealStoreUnreadableException if the store exists but cannot be
     *   enumerated or a listed name cannot be read: never an empty list, which
     *   would hide the secrets.
     */
    suspend fun list(): List<String> = withContext(Dispatchers.IO) {
        // Not File.listFiles(): it answers null for a failed enumeration as
        // well as for a missing directory.
        val entries = try {
            Files.newDirectoryStream(dir.toPath()).use { stream -> stream.map { it.fileName.toString() }.toSet() }
        } catch (e: java.nio.file.NoSuchFileException) {
            return@withContext emptyList()
        } catch (e: IOException) {
            throw SealStoreUnreadableException(e)
        } catch (e: DirectoryIteratorException) {
            // Its constructor requires a cause, but the type admits none.
            throw SealStoreUnreadableException(e.cause ?: IOException(e))
        }
        // Pairs from the one enumeration, not File.exists(), which answers
        // false when the lookup fails.
        entries.filter { it.endsWith(NAME_SUFFIX) }
            .filter { it.removeSuffix(NAME_SUFFIX) + SEALED_SUFFIX in entries }
            .mapNotNull { nameFile ->
                try {
                    String(Files.readAllBytes(File(dir, nameFile).toPath()), Charsets.UTF_8)
                } catch (e: java.nio.file.NoSuchFileException) {
                    null // deleted since the enumeration
                } catch (e: IOException) {
                    throw SealStoreUnreadableException(e)
                }
            }
            .sorted()
    }

    /**
     * The ciphertext of [name], or null if it is not there. Not File.exists(),
     * which answers false when the lookup fails and would report a secret
     * that cannot be read as missing; such a failure throws [IOException].
     */
    private fun readSealed(name: String): ByteArray? =
        try {
            Files.readAllBytes(File(dir, fileId(name) + SEALED_SUFFIX).toPath())
        } catch (e: java.nio.file.NoSuchFileException) {
            null
        }

    private fun write(name: String, ciphertext: ByteArray) {
        dir.mkdirs()
        val id = fileId(name)
        // The name first: a write that fails between the two leaves at worst a
        // name without ciphertext, which list() skips, never a hidden secret.
        replace(File(dir, id + NAME_SUFFIX), name.toByteArray(Charsets.UTF_8))
        replace(File(dir, id + SEALED_SUFFIX), ciphertext)
    }

    /** Writes [bytes] to a temporary file and renames it over [target]. */
    private fun replace(target: File, bytes: ByteArray) {
        val tmp = File(dir, target.name + ".tmp")
        tmp.writeBytes(bytes)
        if (!tmp.renameTo(target)) {
            tmp.delete()
            throw IOException("failed to persist sealed secret")
        }
    }

    /** Filename stem for [name]: a digest, so distinct names stay distinct. */
    private fun fileId(name: String): String = SyncCodec.sha256Hex(name.toByteArray(Charsets.UTF_8))
}
