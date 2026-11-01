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
package com.automatethethings.xkey.crypto

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.KeyStore
import java.security.SecureRandom

/**
 * Instrumented tests for how [SoftwareKeyStore] derives a filename from a key
 * id.
 *
 * The store used to build one by replacing every character outside
 * `[A-Za-z0-9._-]` with `_`, which maps `a/b`, `a:b`, and `a b` onto the same
 * name. In a key store that is not a cosmetic problem: storing one key
 * overwrote an unrelated key's material, and the victim then decrypted,
 * signed, or exported with someone else's bytes under its own metadata. Key ids
 * reach this store from the desktop over the pairing channel, so the colliding
 * shapes are not hypothetical.
 *
 * Naming files by a digest of the id removes the collision class entirely.
 *
 * Each run uses its own [KeystoreAeadCipher] alias so it cannot disturb the
 * shared `xkey_software_key_store` key, and removes that alias afterwards.
 */
@RunWith(AndroidJUnit4::class)
class SoftwareKeyStoreNamingTest {

    private val suffix = System.nanoTime()
    private val cipherAlias = "test_software_key_naming_$suffix"

    private lateinit var context: Context
    private lateinit var store: SoftwareKeyStore
    private lateinit var directory: File

    private val storedIds = mutableListOf<String>()

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        store = SoftwareKeyStore(context, KeystoreAeadCipher(cipherAlias))
        directory = File(context.filesDir, "software_keys")
    }

    @After
    fun tearDown() {
        storedIds.forEach { store.delete(it) }
        storedIds.clear()
        runCatching {
            KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(cipherAlias)
        }
    }

    private fun newKeyId(label: String): String =
        "sw-$label-$suffix".also { storedIds.add(it) }

    private fun softwareKey(
        keyId: String,
        material: ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }
    ) = SoftwareKey(
        keyId = keyId,
        algorithm = "AES-256",
        keyType = "symmetric",
        keySize = 256,
        exportable = true,
        shareable = true,
        material = material
    )

    /** The filename stem [SoftwareKeyStore] uses for [keyId]. */
    private fun stem(keyId: String) = SyncCodec.sha256Hex(keyId.toByteArray(Charsets.UTF_8))

    private fun legacyStem(keyId: String) = keyId.replace(Regex("[^A-Za-z0-9._-]"), "_")

    // -------------------------------------------------------------------------
    // Distinct ids stay distinct
    // -------------------------------------------------------------------------

    @Test
    fun put_keepsEveryPunctuationVariantOfAnIdSeparate() {
        val ids = listOf(
            "sw dup-$suffix",
            "sw;dup-$suffix",
            "sw=dup-$suffix",
            "sw@dup-$suffix"
        ).onEach { storedIds.add(it) }

        ids.forEachIndexed { index, id ->
            store.put(softwareKey(id, ByteArray(32) { index.toByte() }))
        }

        ids.forEachIndexed { index, id ->
            assertArrayEquals(
                "'$id' must keep its own material",
                ByteArray(32) { index.toByte() },
                store.get(id)!!.material
            )
        }
    }

    @Test
    fun contains_answersOnlyForTheExactId() {
        val keyId = "sw/exact-$suffix".also { storedIds.add(it) }
        store.put(softwareKey(keyId))

        assertTrue(store.contains(keyId))
        assertFalse(
            "a mangled spelling must not resolve to a stored key",
            store.contains(legacyStem(keyId))
        )
    }

    @Test
    fun delete_removesOnlyTheKeyItWasGiven() {
        val target = "sw/delete-$suffix".also { storedIds.add(it) }
        val neighbour = "sw:delete-$suffix".also { storedIds.add(it) }
        store.put(softwareKey(target))
        store.put(softwareKey(neighbour))

        store.delete(target)

        assertFalse(store.contains(target))
        assertTrue("deleting one key must leave its former filename neighbour alone", store.contains(neighbour))
    }

    @Test
    fun put_namesFilesByADigestOfTheId() {
        val keyId = newKeyId("digest")
        store.put(softwareKey(keyId))

        assertTrue(File(directory, "${stem(keyId)}.key").exists())
        assertTrue(File(directory, "${stem(keyId)}.meta").exists())
        assertFalse(
            "an id must not appear in a filename in any recoverable form",
            File(directory, "${legacyStem(keyId)}.key").exists()
        )
    }

    @Test
    fun get_returnsTheOriginalIdentifier() {
        val keyId = "sw/original id:$suffix".also { storedIds.add(it) }
        store.put(softwareKey(keyId))

        assertEquals(keyId, store.get(keyId)!!.keyId)
    }

    // -------------------------------------------------------------------------
    // Records written by an older build
    // -------------------------------------------------------------------------

    @Test
    fun aRecordFromAnOlderBuildIsFoundUnderItsId() {
        val keyId = "sw/legacy-$suffix".also { storedIds.add(it) }
        val material = ByteArray(32) { 0x5A }
        store.put(softwareKey(keyId, material))

        // Put the record back where the previous build would have written it.
        renameRecord(from = stem(keyId), to = legacyStem(keyId))

        val migrating = SoftwareKeyStore(context, KeystoreAeadCipher(cipherAlias))
        val recovered = migrating.get(keyId)

        assertNotNull("an existing key must not become unreachable", recovered)
        assertArrayEquals(material, recovered!!.material)
        assertEquals(keyId, recovered.keyId)
    }

    @Test
    fun aRecordFromAnOlderBuildIsMovedOntoItsDigestName() {
        val keyId = "sw/legacy-move-$suffix".also { storedIds.add(it) }
        store.put(softwareKey(keyId))
        renameRecord(from = stem(keyId), to = legacyStem(keyId))

        SoftwareKeyStore(context, KeystoreAeadCipher(cipherAlias)).contains(keyId)

        assertTrue(File(directory, "${stem(keyId)}.key").exists())
        assertFalse("the old pair is moved, not copied", File(directory, "${legacyStem(keyId)}.key").exists())
        assertFalse(File(directory, "${legacyStem(keyId)}.meta").exists())
    }

    private fun renameRecord(from: String, to: String) {
        assertTrue(File(directory, "$from.key").renameTo(File(directory, "$to.key")))
        assertTrue(File(directory, "$from.meta").renameTo(File(directory, "$to.meta")))
    }
}
