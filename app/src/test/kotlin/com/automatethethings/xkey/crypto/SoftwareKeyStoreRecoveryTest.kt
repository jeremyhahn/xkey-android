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
import com.automatethethings.xkey.storage.SOFTWARE_ENTRY
import com.automatethethings.xkey.storage.deleteKeyMaterialGeneration
import com.automatethethings.xkey.storage.keyMaterialGeneration
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * #255 verify r2y: the software key store's two remaining ways to answer for
 * a key it cannot vouch for.
 *
 * - An older build's record whose metadata cannot be parsed while its
 *   material is there could be any id's: every id reads as unreadable, so a
 *   caller refuses instead of falling back to another credential under it.
 * - A delete stopped between its two unlinks leaves a metadata-only record;
 *   its generation is tracked, and the replay of the delete at the next
 *   start retires it, so the id is free again.
 */
class SoftwareKeyStoreRecoveryTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val context = mockk<Context>()

    @After
    fun tearDown() = unmockkAll()

    private fun store(filesDir: File): SoftwareKeyStore {
        every { context.filesDir } returns filesDir
        val cipher = mockk<KeystoreAeadCipher>()
        every { cipher.encrypt(any()) } answers { firstArg() }
        return SoftwareKeyStore(context, cipher)
    }

    private fun key(id: String) =
        SoftwareKey(id, "AES", "symmetric", 256, exportable = true, shareable = true, material = ByteArray(32) { 1 })

    @Test
    fun aLegacyRecordWithMalformedMetadataBesideItsMaterialIsUnreadable() {
        val filesDir = tmp.newFolder("files")
        val dir = File(filesDir, "software_keys").apply { mkdirs() }
        File(dir, "k.meta").writeText("{not json")
        File(dir, "k.key").writeBytes(ByteArray(4))
        val store = store(filesDir)

        assertEquals(KeyPresence.UNREADABLE, store.presence("k"))
        assertEquals(KeyPresence.UNREADABLE, store.presence("other"))
        val failure = runCatching { store.contains("k") }.exceptionOrNull()
        assertTrue("contains read a malformed record as no key: $failure", failure is KeyPresenceUnreadableException)
    }

    @Test
    fun aMalformedLegacyRecordNeverHidesAKeyStoredUnderTheId() {
        val filesDir = tmp.newFolder("files")
        val dir = File(filesDir, "software_keys").apply { mkdirs() }
        File(dir, "k.meta").writeText("{not json")
        File(dir, "k.key").writeBytes(ByteArray(4))
        val store = store(filesDir)
        store.put(key("held"))

        assertEquals(KeyPresence.PRESENT, store.presence("held"))
    }

    @Test
    fun aMalformedLegacyMetadataWithoutMaterialHoldsNoKey() {
        val filesDir = tmp.newFolder("files")
        val dir = File(filesDir, "software_keys").apply { mkdirs() }
        File(dir, "k.meta").writeText("{not json")
        val store = store(filesDir)

        assertEquals(KeyPresence.ABSENT, store.presence("k"))
    }

    @Test
    fun aMetadataOnlyRecordHasAGenerationAndItsDeleteRetiresIt() {
        val filesDir = tmp.newFolder("files")
        val store = store(filesDir)
        store.put(key("k"))
        val generation = store.generation("k")
        assertNotNull(generation)
        interruptDelete(filesDir, "k")

        val left = store.generation("k")
        assertNotNull("a metadata-only record had no generation", left)
        assertTrue(left!!.startsWith(SoftwareKeyStore.METADATA_ONLY))
        assertEquals(KeyPresence.PRESENT, store.presence("k"))

        // The interrupted delete's own generation: the record is retired.
        assertTrue(store.deleteGeneration("k", generation!!))
        assertEquals(null, store.generation("k"))
        assertEquals(KeyPresence.ABSENT, store.presence("k"))
    }

    @Test
    fun aDeleteOfAnotherGenerationLeavesAKeyStoredSince() {
        val filesDir = tmp.newFolder("files")
        val store = store(filesDir)
        store.put(key("k"))
        val current = store.generation("k")

        assertTrue(store.deleteGeneration("k", "an-earlier-generation"))
        assertEquals(current, store.generation("k"))
        assertEquals(KeyPresence.PRESENT, store.presence("k"))
    }

    /**
     * A process stop between the two unlinks of delete(): at the next start
     * the delete's tombstone replays ([deleteKeyMaterialGeneration] with the
     * generation it recorded), retires the metadata-only record and frees the
     * id, which a new key can take.
     */
    @Test
    fun aDeleteStoppedBetweenItsUnlinksIsCompletedByTheReplayAtRestart() {
        val filesDir = tmp.newFolder("files")
        every { context.filesDir } returns filesDir
        mockkStatic(java.security.KeyStore::class)
        every { java.security.KeyStore.getInstance(any<String>()) } returns mockk(relaxed = true)
        val keystore = mockk<KeystoreManager>(relaxed = true)
        every { keystore.userKeyGeneration(any()) } returns emptyMap()
        store(filesDir).put(key("k"))

        // The delete records its generation (its tombstone), then stops.
        val tombstone = keyMaterialGeneration(context, "k", keystore, UserKeyKind.GENERAL)
        assertTrue(SOFTWARE_ENTRY in tombstone)
        interruptDelete(filesDir, "k")
        assertEquals("the stopped delete freed the id", KeyPresence.PRESENT, store(filesDir).presence("k"))

        // Restart: a new store instance, and the tombstone's replay.
        assertTrue(deleteKeyMaterialGeneration(context, "k", tombstone, keystore))
        val restarted = store(filesDir)
        assertEquals(KeyPresence.ABSENT, restarted.presence("k"))
        assertTrue(keyMaterialGeneration(context, "k", keystore, UserKeyKind.GENERAL).isEmpty())

        // The id is reusable: a key generated or imported under it is held.
        restarted.put(key("k"))
        assertEquals(KeyPresence.PRESENT, restarted.presence("k"))
        assertFalse(restarted.generation("k")!!.startsWith(SoftwareKeyStore.METADATA_ONLY))
    }

    /** delete()'s first unlink, the material, without its second. */
    private fun interruptDelete(filesDir: File, keyId: String) {
        val stem = SyncCodec.sha256Hex(keyId.toByteArray(Charsets.UTF_8))
        val dir = File(filesDir, "software_keys")
        assertTrue(File(dir, "$stem.key").delete())
        assertTrue(File(dir, "$stem.meta").exists())
    }
}
