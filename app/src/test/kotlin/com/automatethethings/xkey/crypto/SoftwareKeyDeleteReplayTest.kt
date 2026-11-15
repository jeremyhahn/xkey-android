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
import android.content.SharedPreferences
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.spyk
import io.mockk.unmockkAll
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.security.KeyStore
import java.security.MessageDigest

/**
 * #255 verify r5: a software key delete ignored its first unlink. When the
 * material's unlink failed and the metadata's succeeded, the material was
 * left with no metadata; it read as unreadable, so every replay of the
 * acknowledged delete threw in its presence checks before it could retry
 * the unlink, and the key's material stayed for good. The delete now
 * removes the metadata only once the material is gone, and a replay over
 * a material-only or metadata-only leftover finishes the delete.
 */
class SoftwareKeyDeleteReplayTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private lateinit var filesDir: File
    private lateinit var keystore: KeystoreManager

    /** Whether the material's unlink fails, as an I/O error would. */
    private var materialUnlinkFails = false

    private lateinit var store: SoftwareKeyStore

    @Before
    fun setUp() {
        mockkStatic(android.util.Log::class)
        every { android.util.Log.d(any(), any<String>()) } returns 0
        every { android.util.Log.w(any(), any<String>()) } returns 0
        every { android.util.Log.w(any(), any<String>(), any()) } returns 0
        val platform = mockk<KeyStore>(relaxed = true)
        every { platform.containsAlias(any()) } returns false
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance(any<String>()) } returns platform
        val prefs = mockk<SharedPreferences>()
        every { prefs.contains(any()) } returns false
        every { prefs.getString(any(), any()) } answers { secondArg() }
        filesDir = tmp.newFolder()
        val context = mockk<Context>()
        every { context.filesDir } returns filesDir
        val cipher = mockk<KeystoreAeadCipher>()
        every { cipher.encrypt(any()) } answers { firstArg<ByteArray>().copyOf() }
        every { cipher.decrypt(any()) } answers { firstArg<ByteArray>().copyOf() }
        store = SoftwareKeyStore(context, cipher) { file ->
            if (materialUnlinkFails && file.name.endsWith(".key")) false else file.delete()
        }
        keystore = spyk(KeystoreManager(mockk<Context>(relaxed = true)))
        every { keystore.ed25519Prefs() } returns prefs
        every { keystore.softwareKeys() } returns store
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    private val dir get() = File(filesDir, "software_keys")

    private fun file(suffix: String) = File(dir, digest(ID) + suffix)

    @Test
    fun aFailedMaterialUnlinkKeepsTheRecordWholeAndItsReplayFinishesTheDelete() {
        store.put(SoftwareKey(ID, "AES", "symmetric", 256, exportable = true, shareable = true, material = ByteArray(32) { 3 }))
        val generation = store.generation(ID)!!

        materialUnlinkFails = true
        assertFalse("a delete whose material unlink failed reported done", store.deleteGeneration(ID, generation))
        assertTrue("the material is left", file(".key").isFile)
        assertTrue("the metadata went before the material", file(".meta").isFile)
        assertReplayable()

        materialUnlinkFails = false
        assertTrue("the replay did not finish the delete", store.deleteGeneration(ID, generation))
        assertGone()
    }

    /** What an older build's delete left: the material, its metadata gone. */
    @Test
    fun aMaterialOnlyLeftoverIsReplayedToACompleteDelete() {
        dir.mkdirs()
        file(".key").writeBytes(ByteArray(32) { 3 })
        val generation = store.generation(ID)!!
        assertReplayable()
        assertTrue("the replay did not finish the delete", store.deleteGeneration(ID, generation))
        assertGone()
    }

    /** A delete stopped between its unlinks: the metadata, its material gone. */
    @Test
    fun aMetadataOnlyLeftoverIsReplayedToACompleteDelete() {
        dir.mkdirs()
        file(".meta").writeText("""{"keyId":"$ID"}""")
        assertReplayable()
        assertTrue("the replay did not finish the delete", store.deleteGeneration(ID, "an earlier generation"))
        assertGone()
    }

    /**
     * #255 verify r2z (2): a metadata-only record whose stat succeeds but
     * whose read fails threw an IOException out of the delete's generation
     * read, past the screens' refusal, and crashed the app. The delete is
     * now refused as a store that cannot be read, nothing deleted.
     */
    @Test
    fun aDeleteOverAnUnreadableMetadataOnlyRecordIsRefusedNotACrash() = kotlinx.coroutines.test.runTest {
        dir.mkdirs()
        // Listed and stat'ed, but every read of it fails.
        assertTrue(file(".meta").mkdirs())
        assertThrowsUnreadable { store.generation(ID) }
        val dao = mockk<com.automatethethings.xkey.storage.dao.KeyPolicyDao>(relaxed = true) {
            io.mockk.coEvery { deletion(any()) } returns null
            io.mockk.coEvery { keyInstance(any()) } returns 1L
        }
        val policies = com.automatethethings.xkey.storage.KeyPolicyStore(dao, object : com.automatethethings.xkey.storage.KeyPolicyStore.Transactor {
            override suspend fun <T> run(block: suspend () -> T): T = block()
        })
        val key = mockk<com.automatethethings.xkey.storage.entity.KeyEntity> {
            every { keyId } returns ID
            every { id } returns 1L
            every { isSystemKey } returns false
        }

        val outcome = com.automatethethings.xkey.ui.deleteUserKey(
            key, policies, com.automatethethings.xkey.storage.keyMaterialDeleter(mockk(relaxed = true), keystore)
        )

        assertTrue("the delete was not refused: $outcome", outcome is com.automatethethings.xkey.ui.UserKeyDelete.Refused)
        io.mockk.coVerify(exactly = 0) { dao.putDeletion(any<com.automatethethings.xkey.storage.entity.KeyDeletionEntity>()) }
        assertTrue("the record was deleted", file(".meta").isDirectory)
    }

    /**
     * #255 verify r2z (1): an older build's record whose metadata is listed
     * but cannot be read could be any id's: it is unreadable for every id,
     * never read as an id's key, so no internal key reads as a user key.
     */
    @Test
    fun anUnreadableLegacyRecordIsUnreadableNeverAnIdsKey() {
        dir.mkdirs()
        assertTrue(File(dir, "legacy_record.meta").mkdirs())
        assertEquals(KeyPresence.UNREADABLE, store.presence("xkey_seal_store_key"))
        assertEquals(KeyPresence.UNREADABLE, store.presence(ID))
        assertThrowsUnreadable { keystore.userKeyIdInUse("xkey_seal_store_key") }
        assertThrowsUnreadable { keystore.holdsInternalKey("xkey_seal_store_key") }
        assertThrowsUnreadable { store.get(ID) }
    }

    private inline fun assertThrowsUnreadable(read: () -> Any?) {
        try {
            read()
        } catch (e: KeyPresenceUnreadableException) {
            return
        }
        throw AssertionError("read as readable")
    }

    /** The replay's checks of the id read the leftover as the id's key, never a refusal. */
    private fun assertReplayable() {
        assertEquals(KeyPresence.PRESENT, store.presence(ID))
        assertTrue(keystore.userKeyIdInUse(ID))
        assertFalse(keystore.holdsInternalKey(ID))
    }

    private fun assertGone() {
        assertFalse(file(".key").exists())
        assertFalse(file(".meta").exists())
        assertEquals(KeyPresence.ABSENT, store.presence(ID))
        assertNull(store.generation(ID))
    }

    private fun digest(id: String): String =
        MessageDigest.getInstance("SHA-256").digest(id.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }

    private companion object {
        const val ID = "deleted-key"
    }
}
