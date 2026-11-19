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

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import com.automatethethings.xkey.crypto.KeyPresence
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.SoftwareKeyStore
import com.automatethethings.xkey.crypto.UserKeyKind
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.spyk
import io.mockk.unmockkAll
import kotlinx.coroutines.test.runTest
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.security.KeyStore
import kotlin.random.Random

/**
 * #255 review r9: an older build's record of a software key that cannot be
 * moved onto its digest name is still the key's material. A delete of the
 * key records it, keeps its tombstone (and so the deleted-key gate) while
 * it remains, and replays until it is gone, whether the record is unlinked
 * where it lies or moved onto the digest name first.
 */
class UnmigratedSoftwareKeyDeletionTest {

    private lateinit var files: File
    private lateinit var context: Context
    private lateinit var keystore: KeystoreManager

    /** Whether the store's file moves (the legacy migration) succeed. */
    private var renames = false

    /** Whether unlinks of the legacy record succeed. */
    private var legacyUnlinks = false

    private val restore = softwareKeyStoreOf

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.d(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>(), any()) } returns 0
        every { Log.e(any(), any<String>(), any()) } returns 0
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance(any<String>()) } returns mockk(relaxed = true)

        files = java.nio.file.Files.createTempDirectory("software-keys").toFile()
        context = mockk(relaxed = true)
        every { context.filesDir } returns files
        val prefs = mockk<SharedPreferences>()
        every { prefs.getString(any(), any()) } answers { secondArg() }
        every { prefs.contains(any()) } returns false
        keystore = spyk(KeystoreManager(context))
        every { keystore.ed25519Prefs() } returns prefs
        every { keystore.holdsEd25519Keys() } returns true
        // Every reader of the store moves and unlinks as the test says.
        every { keystore.softwareKeys() } answers { store() }

        softwareKeyStoreOf = { store(it) }
    }

    @After
    fun tearDown() {
        softwareKeyStoreOf = restore
        files.deleteRecursively()
        unmockkAll()
    }

    private fun store(context: Context = this.context) = SoftwareKeyStore(
        context,
        unlink = { file -> if (!legacyUnlinks && file.name.startsWith(LEGACY)) false else file.delete() },
        rename = { from, to -> renames && from.renameTo(to) }
    )

    private val legacyFiles get() = listOf(File(files, "software_keys/$LEGACY.key"), File(files, "software_keys/$LEGACY.meta"))

    /** An older build's record of [ID], under its old sanitised name. */
    private fun legacyRecord() {
        val dir = File(files, "software_keys").apply { mkdirs() }
        File(dir, "$LEGACY.key").writeBytes(Random.nextBytes(44))
        File(dir, "$LEGACY.meta").writeText(
            JSONObject().put("keyId", ID).put("algorithm", "AES256-GCM").put("keyType", "symmetric")
                .put("keySize", 256).put("exportable", true).put("shareable", true).toString()
        )
    }

    @Test
    fun anUnmigratedRecordIsTheKeysGeneration() {
        legacyRecord()
        assertEquals(KeyPresence.PRESENT, store().presence(ID))
        assertNotNull("presence and generation disagree on the unmigrated record", store().generation(ID))
    }

    @Test
    fun aDeleteKeepsItsTombstoneUntilTheUnmigratedRecordIsUnlinked() = runTest {
        legacyRecord()
        val tables = FakeKeyPolicyTables()
        val instance = tables.addKey(ID, SharingPolicyType.ALL_PEERS)
        val store = tables.store()

        store.deleteKey(ID, instance, keyMaterialDeleter(context, keystore, UserKeyKind.GENERAL))
        assertTrue("the legacy record went though its unlink failed", legacyFiles.all { it.exists() })
        assertNotNull("the tombstone was dropped while the legacy material remains", tables.deletions.value[ID])
        val use = runCatching { store.withUsableKey(ID, UserKeyKind.GENERAL) { store().get(ID) } }.exceptionOrNull()
        assertTrue("the deleted key was usable: $use", use is KeyPolicyStore.KeyDeletedException)

        replayKeyDeletions(context, store, keystore)
        assertNotNull("a replay that deleted nothing dropped the tombstone", tables.deletions.value[ID])

        legacyUnlinks = true
        replayKeyDeletions(context, store, keystore)
        assertFalse("the legacy record survived the replay", legacyFiles.any { it.exists() })
        assertEquals(KeyPresence.ABSENT, store().presence(ID))
        assertEquals("the replay left the tombstone", null, tables.deletions.value[ID])
    }

    @Test
    fun aRecordMovedOntoItsDigestNameSinceIsStillTheOneOwed() = runTest {
        legacyRecord()
        val tables = FakeKeyPolicyTables()
        val instance = tables.addKey(ID, SharingPolicyType.ALL_PEERS)
        val store = tables.store()

        store.deleteKey(ID, instance, keyMaterialDeleter(context, keystore, UserKeyKind.GENERAL))
        assertNotNull(tables.deletions.value[ID])

        renames = true
        replayKeyDeletions(context, store, keystore)
        assertEquals("the moved record survived the replay", KeyPresence.ABSENT, store().presence(ID))
        assertTrue("the software store still holds files", File(files, "software_keys").listFiles().orEmpty().isEmpty())
        assertEquals("the replay left the tombstone", null, tables.deletions.value[ID])
    }

    private companion object {
        const val ID = "k/legacy"
        const val LEGACY = "k_legacy"
    }
}
