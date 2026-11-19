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
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.security.KeyStore
import java.util.concurrent.atomic.AtomicInteger
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
    }

    @After
    fun tearDown() {
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

    /**
     * The bypass guard of the one choke point: every software-store record
     * a delete reads or removes goes through [SoftwareKeyStore]'s record
     * walk, and the deletion path builds no store of its own past its seam.
     */
    @Test
    fun everyDeleteOfSoftwareMaterialGoesThroughTheRecordWalk() {
        val main = listOf(File("src/main/kotlin"), File("app/src/main/kotlin")).first { it.isDirectory }
        val store = File(main, "com/automatethethings/xkey/crypto/SoftwareKeyStore.kt").readText()
        assertEquals("a file of the store is unlinked outside deleteRecord", 2, Regex("""\bunlink\(""").findAll(store).count())
        assertTrue("generation reads past the record walk", "return records(keyId).values" in store)
        assertTrue("deleteGeneration reads past the record walk", "for ((stem, tag) in records(keyId)) if (doomed(tag)) deleteRecord(stem)" in store)
        assertTrue("delete skips the legacy records", "for (stem in listOf(own) + legacy.sorted()) deleteRecord(stem)" in store)
        assertFalse("the store renames a file past its seam", Regex("""\.renameTo\(""").findAll(store).count() > 1)
        val replay = File(main, "com/automatethethings/xkey/storage/KeyDeletionReplay.kt").readText()
        assertEquals("the deletion path builds a store of its own", 0, Regex("""SoftwareKeyStore\(""").findAll(replay).count())
        assertEquals("the deletion path reads past the keystore's store", 2, Regex("""keystore\.softwareKeys\(\)""").findAll(replay).count())
    }

    /**
     * #255 review: a stored key's ownership ([rowOwnerKind] through
     * [keyMaterialGeneration]) is read from the software key store the
     * [KeystoreManager] keeps. A store built per call would read the files
     * directory again and rescan every record's metadata; the kept one does
     * neither, so a record written past the store (no write it counts) stays
     * unseen until the store's own next write.
     */
    @Test
    fun ownershipResolutionReusesTheKeystoresSoftwareStore() {
        val filesDirReads = AtomicInteger()
        val counted = mockk<Context>(relaxed = true)
        every { counted.filesDir } answers { filesDirReads.incrementAndGet(); files }
        val prefs = mockk<SharedPreferences>()
        every { prefs.getString(any(), any()) } answers { secondArg() }
        every { prefs.contains(any()) } returns false
        val manager = spyk(KeystoreManager(counted))
        every { manager.ed25519Prefs() } returns prefs
        every { manager.holdsEd25519Keys() } returns true
        legacyRecord()

        val first = keyMaterialGeneration(counted, ID, manager, UserKeyKind.GENERAL)
        assertNotNull("the software record is not part of the generation", first[SOFTWARE_ENTRY])
        val store = manager.softwareKeys()
        val reads = filesDirReads.get()

        // Another record naming the id, written past the store: only a new
        // store or a rescan of the metadata would see it.
        File(files, "software_keys/${LEGACY}2.key").writeBytes(Random.nextBytes(44))
        File(files, "software_keys/${LEGACY}2.meta").writeText(JSONObject().put("keyId", ID).toString())

        repeat(3) {
            assertEquals("a repeated ownership read rescanned the store", first, keyMaterialGeneration(counted, ID, manager, UserKeyKind.GENERAL))
        }
        assertEquals(UserKeyKind.GENERAL, manager.rowOwnerKind(counted, ID, null))
        assertSame("the keystore built a second software store", store, manager.softwareKeys())
        assertEquals("an ownership read built a software store", reads, filesDirReads.get())
    }

    private companion object {
        const val ID = "k/legacy"
        const val LEGACY = "k_legacy"
    }
}
