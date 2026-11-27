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
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.spyk
import io.mockk.unmockkAll
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeFalse
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.security.KeyStore

/**
 * #255 review r8: a software key store directory that can be listed but not
 * searched (read but no execute permission) lists its key files, yet every
 * lookup of one fails. File.exists() answers false on that failure, so the
 * store read its stored key as absent and export fell back to a credential
 * sharing the id, or a second key could be created under it. Presence is
 * probed with [filePresence], which tells a missing file from a failed
 * lookup: the store is unreadable, and export and key creation refuse.
 */
class SoftwareKeyStoreSearchProbeTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private lateinit var dir: File
    private lateinit var store: SoftwareKeyStore
    private lateinit var keystore: KeystoreManager

    /** Keystore aliases present. */
    private val entries = HashSet<String>()

    @Before
    fun setUp() {
        // Main's shared ML-DSA store is per process: each test starts with none.
        com.automatethethings.xkey.crypto.PqcSoftwareKeyStore.clearSharedForTest()
        mockkStatic(android.util.Log::class)
        every { android.util.Log.d(any(), any<String>()) } returns 0
        every { android.util.Log.w(any(), any<String>()) } returns 0
        every { android.util.Log.w(any(), any<String>(), any()) } returns 0
        val filesDir = tmp.newFolder("files")
        val context = mockk<Context>()
        every { context.filesDir } returns filesDir
        val cipher = mockk<KeystoreAeadCipher>()
        every { cipher.encrypt(any()) } answers { firstArg() }
        every { cipher.decrypt(any()) } answers { firstArg() }
        store = SoftwareKeyStore(context, cipher)
        dir = File(filesDir, "software_keys")

        val platform = mockk<KeyStore>(relaxed = true)
        every { platform.containsAlias(any()) } answers { firstArg<String>() in entries }
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance(any<String>()) } returns platform
        keystore = spyk(KeystoreManager(mockk<Context>(relaxed = true)))
        every { keystore.ed25519Presence(any()) } returns KeyPresence.ABSENT
        every { keystore.softwareKeys() } returns store
    }

    @After
    fun tearDown() {
        com.automatethethings.xkey.crypto.PqcSoftwareKeyStore.clearSharedForTest()
        dir.setExecutable(true, false)
        unmockkAll()
    }

    /** Stores [SHARED] in software and makes [dir] listable but not searchable. */
    private fun unsearchable() {
        store.put(SoftwareKey(SHARED, "AES", "symmetric", 256, exportable = true, shareable = true, material = ByteArray(32)))
        entries += KeystoreManager.userKeyAlias(SHARED, UserKeyKind.CREDENTIAL)
        assertEquals(KeyPresence.PRESENT, store.presence(SHARED))
        assertTrue(dir.setExecutable(false, false))
        // Root searches any directory: the case cannot arise there.
        assumeFalse("running as root", File(dir, dir.list()!!.first()).exists())
        assertTrue("the directory still lists", dir.list()!!.isNotEmpty())
    }

    @Test
    fun aMissingFileIsAbsentAndAFailedLookupUnreadable() {
        assertEquals(KeyPresence.ABSENT, filePresence(File(dir, "none.key")))
        unsearchable()
        val listed = File(dir, dir.list()!!.first())
        assertEquals(KeyPresence.UNREADABLE, filePresence(listed))
        assertEquals(KeyPresence.UNREADABLE, filePresence(File(dir, "none.key")))
    }

    @Test
    fun aListableButUnsearchableStoreIsUnreadableNeverAbsent() {
        unsearchable()
        assertEquals(KeyPresence.UNREADABLE, store.presence(SHARED))
        assertEquals(KeyPresence.UNREADABLE, store.presence("never-stored"))
        assertRefuses("contains") { store.contains(SHARED) }
        assertRefuses("get") { store.get(SHARED) }
        assertRefuses("generation") { store.generation(SHARED) }
    }

    @Test
    fun exportAndKeyCreationRefuseOnAnUnsearchableStore() {
        unsearchable()
        // The credential sharing the id is never exported in the software key's place.
        assertRefuses("exportKind") { keystore.exportKind(SHARED) }
        // A second key is never created under the software key's id.
        assertRefuses("userKeyIdInUse") { keystore.userKeyIdInUse(SHARED) }
        assertRefuses("userKeyIdInUse(new id)") { keystore.userKeyIdInUse("never-stored") }
    }

    @Test
    fun noKeyStorePresenceProbeUsesFileExists() {
        val main = listOf(File("src/main/kotlin"), File("app/src/main/kotlin")).first { it.isDirectory }
        val probes = Regex("""\.(exists|isFile)\(\)""")
        for (name in listOf("SoftwareKeyStore.kt", "KeystoreManager.kt")) {
            val text = File(main, "com/automatethethings/xkey/crypto/$name").readLines()
                .filterNot { it.trimStart().startsWith("*") || it.trimStart().startsWith("//") }
            val found = text.filter { probes.containsMatchIn(it) }
            assertTrue("$name probes key presence with File.exists()/isFile(): $found", found.isEmpty())
        }
    }

    private fun assertRefuses(what: String, block: () -> Any?) {
        val failure = runCatching { block() }.exceptionOrNull()
        assertTrue("$what read an unsearchable store as absent: $failure", failure is KeyPresenceUnreadableException)
    }

    private companion object {
        const val SHARED = "shared-id"
    }
}
