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
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * #255 review r6: the software key store's presence probe is three-way. A
 * stored key is present, an id never stored is absent, and a store that
 * cannot be listed is unreadable, never absent; [SoftwareKeyStore.contains]
 * refuses on it rather than reading it as no key.
 */
class SoftwareKeyStorePresenceTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private fun store(filesDir: File): SoftwareKeyStore {
        val context = mockk<Context>()
        every { context.filesDir } returns filesDir
        val cipher = mockk<KeystoreAeadCipher>()
        every { cipher.encrypt(any()) } answers { firstArg() }
        return SoftwareKeyStore(context, cipher)
    }

    @Test
    fun aStoredKeyIsPresentAndAnotherIdAbsent() {
        val store = store(tmp.root)
        store.put(SoftwareKey("k", "AES", "symmetric", 256, exportable = true, shareable = true, material = ByteArray(32)))
        assertEquals(KeyPresence.PRESENT, store.presence("k"))
        assertEquals(KeyPresence.ABSENT, store.presence("other"))
        assertTrue(store.contains("k"))
    }

    @Test
    fun aStoreThatCannotBeListedIsUnreadable() {
        // The store's directory is a plain file: it exists but lists nothing.
        val filesDir = tmp.newFolder("files")
        File(filesDir, "software_keys").writeText("not a directory")
        val store = store(filesDir)
        assertEquals(KeyPresence.UNREADABLE, store.presence("k"))
        val failure = runCatching { store.contains("k") }.exceptionOrNull()
        assertTrue("contains read an unreadable store as absent: $failure", failure is KeyPresenceUnreadableException)
    }

    @Test
    fun aRecordOfAnOlderBuildIsPresent() {
        val filesDir = tmp.newFolder("files")
        val dir = File(filesDir, "software_keys").apply { mkdirs() }
        // An older build's record of "k", under its old sanitised name.
        File(dir, "k.meta").writeText("""{"keyId":"k"}""")
        File(dir, "k.key").writeBytes(ByteArray(4))
        val store = store(filesDir)
        assertEquals(KeyPresence.PRESENT, store.presence("k"))
        assertEquals(KeyPresence.ABSENT, store.presence("other"))
    }
}
