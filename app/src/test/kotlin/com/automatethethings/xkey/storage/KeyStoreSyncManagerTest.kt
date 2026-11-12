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

import android.util.Log
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.storage.dao.KeyDao
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import java.security.KeyStore
import java.util.Collections
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test

class KeyStoreSyncManagerTest {

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.d(any(), any<String>()) } returns 0
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    /**
     * FileEncryptor's ephemeral agreement key (`xkey_key_ephemeral_<UUID>`)
     * exists only during one encryption; discovery meanwhile gives it no row,
     * so it never has sharing controls.
     */
    @Test
    fun discoveryGivesAnEphemeralFileEncryptionKeyNoRow() = runBlocking<Unit> {
        val keyStore = mockk<KeyStore>(relaxed = true)
        every { keyStore.aliases() } returns Collections.enumeration(listOf("xkey_key_ephemeral_1234"))
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance("AndroidKeyStore") } returns keyStore
        val keyDao = mockk<KeyDao>(relaxed = true)
        coEvery { keyDao.exists(any()) } returns false

        val discovered = KeyStoreSyncManager(mockk<KeystoreManager>(), mockk(relaxed = true), keyDao)
            .discoverKeystoreEntries()

        assertEquals(0, discovered)
        coVerify(exactly = 0) { keyDao.insert(any()) }
    }

    /**
     * A row's key ID maps to the aliases discovery gives that ID, never to
     * another key's: `xkey_key_a` is hardware key `a`'s alias, not one of
     * software key `xkey_key_a`'s.
     */
    @Test
    fun aKeyIdMapsOnlyToTheAliasesDiscoveredUnderIt() {
        assertEquals(
            listOf("xkey_credential_xkey_key_a", "xkey_key_xkey_key_a"),
            KeyStoreSyncManager.keystoreAliasesOf("xkey_key_a")
        )
        assertEquals(
            listOf("xkey_credential_a", "xkey_key_a", "a"),
            KeyStoreSyncManager.keystoreAliasesOf("a")
        )
        assertEquals(
            listOf("xkey_credential_xkey_root_ca", "xkey_key_xkey_root_ca", "xkey_root_ca"),
            KeyStoreSyncManager.keystoreAliasesOf("xkey_root_ca")
        )
    }
}
