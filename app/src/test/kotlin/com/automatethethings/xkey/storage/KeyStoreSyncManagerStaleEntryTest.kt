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
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.storage.dao.CredentialMetadataDao
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.KeyEntity
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.spyk
import io.mockk.unmockkAll
import io.mockk.verify
import java.security.KeyStore
import java.util.Collections
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Before
import org.junit.Test

/**
 * A software key store that cannot be read says nothing about whether a key
 * is in it. The sync removes a key row only when the key is definitely
 * absent, so an unreadable store keeps every row it could hold, and the
 * failure is logged as an error instead of passing as a stale entry.
 */
class KeyStoreSyncManagerStaleEntryTest {

    private lateinit var keyStore: KeyStore

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.d(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>(), any()) } returns 0
        every { Log.e(any(), any<String>()) } returns 0
        every { Log.e(any(), any<String>(), any()) } returns 0
        keyStore = mockk(relaxed = true)
        every { keyStore.containsAlias(any()) } returns false
        every { keyStore.aliases() } answers { Collections.emptyEnumeration() }
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance("AndroidKeyStore") } returns keyStore
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `sync keeps a key row while the software key store cannot be read`() = runBlocking<Unit> {
        val manager = spyk(KeystoreManager(mockk<Context>(relaxed = true)))
        every { manager.softwareEd25519Supported() } returns true
        every { manager.ed25519Prefs() } throws IllegalStateException("master key unreadable")
        val credentialDao = mockk<CredentialMetadataDao>(relaxed = true)
        coEvery { credentialDao.getAll() } returns emptyList()
        val keyDao = mockk<KeyDao>(relaxed = true)
        val key = mockk<KeyEntity>(relaxed = true)
        every { key.keyId } returns "ed"
        every { key.source } returns "local"
        coEvery { keyDao.getAll() } returns listOf(key)

        KeyStoreSyncManager(manager, credentialDao, keyDao).syncAll()

        coVerify(exactly = 0) { keyDao.deleteByKeyId(any()) }
        verify { Log.e(any(), match<String> { "ed" in it }, any()) }
    }

    @Test
    fun `sync still removes the row of a key absent from a readable store`() = runBlocking<Unit> {
        val prefs = mockk<SharedPreferences>()
        every { prefs.contains(any()) } returns false
        val manager = spyk(KeystoreManager(mockk<Context>(relaxed = true)))
        every { manager.softwareEd25519Supported() } returns true
        every { manager.ed25519Prefs() } returns prefs
        val credentialDao = mockk<CredentialMetadataDao>(relaxed = true)
        coEvery { credentialDao.getAll() } returns emptyList()
        val keyDao = mockk<KeyDao>(relaxed = true)
        val key = mockk<KeyEntity>(relaxed = true)
        every { key.keyId } returns "gone"
        every { key.source } returns "local"
        coEvery { keyDao.getAll() } returns listOf(key)

        KeyStoreSyncManager(manager, credentialDao, keyDao).syncAll()

        coVerify { keyDao.deleteByKeyId("gone") }
    }
}
