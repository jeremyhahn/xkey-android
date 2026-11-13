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
import com.automatethethings.xkey.piv.PivSlot
import com.automatethethings.xkey.piv.PivTestCertificates
import com.automatethethings.xkey.storage.dao.CredentialMetadataDao
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.KeyEntity
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Before
import org.junit.Test
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.util.Collections

/**
 * A PIV slot key (`xkey_piv_*`) belongs to [com.automatethethings.xkey.piv.PivKeyManager]
 * and its `piv_slots` row. If the sync listed it as a general key, the key
 * management screen could delete it behind `piv_slots`, leaving a row that
 * claims a key the Keystore no longer holds (#173).
 */
class KeyStoreSyncManagerTest {

    private lateinit var keyStore: KeyStore
    private lateinit var keystoreManager: KeystoreManager
    private lateinit var credentialDao: CredentialMetadataDao
    private lateinit var keyDao: KeyDao

    private val pivAlias = PivSlot.AUTHENTICATION.keystoreAlias
    private val generalAlias = "xkey_key_general-1"

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.d(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>(), any()) } returns 0

        val certificate = CertificateFactory.getInstance("X.509").generateCertificate(
            PivTestCertificates.selfSigned(PivTestCertificates.ecKeyPair()).inputStream()
        )
        keyStore = mockk(relaxed = true)
        every { keyStore.aliases() } answers { Collections.enumeration(listOf(pivAlias, generalAlias)) }
        every { keyStore.getCertificate(any()) } returns certificate
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance("AndroidKeyStore") } returns keyStore

        keystoreManager = mockk(relaxed = true)
        every { keystoreManager.resolveKeystoreAlias(any()) } answers { firstArg() }
        credentialDao = mockk(relaxed = true)
        coEvery { credentialDao.getAll() } returns emptyList()
        keyDao = mockk(relaxed = true)
        coEvery { keyDao.exists(any()) } returns false
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `a PIV slot alias is not discovered as a general key`() = runTest {
        coEvery { keyDao.getAll() } returns emptyList()

        KeyStoreSyncManager(keystoreManager, credentialDao, keyDao).syncAll()

        coVerify(exactly = 0) { keyDao.insert(match { it.keyId.startsWith("xkey_piv_") }) }
        coVerify { keyDao.insert(match { it.keyId == "general-1" }) }
    }

    @Test
    fun `a PIV slot alias listed by an earlier sync is removed from the keys table`() = runTest {
        val listed = mockk<KeyEntity>(relaxed = true)
        every { listed.keyId } returns pivAlias
        every { listed.source } returns "local"
        coEvery { keyDao.getAll() } returns listOf(listed)
        // KeystoreManager never resolves a raw PIV slot alias.
        every { keystoreManager.resolveKeystoreAlias(pivAlias) } returns null

        KeyStoreSyncManager(keystoreManager, credentialDao, keyDao).syncAll()

        coVerify { keyDao.deleteByKeyId(pivAlias) }
    }

    @Test
    fun `a general key whose logical id starts with the PIV prefix is kept`() = runTest {
        val generalId = "xkey_piv_example"
        val listed = mockk<KeyEntity>(relaxed = true)
        every { listed.keyId } returns generalId
        every { listed.source } returns "local"
        coEvery { keyDao.getAll() } returns listOf(listed)
        // local.generateKey stores it at the general alias xkey_key_<keyId>.
        every { keystoreManager.resolveKeystoreAlias(generalId) } returns "xkey_key_$generalId"

        KeyStoreSyncManager(keystoreManager, credentialDao, keyDao).syncAll()

        coVerify(exactly = 0) { keyDao.deleteByKeyId(generalId) }
    }
}
