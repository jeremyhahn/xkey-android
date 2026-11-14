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
import kotlinx.coroutines.async
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.assertEquals
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

    /** The key, policy and tombstone tables the store reads. */
    private val tables = FakeKeyPolicyTables()

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

        KeyStoreSyncManager(keystoreManager, credentialDao, keyDao, tables.store()).syncAll()

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

        KeyStoreSyncManager(keystoreManager, credentialDao, keyDao, tables.store()).syncAll()

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

        KeyStoreSyncManager(keystoreManager, credentialDao, keyDao, tables.store()).syncAll()

        coVerify(exactly = 0) { keyDao.deleteByKeyId(generalId) }
    }

    /**
     * Round 9 (2): material whose key row is deleted and whose material
     * delete is still owed (a deletion tombstone) is never listed again as a
     * key with default metadata; the replay deletes it.
     */
    @Test
    fun `a key with a pending deletion is not rediscovered`() = runTest {
        coEvery { keyDao.getAll() } returns emptyList()

        val store = tables.store()
        assertTrue(store.deleteMaterial("general-1", materialDelete { false }))

        KeyStoreSyncManager(keystoreManager, credentialDao, keyDao, store).syncAll()

        coVerify(exactly = 0) { keyDao.insert(match { it.keyId == "general-1" }) }
    }

    /**
     * Round 10 (5): a FIDO2 credential whose key row was deleted while its
     * material delete is still owed is not copied back from
     * credential_metadata either.
     */
    @Test
    fun `a credential with a pending deletion is not synced back`() = runTest {
        val credential = mockk<com.automatethethings.xkey.storage.entity.CredentialMetadataEntity>(relaxed = true)
        every { credential.credentialId } returns "cred-1"
        every { credential.rpId } returns "example.com"
        coEvery { credentialDao.getAll() } returns listOf(credential)
        coEvery { keyDao.getAll() } returns emptyList()

        val store = tables.store()
        assertTrue(store.deleteMaterial("cred-1", materialDelete { false }))

        KeyStoreSyncManager(keystoreManager, credentialDao, keyDao, store).syncAll()

        coVerify(exactly = 0) { keyDao.insert(match { it.keyId == "cred-1" }) }
    }

    /**
     * Round 11 (3): a deletion that runs while the sync is between its
     * tombstone check and its insert never ends with the key row listed
     * again under a tombstone still owed: the check and the insert are one
     * step under the key's material lock, so the delete runs after the
     * insert and finds the row.
     */
    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
    @Test
    fun `a deletion racing the sync never leaves a row under a tombstone`() = runTest {
        coEvery { keyDao.getAll() } returns emptyList()
        val store = tables.store()
        var deletion: kotlinx.coroutines.Deferred<Boolean>? = null
        coEvery { keyDao.insert(match { it.keyId == "general-1" }) } coAnswers {
            // A delete of the id starts while the sync's insert is landing.
            deletion = async(UnconfinedTestDispatcher(testScheduler)) { store.deleteMaterial("general-1", materialDelete { false }) }
            tables.addKey("general-1", com.automatethethings.xkey.storage.entity.SharingPolicyType.PRIVATE)
        }

        KeyStoreSyncManager(keystoreManager, credentialDao, keyDao, store).syncAll()
        deletion!!.await()

        val listed = tables.keyInstance("general-1") != null
        assertFalse("the sync listed a key under a tombstone still owed", listed && store.isDeletionPending("general-1"))
    }

    /** Round 10 (5) bypass guard: the sync inserts a key row in one place, its tombstone check. */
    @Test
    fun `the sync inserts key rows only through its tombstone check`() {
        val source = listOf(
            java.io.File("src/main/kotlin/com/automatethethings/xkey/storage/KeyStoreSyncManager.kt"),
            java.io.File("app/src/main/kotlin/com/automatethethings/xkey/storage/KeyStoreSyncManager.kt")
        ).first { it.isFile }.readText()
        assertEquals(1, Regex("""keyDao\.(insert|insertAll|upsert)\(""").findAll(source).count())
        assertTrue("keyPolicyStore.insertDiscovered(entity.keyId) { keyDao.insert(entity) }" in source)
    }
}
