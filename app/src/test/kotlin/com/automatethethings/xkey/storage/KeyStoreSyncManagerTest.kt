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
import kotlinx.coroutines.runBlocking
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
        every { keystoreManager.holdsAnyKey(any()) } returns true
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
        every { keystoreManager.holdsAnyKey(pivAlias) } returns false

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
        every { keystoreManager.holdsAnyKey(generalId) } returns true

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

        val discovered = KeyStoreSyncManager(mockk<KeystoreManager>(), mockk(relaxed = true), keyDao, tables.store())
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

    /**
     * Codex round 3 (#270): a user key whose ID equals an internal alias
     * (`xkey_key_xkey_seal_store_key`, key `xkey_seal_store_key`) is the
     * key the row names, so the internal alias of the same name never marks
     * that row protected, whichever alias the Keystore lists first.
     */
    @Test
    fun aUserKeyNamedLikeAnInternalAliasStaysAUserKey() = runBlocking<Unit> {
        val internal = "xkey_seal_store_key"
        val user = "xkey_key_$internal"
        every { keyStore.containsAlias(any()) } answers { firstArg<String>() in setOf(internal, user) }
        val userRow = KeyEntity(keyId = internal, keyType = "signing", algorithm = "ES256", label = internal, keySizeBits = 256, source = "local")
        coEvery { keyDao.getByKeyId(internal) } returns userRow
        val inserted = mutableListOf<KeyEntity>()
        coEvery { keyDao.insert(capture(inserted)) } returns 1L

        for (order in listOf(listOf(internal, user), listOf(user, internal))) {
            every { keyStore.aliases() } answers { Collections.enumeration(order) }
            // The row is new: discovery inserts it from whichever alias it meets.
            coEvery { keyDao.exists(internal) } returns false
            KeyStoreSyncManager(keystoreManager, credentialDao, keyDao, tables.store()).discoverKeystoreEntries()
            // The row exists: the internal alias must not flip it to a system key.
            coEvery { keyDao.exists(internal) } returns true
            KeyStoreSyncManager(keystoreManager, credentialDao, keyDao, tables.store()).discoverKeystoreEntries()
        }

        assertTrue("the user key was never discovered", inserted.any { it.keyId == internal })
        assertFalse("the user key was listed as a system key", inserted.any { it.keyId == internal && it.isSystemKey })
        coVerify(exactly = 0) { keyDao.update(match { it.keyId == internal && it.isSystemKey }) }
        // The internal alias itself stays protected from a user delete.
        assertTrue(KeyStoreSyncManager.isProtectedAlias(internal))
        assertFalse(KeyStoreSyncManager.isProtectedAlias(user))
    }

    /** The internal key alone keeps the protection an earlier sync failed to give its row. */
    @Test
    fun anInternalKeyRowIsStillMarkedProtected() = runBlocking<Unit> {
        val internal = "xkey_seal_store_key"
        every { keyStore.aliases() } answers { Collections.enumeration(listOf(internal)) }
        every { keyStore.containsAlias(any()) } answers { firstArg<String>() == internal }
        coEvery { keyDao.exists(internal) } returns true
        coEvery { keyDao.getByKeyId(internal) } returns
            KeyEntity(keyId = internal, keyType = "signing", algorithm = "ES256", label = internal, keySizeBits = 256, source = "local")

        KeyStoreSyncManager(keystoreManager, credentialDao, keyDao, tables.store()).discoverKeystoreEntries()

        coVerify(exactly = 1) { keyDao.update(match { it.keyId == internal && it.isSystemKey }) }
    }
}
