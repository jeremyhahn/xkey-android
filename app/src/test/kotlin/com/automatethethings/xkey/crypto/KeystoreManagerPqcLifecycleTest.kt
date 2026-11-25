/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
 *
 * This file is part of xkey-android.
 *
 * xkey-android is dual-licensed:
 *
 * 1. GNU Affero General Public License v3.0 (AGPL-3.0)
 *    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
 *
 * 2. Commercial License
 *    Contact licensing@automatethethings.com for commercial licensing options.
 */

package com.automatethethings.xkey.crypto

import android.content.Context
import android.util.Log
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.storage.KeyStoreSyncManager
import com.automatethethings.xkey.storage.dao.CredentialMetadataDao
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.FakeKeyPolicyTables
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import com.automatethethings.xkey.storage.keyMaterialDeleter
import com.automatethethings.xkey.ui.UserKeyDelete
import com.automatethethings.xkey.ui.deleteUserKey
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mockk.verify
import java.io.File
import java.security.KeyStore
import java.util.Collections
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * A software ML-DSA key through [KeystoreManager] from generation to
 * deletion: it keeps the user-authentication policy it was made with however
 * a caller asks it to sign, and once its key goes, nothing signs with it.
 */
class KeystoreManagerPqcLifecycleTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val keyStore = mockk<KeyStore>(relaxed = true)
    private lateinit var context: Context
    private lateinit var store: PqcSoftwareKeyStore
    private lateinit var manager: KeystoreManager
    private lateinit var defaultClock: () -> Long

    /** The fake clock's time, in the store's clock base. */
    private var now = 1_000_000L

    @Before
    fun setUp() {
        // Main's shared ML-DSA store is per process: each test starts with none.
        com.automatethethings.xkey.crypto.PqcSoftwareKeyStore.clearSharedForTest()
        mockkStatic(Log::class)
        every { Log.d(any(), any<String>()) } returns 0
        every { Log.i(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>(), any()) } returns 0
        every { Log.e(any(), any<String>()) } returns 0
        every { Log.e(any(), any<String>(), any()) } returns 0

        every { keyStore.containsAlias(any()) } returns false
        every { keyStore.aliases() } answers { Collections.emptyEnumeration() }
        every { keyStore.getCertificate(any()) } returns null
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance("AndroidKeyStore") } returns keyStore

        mockkObject(AuditLogger)
        every { AuditLogger.logKeyCreated(any(), any(), any(), any(), any()) } returns Unit
        every { AuditLogger.logKeyDeleted(any(), any(), any()) } returns Unit

        // A stand-in seal: the bytes reversed.
        val cipher = mockk<KeystoreAeadCipher>()
        every { cipher.encrypt(any()) } answers { firstArg<ByteArray>().reversedArray() }
        every { cipher.decrypt(any()) } answers { firstArg<ByteArray>().reversedArray() }
        context = mockk(relaxed = true)
        every { context.filesDir } returns tmp.root
        every { context.applicationContext } returns context
        store = PqcSoftwareKeyStore(context, cipher)

        defaultClock = PqcSoftwareKeyStore.clock
        PqcSoftwareKeyStore.clock = { now }
        manager = KeystoreManager(context, sdkInt = 34, pqcStore = store)
    }

    @After
    fun tearDown() {
        com.automatethethings.xkey.crypto.PqcSoftwareKeyStore.clearSharedForTest()
        PqcSoftwareKeyStore.clock = defaultClock
        unmockkAll()
    }

    private fun generate(keyId: String, authDurationSeconds: Int): ByteArray =
        manager.generateMlDsaKey(keyId, SET, PqcBacking.SOFTWARE, authDurationSeconds = authDurationSeconds)

    private fun signApproved(keyId: String, spki: ByteArray, userAuthenticatedAt: Long? = null): ByteArray =
        runBlocking {
            manager.signApprovedMlDsa(KeystoreManager.generalKeyAlias(keyId), spki, DATA, SET, userAuthenticatedAt)
        }

    @Test
    fun `a per-use software key refuses to sign without a user authentication`() {
        val spki = generate("perUse", 0)

        assertTrue(manager.pqcSoftwareKeyRequiresUserAuth("perUse"))
        assertThrows(BiometricRequiredException::class.java) { signApproved("perUse", spki) }
        assertThrows("an old authentication is not this use", BiometricRequiredException::class.java) {
            signApproved("perUse", spki, userAuthenticatedAt = now - 60_000)
        }
        assertEquals(SET.signatureBytes, signApproved("perUse", spki, userAuthenticatedAt = now).size)
    }

    @Test
    fun `a time-window software key signs only inside its window`() {
        val spki = generate("window", 30)

        assertTrue(manager.pqcSoftwareKeyRequiresUserAuth("window"))
        assertThrows(BiometricRequiredException::class.java) { signApproved("window", spki) }
        assertThrows(BiometricRequiredException::class.java) {
            signApproved("window", spki, userAuthenticatedAt = now - 31_000)
        }
        assertThrows("an authentication from the future is refused", BiometricRequiredException::class.java) {
            signApproved("window", spki, userAuthenticatedAt = now + 1_000)
        }
        assertEquals(SET.signatureBytes, signApproved("window", spki, userAuthenticatedAt = now - 10_000).size)
    }

    @Test
    fun `a software key made without user authentication signs without one`() {
        val spki = generate("open", -1)

        assertFalse(manager.pqcSoftwareKeyRequiresUserAuth("open"))
        assertEquals(SET.signatureBytes, signApproved("open", spki).size)
    }

    @Test
    fun `a caller that skips the manager and signs through the store is refused too`() {
        generate("direct", 0)
        val alias = KeystoreManager.generalKeyAlias("direct")

        assertThrows(BiometricRequiredException::class.java) { store.sign(alias, SET, DATA) }
        assertEquals(SET.signatureBytes, store.sign(alias, SET, DATA, userAuthenticatedAt = now).size)
    }

    private fun row(keyId: String) = KeyEntity(
        keyId = keyId, keyType = "signing", algorithm = SET.wireName, label = keyId,
        keySizeBits = SET.publicKeyBytes * 8, source = "local"
    )

    @Test
    fun `a full sync keeps the row of a live software key and drops one whose record is gone`() {
        generate("live", -1)
        generate("gone", -1)
        store.delete(KeystoreManager.generalKeyAlias("gone"))
        val rows = listOf(row("live"), row("gone"))
        val deleted = mutableListOf<String>()
        val keyDao = mockk<KeyDao>(relaxed = true)
        coEvery { keyDao.getAll() } returns rows
        coEvery { keyDao.deleteByKeyId(any()) } answers { deleted += firstArg<String>(); 1 }
        coEvery { keyDao.countAll() } returns rows.size
        val credentialDao = mockk<CredentialMetadataDao>(relaxed = true)
        coEvery { credentialDao.getAll() } returns emptyList()

        assertTrue(manager.keyMaterialExists("live"))
        assertFalse(manager.keyMaterialExists("gone"))
        runBlocking { KeyStoreSyncManager(manager, credentialDao, keyDao, FakeKeyPolicyTables().store()).syncAll() }

        assertEquals(listOf("gone"), deleted)
    }

    /** Deletes [keyId]'s key row through the app's one user key delete. */
    private fun deleteRow(tables: FakeKeyPolicyTables, keyId: String, keystore: KeystoreManager = manager): UserKeyDelete =
        runBlocking {
            deleteUserKey(
                tables.key(keyId)!!, tables.store(), keyMaterialDeleter(context, keystore, UserKeyKind.GENERAL)
            )
        }

    private fun rowOf(tables: FakeKeyPolicyTables, keyId: String, spki: ByteArray) {
        tables.addKey(keyId, SharingPolicyType.PRIVATE, keyType = "signing", publicKeyDer = spki, source = "local")
    }

    @Test
    fun `deleting the row of a software key deletes its record and it signs no more`() {
        val spki = generate("doomed", -1)
        val tables = FakeKeyPolicyTables()
        rowOf(tables, "doomed", spki)

        assertEquals(UserKeyDelete.DELETED, deleteRow(tables, "doomed"))

        assertNull(tables.key("doomed"))
        assertTrue("no delete is left owed", tables.deletions.value.isEmpty())
        assertFalse(manager.pqcSoftwareKeyExists("doomed"))
        assertFalse(manager.generalKeyExists("doomed"))
        assertThrows(KeyNotFoundException::class.java) { signApproved("doomed", spki) }
    }

    @Test
    fun `a software key whose record cannot be removed stays owed and is never reported gone`() {
        val spki = generate("stuck", -1)
        store.removeFile = { false }
        val tables = FakeKeyPolicyTables()
        rowOf(tables, "stuck", spki)

        deleteRow(tables, "stuck")
        assertTrue(runCatching { manager.deleteGeneralKey("stuck") }.isFailure)
        assertEquals(GeneratedKeyDiscard.FAILED, manager.deleteKey("stuck", UserKeyKind.GENERAL))

        // The record is left, so its delete stays owed until a replay removes it.
        assertTrue(manager.pqcSoftwareKeyExists("stuck"))
        assertTrue("the delete is not owed", "stuck" in tables.deletions.value)
        assertTrue(runBlocking { tables.store().isDeletionPending("stuck") })

        store.removeFile = { it.delete() }
        runBlocking { tables.store().replayDeletions(keyMaterialDeleter(context, manager)) }
        assertFalse(manager.pqcSoftwareKeyExists("stuck"))
        assertTrue(tables.deletions.value.isEmpty())
        assertThrows(KeyNotFoundException::class.java) { signApproved("stuck", spki) }
    }

    @Test
    fun `no general-key delete path reports a key gone when the store delete throws`() {
        val spki = generate("held", -1)
        val failing = io.mockk.spyk(store)
        every { failing.delete(any()) } throws java.io.IOException("Cannot delete ML-DSA key")
        val held = KeystoreManager(context, sdkInt = 34, pqcStore = failing)
        val tables = FakeKeyPolicyTables()
        rowOf(tables, "held", spki)

        deleteRow(tables, "held", held)
        assertTrue(runCatching { held.deleteGeneralKey("held") }.isFailure)
        assertEquals(GeneratedKeyDiscard.FAILED, held.deleteKey("held", UserKeyKind.GENERAL))

        assertTrue(held.pqcSoftwareKeyExists("held"))
        assertTrue("the delete is not owed", "held" in tables.deletions.value)
    }

    @Test
    fun `no internal wrap key is resolved or deleted and a software key still signs`() {
        val spki = generate("kept", -1)
        every { keyStore.containsAlias(any()) } answers { firstArg<String>() in INTERNAL_ALIASES }

        for (alias in INTERNAL_ALIASES) {
            assertNull(alias, manager.resolveKeystoreAlias(alias, UserKeyKind.GENERAL))
            assertFalse(alias, manager.deleteByAlias(alias))
            assertNotEquals(alias, GeneratedKeyDiscard.DELETED, manager.deleteKey(alias, UserKeyKind.GENERAL))
        }

        verify(exactly = 0) { keyStore.deleteEntry(any()) }
        assertEquals(SET.signatureBytes, signApproved("kept", spki).size)
    }

    @Test
    fun `a software key whose ID is a Keystore key's alias is not shadowed by that key`() {
        val spki = generate("xkey_key_a", -1)
        val hardwareDer = java.security.KeyPairGenerator.getInstance("EC").generateKeyPair().public.encoded
        val certificate = mockk<java.security.cert.Certificate>()
        every { certificate.publicKey.encoded } returns hardwareDer
        every { keyStore.containsAlias("xkey_key_a") } returns true
        every { keyStore.getCertificate("xkey_key_a") } returns certificate

        assertEquals(KeystoreManager.generalKeyAlias("xkey_key_a"), manager.resolveKeystoreAlias("xkey_key_a", UserKeyKind.GENERAL))
        assertArrayEquals(spki, manager.getPublicKeyDER("xkey_key_a", UserKeyKind.GENERAL))
        assertEquals(KeySecurityLevel.SOFTWARE, manager.keySecurityLevel("xkey_key_a", UserKeyKind.GENERAL))

        assertTrue(manager.deleteGeneralKey("xkey_key_a"))
        verify(exactly = 0) { keyStore.deleteEntry("xkey_key_a") }
        assertFalse(manager.pqcSoftwareKeyExists("xkey_key_a"))
        assertTrue("key a is left", manager.generalKeyExists("a"))
        assertArrayEquals(hardwareDer, manager.getPublicKeyDER("a", UserKeyKind.GENERAL))
    }

    @Test
    fun `no raw-alias check of a key ID runs outside resolveKeystoreAlias`() {
        val source = File("src/main/kotlin/com/automatethethings/xkey/crypto/KeystoreManager.kt").readText()
        val rawCheck = Regex("""keyStore\.containsAlias\(keyId\)|hasSoftwareEd25519Key\(keyId\)""")
        val function = Regex("""fun (\w+)\(""")
        val checks = rawCheck.findAll(source).toList()
        assertTrue("the resolver keeps its raw-alias fallback", checks.isNotEmpty())
        for (check in checks) {
            val owner = function.findAll(source.substring(0, check.range.first)).last().groupValues[1]
            // rawAlias is the one raw-alias probe the presence checks share (#255).
            assertTrue("raw-alias check at offset ${check.range.first} in $owner", owner in setOf("resolveKeystoreAlias", "rawAlias"))
        }
    }

    @Test
    fun `every alias a KeystoreAeadCipher is built with in the app is internal`() {
        val call = Regex("""KeystoreAeadCipher\((\w+)\)""")
        val seen = mutableSetOf<String>()
        File("src/main/kotlin").walk().filter { it.extension == "kt" }.forEach { file ->
            val text = file.readText()
            for (match in call.findAll(text)) {
                val name = match.groupValues[1]
                val declaration = Regex("""val $name\s*=\s*KeystoreAeadCipher\.(\w+)""").find(text)
                    ?: throw AssertionError("${file.name}: $name is not taken from KeystoreAeadCipher's internal aliases")
                val alias = KeystoreAeadCipher::class.java.getField(declaration.groupValues[1]).get(null) as String
                assertTrue("${file.name}: $alias", KeystoreAeadCipher.isInternalAlias(alias))
                seen += alias
            }
        }
        assertEquals(4, seen.size)
        for (set in MlDsaParameterSet.entries) {
            assertTrue(KeystoreAeadCipher.isInternalAlias(KeystorePqcBackend.probeAlias(set)))
        }
    }

    private companion object {
        val INTERNAL_ALIASES = listOf(
            "xkey_pqc_wrap", "xkey_software_key_store", "xkey_password_encryption_key",
            "xkey_seal_store_key", "xkey_oath_secret_encryption_key", "xkey_pqc_probe_ml_dsa_44"
        )
        val SET = MlDsaParameterSet.ML_DSA_44
        val DATA = "message".toByteArray()
    }
}
