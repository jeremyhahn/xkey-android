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
import com.automatethethings.xkey.crypto.KeystoreAeadCipher
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.SoftwareKey
import com.automatethethings.xkey.crypto.SoftwareKeyStore
import com.automatethethings.xkey.crypto.UserKeyKind
import com.automatethethings.xkey.storage.entity.KeyDeletionEntity
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkStatic
import io.mockk.spyk
import io.mockk.unmockkAll
import kotlinx.coroutines.async
import kotlinx.coroutines.test.runCurrent
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.security.KeyStore
import java.security.cert.Certificate
import java.util.Date
import kotlin.random.Random

/**
 * The app's confirming deleter, [deleteKeyMaterial], against a real
 * [KeystoreManager] and [SoftwareKeyStore]: it must delete the material of
 * every key type the app stores and report success only once none is left
 * (#193 r12 (3)). The Android Keystore, the Ed25519 preferences and the
 * Keystore cipher of the software store are in-memory fakes.
 */
class KeyDeletionMaterialTypesTest {

    /** Keystore entries: alias to (creation date, certificate bytes or null). */
    private val entries = HashMap<String, Pair<Date, ByteArray?>>()

    /** The Ed25519 preferences. */
    private val ed25519 = HashMap<String, String>()

    /** Keystore aliases whose delete fails. */
    private val stuck = HashSet<String>()

    private lateinit var files: File
    private lateinit var context: Context
    private lateinit var keystore: KeystoreManager
    private var clock = 1_000L

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.d(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>(), any()) } returns 0

        val platform = mockk<KeyStore>(relaxed = true)
        every { platform.containsAlias(any()) } answers { firstArg<String>() in entries }
        every { platform.getCreationDate(any()) } answers { entries[firstArg()]?.first }
        every { platform.getCertificate(any()) } answers {
            entries[firstArg()]?.second?.let { bytes -> mockk<Certificate> { every { encoded } returns bytes } }
        }
        every { platform.deleteEntry(any()) } answers {
            if (firstArg<String>() in stuck) throw java.security.KeyStoreException("stuck")
            entries.remove(firstArg<String>()); Unit
        }
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance(any<String>()) } returns platform

        // The software store's cipher: a fresh IV per encryption, as the
        // Keystore AES-GCM cipher draws one.
        mockkConstructor(KeystoreAeadCipher::class)
        every { anyConstructed<KeystoreAeadCipher>().encrypt(any()) } answers { Random.nextBytes(12) + firstArg<ByteArray>() }
        every { anyConstructed<KeystoreAeadCipher>().decrypt(any()) } answers { firstArg<ByteArray>().copyOfRange(12, firstArg<ByteArray>().size) }

        files = java.nio.file.Files.createTempDirectory("software-keys").toFile()
        context = mockk(relaxed = true)
        every { context.filesDir } returns files

        val prefs = mockk<SharedPreferences>()
        every { prefs.getString(any(), any()) } answers { ed25519[firstArg()] ?: secondArg() }
        every { prefs.contains(any()) } answers { firstArg<String>() in ed25519 }
        every { prefs.edit() } answers {
            val editor = mockk<SharedPreferences.Editor>()
            every { editor.remove(any()) } answers { ed25519.remove(firstArg<String>()); editor }
            every { editor.commit() } returns true
            editor
        }
        keystore = spyk(KeystoreManager(context))
        every { keystore.ed25519Prefs() } returns prefs
    }

    @After
    fun tearDown() {
        files.deleteRecursively()
        unmockkAll()
    }

    private fun keystoreKey(alias: String, certificate: Boolean) {
        entries[alias] = Date(clock++) to (if (certificate) Random.nextBytes(64) else null)
    }

    private fun softwareKey(id: String) {
        SoftwareKeyStore(context).put(SoftwareKey(id, "AES256-GCM", "symmetric", 256, true, true, Random.nextBytes(32)))
    }

    private fun held(id: String) = KeyPolicyStore.KeyMaterialHeld(id)

    /** A delete of [id]'s material as it is now, as the store records and runs it. */
    private fun delete(id: String, source: String): Boolean {
        val generation = readKeyMaterialGeneration(context, held(id), source, keystore)
        return deleteKeyMaterial(context, held(id), KeyDeletionEntity(id, 1L, source, generation), keystore)
    }

    @Test
    fun anEcCredentialKeyIsDeleted() {
        keystoreKey("xkey_credential_k", certificate = true)
        assertTrue(delete("k", "android"))
        assertTrue(entries.isEmpty())
    }

    @Test
    fun anRsaGeneralKeyIsDeleted() {
        keystoreKey("xkey_key_k", certificate = true)
        assertTrue(delete("k", "android"))
        assertTrue(entries.isEmpty())
    }

    /** AES and HMAC Keystore keys have no certificate. */
    @Test
    fun aSymmetricKeystoreKeyIsDeleted() {
        keystoreKey("xkey_key_aes", certificate = false)
        keystoreKey("xkey_key_hmac", certificate = false)
        assertTrue(delete("aes", "android"))
        assertTrue(delete("hmac", "android"))
        assertTrue(entries.isEmpty())
    }

    /** Round 12 (3): Ed25519 material lives in the preferences, not the Keystore. */
    @Test
    fun anEd25519KeyIsDeleted() {
        ed25519["xkey_key_k"] = "c2VjcmV0"
        assertTrue("the deleter reported an Ed25519 key it cannot delete", delete("k", "android"))
        assertTrue("the Ed25519 key is still stored", ed25519.isEmpty())
    }

    @Test
    fun aSoftwareKeyIsDeleted() {
        softwareKey("k")
        assertTrue(delete("k", "android"))
        assertFalse(SoftwareKeyStore(context).contains("k"))
    }

    @Test
    fun everyBackendOfOneIdIsDeleted() {
        keystoreKey("xkey_credential_k", certificate = true)
        keystoreKey("xkey_key_k", certificate = false)
        ed25519["xkey_key_k"] = "c2VjcmV0"
        softwareKey("k")
        assertTrue(delete("k", "android"))
        assertTrue(entries.isEmpty())
        assertTrue(ed25519.isEmpty())
        assertFalse(SoftwareKeyStore(context).contains("k"))
    }

    /**
     * Material that stays (a backend refusing the delete) is reported. The
     * fake behaves as SharedPreferences does: remove() takes the entry out
     * of the in-memory cache at once, and commit() = false means the disk
     * still holds it. The cached absence must not count as a delete
     * (#255 review): the tombstone stays owed and a replay retries it.
     */
    @Test
    fun anEd25519KeyWhoseCommitFailsStaysOwed() {
        ed25519["xkey_key_k"] = "c2VjcmV0"
        val prefs = keystore.ed25519Prefs()!!
        every { prefs.edit() } answers {
            val editor = mockk<SharedPreferences.Editor>()
            every { editor.remove(any()) } answers { ed25519.remove(firstArg<String>()); editor }
            every { editor.commit() } returns false
            editor
        }
        assertFalse("a failed commit was reported as a delete", delete("k", "android"))
    }

    /**
     * An Ed25519 store that cannot be opened is never read as an empty one
     * (#255 review): capturing the generation throws, so the delete is
     * refused before its tombstone or any row removal.
     */
    @Test
    fun anUnreadableEd25519StoreRefusesTheDelete() {
        ed25519["xkey_key_k"] = "c2VjcmV0"
        every { keystore.ed25519Prefs() } throws java.security.GeneralSecurityException("master key unavailable")
        val refused = runCatching { readKeyMaterialGeneration(context, held("k"), "android", keystore) }
        assertTrue("an unreadable Ed25519 store was read as empty", refused.isFailure)
        assertEquals(setOf("xkey_key_k"), ed25519.keys)
    }

    /** A delete of [id]'s [kind] key, as the store records and runs it. */
    private fun delete(id: String, kind: UserKeyKind): Boolean {
        val generation = readKeyMaterialGeneration(context, held(id), "android", keystore, kind)
        return deleteKeyMaterial(context, held(id), KeyDeletionEntity(id, 1L, "android", generation), keystore)
    }

    /**
     * A credential and a general key sharing an id (#255 review): deleting
     * the credential leaves the general key's Keystore, Ed25519 and software
     * material, and the generation it records names none of them.
     */
    @Test
    fun aCredentialDeleteLeavesTheGeneralKeyUnderItsId() {
        keystoreKey("xkey_credential_k", certificate = true)
        keystoreKey("xkey_key_k", certificate = true)
        ed25519["xkey_key_k"] = "c2VjcmV0"
        softwareKey("k")
        val recorded = readKeyMaterialGeneration(context, held("k"), "android", keystore, UserKeyKind.CREDENTIAL)!!
        assertTrue("the credential's generation names another key: $recorded", "xkey_credential_k" in recorded)
        assertFalse("xkey_key_k" in recorded || "software" in recorded)

        assertTrue(delete("k", UserKeyKind.CREDENTIAL))
        assertEquals(setOf("xkey_key_k"), entries.keys)
        assertEquals(setOf("xkey_key_k"), ed25519.keys)
        assertTrue(SoftwareKeyStore(context).contains("k"))
    }

    /** The other direction: deleting the general key leaves the credential. */
    @Test
    fun aGeneralKeyDeleteLeavesTheCredentialUnderItsId() {
        keystoreKey("xkey_credential_k", certificate = true)
        keystoreKey("xkey_key_k", certificate = true)
        ed25519["xkey_credential_k"] = "c2VjcmV0"
        softwareKey("k")
        assertTrue(delete("k", UserKeyKind.GENERAL))
        assertEquals(setOf("xkey_credential_k"), entries.keys)
        assertEquals(setOf("xkey_credential_k"), ed25519.keys)
        assertFalse(SoftwareKeyStore(context).contains("k"))
    }

    /** Which key an RPC delete of a shared id names. */
    @Test
    fun anRpcDeleteNamesOneKeyOfASharedId() {
        val both = setOf("keystore:xkey_credential_k", "keystore:xkey_key_k")
        val general = setOf("software")
        // Legacy deleteKey names a credential.
        assertEquals(UserKeyKind.CREDENTIAL, KeystoreManager.deleteTarget("k", "ec", both, legacy = true))
        assertEquals(UserKeyKind.GENERAL, KeystoreManager.deleteTarget("k", "ec", general, legacy = true))
        // local.deleteKey names the row's key, else a general key.
        assertEquals(UserKeyKind.GENERAL, KeystoreManager.deleteTarget("k", "ec", both, legacy = false))
        assertEquals(UserKeyKind.CREDENTIAL, KeystoreManager.deleteTarget("k", "fido2", both, legacy = false))
        assertEquals(UserKeyKind.GENERAL, KeystoreManager.deleteTarget("k", null, general, legacy = false))
        assertEquals(UserKeyKind.CREDENTIAL, KeystoreManager.deleteTarget("k", null, setOf("ed25519:xkey_credential_k"), legacy = false))
        // One key under the id is the target whatever its row's type says.
        assertEquals(UserKeyKind.CREDENTIAL, KeystoreManager.deleteTarget("k", "ec", setOf("keystore:xkey_credential_k"), legacy = false))
        assertEquals(UserKeyKind.GENERAL, KeystoreManager.deleteTarget("k", "fido2", general, legacy = true))
        // No material: still one kind, never every alias (#270 round 4):
        // the row's, else the one the method names.
        assertEquals(UserKeyKind.GENERAL, KeystoreManager.deleteTarget("k", "ec", emptySet(), legacy = false))
        assertEquals(UserKeyKind.CREDENTIAL, KeystoreManager.deleteTarget("k", "fido2", emptySet(), legacy = false))
        assertEquals(UserKeyKind.GENERAL, KeystoreManager.deleteTarget("k", null, emptySet(), legacy = false))
        assertEquals(UserKeyKind.CREDENTIAL, KeystoreManager.deleteTarget("k", null, emptySet(), legacy = true))
    }

    /**
     * #255 verify: `local.generateKey` makes a fido2-typed key under the
     * general alias. The key screens' delete names the row type's kind
     * (CREDENTIAL); it still deletes that key's material, the only one
     * under the id, and a credential sharing the id still bounds it.
     */
    @Test
    fun aFido2RowsGeneralAliasMaterialIsDeletedByItsRowsKind() {
        keystoreKey("xkey_key_k", certificate = true)
        ed25519["xkey_key_j"] = "c2VjcmV0"
        assertTrue(delete("k", KeystoreManager.userKeyKindOf("fido2")))
        assertTrue(delete("j", KeystoreManager.userKeyKindOf("fido2")))
        assertTrue("a fido2 row's general-alias key was left", entries.isEmpty())
        assertTrue("a fido2 row's general-alias Ed25519 key was left", ed25519.isEmpty())

        keystoreKey("xkey_credential_k", certificate = true)
        keystoreKey("xkey_key_k", certificate = true)
        assertTrue(delete("k", UserKeyKind.CREDENTIAL))
        assertEquals(setOf("xkey_key_k"), entries.keys)
    }

    /**
     * #255 verify: a credential and a general key share an id, the row is
     * the general key's. The credential's delete beside that row fails and
     * stays owed; its retry settles it first, and then only the general
     * key is under the id. The retry deletes the credential it names, never
     * the general key the first delete left.
     */
    @Test
    fun aCredentialDeleteRetryLeavesTheGeneralKeyBesideItsRow() = kotlinx.coroutines.test.runTest {
        val tables = FakeKeyPolicyTables()
        val store = tables.store()
        val row = tables.addKey("k", com.automatethethings.xkey.storage.entity.SharingPolicyType.PRIVATE)
        keystoreKey("xkey_credential_k", certificate = true)
        keystoreKey("xkey_key_k", certificate = true)
        val credential = keyMaterialDeleter(context, keystore, UserKeyKind.CREDENTIAL)

        stuck += "xkey_credential_k"
        assertTrue(store.deleteMaterial("k", credential, besideRow = row))
        assertTrue("the failed delete is not owed", store.isDeletionPending("k"))

        stuck.clear()
        assertTrue(store.deleteMaterial("k", credential, besideRow = row))
        assertFalse("the credential was left", "xkey_credential_k" in entries)
        assertEquals("the retry deleted the general key beside its row", setOf("xkey_key_k"), entries.keys)
        assertFalse(store.isDeletionPending("k"))
    }

    /**
     * #270 round 4: a delete names the one key it removes. A deleter with
     * no kind would select both namespaces, so it records no delete:
     * refused with nothing removed. A credential-only and a general-only
     * delete each remove only their own key.
     */
    @Test
    fun aDeleterWithoutAKindIsRefusedAndNamedDeletesTakeOnlyTheirKey() = kotlinx.coroutines.test.runTest {
        val tables = FakeKeyPolicyTables()
        val store = tables.store()
        val row = tables.addKey("k", com.automatethethings.xkey.storage.entity.SharingPolicyType.PRIVATE)
        keystoreKey("xkey_credential_k", certificate = true)
        keystoreKey("xkey_key_k", certificate = true)
        val kindless = keyMaterialDeleter(context, keystore)

        org.junit.Assert.assertThrows(IllegalStateException::class.java) {
            kotlinx.coroutines.runBlocking { store.deleteMaterial("k", kindless, besideRow = row) }
        }
        org.junit.Assert.assertThrows(IllegalStateException::class.java) {
            kotlinx.coroutines.runBlocking { store.deleteKey("k", row, kindless) }
        }
        assertEquals(setOf("xkey_credential_k", "xkey_key_k"), entries.keys)
        org.junit.Assert.assertNotNull("the row went", tables.key("k"))
        assertFalse(store.isDeletionPending("k"))

        assertTrue(store.deleteMaterial("k", keyMaterialDeleter(context, keystore, UserKeyKind.CREDENTIAL), besideRow = row))
        assertEquals("the credential delete took the general key", setOf("xkey_key_k"), entries.keys)
        assertTrue(store.deleteKey("k", row, keyMaterialDeleter(context, keystore, UserKeyKind.GENERAL)))
        assertTrue("the general delete left its key", entries.isEmpty())
    }

    /**
     * #255 review: a credential delete still owed beside the general key's
     * surviving row refuses uses of the credential only; the general key,
     * whose material and policy the delete kept, stays usable. A whole-key
     * delete still owed refuses both kinds. The gate uses the app's resolver
     * (#255 review r2), so it sees the alias each lookup reads.
     */
    @Test
    fun aPendingCredentialDeleteLeavesTheGeneralKeyBesideItsRowUsable() = kotlinx.coroutines.test.runTest {
        val tables = FakeKeyPolicyTables()
        val store = tables.store(KeyPolicyStore.KeyResolver { id, kind -> keystore.resolveKey(id, kind) })
        val row = tables.addKey("k", com.automatethethings.xkey.storage.entity.SharingPolicyType.PRIVATE)
        keystoreKey("xkey_credential_k", certificate = true)
        keystoreKey("xkey_key_k", certificate = true)
        stuck += "xkey_credential_k"
        assertTrue(store.deleteMaterial("k", keyMaterialDeleter(context, keystore, UserKeyKind.CREDENTIAL), besideRow = row))
        assertTrue("the credential delete is owed", store.isDeletionPending("k"))

        store.requireUsable("k", UserKeyKind.GENERAL)
        assertTrue("the general key was refused", store.withUsableKey("k", UserKeyKind.GENERAL) { true })
        // A general key's lookup reads its own alias while the credential's
        // is still in the Keystore: never the deleted credential.
        assertEquals("xkey_key_k", store.withUsableKey("k", UserKeyKind.GENERAL) { keystore.resolveKeystoreAlias("k", UserKeyKind.GENERAL) })
        assertEquals("xkey_credential_k", keystore.resolveKeystoreAlias("k", UserKeyKind.CREDENTIAL))
        // An id held in both namespaces has no sole kind: a use that names none is refused.
        assertEquals(null, keystore.soleKind("k"))
        for (kind in listOf(UserKeyKind.CREDENTIAL, null)) {
            org.junit.Assert.assertThrows(KeyPolicyStore.KeyDeletedException::class.java) {
                kotlinx.coroutines.runBlocking { store.requireUsable("k", kind) }
            }
        }

        val whole = tables.addKey("g", com.automatethethings.xkey.storage.entity.SharingPolicyType.PRIVATE)
        keystoreKey("xkey_key_g", certificate = true)
        stuck += "xkey_key_g"
        assertTrue(store.deleteKey("g", whole, keyMaterialDeleter(context, keystore, UserKeyKind.GENERAL)))
        for (kind in listOf(UserKeyKind.GENERAL, UserKeyKind.CREDENTIAL, null)) {
            org.junit.Assert.assertThrows(KeyPolicyStore.KeyDeletedException::class.java) {
                kotlinx.coroutines.runBlocking { store.requireUsable("g", kind) }
            }
        }
    }

    /**
     * #255 review r3: a use naming the general key whose own key is absent
     * reads nothing, never the credential sharing its id: every lookup
     * names its namespace. With that credential's delete still owed, a
     * credential use is refused by the gate.
     */
    @Test
    fun aGeneralUseNeverReadsTheCredentialOfItsId() = kotlinx.coroutines.test.runTest {
        val tables = FakeKeyPolicyTables()
        val store = tables.store(KeyPolicyStore.KeyResolver { id, kind -> keystore.resolveKey(id, kind) })
        val row = tables.addKey("c", com.automatethethings.xkey.storage.entity.SharingPolicyType.PRIVATE)
        keystoreKey("xkey_credential_c", certificate = true)
        stuck += "xkey_credential_c"
        assertTrue(store.deleteMaterial("c", keyMaterialDeleter(context, keystore, UserKeyKind.CREDENTIAL), besideRow = row))
        assertTrue("the credential delete is owed", store.isDeletionPending("c"))
        assertEquals(null, keystore.resolveKeystoreAlias("c", UserKeyKind.GENERAL))
        assertEquals(UserKeyKind.CREDENTIAL, keystore.soleKind("c"))

        org.junit.Assert.assertThrows(KeyPolicyStore.KeyDeletedException::class.java) {
            kotlinx.coroutines.runBlocking { store.withUsableKey("c", UserKeyKind.CREDENTIAL) { keystore.getPublicKeyDER("c", UserKeyKind.CREDENTIAL) } }
        }
        assertEquals(null, store.withUsableKey("c", UserKeyKind.GENERAL) { keystore.getPublicKeyDER("c", UserKeyKind.GENERAL) })
    }

    /**
     * #255 review: a use that waited while a delete held the key, and
     * resumed only once the delete succeeded and dropped its tombstone,
     * reads the software key inside the use gate and so finds nothing; a
     * record read before the gate would still hold the deleted bytes.
     */
    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
    @Test
    fun aUseThatWaitedOutACompletedDeleteReadsNoDeletedSoftwareKey() = kotlinx.coroutines.test.runTest {
        val tables = FakeKeyPolicyTables()
        val store = tables.store()
        val instance = tables.addKey("s", com.automatethethings.xkey.storage.entity.SharingPolicyType.ALL_PEERS)
        softwareKey("s")
        val deleter = keyMaterialDeleter(context, keystore, UserKeyKind.GENERAL)
        val inDelete = kotlinx.coroutines.CompletableDeferred<Unit>()
        val release = kotlinx.coroutines.CompletableDeferred<Unit>()
        val slow = object : KeyMaterial by deleter {
            override suspend fun delete(held: KeyPolicyStore.KeyMaterialHeld, tombstone: KeyDeletionEntity): Boolean {
                inDelete.complete(Unit)
                release.await()
                return deleter.delete(held, tombstone)
            }
        }

        val delete = async { store.deleteKey("s", instance, slow) }
        inDelete.await()
        val use = async { store.withUsableKey("s", UserKeyKind.GENERAL) { SoftwareKeyStore(context).get("s") } }
        runCurrent()
        assertFalse("the use ran while the delete held the key", use.isCompleted)

        release.complete(Unit)
        assertTrue(delete.await())
        assertFalse("the delete left its tombstone", store.isDeletionPending("s"))
        org.junit.Assert.assertNull("the waiting use read the deleted key", use.await())
    }

    /**
     * A failed Ed25519 commit stays owed across replays and a restart
     * (#255 review): SharedPreferences' remove() empties the in-memory
     * cache at once, so a replay that read the cache as the truth would
     * skip the commit and drop the tombstone with the key still on disk.
     */
    @Test
    fun aFailedEd25519CommitStaysOwedUntilACommitSucceeds() {
        val disk = HashMap(mapOf("xkey_key_k" to "c2VjcmV0"))
        val cache = HashMap(disk)
        var writable = false
        val prefs = mockk<SharedPreferences>()
        every { prefs.getString(any(), any()) } answers { cache[firstArg()] ?: secondArg() }
        every { prefs.contains(any()) } answers { firstArg<String>() in cache }
        every { prefs.edit() } answers {
            val editor = mockk<SharedPreferences.Editor>()
            every { editor.remove(any()) } answers { cache.remove(firstArg<String>()); editor }
            every { editor.commit() } answers {
                if (writable) { disk.clear(); disk.putAll(cache) }
                writable
            }
            editor
        }
        every { keystore.ed25519Prefs() } returns prefs
        val tombstone = KeyDeletionEntity("k", 1L, "android", readKeyMaterialGeneration(context, held("k"), "android", keystore))

        repeat(3) { assertFalse("replay ${it + 1} dropped an uncommitted delete", deleteKeyMaterial(context, held("k"), tombstone, keystore)) }
        assertEquals(setOf("xkey_key_k"), disk.keys)

        // A restart reloads the cache from disk; the disk still refuses.
        cache.clear(); cache.putAll(disk)
        assertFalse(deleteKeyMaterial(context, held("k"), tombstone, keystore))

        writable = true
        assertTrue(deleteKeyMaterial(context, held("k"), tombstone, keystore))
        assertTrue("the Ed25519 key is still on disk", disk.isEmpty())
    }

    /** An internal key named like the user key's id stays. */
    @Test
    fun onlyTheUserKeyNamespaceIsDeleted() {
        keystoreKey("xkey_key_xkey_seal_store_key", certificate = false)
        keystoreKey("xkey_seal_store_key", certificate = false)
        ed25519["xkey_seal_store_key"] = "c2VjcmV0"
        assertTrue(delete("xkey_seal_store_key", "android"))
        assertEquals(setOf("xkey_seal_store_key"), entries.keys)
        assertEquals(setOf("xkey_seal_store_key"), ed25519.keys)

        // A generation naming another key's alias, with its true tag.
        keystoreKey("xkey_key_other", certificate = true)
        val forged = keystore.userKeyGeneration("other")
        keystore.deleteUserKeyGeneration("k", forged)
        assertTrue("a delete of k reached another key's alias", "xkey_key_other" in entries)
    }

    @Test
    fun aDaemonKeyHoldsNoLocalMaterial() {
        keystoreKey("xkey_key_k", certificate = true)
        assertTrue(delete("k", "xkmsd"))
        assertEquals(setOf("xkey_key_k"), entries.keys)
    }

    /**
     * A generation's delete leaves material written under the id since, of
     * every type: each replacement carries another tag.
     */
    @Test
    fun aReplacedGenerationOfEveryTypeIsLeft() {
        keystoreKey("xkey_credential_k", certificate = true)
        keystoreKey("xkey_key_k", certificate = false)
        ed25519["xkey_key_k"] = "b2xk"
        softwareKey("k")
        val old = keyMaterialGeneration(context, "k", keystore)
        assertEquals(4, old.size)

        keystoreKey("xkey_credential_k", certificate = true)
        keystoreKey("xkey_key_k", certificate = false)
        ed25519["xkey_key_k"] = "bmV3"
        softwareKey("k")
        val now = keyMaterialGeneration(context, "k", keystore)

        assertTrue(deleteKeyMaterialGeneration(context, "k", old, keystore))
        assertEquals("a delete of the old generation reached the new one", now, keyMaterialGeneration(context, "k", keystore))
    }

    /**
     * Round 12 (2): a tombstone's delete removes the generation it recorded,
     * never what the alias holds now: a legacy credential generated again
     * under the alias after the tombstone survives its replay.
     */
    @Test
    fun aTombstoneLeavesACredentialGeneratedAgainUnderItsAlias() {
        keystoreKey("xkey_credential_k", certificate = true)
        val tombstone = KeyDeletionEntity("k", 1L, "android", readKeyMaterialGeneration(context, held("k"), "android", keystore))
        keystoreKey("xkey_credential_k", certificate = true)
        val now = entries.getValue("xkey_credential_k")

        assertTrue(deleteKeyMaterial(context, held("k"), tombstone, keystore))
        assertEquals("the replay deleted the credential generated after it", now, entries["xkey_credential_k"])

        // A tombstone that recorded no generation deletes nothing.
        assertTrue(deleteKeyMaterial(context, held("k"), KeyDeletionEntity("k", 1L, "android", null), keystore))
        assertEquals(now, entries["xkey_credential_k"])
    }
}
