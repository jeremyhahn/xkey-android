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

package com.automatethethings.xkey.protocol

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import com.automatethethings.xkey.crypto.KeystoreAeadCipher
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.SoftwareKey
import com.automatethethings.xkey.crypto.SoftwareKeyStore
import com.automatethethings.xkey.crypto.UserKeyKind
import com.automatethethings.xkey.storage.KeyPolicyStore
import com.automatethethings.xkey.storage.deleteKeyMaterial
import com.automatethethings.xkey.storage.entity.KeyDeletionEntity
import com.automatethethings.xkey.storage.isInternalKey
import com.automatethethings.xkey.storage.keyMaterialGeneration
import com.automatethethings.xkey.storage.readKeyMaterialGeneration
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkStatic
import io.mockk.spyk
import io.mockk.unmockkAll
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
 * `local.deleteKey` deletes the key the request names, by this branch's
 * alias rule (#255): an id is the user key it names, whose aliases are
 * `xkey_credential_<id>` and `xkey_key_<id>`, never read as another key's
 * raw alias. A raw alias with no user key under it is an internal key and
 * is refused ([isInternalKey]) before anything is touched; with a
 * credential and a general key under one id, `local.deleteKey` names the
 * general key ([KeystoreManager.deleteTarget]). Each case runs the
 * handler's own steps against a real [KeystoreManager] and
 * [SoftwareKeyStore], with the Android Keystore, the Ed25519 preferences
 * and the software store's cipher as in-memory fakes.
 */
class LocalDeleteKeyExactIdTest {

    /** Keystore entries: alias to (creation date, certificate bytes). */
    private val entries = HashMap<String, Pair<Date, ByteArray?>>()
    private val ed25519 = HashMap<String, String>()
    private lateinit var context: Context
    private lateinit var keystore: KeystoreManager
    private var clock = 1_000L

    @Before
    fun setUp() {
        // Main's shared ML-DSA store is per process: each test starts with none.
        com.automatethethings.xkey.crypto.PqcSoftwareKeyStore.clearSharedForTest()
        mockkStatic(Log::class)
        every { Log.d(any(), any<String>()) } returns 0
        every { Log.i(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>(), any()) } returns 0
        every { Log.e(any(), any<String>(), any()) } returns 0

        val platform = mockk<KeyStore>(relaxed = true)
        every { platform.containsAlias(any()) } answers { firstArg<String>() in entries }
        every { platform.getCreationDate(any()) } answers { entries[firstArg()]?.first }
        every { platform.getCertificate(any()) } answers {
            entries[firstArg()]?.second?.let { bytes -> mockk<Certificate> { every { encoded } returns bytes } }
        }
        every { platform.deleteEntry(any()) } answers { entries.remove(firstArg<String>()); Unit }
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance(any<String>()) } returns platform

        mockkConstructor(KeystoreAeadCipher::class)
        every { anyConstructed<KeystoreAeadCipher>().encrypt(any()) } answers { Random.nextBytes(12) + firstArg<ByteArray>() }
        every { anyConstructed<KeystoreAeadCipher>().decrypt(any()) } answers {
            firstArg<ByteArray>().copyOfRange(12, firstArg<ByteArray>().size)
        }

        val files: File = java.nio.file.Files.createTempDirectory("software-keys").toFile().apply { deleteOnExit() }
        context = mockk(relaxed = true)
        every { context.applicationContext } returns context
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
        com.automatethethings.xkey.crypto.PqcSoftwareKeyStore.clearSharedForTest()
        unmockkAll()
    }

    private fun keystoreKey(alias: String) {
        entries[alias] = Date(clock++) to Random.nextBytes(64)
    }

    private fun softwareKey(id: String) =
        SoftwareKeyStore(context).put(SoftwareKey(id, "AES256-GCM", "symmetric", 256, true, true, Random.nextBytes(32)))

    /**
     * `local.deleteKey` of [keyId] with no key row, as the handler runs it:
     * null when it is refused as an internal key, else whether the material
     * of the key [KeystoreManager.deleteTarget] names was deleted.
     */
    private fun rpcDelete(keyId: String): Boolean? {
        if (isInternalKey(keyId, keystore)) return null
        val generation = keyMaterialGeneration(context, keyId, keystore).keys
        val kind = KeystoreManager.deleteTarget(keyId, com.automatethethings.xkey.crypto.UserKeyKind.GENERAL, generation, legacy = false)
        val held = KeyPolicyStore.KeyMaterialHeld(keyId)
        val tombstone = readKeyMaterialGeneration(context, held, "android", keystore, kind)
        return deleteKeyMaterial(context, held, KeyDeletionEntity(keyId, 1L, "android", tombstone), keystore)
    }

    /**
     * Software key `xkey_key_a` is generated, then hardware key `a`, whose
     * Keystore entry is `xkey_key_a`. Deleting `xkey_key_a` deletes the
     * software key only: hardware key `a`'s entry remains.
     */
    @Test
    fun deletingASoftwareKeyNamedLikeAHardwareAliasLeavesTheHardwareKey() {
        softwareKey("xkey_key_a")
        keystoreKey("xkey_key_a")

        assertEquals(true, rpcDelete("xkey_key_a"))
        assertFalse("the software key must be deleted", SoftwareKeyStore(context).contains("xkey_key_a"))
        assertEquals("hardware key a must survive", setOf("xkey_key_a"), entries.keys)
        assertTrue("hardware key a is still a user key", keystore.userKeyIdInUse("a"))
    }

    /**
     * The raw alias of a key with no user key of that id never names the key
     * behind it: deleting `xkey_key_b` is refused as an internal key, and
     * hardware key `b` stays.
     */
    @Test
    fun aRawAliasWithNoKeyOfItsOwnIsRefusedAndLeavesItsKey() {
        keystoreKey("xkey_key_b")

        assertEquals("a raw alias is refused before any delete", null, rpcDelete("xkey_key_b"))
        assertEquals(setOf("xkey_key_b"), entries.keys)
        assertTrue(keystore.userKeyIdInUse("b"))
    }

    /**
     * Raw credential alias `xkey_credential_k` names no user key of its own:
     * its delete is refused, and both credential `k` and general key
     * `xkey_key_k` survive it.
     */
    @Test
    fun aRawCredentialAliasIsRefusedAndLeavesBothKeysOfItsId() {
        keystoreKey("xkey_credential_k")
        keystoreKey("xkey_key_k")

        assertEquals(null, rpcDelete("xkey_credential_k"))
        assertEquals(setOf("xkey_credential_k", "xkey_key_k"), entries.keys)
    }

    /**
     * Canonical id `k` with both a credential `xkey_credential_k` and a
     * general key `xkey_key_k` and no row names the general key, as
     * `local.deleteKey` always did: deleting `k` deletes `xkey_key_k` and
     * leaves the credential usable.
     */
    @Test
    fun aCanonicalIdWithBothAliasesDeletesTheGeneralKeyAndLeavesTheCredential() {
        keystoreKey("xkey_credential_k")
        keystoreKey("xkey_key_k")

        assertEquals(true, rpcDelete("k"))
        assertEquals("the credential must survive", setOf("xkey_credential_k"), entries.keys)
        assertTrue(keystore.keyExists("k", UserKeyKind.CREDENTIAL))
    }
}
