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
        every { platform.deleteEntry(any()) } answers { entries.remove(firstArg<String>()); Unit }
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

    @Test
    fun anEcCredentialKeyIsDeleted() {
        keystoreKey("xkey_credential_k", certificate = true)
        assertTrue(deleteKeyMaterial(context, held("k"), "android", keystore))
        assertTrue(entries.isEmpty())
    }

    @Test
    fun anRsaGeneralKeyIsDeleted() {
        keystoreKey("xkey_key_k", certificate = true)
        assertTrue(deleteKeyMaterial(context, held("k"), "android", keystore))
        assertTrue(entries.isEmpty())
    }

    /** AES and HMAC Keystore keys have no certificate. */
    @Test
    fun aSymmetricKeystoreKeyIsDeleted() {
        keystoreKey("xkey_key_aes", certificate = false)
        keystoreKey("xkey_key_hmac", certificate = false)
        assertTrue(deleteKeyMaterial(context, held("aes"), "android", keystore))
        assertTrue(deleteKeyMaterial(context, held("hmac"), "android", keystore))
        assertTrue(entries.isEmpty())
    }

    /** Round 12 (3): Ed25519 material lives in the preferences, not the Keystore. */
    @Test
    fun anEd25519KeyIsDeleted() {
        ed25519["xkey_key_k"] = "c2VjcmV0"
        assertTrue("the deleter reported an Ed25519 key it cannot delete", deleteKeyMaterial(context, held("k"), "android", keystore))
        assertTrue("the Ed25519 key is still stored", ed25519.isEmpty())
    }

    @Test
    fun aSoftwareKeyIsDeleted() {
        softwareKey("k")
        assertTrue(deleteKeyMaterial(context, held("k"), "android", keystore))
        assertFalse(SoftwareKeyStore(context).contains("k"))
    }

    @Test
    fun everyBackendOfOneIdIsDeleted() {
        keystoreKey("xkey_credential_k", certificate = true)
        keystoreKey("xkey_key_k", certificate = false)
        ed25519["xkey_key_k"] = "c2VjcmV0"
        softwareKey("k")
        assertTrue(deleteKeyMaterial(context, held("k"), "android", keystore))
        assertTrue(entries.isEmpty())
        assertTrue(ed25519.isEmpty())
        assertFalse(SoftwareKeyStore(context).contains("k"))
    }

    /** Material that stays (a backend refusing the delete) is reported. */
    @Test
    fun anEd25519KeyThatStaysIsReported() {
        ed25519["xkey_key_k"] = "c2VjcmV0"
        val prefs = keystore.ed25519Prefs()!!
        every { prefs.edit() } answers {
            mockk<SharedPreferences.Editor> {
                every { remove(any()) } returns this
                every { commit() } returns false
            }
        }
        assertFalse(deleteKeyMaterial(context, held("k"), "android", keystore))
    }

    /** An internal key named like the user key's id stays. */
    @Test
    fun onlyTheUserKeyNamespaceIsDeleted() {
        keystoreKey("xkey_key_xkey_seal_store_key", certificate = false)
        keystoreKey("xkey_seal_store_key", certificate = false)
        ed25519["xkey_seal_store_key"] = "c2VjcmV0"
        assertTrue(deleteKeyMaterial(context, held("xkey_seal_store_key"), "android", keystore))
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
        assertTrue(deleteKeyMaterial(context, held("k"), "xkmsd", keystore))
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
}
