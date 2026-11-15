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

import android.app.KeyguardManager
import android.app.NotificationManager
import android.content.Context
import android.os.Looper
import android.util.Log
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.SoftwareKeyStore
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.deleteKeyRow
import com.automatethethings.xkey.storage.entity.KeyEntity
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import java.nio.file.Files
import java.security.KeyStore
import java.util.Collections
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * An install upgraded from a generator that checked only the hardware
 * namespace can hold software key `k` and hardware key `k` (Keystore alias
 * `xkey_key_k`) under one ID. Deleting `k`, by `local.deleteKey` or from its
 * key row, removes both, or refuses and keeps the row: a delete that
 * answers deleted while the hardware private key still serves `local.sign`
 * is never possible.
 */
class KeyDeleteAllMaterialTest {

    private val context = mockk<Context>(relaxed = true)

    /** Keystore aliases present; the general alias of `k` is `xkey_key_k`. */
    private val aliases = Collections.synchronizedSet(hashSetOf("xkey_key_k"))

    /** Software key IDs present. */
    private val software = Collections.synchronizedSet(hashSetOf("k"))

    /** Key rows present. */
    private val rows = Collections.synchronizedSet(hashSetOf("k"))

    private val keyDao = mockk<KeyDao>(relaxed = true)
    private val keystore = mockk<KeystoreManager>(relaxed = true)

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.d(any(), any<String>()) } returns 0
        every { Log.i(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.e(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>(), any()) } returns 0
        every { Log.e(any(), any<String>(), any()) } returns 0

        coEvery { keyDao.exists(any()) } answers { firstArg<String>() in rows }
        coEvery { keyDao.deleteByKeyId(any()) } answers { if (rows.remove(firstArg<String>())) 1 else 0 }
        every { keystore.resolveKeystoreAlias(any()) } answers {
            val id = firstArg<String>()
            listOf("xkey_credential_$id", "xkey_key_$id", id).firstOrNull { it in aliases }
        }
        every { keystore.generalKeyExists(any()) } answers { "xkey_key_${firstArg<String>()}" in aliases }
        every { keystore.deleteGeneralKey(any()) } answers { aliases.remove("xkey_key_${firstArg<String>()}") }
        every { keystore.deleteByAlias(any()) } answers { aliases.remove(firstArg<String>()) }
        coEvery { keystore.signWithAlgorithm(any(), any(), any()) } answers {
            check("xkey_key_${firstArg<String>()}" in aliases) { "no key" }
            ByteArray(64)
        }
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun localDeleteKeyRemovesTheSoftwareAndTheHardwareKeyUnderOneId() = runBlocking<Unit> {
        constructSoftwareStore()
        val handler = realHandler()

        val response = call(handler, MethodNames.LOCAL_DELETE_KEY, JSONObject().put("keyId", "k"))

        assertTrue("deleted=true, got $response", response.optJSONObject("result")?.optBoolean("deleted") == true)
        assertFalse("the software key goes", "k" in software)
        assertFalse("the hardware key goes, left $aliases", "xkey_key_k" in aliases)
        assertFalse("the row goes", "k" in rows)

        val sign = call(
            handler, MethodNames.LOCAL_SIGN,
            JSONObject().put("keyId", "k").put("data", "AAAA").put("algorithm", "SHA256withECDSA")
        )
        assertNotNull("local.sign of a deleted key fails, got $sign", sign.optJSONObject("error"))
    }

    @Test
    fun localDeleteKeyRefusesAndKeepsTheRowWhenTheHardwareKeySurvives() = runBlocking<Unit> {
        constructSoftwareStore()
        // The Keystore refuses to remove the entry.
        every { keystore.deleteGeneralKey(any()) } returns false

        val response = call(realHandler(), MethodNames.LOCAL_DELETE_KEY, JSONObject().put("keyId", "k"))

        assertNotNull("a delete that leaves the hardware key is refused, got $response", response.optJSONObject("error"))
        assertTrue("the row stays while material stands", "k" in rows)
        coVerify(exactly = 0) { keyDao.deleteByKeyId("k") }
    }

    @Test
    fun deleteKeyRowRemovesTheSoftwareAndTheHardwareKeyUnderOneId() = runBlocking<Unit> {
        val deleted = keyDao.deleteKeyRow(row("k"), keystore, softwareStore())

        assertEquals(1, deleted)
        assertFalse("the software key goes", "k" in software)
        assertFalse("the hardware key goes, left $aliases", "xkey_key_k" in aliases)
        assertFalse("the row goes", "k" in rows)
    }

    @Test
    fun deleteKeyRowRefusesAndKeepsTheRowWhenTheHardwareKeySurvives() = runBlocking<Unit> {
        every { keystore.deleteGeneralKey(any()) } returns false
        every { keystore.deleteByAlias(any()) } returns false

        val deleted = keyDao.deleteKeyRow(row("k"), keystore, softwareStore())

        assertEquals("no row is deleted while material stands", 0, deleted)
        assertTrue("the row stays", "k" in rows)
        assertTrue("the hardware key is still there", "xkey_key_k" in aliases)
    }

    /**
     * xKey's own encryption keys live at raw Keystore aliases and are
     * discovered as key rows. The raw-alias fallback of every delete refuses
     * them: their loss would make stored passwords, OATH secrets, sealed
     * data or software keys unreadable.
     */
    @Test
    fun deleteKeyRowRefusesAnInternalEncryptionKeyAndStillDeletesAUserKey() = runBlocking<Unit> {
        software.clear()
        aliases.clear()
        aliases += listOf(INTERNAL, "imported_user_key")
        rows.clear()
        rows += listOf(INTERNAL, "imported_user_key")

        assertEquals("an internal key's row is not deleted", 0, keyDao.deleteKeyRow(row(INTERNAL), keystore, softwareStore()))
        assertTrue("the internal key stays", INTERNAL in aliases)
        assertTrue("its row stays", INTERNAL in rows)

        assertEquals(1, keyDao.deleteKeyRow(row("imported_user_key"), keystore, softwareStore()))
        assertFalse("a user key at a raw alias still goes", "imported_user_key" in aliases)
    }

    @Test
    fun localDeleteKeyRefusesAnInternalEncryptionKey() = runBlocking<Unit> {
        software.clear()
        aliases.clear()
        aliases += INTERNAL
        rows.clear()
        rows += INTERNAL
        constructSoftwareStore()

        val response = call(realHandler(), MethodNames.LOCAL_DELETE_KEY, JSONObject().put("keyId", INTERNAL))

        assertNotNull("deleting an internal key is refused, got $response", response.optJSONObject("error"))
        assertTrue("the internal key stays", INTERNAL in aliases)
        assertTrue("its row stays", INTERNAL in rows)
    }

    /** The legacy deleteKey RPC resolves raw aliases too: it is no way around the refusal. */
    @Test
    fun theLegacyDeleteKeyRefusesAnInternalEncryptionKey() = runBlocking<Unit> {
        aliases.clear()
        aliases += INTERNAL
        every { keystore.keyExists(any()) } answers { firstArg<String>() in aliases }
        every { keystore.deleteKey(any()) } answers { aliases.remove(firstArg<String>()) }
        constructSoftwareStore()

        val response = call(realHandler(), MethodNames.DELETE_KEY, JSONObject().put("credentialId", INTERNAL))

        assertNotNull("deleting an internal key is refused, got $response", response.optJSONObject("error"))
        assertTrue("the internal key stays", INTERNAL in aliases)
    }

    private companion object {
        /** PasswordRepository's encryption key, at its raw Keystore alias. */
        const val INTERNAL = "xkey_password_encryption_key"
    }

    private fun row(id: String) = KeyEntity(
        keyId = id, keyType = "signing", algorithm = "ES256", label = id, keySizeBits = 256, source = "local"
    )

    private fun softwareStore(): SoftwareKeyStore = mockk<SoftwareKeyStore>(relaxed = true).also {
        every { it.contains(any()) } answers { firstArg<String>() in software }
        every { it.delete(any()) } answers { software -= firstArg<String>() }
    }

    private fun constructSoftwareStore() {
        mockkConstructor(SoftwareKeyStore::class)
        every { anyConstructed<SoftwareKeyStore>().contains(any()) } answers { firstArg<String>() in software }
        every { anyConstructed<SoftwareKeyStore>().delete(any()) } answers { software -= firstArg<String>() }
    }

    private suspend fun call(handler: RequestHandler, method: String, params: JSONObject): JSONObject {
        val request = JSONObject().put("jsonrpc", "2.0").put("id", 1).put("method", method).put("params", params)
        return JSONObject(String(handler.handleRawRequest(request.toString().toByteArray())))
    }

    /** The real [RequestHandler] with only its Android and storage edges mocked. */
    private fun realHandler(): RequestHandler {
        mockkStatic(Looper::class)
        every { Looper.getMainLooper() } returns mockk(relaxed = true)
        val database = mockk<XKeyDatabase>(relaxed = true)
        every { database.keyDao() } returns keyDao
        mockkObject(XKeyDatabase.Companion)
        every { XKeyDatabase.getInstance(any()) } returns database
        every { context.getSystemService(Context.KEYGUARD_SERVICE) } returns mockk<KeyguardManager>(relaxed = true)
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance("AndroidKeyStore") } returns mockk(relaxed = true)
        every { context.filesDir } returns Files.createTempDirectory("xkey-files").toFile().apply { deleteOnExit() }
        every { context.getSystemService(NotificationManager::class.java) } returns
            mockk<NotificationManager>(relaxed = true)
        return RequestHandler(context, keystore, biometricLauncher = null, sessionAuthManager = null)
    }
}
