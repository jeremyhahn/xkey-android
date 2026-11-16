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
import com.automatethethings.xkey.storage.KeyNamespace
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.CredentialMetadataDao
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.KeyEntity
import io.mockk.coEvery
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.runs
import io.mockk.unmockkAll
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import java.nio.file.Files
import java.security.KeyStore
import java.util.Collections
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * `local.generateKey` and `local.deleteKey` keep each key row's material
 * namespace: a software key's row records the general namespace, and
 * deleting one namespace's raw alias leaves the other namespace's row and
 * credential metadata of the same ID.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class LocalKeyNamespaceTest {

    private val context = mockk<Context>(relaxed = true)
    private lateinit var mainThread: ExecutorService

    private val aliases = Collections.synchronizedSet(hashSetOf<String>())
    private val rows = Collections.synchronizedMap(hashMapOf<String, KeyEntity>())
    private val metadata = Collections.synchronizedSet(hashSetOf<String>())

    private val keyDao = mockk<KeyDao>(relaxed = true).also { dao ->
        coEvery { dao.exists(any()) } answers { firstArg<String>() in rows }
        coEvery { dao.getByKeyId(any()) } answers { rows[firstArg<String>()] }
        coEvery { dao.insert(any()) } answers { firstArg<KeyEntity>().let { rows[it.keyId] = it }; 1L }
        coEvery { dao.deleteByKeyId(any()) } answers { if (rows.remove(firstArg<String>()) != null) 1 else 0 }
    }
    private val credentials = mockk<CredentialMetadataDao>(relaxed = true).also { dao ->
        coEvery { dao.deleteByCredentialId(any()) } answers { if (metadata.remove(firstArg<String>())) 1 else 0 }
    }
    private val keystore = mockk<KeystoreManager>(relaxed = true).also { ks ->
        every { ks.listAllKeystoreAliases() } answers { aliases.toList() }
        every { ks.resolveKeystoreAlias(any()) } answers {
            val id = firstArg<String>()
            listOf("xkey_credential_$id", "xkey_key_$id", id).firstOrNull { it in aliases }
        }
        every { ks.generalKeyExists(any()) } answers { "xkey_key_${firstArg<String>()}" in aliases }
        every { ks.keyExists(any()) } answers { "xkey_credential_${firstArg<String>()}" in aliases }
        every { ks.deleteGeneralKey(any()) } answers { aliases.remove("xkey_key_${firstArg<String>()}") }
        every { ks.deleteByAlias(any()) } answers { aliases.remove(firstArg<String>()) }
    }

    private fun row(id: String, namespace: KeyNamespace) = KeyEntity(
        keyId = id, keyType = "fido2", algorithm = "ES256", label = id, keySizeBits = 256,
        source = "local", materialNamespace = namespace.stored
    )

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.d(any(), any<String>()) } returns 0
        every { Log.i(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.e(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>(), any()) } returns 0
        every { Log.e(any(), any<String>(), any()) } returns 0
        mainThread = Executors.newSingleThreadExecutor()
        Dispatchers.setMain(mainThread.asCoroutineDispatcher())
        mockkConstructor(SoftwareKeyStore::class)
        every { anyConstructed<SoftwareKeyStore>().contains(any()) } returns false
        every { anyConstructed<SoftwareKeyStore>().put(any()) } just runs
        every { anyConstructed<SoftwareKeyStore>().delete(any()) } just runs
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
        mainThread.shutdownNow()
        unmockkAll()
    }

    @Test
    fun aGeneratedSoftwareKeyRecordsTheGeneralNamespace() = runBlocking<Unit> {
        val response = call(
            MethodNames.LOCAL_GENERATE_KEY,
            JSONObject("""{"keyId":"s","keyType":"secret","algorithm":"AES-256","exportable":true,"requireUserVerification":false}""")
        )

        assertEquals("the generation must succeed, got $response", true, response.has("result"))
        assertEquals(KeyNamespace.GENERAL.stored, rows["s"]?.materialNamespace)
    }

    @Test
    fun deletingAGeneralRawAliasKeepsTheCredentialRowAndMetadataOfItsId() = runBlocking<Unit> {
        aliases += listOf("xkey_credential_k", "xkey_key_k")
        rows["k"] = row("k", KeyNamespace.CREDENTIAL)
        metadata += "k"

        call(MethodNames.LOCAL_DELETE_KEY, JSONObject().put("keyId", "xkey_key_k"))

        assertEquals("only the general key goes", setOf("xkey_credential_k"), aliases.toSet())
        assertEquals("the credential's row survives", setOf("k"), rows.keys.toSet())
        assertEquals("the credential's metadata survives", setOf("k"), metadata.toSet())
    }

    @Test
    fun deletingACredentialRawAliasKeepsTheGeneralRowAndRemovesItsMetadata() = runBlocking<Unit> {
        aliases += listOf("xkey_credential_k", "xkey_key_k")
        rows["k"] = row("k", KeyNamespace.GENERAL)
        metadata += "k"

        call(MethodNames.LOCAL_DELETE_KEY, JSONObject().put("keyId", "xkey_credential_k"))

        assertEquals("only the credential goes", setOf("xkey_key_k"), aliases.toSet())
        assertEquals("the general key's row survives", setOf("k"), rows.keys.toSet())
        assertEquals("the credential's metadata goes with it", emptySet<String>(), metadata.toSet())
    }

    @Test
    fun deletingTheRawAliasOfTheRowsOwnNamespaceDeletesTheRow() = runBlocking<Unit> {
        aliases += listOf("xkey_credential_k", "xkey_key_k")
        rows["k"] = row("k", KeyNamespace.CREDENTIAL)
        metadata += "k"

        call(MethodNames.LOCAL_DELETE_KEY, JSONObject().put("keyId", "xkey_credential_k"))

        assertEquals(setOf("xkey_key_k"), aliases.toSet())
        assertEquals("the credential's row goes", emptySet<String>(), rows.keys.toSet())
        assertEquals(emptySet<String>(), metadata.toSet())
    }

    private suspend fun call(method: String, params: JSONObject): JSONObject {
        val request = JSONObject().put("jsonrpc", "2.0").put("id", 1).put("method", method).put("params", params)
        return JSONObject(String(realHandler().handleRawRequest(request.toString().toByteArray())))
    }

    /** The real [RequestHandler] with only its Android and storage edges mocked. */
    private fun realHandler(): RequestHandler {
        mockkStatic(Looper::class)
        every { Looper.getMainLooper() } returns mockk(relaxed = true)
        val database = mockk<XKeyDatabase>(relaxed = true)
        every { database.keyDao() } returns keyDao
        every { database.credentialMetadataDao() } returns credentials
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
