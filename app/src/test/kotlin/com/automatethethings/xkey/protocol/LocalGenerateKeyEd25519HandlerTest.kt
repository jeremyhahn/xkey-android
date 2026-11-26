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
import com.automatethethings.xkey.crypto.KeySecurityLevel
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.UnsupportedAlgorithmException
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.KeyDao
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import java.nio.file.Files
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test

/** local.generateKey with "EdDSA" through the real [RequestHandler]. */
@OptIn(ExperimentalCoroutinesApi::class)
class LocalGenerateKeyEd25519HandlerTest {

    private val context = mockk<Context>(relaxed = true)
    private lateinit var mainThread: ExecutorService
    private lateinit var keystore: KeystoreManager
    private lateinit var keyDao: KeyDao
    private val tables = com.automatethethings.xkey.storage.FakeKeyPolicyTables()

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.v(any(), any<String>()) } returns 0
        every { Log.d(any(), any<String>()) } returns 0
        every { Log.i(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.e(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>(), any()) } returns 0
        every { Log.e(any(), any<String>(), any()) } returns 0
        mainThread = Executors.newSingleThreadExecutor()
        Dispatchers.setMain(mainThread.asCoroutineDispatcher())

        keystore = mockk(relaxed = true)
        every { keystore.generalKeySecurityLevel(any()) } returns KeySecurityLevel.TEE
        keyDao = mockk(relaxed = true)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
        mainThread.shutdownNow()
        unmockkAll()
    }

    @Test
    fun `EdDSA on API 33+ makes a Keystore key and returns its SPKI DER`() = runBlocking<Unit> {
        val spki = KeyPairGenerator.getInstance("Ed25519").generateKeyPair().public.encoded
        coEvery { keystore.generateKeyForAlgorithm("ed", "EdDSA", any(), any(), any()) } returns spki

        val response = generate("ed", "EdDSA")

        val result = response.optJSONObject("result")
        assertNotNull("EdDSA must succeed, got $response", result)
        val der = Base64.getDecoder().decode(result!!.getString("publicKeyDer"))
        assertEquals("X.509", KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(der)).format)
        assertEquals(256, result.getInt("keySizeBits"))
        assertEquals("EdDSA", tables.key("ed")!!.algorithm)
    }

    @Test
    fun `EdDSA before API 33 is refused with the unsupported-algorithm error`() = runBlocking<Unit> {
        coEvery { keystore.generateKeyForAlgorithm(any(), "EdDSA", any(), any(), any()) } throws
            UnsupportedAlgorithmException("Ed25519 requires API 33+")

        val response = generate("ed", "EdDSA")

        assertNull(response.optJSONObject("result"))
        assertEquals(ErrorCodes.INVALID_ALGORITHM, response.getJSONObject("error").getInt("code"))
        assertNull(tables.key("ed"))
    }

    private suspend fun generate(keyId: String, algorithm: String): JSONObject {
        val params = JSONObject()
            .put("keyId", keyId)
            .put("algorithm", algorithm)
            .put("requireUserVerification", false)
        val request = JSONObject().put("jsonrpc", "2.0").put("id", 1)
            .put("method", MethodNames.LOCAL_GENERATE_KEY)
            .put("params", params)
        return JSONObject(String(realHandler().handleRawRequest(request.toString().toByteArray())))
    }

    /** The real [RequestHandler] with only its Android and storage edges mocked. */
    private fun realHandler(): RequestHandler {
        mockkStatic(Looper::class)
        every { Looper.getMainLooper() } returns mockk(relaxed = true)
        val database = mockk<XKeyDatabase>(relaxed = true)
        every { database.keyDao() } returns keyDao
        every { database.keyPolicyDao() } returns tables
        mockkObject(com.automatethethings.xkey.storage.KeyPolicyStore.Companion)
        every { com.automatethethings.xkey.storage.KeyPolicyStore.of(any(), any()) } answers { tables.store() }
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
