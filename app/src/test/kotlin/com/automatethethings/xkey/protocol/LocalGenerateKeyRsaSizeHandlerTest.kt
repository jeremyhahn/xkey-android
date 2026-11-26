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
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.KeyEntity
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.slot
import io.mockk.unmockkAll
import io.mockk.verify
import java.nio.file.Files
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import java.util.Collections
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
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * `keySizeBits` on `local.generateKey` through the real [RequestHandler]: an
 * RSA request forwards its size to the key generator, and the size the
 * handler returns and stores is the size of the key that was made. A key
 * whose size is not the one asked for is discarded with INTERNAL_ERROR and
 * no row, never stored under the requested size.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class LocalGenerateKeyRsaSizeHandlerTest {

    private val context = mockk<Context>(relaxed = true)
    private lateinit var mainThread: ExecutorService
    private lateinit var keystore: KeystoreManager
    private lateinit var keyDao: KeyDao

    /** The keySizeBits argument of every generateKeyForAlgorithm call, in order. */
    private val forwarded = Collections.synchronizedList(ArrayList<Int?>())
    private val stored = slot<KeyEntity>()

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
        coEvery { keyDao.insert(capture(stored)) } returns 1L
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
        mainThread.shutdownNow()
        unmockkAll()
    }

    /** A keystore that makes an RSA key of the size asked for (2048 when none), or a P-256 key. */
    private fun keystoreMakesTheSizeAskedFor() {
        coEvery { keystore.generateKeyForAlgorithm(any(), any(), any(), any(), any()) } answers {
            val bits = arg<Int?>(4)
            forwarded += bits
            if (secondArg<String>().startsWith("RS")) rsaSpki(bits ?: 2048) else p256Spki()
        }
    }

    @Test
    fun `RS256 with keySizeBits 4096 makes, returns and stores a 4096-bit key`() {
        assertRsaSize(requested = 4096)
    }

    @Test
    fun `RS256 with keySizeBits 3072 makes, returns and stores a 3072-bit key`() {
        assertRsaSize(requested = 3072)
    }

    @Test
    fun `RS256 without keySizeBits forwards no size and records 2048`() = runBlocking<Unit> {
        keystoreMakesTheSizeAskedFor()

        val response = generate("rsa-default", "RS256", keySizeBits = null)

        val result = response.optJSONObject("result")
        assertNotNull("RS256 must succeed, got $response", result)
        assertEquals(listOf<Int?>(null), forwarded.toList())
        assertEquals(2048, result!!.getInt("keySizeBits"))
        assertEquals(2048, stored.captured.keySizeBits)
        assertEquals(2048, modulusBits(result.getString("publicKeyDer")))
    }

    @Test
    fun `ES256 forwards no size`() = runBlocking<Unit> {
        keystoreMakesTheSizeAskedFor()

        val response = generate("ec-default", "ES256", keySizeBits = null)

        val result = response.optJSONObject("result")
        assertNotNull("ES256 must succeed, got $response", result)
        assertEquals(listOf<Int?>(null), forwarded.toList())
        assertEquals(256, result!!.getInt("keySizeBits"))
        assertEquals(256, stored.captured.keySizeBits)
    }

    /**
     * A keystore that ignores the size (a 2048-bit key for a 4096 request)
     * must not leave a key recorded as 4096: the key is discarded, the
     * request fails with INTERNAL_ERROR, and no row is written.
     */
    @Test
    fun `a key made at another size than asked is discarded with INTERNAL_ERROR and no row`() = runBlocking<Unit> {
        coEvery { keystore.generateKeyForAlgorithm(any(), any(), any(), any(), any()) } answers {
            forwarded += arg<Int?>(4)
            rsaSpki(2048)
        }

        val response = generate("rsa-ignored", "RS256", keySizeBits = 4096)

        assertNull("a 2048-bit key for a 4096 request must not succeed, got $response", response.optJSONObject("result"))
        assertEquals(ErrorCodes.INTERNAL_ERROR, response.getJSONObject("error").getInt("code"))
        assertEquals(listOf<Int?>(4096), forwarded.toList())
        verify { keystore.deleteGeneralKey("rsa-ignored") }
        coVerify(exactly = 0) { keyDao.insert(any()) }
    }

    private fun assertRsaSize(requested: Int) = runBlocking<Unit> {
        keystoreMakesTheSizeAskedFor()
        val keyId = "rsa-$requested"

        val response = generate(keyId, "RS256", keySizeBits = requested)

        val result = response.optJSONObject("result")
        assertNotNull("RS256/$requested must succeed, got $response", result)
        assertEquals("the size must reach the key generator", listOf<Int?>(requested), forwarded.toList())
        assertEquals(requested, modulusBits(result!!.getString("publicKeyDer")))
        assertEquals(requested, result.getInt("keySizeBits"))
        assertTrue("the key must be stored", stored.isCaptured)
        assertEquals(keyId, stored.captured.keyId)
        assertEquals(requested, stored.captured.keySizeBits)
    }

    private suspend fun generate(keyId: String, algorithm: String, keySizeBits: Int?): JSONObject {
        val params = JSONObject()
            .put("keyId", keyId)
            .put("algorithm", algorithm)
            .put("requireUserVerification", false)
        keySizeBits?.let { params.put("keySizeBits", it) }
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

    private companion object {
        fun rsaSpki(bits: Int): ByteArray =
            KeyPairGenerator.getInstance("RSA").apply { initialize(bits) }.generateKeyPair().public.encoded

        fun p256Spki(): ByteArray =
            KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
                .generateKeyPair().public.encoded

        fun modulusBits(publicKeyBase64: String): Int {
            val der = Base64.getDecoder().decode(publicKeyBase64)
            val key = KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(der)) as RSAPublicKey
            return key.modulus.bitLength()
        }
    }
}
