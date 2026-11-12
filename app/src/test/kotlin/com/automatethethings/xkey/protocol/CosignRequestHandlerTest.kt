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
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.auth.BiometricActivityLauncher
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.UserCancelledException
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.KeyEntity
import io.mockk.Runs
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.slot
import io.mockk.unmockkAll
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.Base64

/**
 * `cosign.request` signs a peer's content hash only after the owner approves
 * it on the phone (#177). The request goes through the real
 * [RequestHandler.handleRequest], so the dispatch error mapping is exercised;
 * the database, keystore and biometric launcher are mocked.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class CosignRequestHandlerTest {

    private lateinit var keyDao: KeyDao
    private lateinit var keystoreManager: KeystoreManager
    private lateinit var launcher: BiometricActivityLauncher
    private lateinit var context: Context

    private val peerHex = "ab".repeat(32)
    private val hashHex = "0123456789abcdef".repeat(4)
    private val signature = ByteArray(64) { 7 }
    private val publicKeyDer = ByteArray(91) { 3 }

    private val signingKey = key("cosign-signing", "signing")
    private val fido2Key = key("cosign-fido2", "fido2")

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

        mockkStatic(Looper::class)
        every { Looper.getMainLooper() } returns mockk(relaxed = true)

        keyDao = mockk(relaxed = true)
        val database = mockk<XKeyDatabase>(relaxed = true)
        every { database.keyDao() } returns keyDao
        mockkObject(XKeyDatabase.Companion)
        every { XKeyDatabase.getInstance(any()) } returns database

        mockkObject(AuditLogger)
        every { AuditLogger.logCoSignReceived(any(), any()) } just Runs

        Dispatchers.setMain(UnconfinedTestDispatcher())

        context = mockk(relaxed = true)
        every { context.getSystemService(Context.KEYGUARD_SERVICE) } returns
            mockk<KeyguardManager>(relaxed = true)
        every { context.getSystemService(NotificationManager::class.java) } returns
            mockk<NotificationManager>(relaxed = true)

        keystoreManager = mockk(relaxed = true)
        coEvery { keystoreManager.signWithAlgorithm(any(), any(), any()) } returns signature
        every { keystoreManager.getPublicKeyDER(any()) } returns publicKeyDer

        launcher = mockk(relaxed = true)
        coEvery { launcher.requestAuthentication(any(), any(), any(), any()) } just Runs

        coEvery { keyDao.getByKeyId(signingKey.keyId) } returns signingKey
        coEvery { keyDao.getByKeyId(fido2Key.keyId) } returns fido2Key
        coEvery { keyDao.getAll() } returns listOf(signingKey)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
        unmockkAll()
    }

    private fun key(keyId: String, keyType: String) = KeyEntity(
        keyId = keyId,
        keyType = keyType,
        algorithm = "ES256",
        label = "",
        keySizeBits = 256,
        source = "local"
    )

    private fun handler(withLauncher: Boolean = true, peer: String? = peerHex): RequestHandler =
        RequestHandler(
            context = context,
            keystoreManager = keystoreManager,
            biometricLauncher = if (withLauncher) launcher else null,
            sessionAuthManager = null
        ).also { it.setConnectedDevicePublicKeyHex(peer) }

    private fun request(
        hash: String = hashHex,
        keyId: String? = signingKey.keyId,
        hashAlgorithm: String? = "SHA-256"
    ) = Request(
        id = 177L,
        method = MethodNames.COSIGN_REQUEST,
        params = JSONObject().apply {
            put("hash", hash)
            if (keyId != null) put("keyId", keyId)
            if (hashAlgorithm != null) put("hashAlgorithm", hashAlgorithm)
            put("from", "initiator")
        }
    )

    private fun assertError(code: Int, response: Response) {
        assertNull("no result on a refusal", response.result)
        assertEquals(code, response.error?.code)
    }

    private fun assertNothingSigned() {
        coVerify(exactly = 0) { keystoreManager.signWithAlgorithm(any(), any(), any()) }
    }

    @Test
    fun `an approved prompt signs the hash with the named key`() = runTest {
        val subtitle = slot<String>()
        coEvery {
            launcher.requestAuthentication(any(), capture(subtitle), any(), any())
        } just Runs

        val response = handler().handleRequest(request())

        assertNull(response.error)
        assertNotNull(response.result)
        val result = response.result as JSONObject
        assertEquals(Base64.getEncoder().encodeToString(signature), result.getString("signature"))
        assertEquals("ES256", result.getString("algorithm"))
        assertEquals(signingKey.keyId, result.getString("signerName"))
        assertTrue(result.getString("keyFingerprint").isNotEmpty())
        assertTrue(
            "the prompt names the hash: ${subtitle.captured}",
            subtitle.captured.contains(hashHex.take(8))
        )
        coVerify(exactly = 1) {
            keystoreManager.signWithAlgorithm(signingKey.keyId, any(), "ES256")
        }
    }

    @Test
    fun `a cancelled prompt answers BIOMETRIC_FAILED and signs nothing`() = runTest {
        coEvery {
            launcher.requestAuthentication(any(), any(), any(), any())
        } throws UserCancelledException()

        assertError(ErrorCodes.BIOMETRIC_FAILED, handler().handleRequest(request()))
        assertNothingSigned()
    }

    @Test
    fun `no biometric launcher answers BIOMETRIC_FAILED and signs nothing`() = runTest {
        assertError(
            ErrorCodes.BIOMETRIC_FAILED,
            handler(withLauncher = false).handleRequest(request())
        )
        assertNothingSigned()
    }

    @Test
    fun `no confirmed peer answers OPERATION_DENIED`() = runTest {
        assertError(ErrorCodes.OPERATION_DENIED, handler(peer = null).handleRequest(request()))
        assertNothingSigned()
        coVerify(exactly = 0) { launcher.requestAuthentication(any(), any(), any(), any()) }
    }

    @Test
    fun `a named fido2 key answers OPERATION_DENIED`() = runTest {
        assertError(
            ErrorCodes.OPERATION_DENIED,
            handler().handleRequest(request(keyId = fido2Key.keyId))
        )
        assertNothingSigned()
    }

    @Test
    fun `the fallback key skips a fido2 key`() = runTest {
        coEvery { keyDao.getAll() } returns listOf(fido2Key, signingKey)

        val response = handler().handleRequest(request(keyId = null))

        assertNull(response.error)
        coVerify(exactly = 1) {
            keystoreManager.signWithAlgorithm(signingKey.keyId, any(), any())
        }
        coVerify(exactly = 0) {
            keystoreManager.signWithAlgorithm(fido2Key.keyId, any(), any())
        }
    }

    @Test
    fun `the fallback with only a fido2 key finds no signing key`() = runTest {
        coEvery { keyDao.getAll() } returns listOf(fido2Key)

        assertError(
            ErrorCodes.KEY_NOT_FOUND,
            handler().handleRequest(request(keyId = null))
        )
        assertNothingSigned()
    }

    @Test
    fun `a 31-byte hash answers INVALID_PARAMS`() = runTest {
        assertError(
            ErrorCodes.INVALID_PARAMS,
            handler().handleRequest(request(hash = "ab".repeat(31)))
        )
        assertNothingSigned()
    }

    @Test
    fun `an unknown hashAlgorithm answers INVALID_PARAMS`() = runTest {
        assertError(
            ErrorCodes.INVALID_PARAMS,
            handler().handleRequest(request(hashAlgorithm = "MD5"))
        )
        assertNothingSigned()
    }
}
