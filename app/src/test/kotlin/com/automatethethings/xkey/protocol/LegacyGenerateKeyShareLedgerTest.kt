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
import com.automatethethings.xkey.auth.BiometricActivityLauncher
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.remote.SharePermissionLedger
import com.automatethethings.xkey.remote.SharePermissionRevokedException
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.KeyDao
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mockk.verify
import java.nio.file.Files
import java.security.KeyStore
import java.util.Collections
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.withTimeout
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

/**
 * The legacy `generateKey` RPC replaces Keystore material like
 * `local.generateKey` does, so it holds the same rules: it reserves the
 * credential ID across its biometric wait, checks existence again after
 * approval, and generates inside a [SharePermissionLedger] revoke of the ID.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class LegacyGenerateKeyShareLedgerTest {

    private val context = mockk<Context>(relaxed = true)
    private lateinit var mainThread: ExecutorService

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
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
        mainThread.shutdownNow()
        unmockkAll()
    }

    /**
     * Request A (one transport) waits on its biometric approval; request B
     * (another transport, no verification) for the same credential ID arrives
     * meanwhile. B is refused, and a share of the ID that took its baseline
     * while A waited is refused once A generates: A's generation is a revoke.
     * The credential is generated once, never deleted and regenerated.
     */
    @Test
    fun aDelayedLegacyGenerationReservesTheIdAndRevokesAPendingShare() = runBlocking<Unit> {
        val credentialId = "legacy-cred-1"
        val aliases = Collections.synchronizedSet(HashSet<String>())
        val generated = Collections.synchronizedList(ArrayList<String>())
        val keystore = mockk<KeystoreManager>(relaxed = true)
        every { keystore.keyExists(any()) } answers { "xkey_credential_${firstArg<String>()}" in aliases }
        every { keystore.resolveKeystoreAlias(any()) } answers {
            "xkey_credential_${firstArg<String>()}".takeIf { it in aliases }
        }
        coEvery { keystore.generateKeyWithAuthDuration(any(), any(), any()) } answers {
            val id = firstArg<String>()
            generated += id
            aliases += "xkey_credential_$id"
            byteArrayOf(generated.size.toByte())
        }
        every { keystore.getAttestationChain(any()) } returns null
        val keyDao = mockk<KeyDao>(relaxed = true)

        val approve = CompletableDeferred<Unit>()
        val prompted = CompletableDeferred<Unit>()
        val launcher = mockk<BiometricActivityLauncher>(relaxed = true)
        coEvery { launcher.requestAuthentication(any(), any(), any(), any()) } coAnswers {
            prompted.complete(Unit)
            approve.await()
        }
        val transportA = realHandler(keyDao, keystore, launcher)
        val transportB = realHandler(keyDao, keystore, biometricLauncher = null)

        val first = async(Dispatchers.IO) { generate(transportA, credentialId, requireUserVerification = true) }
        withTimeout(TIMEOUT_MS) { prompted.await() }

        val second = generate(transportB, credentialId, requireUserVerification = false)
        assertNotNull("a second generation of a pending ID must be refused, got $second", second.optJSONObject("error"))

        // A share of the ID reads its inputs now, while A waits.
        val share = SharePermissionLedger.baseline(credentialId)

        approve.complete(Unit)
        val firstResponse = withTimeout(TIMEOUT_MS) { first.await() }
        assertNotNull("the approved generation must succeed, got $firstResponse", firstResponse.optJSONObject("result"))

        assertTrue("the credential must be generated once, got $generated", generated == listOf(credentialId))
        verify(exactly = 0) { keystore.deleteKey(credentialId) }
        try {
            SharePermissionLedger.requireUnchanged(share.keyId, share.revision)
            fail("a share whose baseline predates the generation must be refused at admission")
        } catch (_: SharePermissionRevokedException) {
        }
    }

    /**
     * A credential that appears while a generation waits on its approval is
     * refused after approval, not deleted and regenerated.
     */
    @Test
    fun aCredentialCreatedDuringTheApprovalIsNotReplaced() = runBlocking<Unit> {
        val credentialId = "legacy-cred-2"
        val aliases = Collections.synchronizedSet(HashSet<String>())
        val keystore = mockk<KeystoreManager>(relaxed = true)
        every { keystore.keyExists(any()) } answers { "xkey_credential_${firstArg<String>()}" in aliases }
        every { keystore.resolveKeystoreAlias(any()) } answers {
            "xkey_credential_${firstArg<String>()}".takeIf { it in aliases }
        }
        val keyDao = mockk<KeyDao>(relaxed = true)
        val launcher = mockk<BiometricActivityLauncher>(relaxed = true)
        // Another writer creates the credential while the prompt is up.
        coEvery { launcher.requestAuthentication(any(), any(), any(), any()) } answers {
            aliases += "xkey_credential_$credentialId"
        }

        val response = generate(realHandler(keyDao, keystore, launcher), credentialId, requireUserVerification = true)

        assertNotNull("a credential created during the prompt must be refused, got $response", response.optJSONObject("error"))
        coVerify(exactly = 0) { keystore.generateKeyWithAuthDuration(any(), any(), any()) }
    }

    private suspend fun generate(
        handler: RequestHandler,
        credentialId: String,
        requireUserVerification: Boolean
    ): JSONObject {
        val request = JSONObject().put("jsonrpc", "2.0").put("id", 1).put("method", MethodNames.GENERATE_KEY)
            .put(
                "params",
                JSONObject().put("credentialId", credentialId).put("algorithm", CoseAlgorithms.ES256)
                    .put("requireUserVerification", requireUserVerification)
            )
        return JSONObject(String(handler.handleRawRequest(request.toString().toByteArray())))
    }

    /** The real [RequestHandler] with only its Android and storage edges mocked. */
    private fun realHandler(
        keyDao: KeyDao,
        keystore: KeystoreManager,
        biometricLauncher: BiometricActivityLauncher?
    ): RequestHandler {
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
        return RequestHandler(context, keystore, biometricLauncher, sessionAuthManager = null)
    }

    private companion object {
        const val TIMEOUT_MS = 10_000L
    }
}
