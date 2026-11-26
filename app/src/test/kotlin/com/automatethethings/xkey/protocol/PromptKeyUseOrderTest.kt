/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
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
import com.automatethethings.xkey.auth.PromptOwnership
import com.automatethethings.xkey.auth.SessionAuthManager
import com.automatethethings.xkey.crypto.BiometricHelper
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.UserKeyKind
import com.automatethethings.xkey.auth.NotificationKeys
import com.automatethethings.xkey.settings.BiometricAuthMode
import com.automatethethings.xkey.settings.BiometricSettingsData
import com.automatethethings.xkey.settings.UserVerificationPolicy
import com.automatethethings.xkey.storage.KeyPolicyStore
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.KeyPolicyDao
import com.automatethethings.xkey.storage.entity.KeyDeletionEntity
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import java.util.Base64
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * A key use that waits for the approval prompt queue takes its locks in the
 * one order every holder takes them (#255 review): the prompt queue's turn,
 * then the key-use reservation, then the material mutex. A provider
 * assertion holding the queue's turn, an RPC sign of the same credential
 * waiting for its own prompt, and a delete of that credential all finish,
 * whichever of them gets which lock first.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class PromptKeyUseOrderTest {

    private lateinit var context: Context
    private lateinit var keystore: KeystoreManager
    private lateinit var biometricLauncher: BiometricActivityLauncher
    private lateinit var handler: RequestHandler
    private val rpcWaitsForItsPrompt = CompletableDeferred<Unit>()
    @Volatile private var deleted = false

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

        // The key's tombstone appears once its delete has run.
        val policies = mockk<KeyPolicyDao>(relaxed = true)
        coEvery { policies.deletion(any()) } answers {
            if (deleted) mockk<KeyDeletionEntity>(relaxed = true) else null
        }
        coEvery { policies.policyRow(any()) } returns null
        mockkObject(XKeyDatabase.Companion)
        every { XKeyDatabase.getInstance(any()) } returns mockk(relaxed = true) {
            every { keyPolicyDao() } returns policies
        }
        Dispatchers.setMain(UnconfinedTestDispatcher())

        context = mockk(relaxed = true)
        every { context.getSystemService(Context.KEYGUARD_SERVICE) } returns
            mockk<KeyguardManager>(relaxed = true)
        every { context.getSystemService(NotificationManager::class.java) } returns
            mockk<NotificationManager>(relaxed = true)

        keystore = mockk(relaxed = true)
        every { keystore.soleKind(any()) } returns UserKeyKind.CREDENTIAL

        // The launcher's crypto-bound prompt waits for its own turn on the
        // process-wide prompt queue, as the real one does; the on-turn form
        // makes what it signs only once that turn has come.
        biometricLauncher = mockk(relaxed = true)
        coEvery {
            biometricLauncher.requestCryptoSignature(any(), any(), any(), any(), any(), any(), any(), any())
        } coAnswers {
            rpcWaitsForItsPrompt.complete(Unit)
            PromptOwnership.process.turn(NotificationKeys.wakeOnly("rpcSign")) { ByteArray(64) { 7 } }
                ?: error("The RPC sign's turn never came")
        }
        coEvery {
            biometricLauncher.requestCryptoSignatureOnTurn(any(), any(), any(), any(), any(), any(), any(), any())
        } coAnswers {
            val signedData = arg<suspend () -> ByteArray>(1)
            rpcWaitsForItsPrompt.complete(Unit)
            PromptOwnership.process.turn(NotificationKeys.wakeOnly("rpcSign")) {
                signedData()
                ByteArray(64) { 7 }
            } ?: error("The RPC sign's turn never came")
        }

        handler = RequestHandler(
            context = context,
            keystoreManager = keystore,
            biometricLauncher = biometricLauncher,
            sessionAuthManager = SessionAuthManager(clock = { 0L }),
        )
        handler.updateSettings(
            BiometricSettingsData(
                uvPolicy = UserVerificationPolicy.REQUIRED,
                authMode = BiometricAuthMode.PER_OPERATION,
            )
        )
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
        unmockkAll()
    }

    @Test(timeout = 60_000)
    fun `a provider assertion, an RPC sign and a delete of one credential all finish`() = runBlocking(Dispatchers.Default) {
        val store = KeyPolicyStore.of(XKeyDatabase.getInstance(context), keystore)
        val assertionHasTurn = CompletableDeferred<Unit>()
        val assertionGoesOn = CompletableDeferred<Unit>()

        // The credential provider's assertion holds the queue's turn, as
        // GetCredentialHandler's does, and signs under the key's gate inside it.
        val assertion = async {
            runCatching {
                BiometricHelper.inOneTurn("passkeyAssertion") {
                    assertionHasTurn.complete(Unit)
                    assertionGoesOn.await()
                    store.withUsableKey(CREDENTIAL, UserKeyKind.CREDENTIAL) { "signed" }
                }
            }
        }
        assertionHasTurn.await()

        // An RPC sign of the same credential waits for its prompt's turn.
        val rpc = async { sign() }
        rpcWaitsForItsPrompt.await()

        // The owner deletes the credential meanwhile.
        val deletion = async { store.lockKeyMaterial(CREDENTIAL) { deleted = true } }
        // The delete has run, or holds the mutex and waits for a use to end.
        withTimeout(10_000) {
            while (!deletion.isCompleted && KeyPolicyStore.materialLockUsers(CREDENTIAL) < 2) delay(5)
        }
        assertionGoesOn.complete(Unit)

        try {
            withTimeout(10_000) {
                deletion.await()
                assertTrue("the assertion of a deleted key is refused", assertion.await().isFailure)
                assertEquals(ErrorCodes.KEY_NOT_FOUND, rpc.await().error?.code)
            }
        } finally {
            assertion.cancel()
            rpc.cancel()
            deletion.cancel()
        }
    }

    private suspend fun sign(): Response {
        val params = JSONObject()
            .put("credentialId", CREDENTIAL)
            .put("dataHash", Base64.getEncoder().encodeToString(ByteArray(32) { 1 }))
            .put("userVerificationRequired", true)
        val raw = withContext(
            RequestHandler.servedConnection(SessionBindingProvider { null }, null, "usb:one")
        ) {
            handler.handleRawRequest(Request(id = 1, method = MethodNames.SIGN, params = params).toJson())
        }
        return Response.fromJson(raw)
    }

    private companion object {
        const val CREDENTIAL = "credential-1"
    }
}
