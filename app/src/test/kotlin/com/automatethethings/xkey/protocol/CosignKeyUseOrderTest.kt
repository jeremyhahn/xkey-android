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
import com.automatethethings.xkey.auth.NotificationKeys
import com.automatethethings.xkey.auth.PromptOwnership
import com.automatethethings.xkey.crypto.BiometricHelper
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.UserKeyKind
import com.automatethethings.xkey.storage.KeyPolicyStore
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.dao.KeyPolicyDao
import com.automatethethings.xkey.storage.entity.KeyDeletionEntity
import com.automatethethings.xkey.storage.entity.KeyEntity
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.withTimeout
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * #255 review r5: a co-signature of a key that needs the owner for every
 * use reserved the key before its prompt joined the prompt queue, the
 * reverse of every other signer's order. With a signer holding the queue's
 * turn and not yet holding the key, and a delete of the key waiting out the
 * co-sign's use, the three waited on each other. The co-sign now reserves
 * its key only once its prompt's turn has come, so it holds nothing while
 * it waits, and all three finish.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class CosignKeyUseOrderTest {

    private lateinit var context: Context
    private lateinit var keystore: KeystoreManager
    private lateinit var launcher: BiometricActivityLauncher
    private lateinit var handler: RequestHandler
    private val cosignWaitsForItsPrompt = CompletableDeferred<Unit>()
    @Volatile private var deleted = false

    private val signingKey = KeyEntity(
        keyId = KEY,
        keyType = "signing",
        algorithm = "ES256",
        label = "",
        keySizeBits = 256,
        source = "local",
        authDurationSeconds = 0
    )

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
        val keys = mockk<KeyDao>(relaxed = true)
        coEvery { keys.getByKeyId(KEY) } answers { if (deleted) null else signingKey }
        mockkObject(XKeyDatabase.Companion)
        every { XKeyDatabase.getInstance(any()) } returns mockk(relaxed = true) {
            every { keyPolicyDao() } returns policies
            every { keyDao() } returns keys
        }
        Dispatchers.setMain(UnconfinedTestDispatcher())

        context = mockk(relaxed = true)
        every { context.getSystemService(Context.KEYGUARD_SERVICE) } returns
            mockk<KeyguardManager>(relaxed = true)
        every { context.getSystemService(NotificationManager::class.java) } returns
            mockk<NotificationManager>(relaxed = true)

        keystore = mockk(relaxed = true)
        every { keystore.soleKind(any()) } returns UserKeyKind.GENERAL
        every { keystore.exportKind(any()) } returns UserKeyKind.GENERAL
        every { keystore.rowKeyKind(any(), any(), any(), any()) } returns UserKeyKind.GENERAL
        every { keystore.publicKeyDERAt(any()) } returns ByteArray(91) { 3 }

        // The launcher's crypto-bound prompt waits for its own turn on the
        // process-wide prompt queue, as the real one does; the on-turn form
        // makes what it signs only once that turn has come.
        launcher = mockk(relaxed = true)
        coEvery {
            launcher.requestCryptoSignature(any(), any(), any(), any(), any(), any(), any(), any())
        } coAnswers {
            cosignWaitsForItsPrompt.complete(Unit)
            PromptOwnership.process.turn(NotificationKeys.wakeOnly("cosign")) { ByteArray(64) { 7 } }
                ?: error("The co-sign's turn never came")
        }
        coEvery {
            launcher.requestCryptoSignatureOnTurn(any(), any(), any(), any(), any(), any(), any(), any())
        } coAnswers {
            val signedData = arg<suspend () -> ByteArray>(1)
            cosignWaitsForItsPrompt.complete(Unit)
            PromptOwnership.process.turn(NotificationKeys.wakeOnly("cosign")) {
                signedData()
                ByteArray(64) { 7 }
            } ?: error("The co-sign's turn never came")
        }

        handler = RequestHandler(
            context = context,
            keystoreManager = keystore,
            biometricLauncher = launcher,
            sessionAuthManager = null
        ).also { it.setConnectedDevicePublicKeyHex("ab".repeat(32)) }
    }

    @After
    fun tearDown() {
        PromptOwnership.process.forgetSettled()
        Dispatchers.resetMain()
        unmockkAll()
    }

    @Test(timeout = 60_000)
    fun `a signer holding the turn, a per-operation co-sign and a delete of one key all finish`() = runBlocking(Dispatchers.Default) {
        val store = KeyPolicyStore.of(XKeyDatabase.getInstance(context), keystore)
        val signerHasTurn = CompletableDeferred<Unit>()
        val signerGoesOn = CompletableDeferred<Unit>()

        // A signer holds the queue's turn and has not reserved the key yet.
        val signer = async {
            runCatching {
                BiometricHelper.inOneTurn("sign") {
                    signerHasTurn.complete(Unit)
                    signerGoesOn.await()
                    store.withUsableKey(KEY, UserKeyKind.GENERAL) { "signed" }
                }
            }
        }
        signerHasTurn.await()

        // A per-operation co-sign of the key waits for its prompt's turn.
        val cosign = async { handler.handleRequest(cosignRequest()) }
        withTimeout(10_000) { cosignWaitsForItsPrompt.await() }
        assertEquals("the queued co-sign holds the key", 0, KeyPolicyStore.materialLockUsers(KEY))

        // The owner deletes the key meanwhile.
        val deletion = async { store.lockKeyMaterial(KEY) { deleted = true } }
        withTimeout(10_000) {
            while (!deletion.isCompleted && KeyPolicyStore.materialLockUsers(KEY) < 2) delay(5)
        }
        signerGoesOn.complete(Unit)

        try {
            withTimeout(10_000) {
                deletion.await()
                assertTrue("the signer's use of a deleted key is refused", signer.await().isFailure)
                val answer = runCatching { cosign.await() }
                val error = answer.getOrNull()?.error ?: (answer.exceptionOrNull() as? ProtocolException)
                assertNotNull("the co-sign of a deleted key was answered: $answer", error)
            }
        } finally {
            signer.cancel()
            cosign.cancel()
            deletion.cancel()
        }
    }

    private fun cosignRequest() = Request(
        id = 255L,
        method = MethodNames.COSIGN_REQUEST,
        params = JSONObject()
            .put("hash", "0123456789abcdef".repeat(4))
            .put("keyId", KEY)
            .put("hashAlgorithm", "SHA-256")
            .put("from", "initiator")
    )

    private companion object {
        const val KEY = "cosign-key"
    }
}
