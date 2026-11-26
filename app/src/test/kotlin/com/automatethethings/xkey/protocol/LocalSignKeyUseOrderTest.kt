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
import com.automatethethings.xkey.crypto.BiometricRequiredException
import com.automatethethings.xkey.crypto.CryptoObjectSigner
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.UserKeyKind
import com.automatethethings.xkey.settings.DeviceLookup
import com.automatethethings.xkey.settings.PairedDeviceData
import com.automatethethings.xkey.settings.PairedDeviceRepository
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
 * #255 review (PR #270 at 9b6c00f5): local.sign of a per-operation key
 * reserved the key's use before its CryptoObject prompt joined the prompt
 * queue, the reverse of [KeyPolicyStore.withKeyUseOnTurn]'s order. With a
 * signer holding the queue's turn and not yet holding the key, and a delete
 * of the key waiting out local.sign's use, the three waited on each other.
 * local.sign now reserves its key only once its prompt's turn has come, so
 * it holds nothing while it waits, and all three finish: for a JCA key and
 * for an ML-DSA key.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class LocalSignKeyUseOrderTest {

    private lateinit var context: Context
    private lateinit var keystore: KeystoreManager
    private lateinit var launcher: BiometricActivityLauncher
    private lateinit var handler: RequestHandler
    private val signWaitsForItsPrompt = CompletableDeferred<Unit>()
    @Volatile private var deleted = false
    @Volatile private var algorithm = "ES256"

    private fun row() = KeyEntity(
        keyId = KEY,
        keyType = "signing",
        algorithm = algorithm,
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
        coEvery { keys.getByKeyId(KEY) } answers { if (deleted) null else row() }
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

        // A per-operation key signs only through the CryptoObject prompt it is handed.
        val alias = KeystoreManager.generalKeyAlias(KEY)
        keystore = mockk(relaxed = true)
        every { keystore.soleKind(any()) } returns UserKeyKind.GENERAL
        every { keystore.exportKind(any()) } returns UserKeyKind.GENERAL
        every { keystore.rowKeyKind(any(), any(), any(), any()) } returns UserKeyKind.GENERAL
        every { keystore.publicKeyDERAt(any()) } returns ByteArray(91) { 3 }
        every { keystore.generalKeyExists(KEY) } returns true
        every { keystore.pqcSoftwareKeyRequiresUserAuth(KEY) } returns false
        every { keystore.isPerOperationKey(alias) } returns true
        coEvery { keystore.signApproved(alias, any(), any(), any(), any()) } coAnswers {
            val signer = arg<CryptoObjectSigner?>(4) ?: throw BiometricRequiredException()
            signer.sign(alias, arg(3), arg(2))
        }
        coEvery { keystore.signApprovedMlDsa(alias, any(), any(), any(), any(), any()) } coAnswers {
            val signer = arg<CryptoObjectSigner?>(5) ?: throw BiometricRequiredException()
            signer.sign(alias, "ML-DSA-65", arg(2))
        }

        // The launcher's crypto-bound prompt waits for its own turn on the
        // process-wide prompt queue, as the real one does; the on-turn form
        // makes what it signs only once that turn has come.
        launcher = mockk(relaxed = true)
        coEvery {
            launcher.requestCryptoSignature(any(), any(), any(), any(), any(), any(), any(), any())
        } coAnswers {
            signWaitsForItsPrompt.complete(Unit)
            PromptOwnership.process.turn(NotificationKeys.wakeOnly("sign")) { ByteArray(64) { 7 } }
                ?: error("local.sign's turn never came")
        }
        coEvery {
            launcher.requestCryptoSignatureOnTurn(any(), any(), any(), any(), any(), any(), any(), any())
        } coAnswers {
            val signedData = arg<suspend () -> ByteArray>(1)
            signWaitsForItsPrompt.complete(Unit)
            PromptOwnership.process.turn(NotificationKeys.wakeOnly("sign")) {
                signedData()
                ByteArray(64) { 7 }
            } ?: error("local.sign's turn never came")
        }

        val pairedDevices = mockk<PairedDeviceRepository>()
        every { pairedDevices.lookupDevice(any()) } returns DeviceLookup.Paired(
            mockk<PairedDeviceData>(relaxed = true) {
                every { deviceName } returns "Desktop"
                every { requireAttestationForKeyUse } returns false
            }
        )
        handler = RequestHandler(
            context = context,
            keystoreManager = keystore,
            biometricLauncher = launcher,
            sessionAuthManager = null,
            pairedDeviceRepository = pairedDevices,
            pinManager = mockk(relaxed = true)
        ).also { it.setConnectedDevicePublicKeyHex(PEER) }
    }

    @After
    fun tearDown() {
        PromptOwnership.process.forgetSettled()
        Dispatchers.resetMain()
        unmockkAll()
    }

    @Test(timeout = 60_000)
    fun `a signer holding the turn, a per-operation local sign and a delete of one key all finish`() =
        signerLocalSignAndDeleteFinish("ES256")

    @Test(timeout = 60_000)
    fun `a signer holding the turn, a per-operation ML-DSA local sign and a delete of one key all finish`() =
        signerLocalSignAndDeleteFinish("ML-DSA-65")

    private fun signerLocalSignAndDeleteFinish(keyAlgorithm: String) = runBlocking(Dispatchers.Default) {
        algorithm = keyAlgorithm
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

        // A per-operation local.sign of the key waits for its prompt's turn.
        val localSign = async { runCatching { localSign() } }
        withTimeout(10_000) { signWaitsForItsPrompt.await() }
        assertEquals("the queued local.sign holds the key", 0, KeyPolicyStore.materialLockUsers(KEY))

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
                val answer = localSign.await()
                val refused = answer.exceptionOrNull() != null || answer.getOrNull()?.has("error") == true
                assertTrue("local.sign of a deleted key was refused: $answer", refused)
            }
        } finally {
            signer.cancel()
            localSign.cancel()
            deletion.cancel()
        }
    }

    private suspend fun localSign(): JSONObject {
        val data = Base64.getEncoder().encodeToString("to sign".toByteArray())
        val request = """{"jsonrpc":"2.0","id":1,"method":"${MethodNames.LOCAL_SIGN}",""" +
            """"params":{"keyId":"$KEY","data":"$data","userVerificationRequired":true}}"""
        return withContext(RequestHandler.servedConnection(binding, PEER, "test:connection")) {
            JSONObject(String(handler.handleRawRequest(request.toByteArray(Charsets.UTF_8)), Charsets.UTF_8))
        }
    }

    private companion object {
        const val KEY = "local-sign-key"
        const val PEER = "aa01"
        val binding = SessionBindingProvider {
            SessionBinding(ByteArray(32) { 3 }, ByteArray(32) { 4 }, ByteArray(0))
        }
    }
}
