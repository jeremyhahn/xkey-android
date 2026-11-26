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
import com.automatethethings.xkey.auth.PromptOwnership
import com.automatethethings.xkey.crypto.BiometricRequiredException
import com.automatethethings.xkey.crypto.CryptoObjectSigner
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.UserKeyKind
import com.automatethethings.xkey.settings.DeviceLookup
import com.automatethethings.xkey.settings.PairedDeviceData
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.dao.KeyPolicyDao
import com.automatethethings.xkey.storage.entity.KeyEntity
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import java.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.withContext
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * local.sign of an Ed25519 key runs the user-verification prompt and the key
 * policy checks an ES256 key runs; a legacy software Ed25519 key is refused.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class LocalSignEd25519Test {

    private lateinit var context: Context
    private lateinit var keystore: KeystoreManager
    private lateinit var launcher: BiometricActivityLauncher
    private lateinit var handler: RequestHandler
    private lateinit var keys: KeyDao
    private lateinit var policies: KeyPolicyDao
    private val promptAlgorithms = mutableListOf<List<Any?>>()
    @Volatile private var promptApproves = true
    @Volatile private var signed = false

    private fun row(algorithm: String) = KeyEntity(
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

        policies = mockk(relaxed = true)
        coEvery { policies.deletion(any()) } returns null
        coEvery { policies.policyRow(any()) } returns null
        keys = mockk(relaxed = true)
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

        val alias = KeystoreManager.generalKeyAlias(KEY)
        keystore = mockk(relaxed = true)
        every { keystore.soleKind(any()) } returns UserKeyKind.GENERAL
        every { keystore.exportKind(any()) } returns UserKeyKind.GENERAL
        every { keystore.rowKeyKind(any(), any(), any(), any()) } returns UserKeyKind.GENERAL
        every { keystore.publicKeyDERAt(any()) } returns ByteArray(44) { 3 }
        every { keystore.generalKeyExists(KEY) } returns true
        every { keystore.hasSoftwareEd25519Key(any()) } returns false
        every { keystore.pqcSoftwareKeyRequiresUserAuth(KEY) } returns false
        every { keystore.isPerOperationKey(alias) } returns true
        coEvery { keystore.signApproved(alias, any(), any(), any(), any()) } coAnswers {
            val signer = arg<CryptoObjectSigner?>(4) ?: throw BiometricRequiredException()
            signer.sign(alias, arg(3), arg(2)).also { signed = true }
        }

        // The crypto-bound prompt signs only when the user approves it.
        launcher = mockk(relaxed = true)
        coEvery {
            launcher.requestCryptoSignatureOnTurn(any(), any(), any(), any(), any(), any(), any(), any())
        } coAnswers {
            promptAlgorithms += args.toList()
            if (!promptApproves) throw BiometricRequiredException()
            arg<suspend () -> ByteArray>(1)()
            ByteArray(64) { 7 }
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
    fun `an ES256 and an EdDSA key both sign through the user-verification prompt and the key policy`() {
        for ((algorithm, jca) in listOf("ES256" to "SHA256withECDSA", "EdDSA" to "Ed25519")) {
            promptAlgorithms.clear()
            signed = false
            coEvery { keys.getByKeyId(KEY) } returns row(algorithm)

            val answer = localSign()

            assertTrue("$algorithm signs: $answer", answer.has("result"))
            assertTrue("$algorithm signed in the prompt", signed)
            assertEquals("$algorithm was prompted once", 1, promptAlgorithms.size)
            assertTrue("$algorithm prompt used $jca: $promptAlgorithms", jca in promptAlgorithms.single())
        }
        coVerify(atLeast = 2) { policies.deletion(KEY) }
    }

    @Test(timeout = 60_000)
    fun `an EdDSA sign the user does not approve is refused and signs nothing`() {
        coEvery { keys.getByKeyId(KEY) } returns row("EdDSA")
        promptApproves = false

        val answer = localSign()

        assertTrue("refused: $answer", answer.has("error"))
        assertEquals(1, promptAlgorithms.size)
        assertFalse(signed)
    }

    @Test(timeout = 60_000)
    fun `a deleted EdDSA key is refused by the key policy before any prompt`() {
        coEvery { keys.getByKeyId(KEY) } returns row("EdDSA")
        coEvery { policies.deletion(KEY) } returns mockk(relaxed = true)

        val answer = localSign()

        assertTrue("refused: $answer", answer.has("error"))
        assertTrue(promptAlgorithms.isEmpty())
        assertFalse(signed)
    }

    @Test(timeout = 60_000)
    fun `a legacy software Ed25519 key is refused clearly and is never read`() {
        coEvery { keys.getByKeyId(KEY) } returns row("Ed25519")
        every { keystore.generalKeyExists(KEY) } returns false
        every { keystore.hasSoftwareEd25519Key(KeystoreManager.generalKeyAlias(KEY)) } returns true

        val answer = localSign()

        val error = answer.getJSONObject("error")
        assertEquals(ErrorCodes.INVALID_ALGORITHM, error.getInt("code"))
        assertTrue(error.getString("message"), "legacy software Ed25519" in error.getString("message"))
        assertTrue(promptAlgorithms.isEmpty())
        assertFalse(signed)
    }

    private fun localSign(): JSONObject = runBlocking(Dispatchers.Default) {
        val data = Base64.getEncoder().encodeToString("to sign".toByteArray())
        val request = """{"jsonrpc":"2.0","id":1,"method":"${MethodNames.LOCAL_SIGN}",""" +
            """"params":{"keyId":"$KEY","data":"$data","userVerificationRequired":true}}"""
        withContext(RequestHandler.servedConnection(binding, PEER, "test:connection")) {
            JSONObject(String(handler.handleRawRequest(request.toByteArray(Charsets.UTF_8)), Charsets.UTF_8))
        }
    }

    private companion object {
        const val KEY = "ed-sign-key"
        const val PEER = "aa01"
        val binding = SessionBindingProvider {
            SessionBinding(ByteArray(32) { 3 }, ByteArray(32) { 4 }, ByteArray(0))
        }
    }
}
