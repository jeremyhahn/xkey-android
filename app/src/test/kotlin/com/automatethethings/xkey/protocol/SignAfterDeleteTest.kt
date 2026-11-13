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
import com.automatethethings.xkey.auth.SessionAuthManager
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.settings.BiometricAuthMode
import com.automatethethings.xkey.settings.BiometricSettingsData
import com.automatethethings.xkey.settings.UserVerificationPolicy
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.KeyPolicyDao
import com.automatethethings.xkey.storage.entity.KeyDeletionEntity
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import java.io.File
import java.util.Base64
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.withContext
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test

/**
 * A request that waits in an approval prompt while the key it uses is
 * deleted never runs crypto with that key (#255 review, ruling 554).
 *
 * The dispatch gate checks the key once, before the handler; a sign then
 * waits in its prompt, and a delete can report success meanwhile. Every
 * crypto call of a user key in the protocol handlers runs inside
 * KeyPolicyStore.withUsableKey, which rechecks the key under the lock every
 * delete takes. The sweep below keeps a new crypto call from bypassing it.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class SignAfterDeleteTest {

    private lateinit var keystore: KeystoreManager
    private lateinit var biometricLauncher: BiometricActivityLauncher
    private lateinit var handler: RequestHandler
    private val approval = CompletableDeferred<Unit>()
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

        // The key's tombstone appears once its delete has reported success.
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

        val context = mockk<Context>(relaxed = true)
        every { context.getSystemService(Context.KEYGUARD_SERVICE) } returns
            mockk<KeyguardManager>(relaxed = true)
        every { context.getSystemService(NotificationManager::class.java) } returns
            mockk<NotificationManager>(relaxed = true)

        keystore = mockk(relaxed = true)
        every { keystore.keyExists(any()) } returns true
        coEvery { keystore.signWithoutBiometric(any(), any()) } returns ByteArray(64) { 7 }

        // The prompt stays open until the test approves it.
        biometricLauncher = mockk(relaxed = true)
        coEvery { biometricLauncher.requestAuthentication(any(), any(), any(), any(), any()) } coAnswers {
            approval.await()
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
                authMode = BiometricAuthMode.PER_SESSION,
            )
        )
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
        unmockkAll()
    }

    @Test
    fun `a sign approved after its key was deleted is refused before any signing`() = runTest {
        val pending = async { sign() }
        runCurrent()

        // The user deletes the key while the sign's prompt is open, and the
        // delete reports success; then the prompt is approved.
        deleted = true
        approval.complete(Unit)
        val response = pending.await()

        assertEquals(ErrorCodes.KEY_NOT_FOUND, response.error?.code)
        coVerify(exactly = 0) { keystore.signWithoutBiometric(any(), any()) }
    }

    @Test
    fun `a sign approved while its key is still there signs`() = runTest {
        val pending = async { sign() }
        runCurrent()
        approval.complete(Unit)

        assertEquals(null, pending.await().error)
        coVerify(exactly = 1) { keystore.signWithoutBiometric(any(), any()) }
    }

    @Test
    fun `every crypto call of a user key in the protocol handlers runs inside withUsableKey`() {
        val root = listOf(File("src/main/kotlin"), File("app/src/main/kotlin")).first { it.isDirectory }
        val crypto = Regex(
            """keystoreManager\.(sign|signWithoutBiometric|signWithAlgorithm|rsaDecrypt\w*|decrypt\w*|encrypt\w*|symmetric\w*|computeHMAC\w*|performECDH|ecdh\w*)\(""" +
                """|requestCryptoSignature\(|SoftwareKeyOps\.(aesGcm\w*|hmac|sign\w*|ecdh\w*)\("""
        )
        val bypasses = File(root, "com/automatethethings/xkey/protocol").listFiles { f -> f.extension == "kt" }!!
            .flatMap { file ->
                val lines = file.readLines()
                lines.mapIndexedNotNull { i, line ->
                    val code = line.substringBefore("//")
                    if (!crypto.containsMatchIn(code) || "withUsableKey(" in code) return@mapIndexedNotNull null
                    // The user-verification key is the app's own, never a peer's key to delete.
                    if (lines.getOrNull(i + 1)?.contains("\"user-verification\"") == true) return@mapIndexedNotNull null
                    "${file.name}:${i + 1}"
                }
            }
        assertEquals(emptyList<String>(), bypasses)
    }

    private suspend fun sign(): Response {
        val params = JSONObject()
            .put("credentialId", "credential-1")
            .put("dataHash", Base64.getEncoder().encodeToString(ByteArray(32) { 1 }))
            .put("userVerificationRequired", true)
        val raw = withContext(
            RequestHandler.servedConnection(SessionBindingProvider { null }, null, "usb:one")
        ) {
            handler.handleRawRequest(Request(id = 1, method = MethodNames.SIGN, params = params).toJson())
        }
        return Response.fromJson(raw)
    }
}
