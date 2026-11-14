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
import android.content.Intent
import android.os.Looper
import android.util.Log
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.auth.BiometricActivityLauncher
import com.automatethethings.xkey.auth.BiometricActivityLauncher.BiometricResult
import com.automatethethings.xkey.auth.BiometricNotificationHelper
import com.automatethethings.xkey.auth.PendingAuthentications
import com.automatethethings.xkey.auth.PromptOwnership
import com.automatethethings.xkey.crypto.BiometricException
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.runs
import io.mockk.unmockkAll
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.Base64

/**
 * Pins what two requests for one key do when both wait in the approval queue
 * and the owner approves both (#178).
 *
 * Approval prompts take turns, so a request's checks run long before it acts.
 * Two creations of one new key id must not both reach the key generator (it
 * replaces an existing alias, destroying the first key), and two assertions
 * with one passkey must not both sign the counter they read before the wait.
 *
 * Requests go through the real [RequestHandler.handleRequest] on handlers of
 * their own, as on two connections; prompts go through a real
 * [PendingAuthentications]. The key store and the key table are small
 * stateful fakes over the mocked [KeystoreManager] and [KeyDao].
 */
@OptIn(ExperimentalCoroutinesApi::class)
class QueuedApprovalRaceTest {

    private lateinit var keyDao: KeyDao
    private lateinit var policies: com.automatethethings.xkey.storage.dao.KeyPolicyDao
    private lateinit var keystore: KeystoreManager
    private lateinit var context: Context
    private lateinit var launcher: BiometricActivityLauncher

    private val peer = "ab".repeat(32)

    /** Aliases present in the fake Keystore. */
    private val aliases = mutableSetOf<String>()

    /** Generator calls that replaced an alias already present: a destroyed key. */
    private var replaced = 0

    /** The passkey's stored signature counter. */
    private var storedSignCount = 0L

    /** The request ids the approval prompts were launched for, in launch order. */
    private val prompts = mutableListOf<String>()
    private lateinit var approvals: PendingAuthentications

    private val credentialId = "Y3JlZC0xNzg="

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
        coEvery { keyDao.getByKeyId(credentialId) } answers { passkey(storedSignCount) }
        coEvery { keyDao.updateSignCount(credentialId, any(), any()) } answers {
            storedSignCount = secondArg()
        }
        val database = mockk<XKeyDatabase>(relaxed = true)
        every { database.keyDao() } returns keyDao
        // No earlier delete under any id is owed.
        policies = mockk(relaxed = true)
        coEvery { policies.deletion(any()) } returns null
        every { database.keyPolicyDao() } returns policies
        // The store's transaction runs inline: a mock database has no Room
        // transaction executor, so withTransaction would never return (#193).
        mockkObject(com.automatethethings.xkey.storage.KeyPolicyStore.Companion)
        every { com.automatethethings.xkey.storage.KeyPolicyStore.of(any()) } answers {
            com.automatethethings.xkey.storage.KeyPolicyStore(
                policies,
                object : com.automatethethings.xkey.storage.KeyPolicyStore.Transactor {
                    override suspend fun <T> run(block: suspend () -> T): T = block()
                },
                java.util.concurrent.ConcurrentHashMap()
            )
        }
        mockkObject(XKeyDatabase.Companion)
        every { XKeyDatabase.getInstance(any()) } returns database

        mockkObject(AuditLogger)
        every { AuditLogger.logFido2Registration(any(), any(), any(), any()) } just runs
        every { AuditLogger.logFido2Authentication(any(), any(), any()) } just runs

        keystore = mockk(relaxed = true)
        coEvery { keystore.generalKeyExists(any()) } answers { firstArg<String>() in aliases }
        coEvery { keystore.keyExists(any()) } answers { firstArg<String>() in aliases }
        coEvery { keystore.generateKeyForAlgorithm(any(), any(), any(), any()) } answers {
            create(firstArg())
            ByteArray(91) { 1 }
        }
        coEvery { keystore.generateKeyWithAuthDuration(any(), any(), any()) } answers {
            create(firstArg())
            ByteArray(77) { 2 }
        }
        coEvery { keystore.signWithoutBiometric(credentialId, any()) } returns ByteArray(70) { 3 }

        Dispatchers.setMain(UnconfinedTestDispatcher())

        context = mockk(relaxed = true)
        val keyguard = mockk<KeyguardManager>(relaxed = true)
        every { keyguard.isKeyguardLocked } returns false
        every { context.getSystemService(Context.KEYGUARD_SERVICE) } returns keyguard
        every { context.getSystemService(NotificationManager::class.java) } returns
            mockk<NotificationManager>(relaxed = true)

        mockkConstructor(BiometricNotificationHelper::class)
        every {
            anyConstructed<BiometricNotificationHelper>()
                .showBiometricRequiredNotification(any(), any(), any(), any(), any(), any())
        } just runs
        every { anyConstructed<BiometricNotificationHelper>().cancelNotification(any<String>()) } just runs

        launcher = mockk(relaxed = true)
        // Prompts take turns on a screen of this test's own, as on the phone.
        approvals = PendingAuthentications(PromptOwnership(), expirePrompt = { false })
        coEvery { launcher.requestAuthentication(any(), any(), any(), any(), any()) } coAnswers {
            val onLaunch = arg<(String, Intent) -> Unit>(4)
            val launch = { requestId: String ->
                prompts += requestId
                onLaunch(requestId, mockk())
            }
            when (val result = approvals.await(launch = launch)) {
                is BiometricResult.Success -> Unit
                is BiometricResult.Error -> throw BiometricException(result.code, result.message)
            }
        }
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
        unmockkAll()
    }

    /** The fake generator: like the real one, it deletes an existing alias first. */
    private fun create(alias: String) {
        if (!aliases.add(alias)) replaced++
    }

    private fun handler(): RequestHandler = RequestHandler(
        context = context,
        keystoreManager = keystore,
        biometricLauncher = launcher,
        sessionAuthManager = null
    ).also { it.setConnectedDevicePublicKeyHex(peer) }

    private fun passkey(signCount: Long) = KeyEntity(
        id = 1L,
        keyId = credentialId,
        keyType = KeyTypes.FIDO2,
        algorithm = "ES256",
        label = "Passkey",
        keySizeBits = 256,
        shareable = true,
        sharingPolicy = SharingPolicyType.ALL_PEERS,
        source = "remote_ble",
        rpId = "example.com",
        rpName = "Example",
        signCount = signCount
    )

    /** Approves every prompt as it comes up until both requests have answered. */
    private fun TestScope.approveEveryPrompt(vararg requests: Deferred<Response>) {
        var approved = 0
        runCurrent()
        while (requests.any { it.isActive }) {
            assertTrue("a request waits with no prompt up", approved < prompts.size)
            assertTrue(approvals.complete(prompts[approved++], BiometricResult.Success))
            runCurrent()
        }
    }

    private fun localGenerateKey(id: Long, keyId: String) = Request(
        id = id,
        method = MethodNames.LOCAL_GENERATE_KEY,
        params = JSONObject().put("keyId", keyId).put("algorithm", "ES256")
    )

    private fun legacyGenerateKey(id: Long, credentialId: String) = Request(
        id = id,
        method = MethodNames.GENERATE_KEY,
        params = JSONObject().put("credentialId", credentialId).put("algorithm", CoseAlgorithms.ES256)
    )

    private fun assertion(id: Long) = Request(
        id = id,
        method = MethodNames.LOCAL_SIGN_FIDO2_ASSERTION,
        params = JSONObject()
            .put("credentialId", credentialId)
            .put("clientDataHash", Base64.getEncoder().encodeToString(ByteArray(32) { id.toByte() }))
            .put("rpId", "example.com")
            .put("userVerificationRequired", true)
    )

    @Test
    fun `two approved local generateKey requests for one new key id create it once`() = runTest {
        val first = async { handler().handleRequest(localGenerateKey(1L, "key-178")) }
        val second = async { handler().handleRequest(localGenerateKey(2L, "key-178")) }

        approveEveryPrompt(first, second)

        val answers = listOf(first.await(), second.await())
        assertEquals("exactly one creates the key", 1, answers.count { it.error == null })
        assertEquals(
            "the other is told the key exists",
            listOf(ErrorCodes.KEY_EXISTS),
            answers.mapNotNull { it.error?.code }
        )
        assertEquals("the first key is never replaced", 0, replaced)
        coVerify(exactly = 1) { keystore.generateKeyForAlgorithm("key-178", any(), any(), any()) }
        // Through the store, which inserts the key row with its policy row (#193).
        coVerify(exactly = 1) { policies.insertKey(any()) }
    }

    @Test
    fun `two approved legacy generateKey requests for one new credential create it once`() = runTest {
        val first = async { handler().handleRequest(legacyGenerateKey(1L, "cred-178")) }
        val second = async { handler().handleRequest(legacyGenerateKey(2L, "cred-178")) }

        approveEveryPrompt(first, second)

        val answers = listOf(first.await(), second.await())
        assertEquals("exactly one creates the credential", 1, answers.count { it.error == null })
        // The legacy method keeps its own refusal for an existing credential.
        assertEquals(listOf(ErrorCodes.INVALID_PARAMS), answers.mapNotNull { it.error?.code })
        assertEquals(
            listOf("Credential already exists"),
            answers.mapNotNull { it.error?.message }
        )
        assertEquals("the first credential is never replaced", 0, replaced)
        coVerify(exactly = 1) { keystore.generateKeyWithAuthDuration("cred-178", any(), any()) }
    }

    @Test
    fun `a generation approved after the key was created elsewhere never reaches the generator`() = runTest {
        val request = async { handler().handleRequest(localGenerateKey(1L, "key-178")) }
        runCurrent()
        // Another creator (not a wire request) makes the key while the prompt is up.
        aliases += "key-178"

        approveEveryPrompt(request)

        assertEquals(ErrorCodes.KEY_EXISTS, request.await().error?.code)
        coVerify(exactly = 0) { keystore.generateKeyForAlgorithm(any(), any(), any(), any()) }
        assertEquals(0, replaced)
    }

    @Test
    fun `two approved assertions with one passkey sign distinct increasing counters`() = runTest {
        storedSignCount = 7L
        val first = async { handler().handleRequest(assertion(1L)) }
        val second = async { handler().handleRequest(assertion(2L)) }

        approveEveryPrompt(first, second)

        val counts = listOf(first.await(), second.await()).map { response ->
            assertNull(response.error)
            val authData = Base64.getDecoder().decode(response.result!!.getString("authenticatorData"))
            val signed = authData.copyOfRange(33, 37).fold(0L) { acc, b -> (acc shl 8) or (b.toLong() and 0xFF) }
            assertEquals("the reported counter is the signed one", signed, response.result!!.getLong("signCount"))
            signed
        }
        assertEquals(listOf(8L, 9L), counts.sorted())
        assertEquals("the stored counter is the larger one", 9L, storedSignCount)
    }
}
