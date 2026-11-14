/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
 *
 * This file is part of xkey-android.
 *
 * xkey-android is dual-licensed:
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
import com.automatethethings.xkey.auth.BiometricNotificationHelper
import com.automatethethings.xkey.auth.NotificationKeys
import com.automatethethings.xkey.auth.PromptOwnership
import com.automatethethings.xkey.crypto.BiometricLockoutException
import com.automatethethings.xkey.crypto.BiometricUnavailableException
import com.automatethethings.xkey.crypto.KeyGenerationException
import com.automatethethings.xkey.crypto.KeyInvalidatedException
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.UserCancelledException
import com.automatethethings.xkey.crypto.UserVerificationKey
import com.automatethethings.xkey.crypto.UserVerificationPrompt
import com.automatethethings.xkey.storage.XKeyDatabase
import io.mockk.coVerify
import io.mockk.Runs
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.Date
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.withContext
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * `local.verifyUser` on the real [RequestHandler] (#13).
 *
 * The UVK is a software P-256 key behind the [UserVerificationKey] seam and the
 * biometric prompt is a [UserVerificationPrompt] that signs with it, so each
 * answer can be verified end to end. The Android edges are mocked as in
 * [AttestationPolicyCallerPeerTest]. There is no AndroidKeyStore on the JVM, so
 * any touch of the Device Attestation Key would fail the request: a successful
 * verify-user answer is itself proof that the DAK was left alone.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class VerifyUserHandlerTest {

    private lateinit var context: Context
    private lateinit var biometricLauncher: BiometricActivityLauncher
    private lateinit var uvk: FakeUserVerificationKey
    private lateinit var prompt: FakePrompt
    private lateinit var handler: RequestHandler

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

        mockkObject(XKeyDatabase.Companion)
        every { XKeyDatabase.getInstance(any()) } returns mockk(relaxed = true)

        Dispatchers.setMain(UnconfinedTestDispatcher())

        context = mockk(relaxed = true)
        every { context.getSystemService(Context.KEYGUARD_SERVICE) } returns
            mockk<KeyguardManager>(relaxed = true)
        every { context.getSystemService(NotificationManager::class.java) } returns
            mockk<NotificationManager>(relaxed = true)

        biometricLauncher = mockk(relaxed = true)
        uvk = FakeUserVerificationKey()
        prompt = FakePrompt(uvk)
        handler = RequestHandler(
            context = context,
            keystoreManager = mockk<KeystoreManager>(relaxed = true),
            biometricLauncher = biometricLauncher,
            sessionAuthManager = null,
            userVerificationKey = uvk,
            userVerificationPrompt = prompt
        )
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
        unmockkAll()
    }

    // -----------------------------------------------------------------
    // Success
    // -----------------------------------------------------------------

    @Test
    fun aVerifiedUserIsAnsweredWithTheChainAndASignatureOverTheTranscript() = runTest {
        val response = answer(verifyUserRequest(id = 42, generation = 7uL))

        assertNull("no error expected: ${response.error?.message}", response.error)
        assertEquals(42L, response.id)
        assertEquals(7uL, response.generation)
        val result = LocalVerifyUserResult.fromJson(response.result!!)
        assertEquals(2, result.protocolVersion)
        assertEquals("ES256", result.signatureAlgorithm)
        assertEquals(uvk.chain().map { Base64.getEncoder().encodeToString(it.encoded) }, result.certificateChain)
        assertTrue(
            "the signature must verify over the verify-user transcript",
            verifies(uvk.keyPair, expectedTranscript(uvk), Base64.getDecoder().decode(result.signature))
        )
        assertEquals(1, prompt.prompts)
    }

    // -----------------------------------------------------------------
    // Refusals: errors, never a result
    // -----------------------------------------------------------------

    @Test
    fun aCancelledPromptIsUserCancelledAndNoResult() = runTest {
        prompt.failWith = UserCancelledException()

        assertRefused(ErrorCodes.USER_CANCELLED)
    }

    @Test
    fun aLockedOutBiometricIsBiometricLockoutAndNoResult() = runTest {
        prompt.failWith = BiometricLockoutException(isPermanent = false)

        assertRefused(ErrorCodes.BIOMETRIC_LOCKOUT)
    }

    @Test
    fun noClassThreeBiometricIsBiometricFailedAndNoPrompt() = runTest {
        uvk.chainFailure = BiometricUnavailableException("no Class 3 biometric is enrolled")

        assertRefused(ErrorCodes.BIOMETRIC_FAILED)
        assertEquals(0, prompt.prompts)
    }

    @Test
    fun aUvkThatCannotBeMadeIsKeyGenerationFailedAndNoPrompt() = runTest {
        uvk.chainFailure = KeyGenerationException("no attestation chain")

        assertRefused(ErrorCodes.KEY_GENERATION_FAILED)
        assertEquals(0, prompt.prompts)
    }

    /** A request that names no connection has no binding of its own, and borrows none. */
    @Test
    fun aRequestOnNoConnectionIsARefusalWithoutAPrompt() = runTest {
        val response = Response.fromJson(handler.handleRawRequest(verifyUserRequest().toJson()))

        assertEquals(ErrorCodes.ATTESTATION_FAILED, response.error?.code)
        assertNull("a refusal carries no result", response.result)
        assertEquals(0, prompt.prompts)
    }

    @Test
    fun aConnectionWithNoBindingIsARefusalWithoutAPrompt() = runTest {
        val response = onConnection(SessionBindingProvider { null }) {
            Response.fromJson(handler.handleRawRequest(verifyUserRequest().toJson()))
        }

        assertEquals(ErrorCodes.ATTESTATION_FAILED, response.error?.code)
        assertNull("a refusal carries no result", response.result)
        assertEquals(0, prompt.prompts)
    }

    @Test
    fun aWrongVersionIsInvalidParamsWithoutAPrompt() = runTest {
        val response = answer(verifyUserRequest(version = 1))

        assertEquals(ErrorCodes.INVALID_PARAMS, response.error?.code)
        assertEquals(0, prompt.prompts)
    }

    @Test
    fun aShortNonceIsInvalidParamsWithoutAPrompt() = runTest {
        val response = answer(verifyUserRequest(nonceSize = 31))

        assertEquals(ErrorCodes.INVALID_PARAMS, response.error?.code)
        assertEquals(0, prompt.prompts)
    }

    // -----------------------------------------------------------------
    // Biometric enrollment invalidated the UVK
    // -----------------------------------------------------------------

    @Test
    fun anInvalidatedUvkIsRegeneratedOnceAndTheAnswerUsesTheNewKey() = runTest {
        val oldChain = uvk.chain()
        prompt.invalidations = 1

        val response = answer(verifyUserRequest())

        assertNull("no error expected: ${response.error?.message}", response.error)
        assertEquals(1, uvk.regenerations)
        assertEquals(2, prompt.prompts)
        val result = LocalVerifyUserResult.fromJson(response.result!!)
        assertFalse(
            "the answer must carry the regenerated chain",
            result.certificateChain.first() == Base64.getEncoder().encodeToString(oldChain.first().encoded)
        )
        assertTrue(
            "the signature must verify under the regenerated key and its fingerprint",
            verifies(uvk.keyPair, expectedTranscript(uvk), Base64.getDecoder().decode(result.signature))
        )
    }

    @Test
    fun aSecondInvalidationIsNotRetriedAgain() = runTest {
        prompt.invalidations = 2

        assertRefused(ErrorCodes.SIGNING_FAILED)
        assertEquals(1, uvk.regenerations)
        assertEquals(2, prompt.prompts)
    }

    // -----------------------------------------------------------------
    // Revocation and the DAK
    // -----------------------------------------------------------------

    /**
     * Revocation cancels the request job (#59), and the pending prompt goes
     * with it. Dropping whatever the cancelled job returns is the transport's
     * part: it answers nothing on a revoked session.
     */
    @Test
    fun cancellingTheRequestCancelsThePendingPrompt() = runTest {
        val prompted = CompletableDeferred<Unit>()
        val promptCancelled = CompletableDeferred<Unit>()
        val suspending = UserVerificationPrompt { _, _, _, _ ->
            prompted.complete(Unit)
            try {
                awaitCancellation()
            } finally {
                promptCancelled.complete(Unit)
            }
        }
        val revocable = RequestHandler(
            context = context,
            keystoreManager = mockk(relaxed = true),
            biometricLauncher = biometricLauncher,
            sessionAuthManager = null,
            userVerificationKey = uvk,
            userVerificationPrompt = suspending
        )
        val job = launch(UnconfinedTestDispatcher(testScheduler)) {
            onConnection { revocable.handleRawRequest(verifyUserRequest().toJson()) }
        }
        prompted.await()
        job.cancel()
        job.join()

        assertTrue("the prompt must be cancelled", promptCancelled.isCompleted)
        assertTrue("the request job must end cancelled", job.isCancelled)
    }

    /** `local.attestDevice` still answers to the DAK: it never reaches the UVK or its prompt. */
    @Test
    fun attestDeviceNeverTouchesTheUvk() = runTest {
        val nonce = ByteArray(AttestTranscript.BINDING_SIZE) { (it + 1).toByte() }
        val params = JSONObject()
            .put("protocolVersion", AttestTranscript.PROTOCOL_VERSION)
            .put("purpose", AttestTranscript.PURPOSE_REATTEST)
            .put("nonce", Base64.getEncoder().encodeToString(nonce))

        handler.handleRequest(Request(id = 1, method = MethodNames.LOCAL_ATTEST_DEVICE, params = params))

        assertEquals(0, uvk.uses)
        assertEquals(0, prompt.prompts)
    }

    /** `local.verifyUser` uses its own prompt, never the attestation presence prompt. */
    @Test
    fun verifyUserNeverUsesTheAttestationPresencePrompt() = runTest {
        onConnection { handler.handleRequest(verifyUserRequest()) }

        coVerify(exactly = 0) { biometricLauncher.requestAuthentication(any(), any(), any(), any(), any()) }
    }

    /**
     * A setKeyPolicy approval holds the screen on a locked phone; verifyUser
     * from a second connection waits its turn in the one prompt queue: no
     * wake notification and no prompt until the approval settles.
     */
    @Test
    fun verifyUserWaitsForTheActiveApprovalBeforeItsWakeNotificationAndPrompt() = runTest {
        val keyguard = mockk<KeyguardManager>()
        every { keyguard.isKeyguardLocked } returns true
        every { context.getSystemService(Context.KEYGUARD_SERVICE) } returns keyguard
        mockkConstructor(BiometricNotificationHelper::class)
        val posted = mutableListOf<String>()
        every {
            anyConstructed<BiometricNotificationHelper>()
                .showBiometricRequiredNotification(any(), any(), any(), any(), any(), any())
        } answers {
            val key = arg<String>(2)
            assertEquals(
                "a notification is posted only on its own queue turn",
                PromptOwnership.State.ACTIVE,
                PromptOwnership.process.state(key)
            )
            posted += key
        }
        every { anyConstructed<BiometricNotificationHelper>().cancelNotification(any()) } just Runs
        val locked = RequestHandler(
            context = context,
            keystoreManager = mockk<KeystoreManager>(relaxed = true),
            biometricLauncher = biometricLauncher,
            sessionAuthManager = null,
            userVerificationKey = uvk,
            userVerificationPrompt = prompt
        )
        val approval = NotificationKeys.approval("setKeyPolicy-held")
        PromptOwnership.process.enqueue(
            approval, PromptOwnership.Kind.SHARING_APPROVAL, "first",
            clock = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Job()),
            onQueueExpired = {},
        ) {}
        try {
            val response = async(UnconfinedTestDispatcher(testScheduler)) {
                onConnection { Response.fromJson(locked.handleRawRequest(verifyUserRequest().toJson())) }
            }
            runCurrent()

            assertEquals("no wake notification while the approval holds the screen", emptyList<String>(), posted)
            assertEquals("no prompt while the approval holds the screen", 0, prompt.prompts)
            assertFalse(response.isCompleted)

            PromptOwnership.process.settle(approval, PromptOwnership.Outcome.APPROVED)
            val answered = response.await()

            assertNull("no error expected: ${answered.error?.message}", answered.error)
            assertEquals(1, prompt.prompts)
            assertEquals(1, posted.size)
            assertTrue(posted.single().startsWith("wake-verifyUser-"))
            assertEquals(PromptOwnership.State.SETTLED, PromptOwnership.process.state(posted.single()))
        } finally {
            PromptOwnership.process.end(approval)
        }
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    /** Sends [request] over the raw wire path a transport uses, on a served connection. */
    private suspend fun answer(request: Request): Response =
        onConnection { Response.fromJson(handler.handleRawRequest(request.toJson())) }

    /** Runs [block] as a request arriving on a served connection with [binding]. */
    private suspend fun <T> onConnection(
        binding: SessionBindingProvider = sessionBinding,
        block: suspend () -> T
    ): T = withContext(RequestHandler.servedConnection(binding, PEER, "test:connection")) { block() }

    private suspend fun assertRefused(expected: Int) {
        val response = answer(verifyUserRequest())
        assertNotNull("expected an error", response.error)
        assertEquals(expected, response.error!!.code)
        assertNull("a refusal carries no result", response.result)
    }

    private fun verifyUserRequest(
        id: Long = 1,
        generation: ULong? = null,
        version: Int = AttestTranscript.PROTOCOL_VERSION,
        nonceSize: Int = AttestTranscript.BINDING_SIZE
    ): Request {
        val params = JSONObject()
            .put("protocolVersion", version)
            .put("nonce", Base64.getEncoder().encodeToString(ByteArray(nonceSize) { (0x40 + it).toByte() }))
        return Request(id = id, method = MethodNames.LOCAL_VERIFY_USER, params = params, generation = generation)
    }

    private fun expectedTranscript(key: FakeUserVerificationKey): ByteArray = AttestTranscript.build(
        purpose = AttestTranscript.PURPOSE_VERIFY_USER,
        nonce = ByteArray(AttestTranscript.BINDING_SIZE) { (0x40 + it).toByte() },
        channelBinding = sessionBinding.binding()!!.let {
            AttestTranscript.channelBinding(
                initiatorStaticPublicKey = it.initiatorStaticPublicKey,
                responderStaticPublicKey = it.responderStaticPublicKey,
                prologue = it.prologue
            )
        },
        deviceFingerprint = AttestedKeyFingerprint.of(key.chain().first().encoded)
    )

    private fun verifies(keyPair: KeyPair, message: ByteArray, signature: ByteArray): Boolean =
        Signature.getInstance("SHA256withECDSA").run {
            initVerify(keyPair.public)
            update(message)
            verify(signature)
        }

    /** A software UVK with a two-certificate chain whose leaf certifies [keyPair]. */
    private class FakeUserVerificationKey : UserVerificationKey {
        var keyPair: KeyPair = newKeyPair()
            private set
        private var certificates = chainFor(keyPair)
        var chainFailure: Exception? = null
        var regenerations = 0
            private set
        var uses = 0
            private set

        override fun exists(): Boolean = true

        override fun chain(): List<X509Certificate> {
            uses++
            chainFailure?.let { throw it }
            return certificates
        }

        override fun regenerate(): List<X509Certificate> {
            regenerations++
            keyPair = newKeyPair()
            certificates = chainFor(keyPair)
            return certificates
        }

        override fun initSignature(): Signature {
            uses++
            return Signature.getInstance("SHA256withECDSA").apply { initSign(keyPair.private) }
        }
    }

    /**
     * Signs with the UVK as the Class 3 prompt would after the user
     * approves, or fails the way the prompt reports a refusal.
     */
    private class FakePrompt(private val key: FakeUserVerificationKey) : UserVerificationPrompt {
        var prompts = 0
            private set
        var lastMessage: ByteArray? = null
            private set
        var failWith: Exception? = null
        var invalidations = 0

        override suspend fun sign(
            message: ByteArray,
            title: String,
            subtitle: String,
            showOnLockScreen: Boolean
        ): ByteArray {
            prompts++
            lastMessage = message
            if (invalidations > 0) {
                invalidations--
                throw KeyInvalidatedException("invalidated by a new enrollment")
            }
            failWith?.let { throw it }
            return key.initSignature().run {
                update(message)
                sign()
            }
        }
    }

    private companion object {
        val sessionBinding = SessionBindingProvider {
            SessionBinding(ByteArray(32) { 3 }, ByteArray(32) { 4 }, ByteArray(0))
        }
        val PEER = "03".repeat(32)

        fun newKeyPair(): KeyPair = KeyPairGenerator.getInstance("EC")
            .apply { initialize(ECGenParameterSpec("secp256r1")) }
            .generateKeyPair()

        fun chainFor(leafKey: KeyPair): List<X509Certificate> {
            val root = newKeyPair()
            return listOf(
                certificate("CN=UVK", leafKey, "CN=Root", root),
                certificate("CN=Root", root, "CN=Root", root)
            )
        }

        fun certificate(subject: String, subjectKey: KeyPair, issuer: String, issuerKey: KeyPair): X509Certificate {
            val now = System.currentTimeMillis()
            val holder = JcaX509v3CertificateBuilder(
                X500Name(issuer),
                BigInteger.valueOf(now),
                Date(now - 60_000),
                Date(now + 3_600_000),
                X500Name(subject),
                subjectKey.public
            ).build(JcaContentSignerBuilder("SHA256withECDSA").build(issuerKey.private))
            return JcaX509CertificateConverter().getCertificate(holder)
        }
    }
}
