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

import android.content.Context
import androidx.biometric.BiometricManager
import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.auth.SessionAuthManager
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.settings.AttestationBiometricPolicy
import com.automatethethings.xkey.settings.BiometricAuthMode
import com.automatethethings.xkey.settings.BiometricSettingsData
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.settings.UserVerificationPolicy
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.ui.MainActivity
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.json.JSONObject
import org.junit.AfterClass
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeFalse
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.atomic.AtomicLong

/**
 * The user-verification gates in [RequestHandler]: which requests demand a
 * prompt, and what happens when the prompt cannot be shown.
 *
 * Three things decide whether a request prompts -- the UV policy, the
 * per-request `requireUserVerification` flag, and (for attestation) the
 * [AttestationBiometricPolicy] -- and every existing suite pins all three to
 * their headless values so the handlers can be driven without a sensor. That
 * leaves the whole decision tree unexercised, including the arm that says a
 * *known* peer may skip attestation verification, which is a security-relevant
 * exemption.
 *
 * The prompt itself cannot be answered from a test, but two things around it
 * can be:
 *
 * - With no activity and no service launcher attached, the handler must refuse
 *   with a typed error rather than dereference a null helper. Which arm of the
 *   policy tree ran is then visible in the refusal.
 * - With an activity attached on a device that has nothing enrolled, the
 *   prompt is reached and fails; the request must come back as a well-formed
 *   error frame instead of hanging the transport.
 *
 * Tests in the second group are skipped on a device with a usable biometric,
 * because there the prompt would sit waiting for a real user.
 *
 * Every key is per-run and removed in [tearDown].
 */
@RunWith(AndroidJUnit4::class)
class RequestHandlerBiometricGateTest {

    companion object {
        private lateinit var context: Context
        private lateinit var handler: RequestHandler
        private lateinit var pairedDevices: PairedDeviceRepository

        /** Unique per run so nothing collides with a previous run's leftovers. */
        private val runId = System.currentTimeMillis().toString(36)

        /** The peer identity this suite pairs with: 32 bytes of hex, unique per run. */
        private val peerKeyHex =
            ("fc" + java.lang.Long.toHexString(System.nanoTime())).padEnd(64, '0')

        /** A peer that is never added to the repository. */
        private const val UNKNOWN_PEER_HEX =
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"

        private val peerName = "BiometricGateTest Desktop $runId"

        private val nextRequestId = AtomicLong(1)

        /** FIDO2 credential ids created through the legacy `generateKey`. */
        private val createdCredentialIds = mutableSetOf<String>()

        /** General key ids created through `local.generateKey`. */
        private val createdKeyIds = mutableSetOf<String>()

        @JvmStatic
        @BeforeClass
        fun setUp() {
            context = ApplicationProvider.getApplicationContext()
            pairedDevices = PairedDeviceRepository(context)
            handler = RequestHandler(
                context = context,
                keystoreManager = KeystoreManager(context),
                biometricLauncher = null,
                sessionAuthManager = SessionAuthManager(),
                pairedDeviceRepository = pairedDevices
            )
            pairedDevices.addDevice(peerKeyHex, peerName)
        }

        @JvmStatic
        @AfterClass
        fun tearDown() {
            handler.setActivity(null)
            runBlocking {
                val db = XKeyDatabase.getInstance(context)
                val keystoreManager = KeystoreManager(context)
                for (credentialId in createdCredentialIds) {
                    runCatching { keystoreManager.deleteKey(credentialId) }
                    runCatching { db.auditLogDao().deleteByKeyId(credentialId) }
                }
                val ids = createdKeyIds.toMutableSet()
                for (entity in db.keyDao().getAll()) {
                    if (entity.keyId.contains(runId)) ids.add(entity.keyId)
                }
                for (keyId in ids) {
                    runCatching { keystoreManager.deleteGeneralKey(keyId) }
                    runCatching { db.keyDao().deleteByKeyId(keyId) }
                    runCatching { db.auditLogDao().deleteByKeyId(keyId) }
                }
            }
            pairedDevices.removeDevice(peerKeyHex)
        }
    }

    /** The authenticated peer of the connection requests arrive on. */
    private var servedPeer: String? = null

    /**
     * Baseline: a confirmed, unrestricted peer, no activity attached, and the
     * headless policy every other suite runs with. Each test opts into the
     * gate it is about.
     */
    @Before
    fun resetHandlerState() {
        handler.setActivity(null)
        connectPeer(peerKeyHex)
        pairedDevices.updateDeviceSettings(
            publicKeyHex = peerKeyHex,
            requireAttestationForKeyUse = false,
            requireAttestationForKeyAttestation = false,
            attestationGracePeriodMinutes = 60
        )
        handler.updateSettings(
            BiometricSettingsData(
                uvPolicy = UserVerificationPolicy.DISABLED,
                attestationBiometricPolicy = AttestationBiometricPolicy.NEVER
            )
        )
    }

    // ------------------------------------------------------------------
    // Attestation policy: ALWAYS
    // ------------------------------------------------------------------

    @Test
    fun attestKeyUnderTheAlwaysPolicyRefusesWhenItCannotPrompt() {
        requireBiometricFor(AttestationBiometricPolicy.ALWAYS)

        val response = call(
            "local.attestKey",
            JSONObject().put("keyId", "gate-$runId").put("nonce", b64(randomNonce()))
        )

        assertEquals(ErrorCodes.INTERNAL_ERROR, response.errorCode())
        assertTrue(
            "the refusal must say a prompt was needed, got: ${response.errorMessage()}",
            response.errorMessage().contains("biometric prompt")
        )
    }

    @Test
    fun attestDeviceUnderTheAlwaysPolicyRefusesWhenItCannotPrompt() {
        requireBiometricFor(AttestationBiometricPolicy.ALWAYS)

        val response = call("local.attestDevice", attestDeviceParams())

        assertEquals(ErrorCodes.INTERNAL_ERROR, response.errorCode())
        assertTrue(response.errorMessage().contains("biometric prompt"))
    }

    /**
     * ALWAYS only means "always" while user verification is switched on at
     * all. With UV disabled there is nothing to prompt with, and attestation
     * must still work.
     */
    @Test
    fun theAlwaysPolicyIsInertWhileUserVerificationIsDisabled() {
        handler.updateSettings(
            BiometricSettingsData(
                uvPolicy = UserVerificationPolicy.DISABLED,
                attestationBiometricPolicy = AttestationBiometricPolicy.ALWAYS
            )
        )

        val result = call(
            "local.attestKey",
            JSONObject().put("keyId", "inert-$runId").put("nonce", b64(randomNonce()))
        ).ok()

        assertTrue(result.getJSONArray("certificateChain").length() > 0)
    }

    // ------------------------------------------------------------------
    // Attestation policy: PAIRED_DEVICES_SKIP
    // ------------------------------------------------------------------

    /**
     * The exemption itself: a peer already recorded in the paired-device store
     * attests without a prompt, even with user verification switched on.
     */
    @Test
    fun aKnownPeerSkipsTheAttestationPrompt() {
        requireBiometricFor(AttestationBiometricPolicy.PAIRED_DEVICES_SKIP)
        connectPeer(peerKeyHex)

        val result = call(
            "local.attestKey",
            JSONObject().put("keyId", "known-$runId").put("nonce", b64(randomNonce()))
        ).ok()

        assertTrue(result.getJSONArray("certificateChain").length() > 0)
    }

    @Test
    fun aKnownPeerAlsoSkipsThePromptForDeviceAttestation() {
        requireBiometricFor(AttestationBiometricPolicy.PAIRED_DEVICES_SKIP)
        connectPeer(peerKeyHex)

        val result = call("local.attestDevice", attestDeviceParams()).ok()

        assertEquals("android-keystore", result.getString("format"))
    }

    /**
     * The other side of the exemption: a peer the phone has never paired with
     * does not get it, so the prompt is required and the request is refused
     * when it cannot be shown.
     */
    @Test
    fun anUnpairedPeerDoesNotSkipTheAttestationPrompt() {
        requireBiometricFor(AttestationBiometricPolicy.PAIRED_DEVICES_SKIP)
        connectPeer(UNKNOWN_PEER_HEX)

        val response = call(
            "local.attestKey",
            JSONObject().put("keyId", "unknown-$runId").put("nonce", b64(randomNonce()))
        )

        assertEquals(ErrorCodes.INTERNAL_ERROR, response.errorCode())
        assertTrue(response.errorMessage().contains("biometric prompt"))
    }

    /**
     * An anonymous session has no identity to check against the paired-device
     * store, so it must fall to the conservative side of the exemption rather
     * than be treated as known.
     */
    @Test
    fun anAnonymousSessionDoesNotSkipTheAttestationPrompt() {
        requireBiometricFor(AttestationBiometricPolicy.PAIRED_DEVICES_SKIP)
        connectPeer(null)

        val response = call(
            "local.attestKey",
            JSONObject().put("keyId", "anon-$runId").put("nonce", b64(randomNonce()))
        )

        assertEquals(ErrorCodes.INTERNAL_ERROR, response.errorCode())
        assertTrue(response.errorMessage().contains("biometric prompt"))
    }

    // ------------------------------------------------------------------
    // Key generation with user verification requested
    // ------------------------------------------------------------------

    @Test
    fun localGenerateKeyRefusesWhenItCannotPromptForUserVerification() {
        handler.updateSettings(verificationRequired())

        val keyId = "uv-gen-$runId"
        createdKeyIds.add(keyId)
        val response = call(
            "local.generateKey",
            JSONObject()
                .put("keyId", keyId)
                .put("keyType", "signing")
                .put("algorithm", "ES256")
                .put("requireUserVerification", true)
                .put("preferStrongBox", false)
        )

        assertEquals(ErrorCodes.INTERNAL_ERROR, response.errorCode())
        assertTrue(response.errorMessage().contains("biometric prompt"))
    }

    // ------------------------------------------------------------------
    // Signing: the fall-back into the prompt path
    // ------------------------------------------------------------------

    /**
     * `sign` tries the no-prompt path first and falls into the prompt path
     * when the key rejects the attempt. An RSA key reaches that state on this
     * code path for a structural reason -- the no-prompt path hardcodes ECDSA
     * -- so it exercises the fall-back without needing an auth-bound key.
     */
    @Test
    fun signFallsIntoThePromptPathWhenTheFirstAttemptFails() {
        val keyId = generateGeneralKey("rsa-fallback-$runId", "RS256")

        val response = call(
            "sign",
            JSONObject()
                .put("credentialId", keyId)
                .put("dataHash", b64(randomNonce()))
                .put("userVerificationRequired", false)
        )

        assertEquals(ErrorCodes.INTERNAL_ERROR, response.errorCode())
        assertTrue(
            "the fall-back must end in the prompt path, got: ${response.errorMessage()}",
            response.errorMessage().contains("biometric prompt")
        )
    }

    /**
     * With verification demanded up front the no-prompt attempt is skipped
     * entirely, and the request goes straight to the prompt path.
     */
    @Test
    fun signGoesStraightToThePromptPathWhenVerificationIsDemanded() {
        val credentialId = generateCredential("uv-sign-refused-$runId")
        handler.updateSettings(verificationRequired())

        val response = call(
            "sign",
            JSONObject()
                .put("credentialId", credentialId)
                .put("dataHash", b64(randomNonce()))
                .put("userVerificationRequired", true)
        )

        assertEquals(ErrorCodes.INTERNAL_ERROR, response.errorCode())
        assertTrue(response.errorMessage().contains("biometric prompt"))
    }

    /**
     * The same request with an activity attached takes the crypto-bound
     * branch: the key was created while verification was disabled, so it is
     * not bound to an authenticator and the signature object is already
     * usable. No prompt is shown, and the response must still report the
     * verification the caller asked for.
     */
    @Test
    fun signThroughTheActivityHelperSignsWithoutShowingAPrompt() {
        val credentialId = generateCredential("uv-sign-$runId")

        withActivityAttached {
            handler.updateSettings(verificationRequired())

            val result = call(
                "sign",
                JSONObject()
                    .put("credentialId", credentialId)
                    .put("dataHash", b64(randomNonce()))
                    .put("userVerificationRequired", true)
            ).ok()

            assertTrue(
                "a signature must come back",
                result.getString("signature").isNotEmpty()
            )
            assertTrue(
                "the crypto-bound path reports the user as verified",
                result.getBoolean("userVerified")
            )
        }
    }

    // ------------------------------------------------------------------
    // With an activity attached: the prompt is reached and fails
    // ------------------------------------------------------------------

    /**
     * The prompt path itself, on a device where the prompt cannot succeed. The
     * point is not the error code but that the request completes at all: a
     * prompt that never resolves would leave the transport waiting forever.
     */
    @Test
    fun attestKeyReachesThePromptAndStillAnswers() {
        assumeNoUsableBiometric()
        requireBiometricFor(AttestationBiometricPolicy.ALWAYS)

        withActivityAttached {
            val response = call(
                "local.attestKey",
                JSONObject().put("keyId", "prompted-$runId").put("nonce", b64(randomNonce()))
            )

            assertTrue("the request must answer, not hang", response.isError())
            assertTrue(
                "a prompt that cannot run must not be reported as a missing activity",
                !response.errorMessage().contains("No activity")
            )
        }
    }

    @Test
    fun attestDeviceReachesThePromptAndStillAnswers() {
        assumeNoUsableBiometric()
        requireBiometricFor(AttestationBiometricPolicy.ALWAYS)

        withActivityAttached {
            val response = call("local.attestDevice", attestDeviceParams())

            assertTrue(response.isError())
            assertTrue(!response.errorMessage().contains("No activity"))
        }
    }

    @Test
    fun localGenerateKeyReachesThePromptAndStillAnswers() {
        assumeNoUsableBiometric()

        val keyId = "prompted-gen-$runId"
        createdKeyIds.add(keyId)

        withActivityAttached {
            handler.updateSettings(verificationRequired())

            val response = call(
                "local.generateKey",
                JSONObject()
                    .put("keyId", keyId)
                    .put("keyType", "signing")
                    .put("algorithm", "ES256")
                    .put("requireUserVerification", true)
                    .put("preferStrongBox", false)
            )

            assertTrue(response.isError())
            assertTrue(!response.errorMessage().contains("No activity"))
        }
    }

    @Test
    fun theLegacyGenerateKeyReachesThePromptAndStillAnswers() {
        assumeNoUsableBiometric()

        val credentialId = "prompted-cred-$runId"
        createdCredentialIds.add(credentialId)

        withActivityAttached {
            handler.updateSettings(verificationRequired())

            val response = call(
                "generateKey",
                JSONObject()
                    .put("credentialId", credentialId)
                    .put("algorithm", CoseAlgorithms.ES256)
                    .put("requireUserVerification", true)
                    .put("preferStrongBox", false)
            )

            assertTrue(response.isError())
            assertTrue(!response.errorMessage().contains("No activity"))
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /** Settings that demand verification for every operation. */
    private fun verificationRequired(): BiometricSettingsData =
        BiometricSettingsData(
            uvPolicy = UserVerificationPolicy.REQUIRED,
            authMode = BiometricAuthMode.PER_OPERATION,
            attestationBiometricPolicy = AttestationBiometricPolicy.NEVER
        )

    /** Settings that demand verification and apply [policy] to attestation. */
    private fun requireBiometricFor(policy: AttestationBiometricPolicy) {
        handler.updateSettings(
            BiometricSettingsData(
                uvPolicy = UserVerificationPolicy.REQUIRED,
                authMode = BiometricAuthMode.PER_OPERATION,
                attestationBiometricPolicy = policy
            )
        )
    }

    /**
     * Runs [block] with a resumed activity attached to the handler, then
     * detaches it. Written without a default argument on purpose: a function
     * that carries a default argument and also builds a coroutine lambda has
     * repeatedly crashed the Kotlin JVM backend in these suites.
     */
    private fun withActivityAttached(block: () -> Unit) {
        val scenario = ActivityScenario.launch(MainActivity::class.java)
        try {
            scenario.moveToState(Lifecycle.State.RESUMED)
            scenario.onActivity { activity -> handler.setActivity(activity) }
            block()
        } finally {
            scenario.onActivity { handler.setActivity(null) }
            scenario.close()
        }
    }

    /**
     * Skips the test on a device that could actually show a prompt, where it
     * would wait for a real user instead of failing.
     */
    private fun assumeNoUsableBiometric() {
        val available = BiometricManager.from(context)
            .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
            BiometricManager.BIOMETRIC_SUCCESS
        assumeFalse("a device with an enrolled biometric would wait for a real user", available)
    }

    /** A FIDO2 credential created through the legacy path, with no auth binding. */
    private fun generateCredential(credentialId: String): String {
        createdCredentialIds.add(credentialId)
        val response = call(
            "generateKey",
            JSONObject()
                .put("credentialId", credentialId)
                .put("algorithm", CoseAlgorithms.ES256)
                .put("requireUserVerification", false)
                .put("preferStrongBox", false)
        )
        assertTrue(
            "credential generation must succeed: " + response.toJsonString(),
            response.isSuccess()
        )
        return credentialId
    }

    /** A general-purpose key created through `local.generateKey`. */
    private fun generateGeneralKey(keyId: String, algorithm: String): String {
        createdKeyIds.add(keyId)
        val response = call(
            "local.generateKey",
            JSONObject()
                .put("keyId", keyId)
                .put("keyType", "signing")
                .put("algorithm", algorithm)
                .put("requireUserVerification", false)
                .put("preferStrongBox", false)
        )
        assertTrue(
            "key generation must succeed: " + response.toJsonString(),
            response.isSuccess()
        )
        return keyId
    }

    private fun call(method: String, params: JSONObject): Response =
        dispatch(method, params)

    /**
     * Written without default arguments on purpose, for the same Kotlin
     * backend reason recorded on [withActivityAttached].
     */
    private fun dispatch(method: String, params: JSONObject?): Response {
        val request = Request(nextRequestId.getAndIncrement(), method, params)
        // local.attestDevice binds its signature to the connection the request
        // arrived on and refuses without one, so every request arrives on a
        // connection with a binding, and the biometric gate is what fails.
        val connection = RequestHandler.servedConnection(
            { SessionBinding(ByteArray(32) { 0x11 }, ByteArray(32) { 0x22 }, ByteArray(0)) },
            servedPeer
        )
        return runBlocking { withContext(connection) { handler.handleRequest(request) } }
    }

    /** The desktop this phone serves: the requests' connection, and the handler's served peer. */
    private fun connectPeer(publicKeyHex: String?) {
        servedPeer = publicKeyHex
        handler.setConnectedDevicePublicKeyHex(publicKeyHex)
    }

    /** A protocol version 2 `local.attestDevice` request (go-xkms#129). */
    private fun attestDeviceParams(): JSONObject = JSONObject()
        .put("protocolVersion", AttestTranscript.PROTOCOL_VERSION)
        .put("nonce", b64(randomNonce()))
        .put("purpose", AttestTranscript.PURPOSE_REATTEST)

    private fun randomNonce(): ByteArray =
        ByteArray(32).also { SecureRandom().nextBytes(it) }

    private fun b64(data: ByteArray): String = Base64.getEncoder().encodeToString(data)

    /**
     * Returns the result of a successful response.
     *
     * [Response.result] is a nullable property of another module, so Kotlin
     * cannot smart-cast it here; every reader goes through this accessor.
     */
    private fun Response.ok(): JSONObject =
        result ?: throw AssertionError("expected a successful response, got: " + toJsonString())

    private fun Response.errorCode(): Int =
        error?.code ?: throw AssertionError("expected an error response, got: " + toJsonString())

    private fun Response.errorMessage(): String =
        error?.message ?: throw AssertionError("expected an error response, got: " + toJsonString())
}
