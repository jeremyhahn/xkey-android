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
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.auth.SessionAuthManager
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.settings.AttestationBiometricPolicy
import com.automatethethings.xkey.settings.BiometricAuthMode
import com.automatethethings.xkey.settings.BiometricSettingsData
import com.automatethethings.xkey.settings.UserVerificationPolicy
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.AfterClass
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import java.security.MessageDigest
import java.security.Signature
import java.util.Base64
import java.util.concurrent.atomic.AtomicLong

/**
 * The un-namespaced base protocol: `ping`, `getInfo`, `generateKey`, `sign`,
 * `loadKey`, `listKeys` and `deleteKey`.
 *
 * These are the methods go-xkms calls before it knows anything about the
 * device (`xkey/pkg/pairing`), and they are a separate implementation from the
 * `local.*` family: they address keys by `credentialId` rather than `keyId`,
 * they live in the FIDO2 keystore alias namespace, and they answer with
 * `GenerateKeyResult`/`SignResult`/`LoadKeyResult`/`GetInfoResult` rather than
 * the `Local*` payloads. `ProtocolIntegrationTest` and
 * [RequestHandlerErrorPathTest] both drive only the `local.*` family, so
 * nothing exercised this half of the router.
 *
 * The suite runs headless: user verification is disabled so no biometric
 * prompt is ever reachable, except in the two cases that deliberately turn it
 * on to prove the handler refuses rather than hangs when there is no activity
 * to prompt from.
 *
 * Every credential created here carries a per-run id and is deleted in
 * [tearDown]; `getInfo` and `listKeys` report a keystore-wide count that other
 * suites assert on.
 */
@RunWith(AndroidJUnit4::class)
class RequestHandlerBaseMethodTest {

    companion object {
        private lateinit var context: Context
        private lateinit var handler: RequestHandler
        private lateinit var keystoreManager: KeystoreManager

        /** Unique per run so nothing collides with a previous run's leftovers. */
        private val runId = System.currentTimeMillis().toString(36)

        private val nextRequestId = AtomicLong(1)

        /** Every credential id this suite persists, torn down in [tearDown]. */
        private val createdCredentialIds = mutableSetOf<String>()

        @JvmStatic
        @BeforeClass
        fun setUp() {
            context = ApplicationProvider.getApplicationContext()
            keystoreManager = KeystoreManager(context)
            handler = RequestHandler(
                context = context,
                keystoreManager = keystoreManager,
                biometricLauncher = null,
                sessionAuthManager = SessionAuthManager()
            )
        }

        @JvmStatic
        @AfterClass
        fun tearDown() {
            for (credentialId in createdCredentialIds) {
                runCatching { keystoreManager.deleteKey(credentialId) }
            }
            // Anything a failing test created without registering it.
            for (credentialId in runCatching { keystoreManager.listCredentials() }.getOrDefault(emptyList())) {
                if (credentialId.contains(runId)) {
                    runCatching { keystoreManager.deleteKey(credentialId) }
                }
            }
        }
    }

    /** Headless baseline: no user verification, so no prompt is reachable. */
    @Before
    fun resetHandlerState() {
        handler.setSessionId(null)
        handler.updateSettings(
            BiometricSettingsData(
                uvPolicy = UserVerificationPolicy.DISABLED,
                attestationBiometricPolicy = AttestationBiometricPolicy.NEVER
            )
        )
    }

    // ------------------------------------------------------------------
    // ping / getInfo / listKeys
    // ------------------------------------------------------------------

    @Test
    fun pingIsAcknowledged() {
        val result = call("ping").ok()

        assertTrue("ping must answer with pong=true", result.getBoolean("pong"))
    }

    @Test
    fun pingIgnoresAnyParametersItIsGiven() {
        val result = call("ping", JSONObject().put("unexpected", "value")).ok()

        assertTrue(result.getBoolean("pong"))
    }

    /**
     * go-xkms reads `supportedAlgorithms`, `maxCredentials` and
     * `currentCredentials` from this frame; the three legacy keys are kept for
     * older peers and must stay consistent with them.
     */
    @Test
    fun getInfoAdvertisesTheGoXkmsContractAndTheLegacyKeys() {
        val result = call("getInfo").ok()

        assertEquals("1.0.0", result.getString("version"))
        assertTrue("deviceName must not be blank", result.getString("deviceName").isNotBlank())

        val advertised = result.getJSONArray("supportedAlgorithms")
        val algorithms = (0 until advertised.length()).map { advertised.getInt(it) }
        assertEquals(CoseAlgorithms.SUPPORTED, algorithms)

        assertEquals(
            GetInfoResult.DEFAULT_MAX_CREDENTIALS,
            result.getInt("maxCredentials")
        )
        assertEquals(
            "currentCredentials and the legacy credentialCount must agree",
            result.getInt("currentCredentials"),
            result.getInt("credentialCount")
        )
        assertTrue(result.has("hasStrongBox"))
        assertTrue(result.has("hasBiometrics"))
    }

    @Test
    fun getInfoAndListKeysReportTheSameCredentialCount() {
        val credentialId = generateCredential("count-$runId")

        val listed = call("listKeys").ok()
        val credentials = listed.getJSONArray("credentials")
        val ids = (0 until credentials.length()).map { credentials.getString(it) }

        assertTrue("the new credential must be listed", ids.contains(credentialId))
        assertEquals(
            "listKeys must report the length of the array it emitted",
            credentials.length(),
            listed.getInt("count")
        )
        assertEquals(
            "getInfo must count the same credentials listKeys enumerates",
            credentials.length(),
            call("getInfo").ok().getInt("currentCredentials")
        )
    }

    // ------------------------------------------------------------------
    // generateKey
    // ------------------------------------------------------------------

    @Test
    fun generateKeyReturnsACosePublicKey() {
        val credentialId = generateCredential("gen-$runId")

        val loaded = call("loadKey", JSONObject().put("credentialId", credentialId)).ok()
        assertTrue("the freshly generated credential must load", loaded.getBoolean("exists"))
        assertEquals(
            "loadKey reports the base protocol's only signing algorithm",
            CoseAlgorithms.ES256,
            loaded.getInt("algorithm")
        )
        assertTrue(
            "loadKey must return the COSE public key",
            Base64.getDecoder().decode(loaded.getString("publicKey")).isNotEmpty()
        )
    }

    @Test
    fun generateKeyRejectsAnAlgorithmTheKeystoreCannotProduce() {
        for (algorithm in listOf(CoseAlgorithms.EDDSA, CoseAlgorithms.HMAC_256, CoseAlgorithms.A256GCM)) {
            val response = call(
                "generateKey",
                JSONObject()
                    .put("credentialId", "unsupported-$algorithm-$runId")
                    .put("algorithm", algorithm)
                    .put("requireUserVerification", false)
            )
            assertEquals(
                "COSE algorithm $algorithm is not a base-protocol signing algorithm",
                ErrorCodes.INVALID_ALGORITHM,
                response.errorCode()
            )
        }
    }

    @Test
    fun generateKeyRefusesToOverwriteAnExistingCredential() {
        val credentialId = generateCredential("dup-$runId")

        val response = call(
            "generateKey",
            JSONObject()
                .put("credentialId", credentialId)
                .put("algorithm", CoseAlgorithms.ES256)
                .put("requireUserVerification", false)
        )

        assertEquals(ErrorCodes.INVALID_PARAMS, response.errorCode())
        assertTrue(response.errorMessage().contains("already exists"))
    }

    @Test
    fun generateKeyRequiresBothOfItsParameters() {
        assertEquals(
            ErrorCodes.INVALID_PARAMS,
            call("generateKey").errorCode()
        )
        assertTrue(
            "a missing credentialId must name the field",
            call("generateKey", JSONObject().put("algorithm", CoseAlgorithms.ES256))
                .errorMessage()
                .contains("credentialId")
        )
        assertTrue(
            "a missing algorithm must name the field",
            call("generateKey", JSONObject().put("credentialId", "no-algorithm-$runId"))
                .errorMessage()
                .contains("algorithm")
        )
    }

    /**
     * With user verification switched on and nothing to prompt from, key
     * creation must refuse. The alternative — generating anyway — would create
     * a credential the user never approved.
     */
    @Test
    fun generateKeyRefusesWhenItCannotPromptForUserVerification() {
        handler.updateSettings(
            BiometricSettingsData(
                uvPolicy = UserVerificationPolicy.REQUIRED,
                authMode = BiometricAuthMode.PER_OPERATION,
                attestationBiometricPolicy = AttestationBiometricPolicy.NEVER
            )
        )

        val credentialId = "uv-refused-$runId"
        createdCredentialIds.add(credentialId)
        val response = call(
            "generateKey",
            JSONObject()
                .put("credentialId", credentialId)
                .put("algorithm", CoseAlgorithms.ES256)
                .put("requireUserVerification", true)
        )

        assertEquals(ErrorCodes.INTERNAL_ERROR, response.errorCode())
        assertTrue(response.errorMessage().contains("No activity available"))
        assertFalse(
            "no credential may exist after a refused generation",
            keystoreManager.keyExists(credentialId)
        )
    }

    /**
     * Each authentication mode maps to a different key authentication window
     * (`calculateAuthDuration`). A device with no lock-screen credential cannot
     * hold an auth-bound key at all, so the honest assertion is that the
     * request either succeeds or reports key generation failure — never an
     * unrelated code, and never a silent downgrade to an unprotected key.
     */
    @Test
    fun generateKeyTranslatesEveryAuthenticationModeIntoAKeyPolicy() {
        for (mode in BiometricAuthMode.entries) {
            handler.updateSettings(
                BiometricSettingsData(
                    uvPolicy = UserVerificationPolicy.REQUIRED,
                    authMode = mode,
                    attestationBiometricPolicy = AttestationBiometricPolicy.NEVER
                )
            )

            val credentialId = "authmode-${mode.name.lowercase()}-$runId"
            createdCredentialIds.add(credentialId)
            val response = call(
                "generateKey",
                JSONObject()
                    .put("credentialId", credentialId)
                    // The prompt is skipped, but the key policy still follows
                    // the authentication mode.
                    .put("requireUserVerification", false)
                    .put("algorithm", CoseAlgorithms.ES256)
            )

            assertTrue(
                "$mode must either produce a key or report KEY_GENERATION_FAILED, got: " +
                    response.toJsonString(),
                response.isSuccess() || response.errorCode() == ErrorCodes.KEY_GENERATION_FAILED
            )
        }
    }

    // ------------------------------------------------------------------
    // sign
    // ------------------------------------------------------------------

    /**
     * The signature has to verify under the public key `loadKey` handed out,
     * over exactly the bytes the peer sent. Anything less would let a broken
     * encoding pass as a working signature.
     */
    @Test
    fun signProducesASignatureThatVerifiesUnderTheAdvertisedPublicKey() {
        val credentialId = generateCredential("sign-$runId")
        val dataHash = MessageDigest.getInstance("SHA-256").digest("co-signed payload".toByteArray())

        val result = call(
            "sign",
            JSONObject()
                .put("credentialId", credentialId)
                .put("dataHash", b64(dataHash))
                .put("userVerificationRequired", false)
        ).ok()

        val signature = Base64.getDecoder().decode(result.getString("signature"))
        assertTrue("the signature must not be empty", signature.isNotEmpty())
        assertFalse(
            "userVerified must report reality, and no verification happened",
            result.getBoolean("userVerified")
        )

        val publicKey = keystoreManager.getPublicKey(credentialId)
            ?: throw AssertionError("the credential has no public key")
        val verifier = Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(publicKey)
        verifier.update(dataHash)
        assertTrue("the signature must verify over the submitted hash", verifier.verify(signature))
    }

    @Test
    fun signRejectsADifferentPayloadUnderTheSameSignature() {
        val credentialId = generateCredential("sign-tamper-$runId")
        val dataHash = MessageDigest.getInstance("SHA-256").digest("original".toByteArray())
        val otherHash = MessageDigest.getInstance("SHA-256").digest("tampered".toByteArray())

        val result = call(
            "sign",
            JSONObject()
                .put("credentialId", credentialId)
                .put("dataHash", b64(dataHash))
                .put("userVerificationRequired", false)
        ).ok()
        val signature = Base64.getDecoder().decode(result.getString("signature"))

        val publicKey = keystoreManager.getPublicKey(credentialId)
            ?: throw AssertionError("the credential has no public key")
        val verifier = Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(publicKey)
        verifier.update(otherHash)
        assertFalse("a signature must not verify over other data", verifier.verify(signature))
    }

    @Test
    fun signingTwiceProducesTwoDistinctEcdsaSignatures() {
        val credentialId = generateCredential("sign-twice-$runId")
        val dataHash = MessageDigest.getInstance("SHA-256").digest("repeat".toByteArray())
        val params = JSONObject()
            .put("credentialId", credentialId)
            .put("dataHash", b64(dataHash))
            .put("userVerificationRequired", false)

        val first = call("sign", params).ok().getString("signature")
        val second = call("sign", params).ok().getString("signature")

        assertNotEquals(
            "ECDSA is randomised; identical signatures would mean a reused nonce",
            first,
            second
        )
    }

    @Test
    fun signRejectsAnUnknownCredential() {
        val response = call(
            "sign",
            JSONObject()
                .put("credentialId", "never-generated-$runId")
                .put("dataHash", b64(ByteArray(32)))
                .put("userVerificationRequired", false)
        )

        assertEquals(ErrorCodes.KEY_NOT_FOUND, response.errorCode())
    }

    @Test
    fun signRequiresBothOfItsParameters() {
        assertEquals(ErrorCodes.INVALID_PARAMS, call("sign").errorCode())
        assertTrue(
            call("sign", JSONObject().put("dataHash", b64(ByteArray(32))))
                .errorMessage()
                .contains("credentialId")
        )
        assertTrue(
            call("sign", JSONObject().put("credentialId", "x-$runId"))
                .errorMessage()
                .contains("dataHash")
        )
    }

    /**
     * When the session demands user verification and the handler has neither a
     * launcher nor an activity, signing must fail loudly. Before the managers
     * were wired through this was the shape of a whole family of silent hangs.
     */
    @Test
    fun signRefusesWhenItCannotPromptForUserVerification() {
        val credentialId = generateCredential("sign-uv-$runId")
        handler.updateSettings(
            BiometricSettingsData(
                uvPolicy = UserVerificationPolicy.REQUIRED,
                authMode = BiometricAuthMode.PER_OPERATION,
                attestationBiometricPolicy = AttestationBiometricPolicy.NEVER
            )
        )

        val response = call(
            "sign",
            JSONObject()
                .put("credentialId", credentialId)
                .put("dataHash", b64(MessageDigest.getInstance("SHA-256").digest(ByteArray(4))))
                .put("userVerificationRequired", true)
        )

        assertEquals(ErrorCodes.INTERNAL_ERROR, response.errorCode())
        assertTrue(response.errorMessage().contains("No activity available"))
    }

    // ------------------------------------------------------------------
    // loadKey / deleteKey
    // ------------------------------------------------------------------

    @Test
    fun loadKeyReportsAnAbsentCredentialWithoutAPublicKey() {
        val result = call(
            "loadKey",
            JSONObject().put("credentialId", "never-generated-$runId")
        ).ok()

        assertFalse(result.getBoolean("exists"))
        assertFalse("an absent credential carries no public key", result.has("publicKey"))
        assertFalse("an absent credential carries no algorithm", result.has("algorithm"))
    }

    @Test
    fun loadKeyRequiresACredentialId() {
        assertEquals(ErrorCodes.INVALID_PARAMS, call("loadKey").errorCode())
        assertTrue(call("loadKey", JSONObject()).errorMessage().contains("credentialId"))
    }

    @Test
    fun deleteKeyRemovesTheCredentialAndIsNotIdempotent() {
        val credentialId = generateCredential("delete-$runId")

        val deleted = call("deleteKey", JSONObject().put("credentialId", credentialId)).ok()
        assertTrue(deleted.getBoolean("deleted"))
        assertFalse(
            "the keystore entry must be gone",
            keystoreManager.keyExists(credentialId)
        )
        assertFalse(
            call("loadKey", JSONObject().put("credentialId", credentialId)).ok().getBoolean("exists")
        )

        assertEquals(
            "deleting the same credential twice must report it is not there",
            ErrorCodes.KEY_NOT_FOUND,
            call("deleteKey", JSONObject().put("credentialId", credentialId)).errorCode()
        )
    }

    @Test
    fun deleteKeyRequiresACredentialId() {
        assertEquals(ErrorCodes.INVALID_PARAMS, call("deleteKey").errorCode())
        assertTrue(call("deleteKey", JSONObject()).errorMessage().contains("credentialId"))
    }

    // ------------------------------------------------------------------
    // Framing
    // ------------------------------------------------------------------

    /** The base methods must be reachable over the raw JSON frame, not only in-process. */
    @Test
    fun theBaseMethodsAnswerOverARawFrame() {
        val response = runBlocking {
            handler.handleRawRequest("""{"id":4242,"method":"ping"}""".toByteArray())
        }
        val parsed = Response.fromJson(response)

        assertEquals(4242L, parsed.id)
        assertTrue(parsed.ok().getBoolean("pong"))
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private fun call(method: String): Response = dispatch(method, null)

    private fun call(method: String, params: JSONObject): Response = dispatch(method, params)

    /**
     * Written without default arguments on purpose: a function that carries a
     * default argument and also builds a coroutine lambda has repeatedly
     * crashed the Kotlin JVM backend in these suites
     * (BackendException at RecordEnclosingMethodsLowering).
     */
    private fun dispatch(method: String, params: JSONObject?): Response {
        val request = Request(nextRequestId.getAndIncrement(), method, params)
        return runBlocking { handler.handleRequest(request) }
    }

    /** Generates a base-protocol credential and registers it for cleanup. */
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
        val result = response.ok()
        assertTrue(
            "generateKey must return a COSE public key",
            Base64.getDecoder().decode(result.getString("publicKey")).isNotEmpty()
        )
        return credentialId
    }

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

    private fun b64(data: ByteArray): String = Base64.getEncoder().encodeToString(data)
}
