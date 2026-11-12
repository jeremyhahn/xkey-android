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
import com.automatethethings.xkey.settings.BiometricSettingsData
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.settings.UserVerificationPolicy
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.storage.entity.KeySharingPolicy
import com.automatethethings.xkey.storage.entity.SharingPolicyType
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
 * Passkey delegation and co-signing: `local.listFido2Credentials`,
 * `local.signFido2Assertion`, `cosign.request` and `cosign.response`.
 *
 * These are the methods that let the desktop borrow the phone's credentials.
 * `listFido2Credentials` is how the desktop discovers which passkeys it may
 * use for a relying party, and `signFido2Assertion` produces the WebAuthn
 * assertion the browser ultimately verifies — so a malformed authenticator
 * data layout or an unenforced sharing policy here is a security failure, not
 * a cosmetic one. Neither had any coverage: `ProtocolIntegrationTest` covers
 * key, PIV, OATH, sync, backup and sharing, and stops short of the FIDO2 and
 * co-signing families.
 *
 * The assertion tests verify the signature against the credential's own public
 * key over exactly the bytes WebAuthn defines, and check the authenticator
 * data layout field by field, because that is what a relying party checks.
 *
 * Every keystore alias, key-store row and sharing policy created here carries a
 * per-run id and is removed in [tearDown]; other suites assert on key counts.
 */
@RunWith(AndroidJUnit4::class)
class RequestHandlerFido2AndCosignTest {

    companion object {
        private lateinit var context: Context
        private lateinit var handler: RequestHandler
        private lateinit var keystoreManager: KeystoreManager
        private lateinit var pairedDevices: PairedDeviceRepository

        /** Unique per run so nothing collides with a previous run's leftovers. */
        private val runId = System.currentTimeMillis().toString(36)

        /** The peer identity this suite pairs with: 32 bytes of hex, unique per run. */
        private val peerKeyHex =
            ("fc" + java.lang.Long.toHexString(System.nanoTime())).padEnd(64, '0')

        /** A peer that is never granted a SELECTED_PEERS policy. */
        private val otherPeerHex =
            ("fb" + java.lang.Long.toHexString(System.nanoTime())).padEnd(64, '0')

        private val peerName = "Fido2Test Desktop $runId"

        /**
         * Relying party this suite owns. Unique per run so the listing
         * assertions cannot see another suite's or another run's credentials.
         */
        private val rpId = "fido2-test-$runId.example"

        private val nextRequestId = AtomicLong(1)

        /** FIDO2 credential ids, held in the credential alias namespace. */
        private val createdCredentialIds = mutableSetOf<String>()

        /** General-purpose key ids, held in the general alias namespace. */
        private val createdGeneralKeyIds = mutableSetOf<String>()

        @JvmStatic
        @BeforeClass
        fun setUp() {
            context = ApplicationProvider.getApplicationContext()
            keystoreManager = KeystoreManager(context)
            pairedDevices = PairedDeviceRepository(context)
            handler = RequestHandler(
                context = context,
                keystoreManager = keystoreManager,
                biometricLauncher = null,
                sessionAuthManager = SessionAuthManager(),
                pairedDeviceRepository = pairedDevices
            )
            pairedDevices.addDevice(peerKeyHex, peerName)
        }

        @JvmStatic
        @AfterClass
        fun tearDown() {
            runBlocking {
                val db = XKeyDatabase.getInstance(context)
                val ids = (createdCredentialIds + createdGeneralKeyIds).toMutableSet()
                for (entity in db.keyDao().getAll()) {
                    if (entity.keyId.contains(runId)) ids.add(entity.keyId)
                }
                for (keyId in ids) {
                    runCatching { keystoreManager.deleteKey(keyId) }
                    runCatching { keystoreManager.deleteGeneralKey(keyId) }
                    runCatching { db.keySharingPolicyDao().clearPoliciesForKey(keyId) }
                    runCatching { db.keyDao().deleteByKeyId(keyId) }
                }
                db.keySharingPolicyDao().clearPoliciesForPeer(peerKeyHex)
                db.keySharingPolicyDao().clearPoliciesForPeer(otherPeerHex)
            }
            pairedDevices.removeDevice(peerKeyHex)
        }
    }

    /** Baseline: a confirmed peer and no user verification, so nothing prompts. */
    @Before
    fun resetHandlerState() {
        handler.setConnectedDevicePublicKeyHex(peerKeyHex)
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
    // local.listFido2Credentials
    // ------------------------------------------------------------------

    @Test
    fun listFido2CredentialsReturnsTheDiscoveryMetadataForAShareableCredential() {
        val credentialId = seedPasskey("list-shared-$runId", SharingPolicyType.ALL_PEERS)

        val credentials = call(
            "local.listFido2Credentials",
            JSONObject().put("rpId", rpId)
        ).ok().getJSONArray("credentials")

        val listed = (0 until credentials.length())
            .map { credentials.getJSONObject(it) }
            .single { it.getString("credentialId") == credentialId }

        assertEquals(rpId, listed.getString("rpId"))
        assertEquals("Fido2 Test RP", listed.getString("rpName"))
        assertEquals("alice", listed.getString("userName"))
        assertEquals("Alice Example", listed.getString("userDisplayName"))
        assertTrue(listed.getBoolean("isDiscoverable"))
        assertTrue("createdAt must be a real timestamp", listed.getLong("createdAt") > 0)
    }

    /** A PRIVATE credential must never appear in a listing sent to a peer. */
    @Test
    fun listFido2CredentialsHidesAPrivateCredential() {
        val private = seedPasskey("list-private-$runId", SharingPolicyType.PRIVATE)
        val shared = seedPasskey("list-visible-$runId", SharingPolicyType.ALL_PEERS)

        val ids = listedCredentialIds()

        assertFalse("a PRIVATE credential must not be offered", ids.contains(private))
        assertTrue(ids.contains(shared))
    }

    /**
     * A SELECTED_PEERS credential is only listed for the peers named in the
     * policy table, so the answer depends on who is asking.
     */
    @Test
    fun listFido2CredentialsAppliesTheSelectedPeersPolicyPerPeer() {
        val credentialId = seedPasskey("list-selected-$runId", SharingPolicyType.SELECTED_PEERS)
        grantPolicy(credentialId, peerKeyHex)

        assertTrue(
            "the peer named in the policy must see the credential",
            listedCredentialIds().contains(credentialId)
        )

        handler.setConnectedDevicePublicKeyHex(otherPeerHex)
        assertFalse(
            "a peer with no policy row must not see the credential",
            listedCredentialIds().contains(credentialId)
        )

        handler.setConnectedDevicePublicKeyHex(null)
        assertFalse(
            "an anonymous session cannot satisfy a SELECTED_PEERS policy",
            listedCredentialIds().contains(credentialId)
        )
    }

    @Test
    fun listFido2CredentialsIsScopedToTheRequestedRelyingParty() {
        val credentialId = seedPasskey("list-scope-$runId", SharingPolicyType.ALL_PEERS)

        val otherRp = call(
            "local.listFido2Credentials",
            JSONObject().put("rpId", "unrelated-$runId.example")
        ).ok().getJSONArray("credentials")

        val ids = (0 until otherRp.length()).map { otherRp.getJSONObject(it).getString("credentialId") }
        assertFalse(
            "a credential must not be offered to a relying party it was not created for",
            ids.contains(credentialId)
        )
    }

    @Test
    fun listFido2CredentialsRequiresAnRpId() {
        assertEquals(
            ErrorCodes.INVALID_PARAMS,
            call("local.listFido2Credentials").errorCode()
        )
        assertEquals(
            ErrorCodes.INVALID_PARAMS,
            call("local.listFido2Credentials", JSONObject()).errorCode()
        )
    }

    // ------------------------------------------------------------------
    // local.signFido2Assertion
    // ------------------------------------------------------------------

    /**
     * The assertion has to be exactly what a relying party verifies:
     * authenticator data of `rpIdHash || flags || signCount`, and a signature
     * over `authenticatorData || clientDataHash` under the credential's own
     * key.
     */
    @Test
    fun signFido2AssertionProducesAVerifiableWebAuthnAssertion() {
        val credentialId = seedPasskey("assert-$runId", SharingPolicyType.ALL_PEERS)
        val clientDataHash = MessageDigest.getInstance("SHA-256")
            .digest("""{"type":"webauthn.get"}""".toByteArray())

        val result = call(
            "local.signFido2Assertion",
            JSONObject()
                .put("credentialId", credentialId)
                .put("clientDataHash", b64(clientDataHash))
                .put("rpId", rpId)
                .put("userVerificationRequired", false)
        ).ok()

        val authData = Base64.getDecoder().decode(result.getString("authenticatorData"))
        assertEquals("authenticator data is 32 + 1 + 4 bytes", 37, authData.size)

        val expectedRpIdHash = MessageDigest.getInstance("SHA-256").digest(rpId.toByteArray())
        assertTrue(
            "the first 32 bytes must be SHA-256 of the rpId",
            authData.copyOfRange(0, 32).contentEquals(expectedRpIdHash)
        )
        assertEquals(
            "user presence must be asserted and user verification must not be",
            0x01,
            authData[32].toInt() and 0xFF
        )
        assertEquals(
            "the counter is four bytes big-endian and starts at one",
            1L,
            signCountOf(authData)
        )
        assertEquals(
            "the reported counter must match the one inside the authenticator data",
            1L,
            result.getLong("signCount")
        )
        assertEquals(
            "the user handle must be echoed for a discoverable credential",
            "dXNlci1oYW5kbGU=",
            result.getString("userHandle")
        )

        val signedData = authData + clientDataHash
        val dataHash = MessageDigest.getInstance("SHA-256").digest(signedData)
        val publicKey = keystoreManager.getPublicKey(credentialId)
            ?: throw AssertionError("the credential has no public key")
        val verifier = Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(publicKey)
        verifier.update(dataHash)
        assertTrue(
            "the assertion signature must verify over authenticatorData || clientDataHash",
            verifier.verify(Base64.getDecoder().decode(result.getString("signature")))
        )
    }

    /**
     * The signature counter is the replay defence a relying party relies on:
     * it must be persisted and strictly increase across assertions.
     */
    @Test
    fun signFido2AssertionAdvancesAndPersistsTheSignatureCounter() {
        val credentialId = seedPasskey("assert-counter-$runId", SharingPolicyType.ALL_PEERS)

        val first = assertionResult(credentialId)
        val second = assertionResult(credentialId)

        assertEquals(1L, first.getLong("signCount"))
        assertEquals(2L, second.getLong("signCount"))
        assertEquals(
            "the persisted counter must match the one that was signed",
            2L,
            signCountOf(Base64.getDecoder().decode(second.getString("authenticatorData")))
        )
        assertEquals(
            "the counter must be written back to the key store",
            2L,
            runBlocking {
                XKeyDatabase.getInstance(context).keyDao().getByKeyId(credentialId)?.signCount
            }
        )
        assertNotEquals(
            "two assertions over different counters must not share a signature",
            first.getString("signature"),
            second.getString("signature")
        )
    }

    @Test
    fun signFido2AssertionRefusesAPrivateCredential() {
        val credentialId = seedPasskey("assert-private-$runId", SharingPolicyType.PRIVATE)

        assertEquals(
            ErrorCodes.OPERATION_DENIED,
            signAssertion(credentialId, rpId).errorCode()
        )
    }

    @Test
    fun signFido2AssertionRefusesAPeerOutsideASelectedPeersPolicy() {
        val credentialId = seedPasskey("assert-selected-$runId", SharingPolicyType.SELECTED_PEERS)
        grantPolicy(credentialId, peerKeyHex)

        assertTrue(signAssertion(credentialId, rpId).isSuccess())

        handler.setConnectedDevicePublicKeyHex(otherPeerHex)
        assertEquals(
            ErrorCodes.OPERATION_DENIED,
            signAssertion(credentialId, rpId).errorCode()
        )
    }

    /**
     * A credential is bound to one relying party. Signing it for another would
     * hand a working assertion to the wrong site.
     */
    @Test
    fun signFido2AssertionRefusesAMismatchedRelyingParty() {
        val credentialId = seedPasskey("assert-rp-$runId", SharingPolicyType.ALL_PEERS)

        val response = signAssertion(credentialId, "attacker-$runId.example")

        assertEquals(ErrorCodes.INVALID_PARAMS, response.errorCode())
        assertTrue(response.errorMessage().contains("rpId"))
    }

    @Test
    fun signFido2AssertionRefusesANonFido2Key() {
        val keyId = generateSigningKey("assert-not-fido2-$runId")

        val response = signAssertion(keyId, rpId)

        assertEquals(ErrorCodes.INVALID_PARAMS, response.errorCode())
        assertTrue(response.errorMessage().contains("FIDO2"))
    }

    @Test
    fun signFido2AssertionRejectsAnUnknownCredential() {
        assertEquals(
            ErrorCodes.KEY_NOT_FOUND,
            signAssertion("never-seeded-$runId", rpId).errorCode()
        )
    }

    @Test
    fun signFido2AssertionRequiresEveryRequiredField() {
        assertEquals(
            ErrorCodes.INVALID_PARAMS,
            call("local.signFido2Assertion").errorCode()
        )
        val required = listOf(
            JSONObject().put("clientDataHash", b64(ByteArray(32))).put("rpId", rpId),
            JSONObject().put("credentialId", "c-$runId").put("rpId", rpId),
            JSONObject().put("credentialId", "c-$runId").put("clientDataHash", b64(ByteArray(32)))
        )
        for (params in required) {
            assertEquals(
                "an incomplete assertion request must be rejected: $params",
                ErrorCodes.INVALID_PARAMS,
                call("local.signFido2Assertion", params).errorCode()
            )
        }
    }

    // ------------------------------------------------------------------
    // cosign.request / cosign.response
    // ------------------------------------------------------------------

    /**
     * Co-signing is an Android-side extension: the desktop hands over a
     * content hash and the phone signs it only once the owner approves a
     * prompt on the phone (#177). This suite's handler has no biometric
     * launcher, so a well-formed request is refused with BIOMETRIC_FAILED and
     * nothing is signed. The approved path, with its result shape, is pinned
     * by the JVM test CosignRequestHandlerTest.
     */
    @Test
    fun cosignRequestWithNoApprovalPromptSignsNothing() {
        val keyId = generateSigningKey("cosign-$runId")
        val contentHash = MessageDigest.getInstance("SHA-256").digest("a witnessed document".toByteArray())
        val contentHashHex = contentHash.joinToString("") { "%02x".format(it) }

        val response = call(
            "cosign.request",
            JSONObject()
                .put("hash", contentHashHex)
                .put("hashAlgorithm", "SHA-256")
                .put("keyId", keyId)
        )

        assertEquals(
            "without the owner's approval the phone must not co-sign",
            ErrorCodes.BIOMETRIC_FAILED,
            response.errorCode()
        )
        assertEquals(null, response.result)
    }

    /**
     * `keyId` is optional: the handler falls back to a stored signing key
     * (never a FIDO2 key) rather than refusing the request as malformed.
     */
    @Test
    fun cosignRequestFallsBackToAStoredSigningKey() {
        generateSigningKey("cosign-fallback-$runId")
        val contentHashHex = "ab".repeat(32)

        val response = call("cosign.request", JSONObject().put("hash", contentHashHex))

        assertEquals(
            "omitting keyId must select a stored key and reach the approval prompt",
            ErrorCodes.BIOMETRIC_FAILED,
            response.errorCode()
        )
    }

    /** A truncated digest must be reported, not signed as whatever it decodes to. */
    @Test
    fun cosignRequestRejectsAMalformedContentHash() {
        val keyId = generateSigningKey("cosign-badhex-$runId")

        assertEquals(
            ErrorCodes.INVALID_PARAMS,
            call("cosign.request", JSONObject().put("hash", "abc").put("keyId", keyId)).errorCode()
        )
        assertEquals(
            "a 31-byte value is not a SHA-256 digest",
            ErrorCodes.INVALID_PARAMS,
            call("cosign.request", JSONObject().put("hash", "ab".repeat(31)).put("keyId", keyId)).errorCode()
        )
    }

    /** An anonymous session cannot ask the owner to vouch for a hash. */
    @Test
    fun cosignRequestRefusesASessionWithNoConfirmedPeer() {
        val keyId = generateSigningKey("cosign-anon-$runId")
        handler.setConnectedDevicePublicKeyHex(null)

        assertEquals(
            ErrorCodes.OPERATION_DENIED,
            call("cosign.request", JSONObject().put("hash", "ab".repeat(32)).put("keyId", keyId)).errorCode()
        )
    }

    @Test
    fun cosignResponseAcknowledgesAWitnessSignature() {
        val result = call(
            "cosign.response",
            JSONObject()
                .put("signature", b64(ByteArray(64)))
                .put("keyFingerprint", "ab".repeat(32))
        ).ok()

        assertEquals("received", result.getString("status"))
    }

    @Test
    fun cosignResponseRequiresBothTheSignatureAndTheFingerprint() {
        assertEquals(ErrorCodes.INVALID_PARAMS, call("cosign.response").errorCode())
        assertEquals(
            ErrorCodes.INVALID_PARAMS,
            call("cosign.response", JSONObject().put("signature", b64(ByteArray(64)))).errorCode()
        )
        assertEquals(
            ErrorCodes.INVALID_PARAMS,
            call("cosign.response", JSONObject().put("keyFingerprint", "ab".repeat(32))).errorCode()
        )
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private fun listedCredentialIds(): List<String> {
        val credentials = call(
            "local.listFido2Credentials",
            JSONObject().put("rpId", rpId)
        ).ok().getJSONArray("credentials")
        return (0 until credentials.length())
            .map { credentials.getJSONObject(it).getString("credentialId") }
    }

    private fun assertionResult(credentialId: String): JSONObject =
        signAssertion(credentialId, rpId).ok()

    private fun signAssertion(credentialId: String, forRpId: String): Response = call(
        "local.signFido2Assertion",
        JSONObject()
            .put("credentialId", credentialId)
            .put("clientDataHash", b64(MessageDigest.getInstance("SHA-256").digest(ByteArray(8))))
            .put("rpId", forRpId)
            .put("userVerificationRequired", false)
    )

    /** Reads the four-byte big-endian signature counter out of authenticator data. */
    private fun signCountOf(authData: ByteArray): Long =
        ((authData[33].toLong() and 0xFF) shl 24) or
            ((authData[34].toLong() and 0xFF) shl 16) or
            ((authData[35].toLong() and 0xFF) shl 8) or
            (authData[36].toLong() and 0xFF)

    /**
     * Creates a passkey the way the on-device credential provider does: an EC
     * key in the credential alias namespace, plus the key-store row that
     * carries its FIDO2 metadata and sharing policy.
     *
     * The base protocol's `generateKey` is what puts the key in the credential
     * alias namespace, which is the namespace `local.signFido2Assertion` signs
     * from.
     */
    private fun seedPasskey(credentialId: String, policy: SharingPolicyType): String {
        createdCredentialIds.add(credentialId)

        val generated = call(
            "generateKey",
            JSONObject()
                .put("credentialId", credentialId)
                .put("algorithm", CoseAlgorithms.ES256)
                .put("requireUserVerification", false)
                .put("preferStrongBox", false)
        )
        assertTrue(
            "the credential key must be generated: " + generated.toJsonString(),
            generated.isSuccess()
        )

        runBlocking {
            XKeyDatabase.getInstance(context).keyDao().insert(
                KeyEntity(
                    keyId = credentialId,
                    keyType = KeyTypes.FIDO2,
                    algorithm = "ES256",
                    label = "Fido2 Test RP",
                    keySizeBits = 256,
                    biometricRequired = false,
                    authDurationSeconds = -1,
                    shareable = policy != SharingPolicyType.PRIVATE,
                    sharingPolicy = policy,
                    source = "test",
                    rpId = rpId,
                    rpName = "Fido2 Test RP",
                    userId = "dXNlci1oYW5kbGU=",
                    userName = "alice",
                    userDisplayName = "Alice Example",
                    isDiscoverable = true,
                    signCount = 0
                )
            )
        }
        return credentialId
    }

    /** Creates a general-purpose signing key through `local.generateKey`. */
    private fun generateSigningKey(keyId: String): String {
        createdGeneralKeyIds.add(keyId)
        val response = call(
            "local.generateKey",
            JSONObject()
                .put("keyId", keyId)
                .put("keyType", KeyTypes.SIGNING)
                .put("algorithm", "ES256")
                .put("label", "")
                .put("requireUserVerification", false)
                .put("preferStrongBox", false)
        )
        assertTrue(
            "the signing key must be generated: " + response.toJsonString(),
            response.isSuccess()
        )
        return keyId
    }

    private fun grantPolicy(keyId: String, peerHex: String) {
        runBlocking {
            XKeyDatabase.getInstance(context).keySharingPolicyDao().setPolicy(
                KeySharingPolicy(keyId = keyId, peerPublicKeyHex = peerHex, allowed = true)
            )
        }
    }

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
