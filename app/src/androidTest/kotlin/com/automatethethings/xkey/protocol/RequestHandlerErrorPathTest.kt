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
import com.automatethethings.xkey.crypto.SoftwareKey
import com.automatethethings.xkey.crypto.SoftwareKeyStore
import com.automatethethings.xkey.pin.PinManager
import com.automatethethings.xkey.piv.PivKeyManager
import com.automatethethings.xkey.settings.AttestationBiometricPolicy
import com.automatethethings.xkey.settings.BiometricSettingsData
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.settings.PinSettingsRepository
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
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.concurrent.atomic.AtomicLong

/**
 * Failure-path and policy coverage for [RequestHandler].
 *
 * [com.automatethethings.xkey.e2e.ProtocolIntegrationTest] drives the same
 * handler through a real socket and proves the happy paths. This suite skips
 * the transport and calls the handler directly, which is the only practical way
 * to reach the branches that matter when something goes wrong: unknown methods,
 * malformed frames, missing and mistyped parameters, every arm of the
 * exception-to-error-code map, the device-attestation gate, and the key-sharing
 * policy matrix.
 *
 * All keys, key-store rows, sharing policies and contacts created here carry a
 * per-run id and are removed in [tearDown]; other suites assert on empty stores.
 */
@RunWith(AndroidJUnit4::class)
class RequestHandlerErrorPathTest {

    companion object {
        private lateinit var context: Context
        private lateinit var handler: RequestHandler

        /**
         * A handler built the way [com.automatethethings.xkey.ble.XKeyGattService]
         * used to build it: without the PIN and PIV managers. Their families
         * must report themselves uninitialised rather than pretend to work.
         */
        private lateinit var bareHandler: RequestHandler

        private lateinit var pairedDevices: PairedDeviceRepository
        private lateinit var softwareKeys: SoftwareKeyStore

        /** Unique per run so nothing collides with a previous run's leftovers. */
        private val runId = System.currentTimeMillis().toString(36)

        /** The peer identity this suite pairs with: 32 bytes of hex, unique per run. */
        private val peerKeyHex =
            ("fe" + java.lang.Long.toHexString(System.nanoTime())).padEnd(64, '0')

        /** A peer that is never added to the repository. */
        private const val UNKNOWN_PEER_HEX =
            "abababababababababababababababababababababababababababababababab"

        /** Device name used for the paired peer; unique so re-adding replaces it. */
        private val peerName = "ErrorPathTest Desktop $runId"

        /**
         * A PIV slot this suite only ever probes for parameter handling. It is
         * never written to, and no other suite generates a key in it.
         */
        private const val PROBE_SLOT = "8b"

        private val nextRequestId = AtomicLong(1)

        /** Every key id this suite persists, torn down in [tearDown]. */
        private val createdKeyIds = mutableSetOf<String>()

        /** Contact labels this suite may have caused to be stored. */
        private val createdContactLabels = mutableSetOf<String>()

        @JvmStatic
        @BeforeClass
        fun setUp() {
            context = ApplicationProvider.getApplicationContext()
            pairedDevices = PairedDeviceRepository(context)
            softwareKeys = SoftwareKeyStore(context)

            handler = RequestHandler(
                context = context,
                keystoreManager = KeystoreManager(context),
                biometricLauncher = null,
                sessionAuthManager = SessionAuthManager(),
                pairedDeviceRepository = pairedDevices,
                pinManager = PinManager(PinSettingsRepository(context)),
                pivKeyManager = PivKeyManager(XKeyDatabase.getInstance(context).pivSlotDao())
            )
            bareHandler = RequestHandler(
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
            runBlocking {
                val db = XKeyDatabase.getInstance(context)
                val keystoreManager = KeystoreManager(context)

                // Anything this run left behind, whether registered explicitly
                // or discovered by its per-run id.
                val ids = createdKeyIds.toMutableSet()
                for (entity in db.keyDao().getAll()) {
                    if (entity.keyId.contains(runId)) ids.add(entity.keyId)
                }
                for (keyId in ids) {
                    runCatching { keystoreManager.deleteGeneralKey(keyId) }
                    runCatching { softwareKeys.delete(keyId) }
                    runCatching { db.keySharingPolicyDao().clearPoliciesForKey(keyId) }
                    runCatching { db.keyDao().deleteByKeyId(keyId) }
                }

                db.keySharingPolicyDao().clearPoliciesForPeer(peerKeyHex)
                db.keySharingPolicyDao().clearPoliciesForPeer(UNKNOWN_PEER_HEX)

                for (contact in db.contactDao().getAll()) {
                    if (createdContactLabels.contains(contact.name)) {
                        runCatching { db.contactDao().deleteById(contact.id) }
                    }
                }
            }
            pairedDevices.removeDevice(peerKeyHex)
        }
    }

    // ------------------------------------------------------------------
    // Baseline: every test starts from a confirmed, unrestricted peer
    // ------------------------------------------------------------------

    @Before
    fun resetHandlerState() {
        handler.setConnectedDevicePublicKeyHex(peerKeyHex)
        bareHandler.setConnectedDevicePublicKeyHex(peerKeyHex)
        requireAttestation(
            forKeyUse = false,
            forKeyAttestation = false,
            graceMinutes = 60
        )
        val headless = BiometricSettingsData(
            uvPolicy = UserVerificationPolicy.DISABLED,
            attestationBiometricPolicy = AttestationBiometricPolicy.NEVER
        )
        handler.updateSettings(headless)
        bareHandler.updateSettings(headless)
    }

    // ------------------------------------------------------------------
    // Dispatch
    // ------------------------------------------------------------------

    @Test
    fun unknownMethodIsMethodNotFound() {
        val response = call("local.thisMethodDoesNotExist")
        assertEquals(ErrorCodes.METHOD_NOT_FOUND, response.errorCode())
        assertTrue(
            "the message should name the method so the desktop can log it",
            response.errorMessage().contains("local.thisMethodDoesNotExist")
        )
    }

    @Test
    fun unknownMethodPreservesTheRequestId() {
        val id = nextRequestId.getAndIncrement()
        val response = runBlocking { handler.handleRequest(Request(id, "nope")) }
        assertEquals(id, response.id)
    }

    // ------------------------------------------------------------------
    // Raw framing (handleRawRequest)
    // ------------------------------------------------------------------

    @Test
    fun rawRequestRoundTripsASuccessfulCall() {
        val response = rawCall("""{"id":77,"method":"ping"}""")
        assertEquals(77L, response.id)
        assertTrue(response.ok().getBoolean("pong"))
    }

    @Test
    fun rawRequestWithNonJsonBytesIsRejected() {
        val response = rawCall("this is not json at all")
        assertTrue(response.isError())
        assertEquals(
            "an unparseable frame is answered on the reserved id 0",
            0L,
            response.id
        )
    }

    @Test
    fun rawRequestWithTruncatedJsonIsRejected() {
        assertTrue(rawCall("""{"id":1,"method":"pin""").isError())
    }

    @Test
    fun rawRequestWithoutAnIdIsRejected() {
        val response = rawCall("""{"method":"ping"}""")
        assertTrue(response.isError())
        assertTrue(response.errorMessage().contains("id"))
    }

    @Test
    fun rawRequestWithoutAMethodIsRejected() {
        val response = rawCall("""{"id":1}""")
        assertTrue(response.isError())
        assertTrue(response.errorMessage().contains("method"))
    }

    @Test
    fun rawRequestWithNonObjectParamsIsRejected() {
        assertTrue(rawCall("""{"id":1,"method":"local.sign","params":42}""").isError())
    }

    @Test
    fun rawRequestWithAJsonArrayBodyIsRejected() {
        assertTrue(rawCall("""["id",1]""").isError())
    }

    @Test
    fun rawRequestForAnUnknownMethodIsAWellFormedErrorFrame() {
        val response = rawCall("""{"id":9,"method":"local.notAMethod"}""")
        assertEquals(9L, response.id)
        assertEquals(ErrorCodes.METHOD_NOT_FOUND, response.errorCode())
    }

    @Test
    fun createErrorResponseProducesAParseableFrame() {
        val bytes = handler.createErrorResponse(5L, ErrorCodes.RATE_LIMITED, "slow down")
        val response = Response.fromJson(bytes)
        assertEquals(5L, response.id)
        assertEquals(ErrorCodes.RATE_LIMITED, response.errorCode())
        assertEquals("slow down", response.errorMessage())
    }

    // ------------------------------------------------------------------
    // Missing parameters, per family
    // ------------------------------------------------------------------

    /**
     * Every method that reads parameters must reject a parameterless call with
     * INVALID_PARAMS rather than throwing its way into a generic internal
     * error. The two styles in the handler (a thrown ProtocolException and a
     * returned error Response) have to agree on the code.
     */
    @Test
    fun everyParameterisedMethodRejectsAMissingParamsObject() {
        val methods = listOf(
            "local.generateKey",
            "local.sign",
            "local.decrypt",
            "local.symmetricEncrypt",
            "local.symmetricDecrypt",
            "local.hmac",
            "local.ecdh",
            "local.getPublicKey",
            "local.getKeyInfo",
            "local.deleteKey",
            "local.setKeyPolicy",
            "local.attestKey",
            "local.oathGenerate",
            "local.oathAdd",
            "local.oathRemove",
            "local.createBackup",
            "local.sharePublicKey",
            "local.shareSymmetric",
            "local.importSharedKey",
            "local.pinVerify",
            "local.pinSet",
            "local.pinChange",
            "local.pinResetLockout",
            "local.pivGenerateKey",
            "local.pivImportCert",
            "local.pivSign",
            "local.pivGetCert",
            "cosign.request",
            "cosign.response"
        )
        for (method in methods) {
            assertEquals(
                "$method must reject a call with no params",
                ErrorCodes.INVALID_PARAMS,
                call(method).errorCode()
            )
        }
    }

    @Test
    fun missingFieldsWithinParamsAreReportedPerField() {
        val cases = mapOf(
            "local.sign" to JSONObject().put("keyId", "x"),
            "local.decrypt" to JSONObject().put("keyId", "x"),
            "local.hmac" to JSONObject().put("keyId", "x"),
            "local.ecdh" to JSONObject().put("keyId", "x"),
            "local.oathGenerate" to JSONObject(),
            "local.oathRemove" to JSONObject(),
            "local.importSharedKey" to JSONObject(),
            "local.sharePublicKey" to JSONObject(),
            "local.shareSymmetric" to JSONObject()
        )
        for (entry in cases) {
            assertEquals(
                "${entry.key} must report the missing field as INVALID_PARAMS",
                ErrorCodes.INVALID_PARAMS,
                call(entry.key, entry.value).errorCode()
            )
        }
    }

    /**
     * `keyId` and `algorithm` stay mandatory. `keyType` does not: go-xkms never
     * sends it, so it is defaulted from the algorithm rather than rejected.
     */
    @Test
    fun generateKeyRequiresAKeyIdAndAnAlgorithm() {
        assertEquals(
            ErrorCodes.INVALID_PARAMS,
            call("local.generateKey", JSONObject().put("keyId", "no-algo-$runId")).errorCode()
        )
        assertEquals(
            ErrorCodes.INVALID_PARAMS,
            call(
                "local.generateKey",
                JSONObject().put("keyType", "signing").put("algorithm", "ES256")
            ).errorCode()
        )
    }

    @Test
    fun oathAddRequiresACredentialObjectWithItsMandatoryFields() {
        assertEquals(
            ErrorCodes.INVALID_PARAMS,
            call("local.oathAdd", JSONObject().put("unrelated", 1)).errorCode()
        )
        assertEquals(
            ErrorCodes.INVALID_PARAMS,
            call(
                "local.oathAdd",
                JSONObject().put("credential", JSONObject().put("name", "only-a-name"))
            ).errorCode()
        )
    }

    /**
     * A wrongly typed `algorithm` must not be coerced into something plausible.
     */
    @Test
    fun mistypedAlgorithmIsRejected() {
        val objectValued = call(
            "local.generateKey",
            JSONObject()
                .put("keyId", "mistyped-$runId")
                .put("keyType", "signing")
                .put("algorithm", JSONObject().put("name", "ES256"))
        )
        assertTrue(objectValued.isError())

        val unknownName = call(
            "local.generateKey",
            JSONObject()
                .put("keyId", "mistyped-$runId")
                .put("keyType", "signing")
                .put("algorithm", "NOT-AN-ALGORITHM")
        )
        assertEquals(ErrorCodes.INVALID_ALGORITHM, unknownName.errorCode())

        val unknownCoseId = call(
            "local.generateKey",
            JSONObject()
                .put("keyId", "mistyped-$runId")
                .put("keyType", "signing")
                .put("algorithm", 424242)
        )
        assertEquals(ErrorCodes.INVALID_ALGORITHM, unknownCoseId.errorCode())
    }

    /**
     * Base64 fields that are not base64 currently fall through to the generic
     * catch-all. The response is still a well-formed error frame, which is what
     * the desktop needs; the code is recorded here so a future tightening to
     * INVALID_PARAMS is a deliberate, visible change.
     */
    @Test
    fun malformedBase64PayloadStillProducesAnErrorFrame() {
        val keyId = generateEcKey("b64-$runId")
        val response = call(
            "local.sign",
            JSONObject().put("keyId", keyId).put("data", "!!!not base64!!!")
        )
        assertEquals(ErrorCodes.INTERNAL_ERROR, response.errorCode())
    }

    // ------------------------------------------------------------------
    // go-xkms wire shapes the desktop actually sends
    // ------------------------------------------------------------------

    /**
     * The Go initiator omits `keyType` entirely; the key type has to be derived
     * from the algorithm instead of failing the request.
     */
    @Test
    fun generateKeyDefaultsTheKeyTypeWhenTheDesktopOmitsIt() {
        val keyId = "no-keytype-$runId"
        createdKeyIds.add(keyId)
        val response = call(
            "local.generateKey",
            JSONObject()
                .put("keyId", keyId)
                .put("algorithm", "ES256")
                .put("requireUserVerification", false)
                .put("preferStrongBox", false)
        )
        val result = response.ok()
        assertTrue(
            "an asymmetric key must return its SPKI on the go-xkms field name",
            result.getString("publicKeyDer").isNotEmpty()
        )
        assertTrue(
            "securityLevel must be one of software/strongbox/tee",
            result.getString("securityLevel") in setOf("software", "strongbox", "tee")
        )
    }

    /** go-xkms names its symmetric algorithms `AES-128-GCM` / `AES-256-GCM`. */
    @Test
    fun generateKeyAcceptsGoSymmetricAlgorithmNames() {
        val cases = mapOf(
            "AES-128-GCM" to 128,
            "AES-256-GCM" to 256
        )
        for (entry in cases) {
            val keyId = "gcm-${entry.value}-$runId"
            createdKeyIds.add(keyId)
            val result = call(
                "local.generateKey",
                JSONObject()
                    .put("keyId", keyId)
                    .put("algorithm", entry.key)
                    .put("requireUserVerification", false)
                    .put("preferStrongBox", false)
            ).ok()
            assertEquals(
                "${entry.key} must produce a ${entry.value}-bit key",
                entry.value.toLong(),
                result.getInt("keySizeBits").toLong()
            )
        }
    }

    // ------------------------------------------------------------------
    // Operating on keys that do not exist
    // ------------------------------------------------------------------

    @Test
    fun operationsOnAnUnknownKeyReportKeyNotFound() {
        val missing = "missing-key-$runId"
        val cases = mapOf(
            "local.sign" to JSONObject().put("keyId", missing).put("data", b64("x".toByteArray()))
                .put("algorithm", "ES256"),
            "local.decrypt" to JSONObject().put("keyId", missing)
                .put("ciphertext", b64(ByteArray(64))),
            "local.symmetricEncrypt" to JSONObject().put("keyId", missing)
                .put("data", b64(ByteArray(16))),
            "local.symmetricDecrypt" to JSONObject().put("keyId", missing)
                .put("data", b64(ByteArray(64))),
            "local.hmac" to JSONObject().put("keyId", missing).put("data", b64(ByteArray(16))),
            "local.ecdh" to JSONObject().put("keyId", missing)
                .put("peerPublicKey", b64(ephemeralPublicKeyDer())),
            "local.getPublicKey" to JSONObject().put("keyId", missing),
            "local.getKeyInfo" to JSONObject().put("keyId", missing),
            "local.setKeyPolicy" to JSONObject().put("keyId", missing).put("shareable", true)
        )
        for (entry in cases) {
            assertEquals(
                "${entry.key} on an unknown key must be KEY_NOT_FOUND",
                ErrorCodes.KEY_NOT_FOUND,
                call(entry.key, entry.value).errorCode()
            )
        }
    }

    /** Deleting something that is already gone is a success, not an error. */
    @Test
    fun deletingAnUnknownKeyIsIdempotent() {
        val response = call("local.deleteKey", JSONObject().put("keyId", "never-existed-$runId"))
        assertTrue(response.ok().getBoolean("deleted"))
    }

    @Test
    fun restoringAnUnknownBackupIsAnError() {
        assertTrue(
            call(
                "local.restoreBackup",
                JSONObject().put("backup_id", "no-such-backup-$runId")
            ).isError()
        )
    }

    @Test
    fun generatingAKeyTwiceReportsKeyExists() {
        val keyId = generateEcKey("dup-$runId")
        val second = call(
            "local.generateKey",
            JSONObject()
                .put("keyId", keyId)
                .put("keyType", "signing")
                .put("algorithm", "ES256")
                .put("requireUserVerification", false)
                .put("preferStrongBox", false)
        )
        assertEquals(ErrorCodes.KEY_EXISTS, second.errorCode())
    }

    // ------------------------------------------------------------------
    // Exception -> error code mapping
    // ------------------------------------------------------------------

    /** An EC key asked to sign with an RSA algorithm: SigningException. */
    @Test
    fun signingFailureMapsToSigningFailed() {
        val keyId = generateEcKey("sign-fail-$runId")
        val response = call(
            "local.sign",
            JSONObject()
                .put("keyId", keyId)
                .put("data", b64("payload".toByteArray()))
                .put("algorithm", "RS256")
        )
        assertEquals(ErrorCodes.SIGNING_FAILED, response.errorCode())
    }

    /** A peer public key that is not a key at all: ECDHException. */
    @Test
    fun ecdhFailureMapsToEcdhFailed() {
        val keyId = generateEcKey("ecdh-fail-$runId")
        val response = call(
            "local.ecdh",
            JSONObject().put("keyId", keyId).put("peerPublicKey", b64(ByteArray(48) { 0x7f }))
        )
        assertEquals(ErrorCodes.ECDH_FAILED, response.errorCode())
    }

    /** Ciphertext too short to even hold the GCM IV: DecryptionException. */
    @Test
    fun decryptionFailureMapsToDecryptionFailed() {
        val keyId = generateAesKey("dec-fail-$runId")
        val response = call(
            "local.symmetricDecrypt",
            JSONObject().put("keyId", keyId).put("data", b64(ByteArray(4)))
        )
        assertEquals(ErrorCodes.DECRYPTION_FAILED, response.errorCode())
    }

    /** Garbage of a plausible length still fails authentication. */
    @Test
    fun tamperedCiphertextMapsToDecryptionFailed() {
        val keyId = generateAesKey("dec-tamper-$runId")
        val encrypted = call(
            "local.symmetricEncrypt",
            JSONObject().put("keyId", keyId).put("data", b64("secret".toByteArray()))
        )
        val ciphertext = unb64(encrypted.ok().getString("data"))
        val last = ciphertext.size - 1
        ciphertext[last] = (ciphertext[last] + 1).toByte()

        val response = call(
            "local.symmetricDecrypt",
            JSONObject().put("keyId", keyId).put("data", b64(ciphertext))
        )
        assertEquals(ErrorCodes.DECRYPTION_FAILED, response.errorCode())
    }

    /** An AES key cannot key a MAC: HMACException. */
    @Test
    fun hmacFailureMapsToHmacFailed() {
        val keyId = generateAesKey("hmac-fail-$runId")
        val response = call(
            "local.hmac",
            JSONObject().put("keyId", keyId).put("data", b64("data".toByteArray()))
        )
        assertEquals(ErrorCodes.HMAC_FAILED, response.errorCode())
    }

    /** An HMAC key cannot drive a cipher: EncryptionException. */
    @Test
    fun encryptionFailureMapsToEncryptionFailed() {
        val keyId = generateHmacKey("enc-fail-$runId")
        val response = call(
            "local.symmetricEncrypt",
            JSONObject().put("keyId", keyId).put("data", b64("data".toByteArray()))
        )
        assertEquals(ErrorCodes.ENCRYPTION_FAILED, response.errorCode())
    }

    /** HMAC-SHA384 has a COSE id but no Keystore support: UnsupportedAlgorithmException. */
    @Test
    fun unsupportedAlgorithmMapsToInvalidAlgorithm() {
        val keyId = "unsupported-$runId"
        createdKeyIds.add(keyId)
        val response = call(
            "local.generateKey",
            JSONObject()
                .put("keyId", keyId)
                .put("keyType", "hmac")
                .put("algorithm", "HMAC-SHA384")
                .put("requireUserVerification", false)
                .put("preferStrongBox", false)
        )
        assertEquals(ErrorCodes.INVALID_ALGORITHM, response.errorCode())
    }

    /** An exportable asymmetric key is a policy refusal, not a crypto failure. */
    @Test
    fun exportableAsymmetricKeyIsRefused() {
        val keyId = "exportable-asym-$runId"
        createdKeyIds.add(keyId)
        val response = call(
            "local.generateKey",
            JSONObject()
                .put("keyId", keyId)
                .put("keyType", "signing")
                .put("algorithm", "ES256")
                .put("exportable", true)
                .put("requireUserVerification", false)
        )
        assertTrue(response.isError())
    }

    // ------------------------------------------------------------------
    // Public key export formats
    // ------------------------------------------------------------------

    @Test
    fun unsupportedExportFormatIsReported() {
        val keyId = generateEcKey("fmt-$runId")
        val response = call(
            "local.getPublicKey",
            JSONObject().put("keyId", keyId).put("format", "jwk")
        )
        assertEquals(ErrorCodes.UNSUPPORTED_FORMAT, response.errorCode())
    }

    @Test
    fun everySupportedExportFormatWorksForAnEcKey() {
        val keyId = generateEcKey("fmt-ok-$runId")
        for (format in listOf("der", "pem", "ssh", "cose")) {
            val result = call(
                "local.getPublicKey",
                JSONObject().put("keyId", keyId).put("format", format)
            ).ok()
            assertEquals(format, result.getString("format"))
            assertTrue(
                "format $format must export something",
                result.getString("publicKey").isNotEmpty()
            )
        }
    }

    /** A symmetric key has no public half to export. */
    @Test
    fun exportingAPublicKeyForASymmetricKeyFails() {
        val keyId = generateAesKey("no-pub-$runId")
        val response = call(
            "local.getPublicKey",
            JSONObject().put("keyId", keyId).put("format", "der")
        )
        assertEquals(ErrorCodes.EXPORT_FAILED, response.errorCode())
    }

    // ------------------------------------------------------------------
    // Device attestation gate
    // ------------------------------------------------------------------

    /**
     * A desktop that has never proved its state must not be able to use keys
     * once the user turns the requirement on.
     */
    @Test
    fun keyUseIsGatedWhenTheDeviceHasNeverAttested() {
        resetPeerToNeverAttested()
        requireAttestation(forKeyUse = true, forKeyAttestation = false, graceMinutes = 60)

        val gatedMethods = mapOf(
            "local.sign" to JSONObject().put("keyId", "any").put("data", b64(ByteArray(4)))
                .put("algorithm", "ES256"),
            "local.decrypt" to JSONObject().put("keyId", "any").put("ciphertext", b64(ByteArray(4))),
            "local.symmetricEncrypt" to JSONObject().put("keyId", "any").put("data", b64(ByteArray(4))),
            "local.symmetricDecrypt" to JSONObject().put("keyId", "any").put("data", b64(ByteArray(32))),
            "local.hmac" to JSONObject().put("keyId", "any").put("data", b64(ByteArray(4))),
            "local.ecdh" to JSONObject().put("keyId", "any").put("peerPublicKey", b64(ByteArray(4)))
        )
        for (entry in gatedMethods) {
            assertEquals(
                "${entry.key} must be gated on device attestation",
                ErrorCodes.DEVICE_ATTESTATION_REQUIRED,
                call(entry.key, entry.value).errorCode()
            )
        }
    }

    /** Key use and key attestation are gated independently. */
    @Test
    fun keyAttestationIsGatedIndependentlyOfKeyUse() {
        resetPeerToNeverAttested()
        requireAttestation(forKeyUse = false, forKeyAttestation = true, graceMinutes = 60)

        assertEquals(
            ErrorCodes.DEVICE_ATTESTATION_REQUIRED,
            call(
                "local.attestKey",
                JSONObject().put("keyId", "any").put("nonce", b64(ByteArray(32)))
            ).errorCode()
        )
        // Key use is still permitted, so this fails on the key rather than the gate.
        assertEquals(
            ErrorCodes.KEY_NOT_FOUND,
            signMissingKey().errorCode()
        )
    }

    /** A recent attestation inside the grace window opens the gate. */
    @Test
    fun aFreshAttestationSatisfiesTheGate() {
        requireAttestation(forKeyUse = true, forKeyAttestation = true, graceMinutes = 60)
        recordAttestationNow()

        assertEquals(
            "the gate must be open, so the call fails on the missing key instead",
            ErrorCodes.KEY_NOT_FOUND,
            signMissingKey().errorCode()
        )
    }

    /** An attestation older than the grace window is not good enough. */
    @Test
    fun anExpiredAttestationClosesTheGateAgain() {
        requireAttestation(forKeyUse = true, forKeyAttestation = true, graceMinutes = 0)
        recordAttestationNow()
        Thread.sleep(50)

        assertEquals(
            ErrorCodes.DEVICE_ATTESTATION_REQUIRED,
            signMissingKey().errorCode()
        )
    }

    /** With no connected identity there is no device policy to apply. */
    @Test
    fun anAnonymousSessionIsNotGated() {
        requireAttestation(forKeyUse = true, forKeyAttestation = true, graceMinutes = 60)
        handler.setConnectedDevicePublicKeyHex(null)

        assertEquals(ErrorCodes.KEY_NOT_FOUND, signMissingKey().errorCode())
    }

    /** A peer with no record in the repository has no policy either. */
    @Test
    fun aPeerWithNoStoredRecordIsNotGated() {
        requireAttestation(forKeyUse = true, forKeyAttestation = true, graceMinutes = 60)
        handler.setConnectedDevicePublicKeyHex(UNKNOWN_PEER_HEX)

        assertEquals(ErrorCodes.KEY_NOT_FOUND, signMissingKey().errorCode())
    }

    // ------------------------------------------------------------------
    // Key sharing policy matrix
    // ------------------------------------------------------------------

    /** Sharing decisions need a peer to decide about. */
    @Test
    fun sharingWithoutAConfirmedPeerIsDenied() {
        handler.setConnectedDevicePublicKeyHex(null)

        assertEquals(
            ErrorCodes.OPERATION_DENIED,
            call("local.importSharedKey", JSONObject().put("key_id", "anything")).errorCode()
        )
        assertEquals(
            ErrorCodes.OPERATION_DENIED,
            call(
                "local.sharePublicKey",
                JSONObject()
                    .put("public_key_pem", pemPublicKey())
                    .put("key_id", "peerless-$runId")
                    .put("label", contactLabel("peerless"))
            ).errorCode()
        )
        assertEquals(
            ErrorCodes.OPERATION_DENIED,
            call(
                "local.shareSymmetric",
                JSONObject().put("wrapped_key", b64(ByteArray(32))).put("label", "peerless-$runId")
            ).errorCode()
        )
    }

    @Test
    fun exportingAnUnknownKeyIdIsKeyNotFound() {
        assertEquals(
            ErrorCodes.KEY_NOT_FOUND,
            call(
                "local.importSharedKey",
                JSONObject().put("key_id", "no-such-key-$runId")
            ).errorCode()
        )
    }

    /** PRIVATE is the default and refuses every peer. */
    @Test
    fun privatePolicyRefusesExport() {
        val keyId = seedSoftwareKey(
            keyId = "share-private-$runId",
            exportable = true,
            shareable = false,
            policy = SharingPolicyType.PRIVATE,
            material = randomMaterial()
        )
        assertEquals(
            ErrorCodes.OPERATION_DENIED,
            call("local.importSharedKey", JSONObject().put("key_id", keyId)).errorCode()
        )
    }

    /** ALL_PEERS admits the confirmed peer and hands over the material. */
    @Test
    fun allPeersPolicyAllowsExportOfSoftwareMaterial() {
        val material = randomMaterial()
        val keyId = seedSoftwareKey(
            keyId = "share-all-$runId",
            exportable = true,
            shareable = true,
            policy = SharingPolicyType.ALL_PEERS,
            material = material
        )
        val result = call("local.importSharedKey", JSONObject().put("key_id", keyId)).ok()
        assertTrue(result.getBoolean("exportable"))
        assertTrue(
            "the exported material must be the key itself",
            unb64(result.getString("wrapped_key")).contentEquals(material)
        )
    }

    /**
     * SELECTED_PEERS consults the policy table. This branch has no other route
     * into it: the wire protocol can only create ALL_PEERS or PRIVATE keys.
     */
    @Test
    fun selectedPeersPolicyConsultsThePolicyTable() {
        val keyId = seedSoftwareKey(
            keyId = "share-selected-$runId",
            exportable = true,
            shareable = true,
            policy = SharingPolicyType.SELECTED_PEERS,
            material = randomMaterial()
        )

        assertEquals(
            "with no policy row the peer is not selected",
            ErrorCodes.OPERATION_DENIED,
            call("local.importSharedKey", JSONObject().put("key_id", keyId)).errorCode()
        )

        setSharingPolicy(keyId, peerKeyHex)
        assertTrue(
            "an explicitly selected peer may export",
            call("local.importSharedKey", JSONObject().put("key_id", keyId)).isSuccess()
        )

        revokeSharingPolicy(keyId, peerKeyHex)
        assertEquals(
            "a revoked policy denies again",
            ErrorCodes.OPERATION_DENIED,
            call("local.importSharedKey", JSONObject().put("key_id", keyId)).errorCode()
        )
    }

    /** A selected peer is not every peer. */
    @Test
    fun selectedPeersPolicyDoesNotLeakToOtherPeers() {
        val keyId = seedSoftwareKey(
            keyId = "share-other-peer-$runId",
            exportable = true,
            shareable = true,
            policy = SharingPolicyType.SELECTED_PEERS,
            material = randomMaterial()
        )
        setSharingPolicy(keyId, UNKNOWN_PEER_HEX)
        assertEquals(
            ErrorCodes.OPERATION_DENIED,
            call("local.importSharedKey", JSONObject().put("key_id", keyId)).errorCode()
        )
    }

    /**
     * Material in the software store with no row in the key store has no
     * recorded policy, so it must be treated as private rather than open.
     */
    @Test
    fun softwareMaterialWithNoKeyStoreRowIsUnshareable() {
        val keyId = "orphan-$runId"
        createdKeyIds.add(keyId)
        softwareKeys.put(
            SoftwareKey(
                keyId = keyId,
                algorithm = "AES",
                keyType = "symmetric",
                keySize = 256,
                exportable = true,
                shareable = true,
                material = randomMaterial()
            )
        )
        assertEquals(
            ErrorCodes.OPERATION_DENIED,
            call("local.importSharedKey", JSONObject().put("key_id", keyId)).errorCode()
        )
    }

    /**
     * Policy can only widen what the backing allows. A hardware key admitted by
     * ALL_PEERS still exports its public half and nothing else.
     */
    @Test
    fun hardwareKeyNeverEmitsWrappedKeyEvenUnderAllPeers() {
        val keyId = "hw-share-$runId"
        createdKeyIds.add(keyId)
        call(
            "local.generateKey",
            JSONObject()
                .put("keyId", keyId)
                .put("keyType", "signing")
                .put("algorithm", "ES256")
                .put("shareable", true)
                .put("requireUserVerification", false)
                .put("preferStrongBox", false)
        ).ok()

        val exported = call("local.importSharedKey", JSONObject().put("key_id", keyId)).ok()
        assertFalse(exported.getBoolean("exportable"))
        assertFalse("a hardware key must never emit raw material", exported.has("wrapped_key"))
        assertTrue(exported.getString("public_key_pem").contains("BEGIN PUBLIC KEY"))
        assertEquals("public", exported.getString("key_type"))
    }

    /**
     * A software key the user marked shareable but not exportable is admitted by
     * policy yet still yields no material: both flags must agree.
     */
    @Test
    fun shareableButNonExportableSoftwareKeyYieldsNoMaterial() {
        val keyId = seedSoftwareKey(
            keyId = "share-noexport-$runId",
            exportable = false,
            shareable = true,
            policy = SharingPolicyType.ALL_PEERS,
            material = randomMaterial()
        )
        val result = call("local.importSharedKey", JSONObject().put("key_id", keyId)).ok()
        assertFalse(result.getBoolean("exportable"))
        assertFalse(result.has("wrapped_key"))
    }

    /** An inbound shared key must not overwrite something already stored. */
    @Test
    fun shareSymmetricRefusesToOverwriteAnExistingKey() {
        val keyId = seedSoftwareKey(
            keyId = "share-clash-$runId",
            exportable = true,
            shareable = false,
            policy = SharingPolicyType.PRIVATE,
            material = randomMaterial()
        )
        val response = call(
            "local.shareSymmetric",
            JSONObject().put("wrapped_key", b64(randomMaterial())).put("label", keyId)
        )
        assertEquals(ErrorCodes.KEY_EXISTS, response.errorCode())
    }

    @Test
    fun sharePublicKeyRejectsAPemThatIsNotAKey() {
        val label = contactLabel("bad-pem")
        val response = call(
            "local.sharePublicKey",
            JSONObject()
                .put(
                    "public_key_pem",
                    "-----BEGIN PUBLIC KEY-----\nnot base64\n-----END PUBLIC KEY-----"
                )
                .put("key_id", "bad-pem-$runId")
                .put("label", label)
        )
        assertTrue(response.isError())
    }

    // ------------------------------------------------------------------
    // Families that depend on an injected manager
    // ------------------------------------------------------------------

    /**
     * Before the managers were wired through, every PIN and PIV call over
     * BLE/USB/TCP failed this way. The behaviour is pinned so a regression is
     * visible, and the wired handler is checked to prove it does not.
     */
    @Test
    fun pinAndPivFamiliesReportThemselvesUninitialisedWithoutTheirManagers() {
        val unmanaged = listOf(
            "local.pinStatus" to JSONObject(),
            "local.pinVerify" to JSONObject().put("pin", "123456"),
            "local.pinSet" to JSONObject().put("pinType", "SO_PIN").put("newPin", "12345678"),
            "local.pinChange" to JSONObject().put("pinType", "USER_PIN").put("currentPin", "1")
                .put("newPin", "2"),
            "local.pinResetLockout" to JSONObject().put("soPin", "12345678"),
            "local.pivListSlots" to JSONObject(),
            "local.pivGenerateKey" to JSONObject().put("slotId", PROBE_SLOT),
            "local.pivImportCert" to JSONObject().put("slotId", PROBE_SLOT)
                .put("certificate", b64(ByteArray(4))),
            "local.pivSign" to JSONObject().put("slotId", PROBE_SLOT).put("data", b64(ByteArray(4))),
            "local.pivGetCert" to JSONObject().put("slotId", PROBE_SLOT)
        )

        for (entry in unmanaged) {
            val response = runBlocking {
                bareHandler.handleRequest(
                    Request(nextRequestId.getAndIncrement(), entry.first, entry.second)
                )
            }
            // FEATURE_UNAVAILABLE, not INTERNAL_ERROR: the peer must be able to
            // tell "this transport does not carry PIN/PIV support" from "the
            // phone hit a bug", and INTERNAL_ERROR has to keep meaning the latter.
            assertEquals(
                "${entry.first} without its manager must report FEATURE_UNAVAILABLE",
                ErrorCodes.FEATURE_UNAVAILABLE,
                response.errorCode()
            )
            assertTrue(
                "${entry.first} should say the feature is unavailable",
                response.errorMessage().contains("not available on this transport")
            )
        }

        // The wired handler answers the read-only calls for real.
        assertTrue(call("local.pinStatus").isSuccess())
        assertTrue(call("local.pivListSlots").isSuccess())
    }

    // ------------------------------------------------------------------
    // PIV parameter validation
    // ------------------------------------------------------------------

    @Test
    fun pivRejectsAnUnknownSlot() {
        val cases = mapOf(
            "local.pivGenerateKey" to JSONObject().put("slotId", "ff"),
            "local.pivSign" to JSONObject().put("slotId", "ff").put("data", b64(ByteArray(4))),
            "local.pivGetCert" to JSONObject().put("slotId", "ff"),
            "local.pivImportCert" to JSONObject().put("slotId", "ff")
                .put("certificate", b64(ByteArray(4)))
        )
        for (entry in cases) {
            assertEquals(
                "${entry.key} must reject an unknown slot",
                ErrorCodes.PIV_INVALID_SLOT,
                call(entry.key, entry.value).errorCode()
            )
        }
    }

    @Test
    fun pivRejectsAnUnknownAlgorithm() {
        assertEquals(
            ErrorCodes.INVALID_ALGORITHM,
            call(
                "local.pivGenerateKey",
                JSONObject().put("slotId", PROBE_SLOT).put("algorithm", "NOPE")
            ).errorCode()
        )
        assertEquals(
            ErrorCodes.INVALID_ALGORITHM,
            call(
                "local.pivSign",
                JSONObject().put("slotId", PROBE_SLOT).put("data", b64(ByteArray(4)))
                    .put("algorithm", "NOPE")
            ).errorCode()
        )
    }

    @Test
    fun pivRequiresDataToSignAndACertificateToImport() {
        assertEquals(
            ErrorCodes.INVALID_PARAMS,
            call("local.pivSign", JSONObject().put("slotId", PROBE_SLOT)).errorCode()
        )
        assertEquals(
            ErrorCodes.INVALID_PARAMS,
            call("local.pivImportCert", JSONObject().put("slotId", PROBE_SLOT)).errorCode()
        )
    }

    /**
     * Reading a certificate from a slot that has none is a distinct code from
     * an invalid slot.
     */
    @Test
    fun readingACertificateFromAnEmptySlotIsSlotNotFound() {
        assertEquals(
            ErrorCodes.PIV_SLOT_NOT_FOUND,
            call("local.pivGetCert", JSONObject().put("slotId", PROBE_SLOT)).errorCode()
        )
    }

    /** go-xkms names the slot field `slot`; the legacy Android name is `slotId`. */
    @Test
    fun pivAcceptsTheGoSlotFieldName() {
        assertEquals(
            "a `slot` of $PROBE_SLOT must resolve to a real slot",
            ErrorCodes.PIV_SLOT_NOT_FOUND,
            call("local.pivGetCert", JSONObject().put("slot", PROBE_SLOT)).errorCode()
        )
    }

    /**
     * go-xkms spells the PIV algorithms `ECDSA-P256` / `ECDSA-P384` /
     * `RSA-2048`. Reaching the signing attempt (which fails on the empty slot)
     * rather than INVALID_ALGORITHM proves the name was understood.
     */
    @Test
    fun pivAcceptsGoAlgorithmNames() {
        for (algorithm in listOf("ECDSA-P256", "ECDSA-P384", "RSA-2048")) {
            val code = call(
                "local.pivSign",
                JSONObject().put("slot", PROBE_SLOT).put("data", b64(ByteArray(4)))
                    .put("algorithm", algorithm)
            ).errorCode()
            assertTrue(
                "$algorithm is a valid go-xkms PIV algorithm name, got code $code",
                code != ErrorCodes.INVALID_ALGORITHM
            )
        }
    }

    /**
     * go-xkms sends the certificate as `certificate_der`. Failing on the empty
     * slot rather than "certificate is required" proves the field was read.
     */
    @Test
    fun pivAcceptsTheGoCertificateFieldName() {
        val code = call(
            "local.pivImportCert",
            JSONObject().put("slot", PROBE_SLOT).put("certificate_der", b64(ByteArray(4)))
        ).errorCode()
        assertTrue(
            "certificate_der must be accepted as the certificate payload, got code $code",
            code != ErrorCodes.INVALID_PARAMS
        )
    }

    // ------------------------------------------------------------------
    // PIN parameter validation
    // ------------------------------------------------------------------

    @Test
    fun pinCallsValidateTheirOwnArguments() {
        assertEquals(
            ErrorCodes.PIN_REQUIRED,
            call("local.pinVerify", JSONObject().put("pinType", "USER_PIN")).errorCode()
        )
        assertEquals(
            ErrorCodes.INVALID_PARAMS,
            call("local.pinSet", JSONObject().put("pinType", "SO_PIN")).errorCode()
        )
        assertEquals(
            ErrorCodes.INVALID_PARAMS,
            call(
                "local.pinChange",
                JSONObject().put("pinType", "USER_PIN").put("newPin", "1")
            ).errorCode()
        )
        assertEquals(
            ErrorCodes.PIN_REQUIRED,
            call("local.pinResetLockout", JSONObject()).errorCode()
        )
    }

    // ------------------------------------------------------------------
    // OATH
    // ------------------------------------------------------------------

    @Test
    fun generatingACodeForAnUnknownCredentialIsInvalidParams() {
        assertEquals(
            ErrorCodes.INVALID_PARAMS,
            call(
                "local.oathGenerate",
                JSONObject().put("credential_id", "nope-$runId")
            ).errorCode()
        )
    }

    // ------------------------------------------------------------------
    // Co-signing
    // ------------------------------------------------------------------

    @Test
    fun cosignRequestWithoutAHashIsInvalidParams() {
        assertEquals(
            ErrorCodes.INVALID_PARAMS,
            call("cosign.request", JSONObject().put("hashAlgorithm", "SHA-256")).errorCode()
        )
    }

    @Test
    fun cosignRequestForAnUnknownKeyIsKeyNotFound() {
        assertEquals(
            ErrorCodes.KEY_NOT_FOUND,
            call(
                "cosign.request",
                JSONObject()
                    .put("hash", "00".repeat(32))
                    .put("keyId", "no-cosign-key-$runId")
            ).errorCode()
        )
    }

    // ------------------------------------------------------------------
    // Sync tolerates empty and malformed payloads
    // ------------------------------------------------------------------

    @Test
    fun syncMethodsAcceptAMissingPayloadWithoutFailing() {
        for (method in listOf("local.syncTrustStore", "local.syncOATH", "local.syncPasswords")) {
            val result = call(method).ok()
            assertNotNull("$method must tolerate an absent payload", result.getJSONArray("remote"))
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private fun call(method: String): Response = dispatch(method, null)

    private fun call(method: String, params: JSONObject): Response = dispatch(method, params)

    /**
     * Written without default arguments on purpose: a function that carries a
     * default argument and also builds a coroutine lambda has repeatedly
     * crashed the Kotlin JVM backend in this file
     * (BackendException at RecordEnclosingMethodsLowering).
     */
    private fun dispatch(method: String, params: JSONObject?): Response {
        val request = Request(nextRequestId.getAndIncrement(), method, params)
        return runBlocking { handler.handleRequest(request) }
    }

    private fun rawCall(json: String): Response {
        val bytes = json.toByteArray()
        val response = runBlocking { handler.handleRawRequest(bytes) }
        return Response.fromJson(response)
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

    private fun unb64(data: String): ByteArray = Base64.getDecoder().decode(data)

    private fun randomMaterial(): ByteArray {
        val material = ByteArray(32)
        SecureRandom().nextBytes(material)
        return material
    }

    /** Names a contact this suite may cause to be stored, so it can be removed. */
    private fun contactLabel(suffix: String): String {
        val label = "ErrorPathTest $suffix $runId"
        createdContactLabels.add(label)
        return label
    }

    /** Signs with a key that is guaranteed not to exist. */
    private fun signMissingKey(): Response = call(
        "local.sign",
        JSONObject().put("keyId", "missing-$runId").put("data", b64(ByteArray(4)))
            .put("algorithm", "ES256")
    )

    /** Generates a hardware EC key through the protocol and registers it for cleanup. */
    private fun generateEcKey(keyId: String): String =
        generateKey(keyId, "signing", "ES256")

    private fun generateAesKey(keyId: String): String =
        generateKey(keyId, "secret", "AES256")

    private fun generateHmacKey(keyId: String): String =
        generateKey(keyId, "hmac", "HMAC-SHA256")

    private fun generateKey(keyId: String, keyType: String, algorithm: String): String {
        createdKeyIds.add(keyId)
        val response = call(
            "local.generateKey",
            JSONObject()
                .put("keyId", keyId)
                .put("keyType", keyType)
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

    /**
     * Writes software key material plus its key-store row directly, which is
     * the only way to produce a SELECTED_PEERS key or an exportable/shareable
     * combination the wire protocol refuses to create.
     */
    private fun seedSoftwareKey(
        keyId: String,
        exportable: Boolean,
        shareable: Boolean,
        policy: SharingPolicyType,
        material: ByteArray
    ): String {
        createdKeyIds.add(keyId)
        softwareKeys.put(
            SoftwareKey(
                keyId = keyId,
                algorithm = "AES",
                keyType = "symmetric",
                keySize = material.size * 8,
                exportable = exportable,
                shareable = shareable,
                material = material
            )
        )
        val entity = KeyEntity(
            keyId = keyId,
            keyType = "secret",
            algorithm = "AES-256",
            label = keyId,
            keySizeBits = material.size * 8,
            exportable = exportable,
            shareable = shareable,
            sharingPolicy = policy,
            source = "test"
        )
        runBlocking { XKeyDatabase.getInstance(context).keyDao().insert(entity) }
        return keyId
    }

    private fun setSharingPolicy(keyId: String, peerHex: String) {
        val policy = KeySharingPolicy(keyId = keyId, peerPublicKeyHex = peerHex, allowed = true)
        runBlocking {
            XKeyDatabase.getInstance(context).keySharingPolicyDao().setPolicy(policy)
        }
    }

    private fun revokeSharingPolicy(keyId: String, peerHex: String) {
        runBlocking {
            XKeyDatabase.getInstance(context).keySharingPolicyDao().revokePolicy(keyId, peerHex)
        }
    }

    private fun requireAttestation(
        forKeyUse: Boolean,
        forKeyAttestation: Boolean,
        graceMinutes: Int
    ) {
        pairedDevices.updateDeviceSettings(
            publicKeyHex = peerKeyHex,
            requireAttestationForKeyUse = forKeyUse,
            requireAttestationForKeyAttestation = forKeyAttestation,
            attestationGracePeriodMinutes = graceMinutes
        )
    }

    /**
     * Re-creates the paired peer so it carries no attestation timestamp. The
     * repository has no API to clear one, and a test that asserts the
     * "never attested" branch must not depend on which tests ran before it.
     */
    private fun resetPeerToNeverAttested() {
        pairedDevices.removeDevice(peerKeyHex)
        pairedDevices.addDevice(peerKeyHex, peerName)
    }

    private fun recordAttestationNow() {
        pairedDevices.updateDeviceAttestation(
            publicKeyHex = peerKeyHex,
            bootHashHex = "00".repeat(32),
            securityLevel = "tee",
            bootStateVerified = true,
            deviceFingerprint = "test-fingerprint"
        )
    }

    private fun ephemeralPublicKeyDer(): ByteArray {
        val generator = KeyPairGenerator.getInstance("EC")
        generator.initialize(ECGenParameterSpec("secp256r1"))
        return generator.generateKeyPair().public.encoded
    }

    private fun pemPublicKey(): String {
        val body = Base64.getMimeEncoder(64, "\n".toByteArray())
            .encodeToString(ephemeralPublicKeyDer())
        return "-----BEGIN PUBLIC KEY-----\n" + body + "\n-----END PUBLIC KEY-----\n"
    }
}
