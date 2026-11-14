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
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import org.junit.AfterClass
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayInputStream
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.concurrent.atomic.AtomicLong

/**
 * Android Key Attestation over the wire: `local.attestKey` and
 * `local.attestDevice`.
 *
 * These are the two methods that let go-xkms decide whether to trust the phone
 * at all — the desktop sends a challenge, the phone answers with a Keystore
 * certificate chain, and `pkg/backend/phone/android/verifier.go` checks the
 * chain and the RootOfTrust it carries. Nothing exercised them before: the
 * `local.*` suites stop at the device-attestation gate and never reach the
 * attestation itself, so the whole extension parser
 * (`parseAttestationExtension`, `parseRootOfTrust`, `tryParseRootOfTrust` and
 * the DER readers under them) ran untested.
 *
 * What is asserted is what a verifier actually depends on: the chain parses as
 * X.509, the challenge the desktop sent is bound into the leaf, the nonce is
 * echoed unchanged, and the reported security level and RootOfTrust fields are
 * values a peer can act on. The concrete values (`tee` vs `strongbox`, locked
 * vs unlocked) are properties of the device the suite runs on and are checked
 * for validity, not for a particular answer.
 *
 * `local.attestKey` cleans up its own ephemeral keystore entry. `local.attestDevice`
 * does not, and must not: since go-xkms#129 it answers with this install's
 * **persistent** Device Attestation Key, whose whole purpose is to outlive the
 * exchange. Reusing it across runs is the behaviour under test in
 * [attestDeviceKeepsTheSameAttestedKeyAcrossChallenges], so [tearDown] sweeps
 * only the paired-peer row this suite adds.
 */
@RunWith(AndroidJUnit4::class)
class RequestHandlerAttestationTest {

    companion object {
        private lateinit var context: Context
        private lateinit var handler: RequestHandler
        private lateinit var pairedDevices: PairedDeviceRepository

        /** Unique per run so nothing collides with a previous run's leftovers. */
        private val runId = System.currentTimeMillis().toString(36)

        /** The peer identity this suite pairs with: 32 bytes of hex, unique per run. */
        private val peerKeyHex =
            ("fd" + java.lang.Long.toHexString(System.nanoTime())).padEnd(64, '0')

        private val peerName = "AttestationTest Desktop $runId"

        private val nextRequestId = AtomicLong(1)

        /** The security levels the Keystore attestation extension can report. */
        private val securityLevels = setOf("software", "tee", "strongbox")

        /**
         * A stand-in for the live Noise session. The real transports supply the
         * peer's and this device's static keys and the handshake prologue; the
         * values only have to be well-formed and stable, because what is under
         * test is that the handler binds to *its own* session rather than to
         * anything the request carries.
         */
        private val initiatorStatic = ByteArray(32) { (0xa0 + it).toByte() }
        private val responderStatic = ByteArray(32) { (0x50 + it).toByte() }
        private val sessionPrologue = ByteArray(32) { (0x10 + it).toByte() }

        /** What the handler must derive, computed independently of the handler. */
        private val sessionChannelBinding: ByteArray by lazy {
            AttestTranscript.channelBinding(initiatorStatic, responderStatic, sessionPrologue)
        }

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
            pairedDevices.removeDevice(peerKeyHex)
        }
    }

    /**
     * The binding of the connection every request here arrives on, as the
     * transport installs it per connection.
     */
    private lateinit var connectionBinding: SessionBindingProvider

    /** The authenticated peer of that connection. */
    private var servedPeer: String? = null

    /**
     * Baseline: a confirmed peer that does not demand a prior device
     * attestation, and no user verification, so the handlers run headless.
     */
    @Before
    fun resetHandlerState() {
        connectPeer(peerKeyHex)
        connectionBinding = SessionBindingProvider {
            SessionBinding(initiatorStatic, responderStatic, sessionPrologue)
        }
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
    // local.attestKey
    // ------------------------------------------------------------------

    @Test
    fun attestKeyReturnsAParseableCertificateChain() {
        val nonce = randomNonce()

        val result = call(
            "local.attestKey",
            JSONObject().put("keyId", "attest-$runId").put("nonce", b64(nonce))
        ).ok()

        val chain = certificates(result.getJSONArray("certificateChain"))
        assertTrue("an attestation must carry at least a leaf certificate", chain.isNotEmpty())
        assertTrue(
            "securityLevel must be one of $securityLevels, got ${result.getString("securityLevel")}",
            securityLevels.contains(result.getString("securityLevel"))
        )
        assertEquals(
            "the challenge nonce must be echoed unchanged",
            b64(nonce),
            result.getString("nonce")
        )
    }

    /**
     * The whole point of the challenge: a verifier has to be able to tell a
     * fresh attestation from a replayed one. Either the challenge is bound
     * into the leaf certificate's attestation extension, or the device does
     * not produce that extension at all — but the same chain must never come
     * back for two different challenges.
     */
    @Test
    fun attestKeyBindsTheChallengeToTheLeafCertificate() {
        val first = randomNonce()
        val second = randomNonce()

        val firstLeaf = attestKeyLeaf(first)
        val secondLeaf = attestKeyLeaf(second)

        assertNotEquals(
            "two challenges must not produce the same attestation",
            Base64.getEncoder().encodeToString(firstLeaf.encoded),
            Base64.getEncoder().encodeToString(secondLeaf.encoded)
        )

        val extension = firstLeaf.getExtensionValue(ATTESTATION_EXTENSION_OID)
        if (extension != null) {
            assertTrue(
                "the attestation extension must embed the challenge the peer sent",
                containsSubsequence(extension, first)
            )
            assertFalse(
                "the challenge must not be the one from another request",
                containsSubsequence(extension, second)
            )
        }
    }

    @Test
    fun attestKeyRequiresBothOfItsParameters() {
        assertEquals(ErrorCodes.INVALID_PARAMS, call("local.attestKey").errorCode())
        assertEquals(
            ErrorCodes.INVALID_PARAMS,
            call("local.attestKey", JSONObject().put("keyId", "attest-$runId")).errorCode()
        )
        assertEquals(
            ErrorCodes.INVALID_PARAMS,
            call("local.attestKey", JSONObject().put("nonce", b64(randomNonce()))).errorCode()
        )
    }

    /**
     * The gate is checked before the parameters are read, so a peer that has
     * not attested recently enough is refused without the handler doing any
     * key work at all.
     */
    @Test
    fun attestKeyIsGatedBeforeItsParametersAreRead() {
        pairedDevices.removeDevice(peerKeyHex)
        pairedDevices.addDevice(peerKeyHex, peerName)
        pairedDevices.updateDeviceSettings(
            publicKeyHex = peerKeyHex,
            requireAttestationForKeyUse = false,
            requireAttestationForKeyAttestation = true,
            attestationGracePeriodMinutes = 60
        )

        assertEquals(
            ErrorCodes.DEVICE_ATTESTATION_REQUIRED,
            call("local.attestKey").errorCode()
        )
    }

    // ------------------------------------------------------------------
    // local.attestDevice
    // ------------------------------------------------------------------

    @Test
    fun attestDeviceReportsTheAndroidKeystoreRootOfTrust() {
        val nonce = randomNonce()

        val result = attestDevice(nonce, AttestTranscript.PURPOSE_PAIR).ok()

        assertEquals(2, result.getInt("protocolVersion"))
        assertEquals("android-keystore", result.getString("format"))
        assertEquals(b64(nonce), result.getString("nonce"))
        assertEquals(AttestTranscript.PURPOSE_PAIR, result.getString("purpose"))
        assertEquals("ES256", result.getString("signatureAlgorithm"))
        assertTrue(
            "securityLevel must be one of $securityLevels, got ${result.getString("securityLevel")}",
            securityLevels.contains(result.getString("securityLevel"))
        )

        val chain = certificates(result.getJSONArray("certificateChain"))
        assertTrue("a device attestation must carry a chain", chain.isNotEmpty())

        // RootOfTrust: bootState is the verifiedBootState enumeration
        // (0=VERIFIED, 1=SELF_SIGNED, 2=UNVERIFIED, 3=FAILED) and the two boot
        // measurements are base64, possibly empty when the device does not
        // publish them.
        // `getInt`/`getBoolean`/`decode` each raise on the wrong shape, so
        // reading the fields is itself the assertion that they are usable.
        val bootState = result.getInt("bootState")
        assertTrue("bootState $bootState is outside the RootOfTrust enumeration", bootState in 0..3)
        result.getBoolean("deviceLocked")
        // Both boot measurements may legitimately be empty: the parser falls
        // back to an empty RootOfTrust when the device publishes no
        // attestation extension. They must still be base64 either way.
        Base64.getDecoder().decode(result.getString("verifiedBootKey"))
        Base64.getDecoder().decode(result.getString("verifiedBootHash"))
    }

    /**
     * The leaf carries the Device Attestation Key's **genesis** challenge, never
     * the live nonce.
     *
     * This is the inversion of the version 1 contract, and the whole reason the
     * owner changed the model: Keystore seals the attestation challenge at key
     * generation, so a leaf that embedded the pairing nonce could only ever
     * belong to a key minted for that pairing. The desktop verifier leaves its
     * `ExpectedNonce` unset for exactly this reason and checks the genesis prefix
     * instead.
     */
    @Test
    fun attestDeviceLeafCarriesTheGenesisChallengeAndNotTheNonce() {
        val nonce = randomNonce()

        val leaf = attestDevice(nonce, AttestTranscript.PURPOSE_PAIR).leaf()

        val extension = leaf.getExtensionValue(ATTESTATION_EXTENSION_OID)
        if (extension != null) {
            assertTrue(
                "the leaf must embed the genesis challenge",
                containsSubsequence(extension, AttestTranscript.GENESIS_CHALLENGE)
            )
            assertFalse(
                "the leaf must NOT embed the live nonce; that model is dead",
                containsSubsequence(extension, nonce)
            )
        }
    }

    /**
     * Identity is stable. Two challenges must return the *same* attested key —
     * this is what makes the SPKI usable as a device fingerprint at all, and it
     * is precisely what version 1 could not do.
     */
    @Test
    fun attestDeviceKeepsTheSameAttestedKeyAcrossChallenges() {
        val first = attestDevice(randomNonce(), AttestTranscript.PURPOSE_PAIR).leaf()
        val second = attestDevice(randomNonce(), AttestTranscript.PURPOSE_REATTEST).leaf()

        assertEquals(
            "the device attestation key must persist across exchanges",
            AttestedKeyFingerprint.hexOf(first.encoded),
            AttestedKeyFingerprint.hexOf(second.encoded)
        )
    }

    /**
     * The core prover check: this replays the desktop verifier's final step
     * (go-xkms#129 §6.7) against a real hardware-backed key — rebuild the
     * transcript from what *the verifier asked for* plus the fingerprint the
     * verifier derives, and check the signature under the leaf's public key.
     */
    @Test
    fun attestDeviceSignatureVerifiesOverTheTranscriptTheVerifierRebuilds() {
        val nonce = randomNonce()

        val result = attestDevice(nonce, AttestTranscript.PURPOSE_REATTEST).ok()
        val leaf = certificates(result.getJSONArray("certificateChain")).first()

        assertTrue(
            "the signature must verify over the rebuilt transcript",
            verifyTranscript(leaf, result, nonce, AttestTranscript.PURPOSE_REATTEST, sessionChannelBinding)
        )
    }

    /**
     * A signature gathered while pairing must not satisfy a reconnect. The
     * purpose is inside the signed bytes, so swapping it has to break
     * verification — otherwise an attacker who watched a pairing could answer a
     * reconnect challenge with it.
     */
    @Test
    fun attestDeviceSignatureIsBoundToItsPurpose() {
        val nonce = randomNonce()

        val result = attestDevice(nonce, AttestTranscript.PURPOSE_PAIR).ok()
        val leaf = certificates(result.getJSONArray("certificateChain")).first()

        assertTrue(
            verifyTranscript(leaf, result, nonce, AttestTranscript.PURPOSE_PAIR, sessionChannelBinding)
        )
        assertFalse(
            "a 'pair' signature must not verify as a 'reattest'",
            verifyTranscript(leaf, result, nonce, AttestTranscript.PURPOSE_REATTEST, sessionChannelBinding)
        )
    }

    // An `attestDeviceDoesNotSignTheChannelBindingThePeerSent` test stood here
    // until the go-xkms#129 addendum removed `channelBinding` from the request.
    // It sent a relayed binding and asserted the signature did not verify under
    // it. With no such field there is nothing to relay and nothing to echo, so
    // the behaviour it guarded is now unreachable rather than merely forbidden
    // — a regression path that cannot be expressed needs no test. Deleted
    // rather than adapted, on purpose: the alternative is a test that pretends
    // to check a property the wire no longer permits anyone to violate.
    //
    // What still protects the derivation: the pinned vectors and the role-swap
    // assertion in AttestTranscriptTest, and
    // attestDeviceSignatureVerifiesOverTheTranscriptTheVerifierRebuilds below,
    // which catches a WRONG derivation because the expected binding is computed
    // here independently of the handler.

    /**
     * With no session there is no channel to bind to, and a transcript that
     * commits to no channel is one the desktop can only reject. Refusing says
     * why, instead of returning a well-formed signature that fails verification
     * for reasons neither side can see.
     */
    @Test
    fun attestDeviceRefusesWhenThereIsNoSessionToBindTo() {
        connectionBinding = SessionBindingProvider { null }

        assertEquals(
            ErrorCodes.ATTESTATION_FAILED,
            attestDevice(randomNonce(), AttestTranscript.PURPOSE_PAIR).errorCode()
        )
    }

    /** Version 1 is gone, and asking for it must not quietly get it. */
    @Test
    fun attestDeviceRefusesAVersion1Request() {
        val params = JSONObject()
            .put("protocolVersion", 1)
            .put("nonce", b64(randomNonce()))
            .put("purpose", AttestTranscript.PURPOSE_PAIR)

        assertEquals(
            ErrorCodes.ATTEST_PROTOCOL_DOWNGRADE,
            call("local.attestDevice", params).errorCode()
        )
    }

    @Test
    fun attestDeviceRequiresItsParameters() {
        assertEquals(
            "a request with no params at all is malformed, not a downgrade",
            ErrorCodes.INVALID_PARAMS,
            call("local.attestDevice").errorCode()
        )
        assertEquals(
            "params that name no version are a version 1 caller",
            ErrorCodes.ATTEST_PROTOCOL_DOWNGRADE,
            call("local.attestDevice", JSONObject()).errorCode()
        )
        assertEquals(
            "a version 2 request still needs a purpose",
            ErrorCodes.INVALID_PARAMS,
            call(
                "local.attestDevice",
                JSONObject().put("protocolVersion", 2).put("nonce", b64(randomNonce()))
            ).errorCode()
        )
        assertEquals(
            "a version 2 request still needs a nonce",
            ErrorCodes.INVALID_PARAMS,
            call(
                "local.attestDevice",
                JSONObject().put("protocolVersion", 2).put("purpose", AttestTranscript.PURPOSE_PAIR)
            ).errorCode()
        )
    }

    /**
     * Device attestation is deliberately not behind the device-attestation
     * gate: it is how a peer satisfies that gate in the first place, so
     * gating it would deadlock the pairing flow.
     */
    @Test
    fun attestDeviceIsNotGatedByThePriorAttestationRequirement() {
        pairedDevices.removeDevice(peerKeyHex)
        pairedDevices.addDevice(peerKeyHex, peerName)
        pairedDevices.updateDeviceSettings(
            publicKeyHex = peerKeyHex,
            requireAttestationForKeyUse = true,
            requireAttestationForKeyAttestation = true,
            attestationGracePeriodMinutes = 60
        )

        val response = attestDevice(randomNonce(), AttestTranscript.PURPOSE_PAIR)

        assertTrue(
            "attestDevice must stay reachable for a peer that has never attested: " +
                response.toJsonString(),
            response.isSuccess()
        )
    }

    /**
     * The reconnect capture: at `xkey device pair` the phone must record
     * SHA-256 of its own attested leaf's SubjectPublicKeyInfo — the exact value
     * the desktop stores and byte-compares on reconnect, and the value the
     * identity ack echoes to rebuild the Noise prologue.
     */
    @Test
    fun attestDeviceBindsTheAttestedKeyFingerprintWhenPairing() {
        // Start from a clean binding so the assertion is about THIS attestation.
        pairedDevices.removeDevice(peerKeyHex)
        pairedDevices.addDevice(peerKeyHex, peerName)
        connectPeer(peerKeyHex)
        assertNull(
            "precondition: a freshly paired device carries no fingerprint yet",
            pairedDevices.getDevice(peerKeyHex)?.deviceFingerprint
        )

        val leaf = attestDevice(randomNonce(), AttestTranscript.PURPOSE_PAIR).leaf()

        val stored = pairedDevices.getDevice(peerKeyHex)?.deviceFingerprint
        assertNotNull("attesting a known, connected peer must bind a fingerprint", stored)
        assertEquals(
            "the bound value must be SHA-256 of the attested leaf SPKI",
            AttestedKeyFingerprint.hexOf(leaf.encoded),
            stored
        )
    }

    /**
     * A reconnect never rewrites the stored fingerprint.
     *
     * On `reattest` the desktop is checking that the attested key is still the
     * one it recorded. Rebinding here would be a silent rebind to whatever key
     * answered — exactly the case `ErrDeviceIdentityChanged` exists to fail
     * closed on. A rotated key is meant to cost a re-pair.
     */
    @Test
    fun attestDeviceDoesNotRebindTheFingerprintOnReattest() {
        pairedDevices.removeDevice(peerKeyHex)
        pairedDevices.addDevice(peerKeyHex, peerName)
        connectPeer(peerKeyHex)
        val stale = "ff".repeat(32)
        pairedDevices.updateDeviceFingerprint(peerKeyHex, stale)

        attestDevice(randomNonce(), AttestTranscript.PURPOSE_REATTEST).ok()

        assertEquals(
            "a reattest must leave the recorded identity alone",
            stale,
            pairedDevices.getDevice(peerKeyHex)?.deviceFingerprint
        )
    }

    /**
     * The binding is only written for the peer the handshake authenticated: an
     * attestation with no connected peer identity must not guess which record
     * to touch.
     */
    @Test
    fun attestDeviceWithoutAConnectedPeerBindsNothing() {
        pairedDevices.removeDevice(peerKeyHex)
        pairedDevices.addDevice(peerKeyHex, peerName)
        connectPeer(null)

        attestDevice(randomNonce(), AttestTranscript.PURPOSE_PAIR).ok()

        assertNull(
            "no connected peer means no fingerprint may be bound",
            pairedDevices.getDevice(peerKeyHex)?.deviceFingerprint
        )
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private fun attestKeyLeaf(nonce: ByteArray): X509Certificate {
        val result = call(
            "local.attestKey",
            JSONObject().put("keyId", "attest-$runId").put("nonce", b64(nonce))
        ).ok()
        return certificates(result.getJSONArray("certificateChain")).first()
    }

    /**
     * Sends a protocol version 2 `local.attestDevice` request.
     *
     * Three fields, and no channel binding: the phone derives that from its own
     * session and the request has no way to suggest one.
     */
    private fun attestDevice(
        nonce: ByteArray,
        purpose: String,
    ): Response = call(
        "local.attestDevice",
        JSONObject()
            .put("protocolVersion", AttestTranscript.PROTOCOL_VERSION)
            .put("nonce", b64(nonce))
            .put("purpose", purpose)
    )

    private fun Response.leaf(): X509Certificate =
        certificates(ok().getJSONArray("certificateChain")).first()

    /**
     * Verifies the response's signature the way the desktop does: rebuild the
     * transcript from the values the verifier holds, then check it under the
     * leaf's public key.
     */
    private fun verifyTranscript(
        leaf: X509Certificate,
        result: JSONObject,
        nonce: ByteArray,
        purpose: String,
        channelBinding: ByteArray,
    ): Boolean {
        val transcript = AttestTranscript.build(
            purpose = purpose,
            nonce = nonce,
            channelBinding = channelBinding,
            deviceFingerprint = AttestedKeyFingerprint.of(leaf.encoded)
        )
        return java.security.Signature.getInstance("SHA256withECDSA").run {
            initVerify(leaf.publicKey)
            update(transcript)
            verify(Base64.getDecoder().decode(result.getString("signature")))
        }
    }

    /** Decodes the wire chain, which is what the go-xkms verifier has to do. */
    private fun certificates(chain: JSONArray): List<X509Certificate> {
        val factory = CertificateFactory.getInstance("X.509")
        return (0 until chain.length()).map { index ->
            val der = Base64.getDecoder().decode(chain.getString(index))
            factory.generateCertificate(ByteArrayInputStream(der)) as X509Certificate
        }
    }

    /** True when [needle] appears anywhere inside [haystack]. */
    private fun containsSubsequence(haystack: ByteArray, needle: ByteArray): Boolean {
        if (needle.isEmpty() || needle.size > haystack.size) return false
        outer@ for (start in 0..(haystack.size - needle.size)) {
            for (offset in needle.indices) {
                if (haystack[start + offset] != needle[offset]) continue@outer
            }
            return true
        }
        return false
    }

    private fun randomNonce(): ByteArray {
        val nonce = ByteArray(32)
        SecureRandom().nextBytes(nonce)
        return nonce
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
        return runBlocking {
            withContext(RequestHandler.servedConnection(connectionBinding, servedPeer, "test:connection")) {
                handler.handleRequest(request)
            }
        }
    }

    /** The desktop this phone serves: the requests' connection, and the handler's served peer. */
    private fun connectPeer(publicKeyHex: String?) {
        servedPeer = publicKeyHex
        handler.setConnectedDevicePublicKeyHex(publicKeyHex)
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

    private fun b64(data: ByteArray): String = Base64.getEncoder().encodeToString(data)
}

/** Android Key Attestation extension OID, as parsed by `RequestHandler`. */
private const val ATTESTATION_EXTENSION_OID = "1.3.6.1.4.1.11129.2.1.17"
