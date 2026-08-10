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
import org.json.JSONArray
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
 * Both handlers clean up their own ephemeral keystore entries, so this suite
 * leaves nothing behind; [tearDown] only sweeps the paired-peer row it adds.
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
     * Baseline: a confirmed peer that does not demand a prior device
     * attestation, and no user verification, so the handlers run headless.
     */
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

        val result = call(
            "local.attestDevice",
            JSONObject().put("nonce", b64(nonce))
        ).ok()

        assertEquals("android-keystore", result.getString("format"))
        assertEquals(b64(nonce), result.getString("nonce"))
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

    @Test
    fun attestDeviceBindsTheChallengeToTheLeafCertificate() {
        val nonce = randomNonce()

        val result = call(
            "local.attestDevice",
            JSONObject().put("nonce", b64(nonce))
        ).ok()

        val leaf = certificates(result.getJSONArray("certificateChain")).first()
        val extension = leaf.getExtensionValue(ATTESTATION_EXTENSION_OID)
        if (extension != null) {
            assertTrue(
                "the attestation extension must embed the challenge the peer sent",
                containsSubsequence(extension, nonce)
            )
        }
    }

    /**
     * Two device attestations must not be interchangeable, whatever the device
     * reports about itself.
     */
    @Test
    fun attestDeviceIsFreshForEveryChallenge() {
        val first = attestDeviceLeaf(randomNonce())
        val second = attestDeviceLeaf(randomNonce())

        assertNotEquals(
            Base64.getEncoder().encodeToString(first.encoded),
            Base64.getEncoder().encodeToString(second.encoded)
        )
    }

    @Test
    fun attestDeviceRequiresANonce() {
        assertEquals(ErrorCodes.INVALID_PARAMS, call("local.attestDevice").errorCode())
        assertEquals(
            ErrorCodes.INVALID_PARAMS,
            call("local.attestDevice", JSONObject()).errorCode()
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

        val response = call(
            "local.attestDevice",
            JSONObject().put("nonce", b64(randomNonce()))
        )

        assertTrue(
            "attestDevice must stay reachable for a peer that has never attested: " +
                response.toJsonString(),
            response.isSuccess()
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

    private fun attestDeviceLeaf(nonce: ByteArray): X509Certificate {
        val result = call(
            "local.attestDevice",
            JSONObject().put("nonce", b64(nonce))
        ).ok()
        return certificates(result.getJSONArray("certificateChain")).first()
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

    private fun b64(data: ByteArray): String = Base64.getEncoder().encodeToString(data)
}

/** Android Key Attestation extension OID, as parsed by `RequestHandler`. */
private const val ATTESTATION_EXTENSION_OID = "1.3.6.1.4.1.11129.2.1.17"
