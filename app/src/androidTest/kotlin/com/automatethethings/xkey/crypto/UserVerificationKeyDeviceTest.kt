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
package com.automatethethings.xkey.crypto

import android.content.Context
import android.os.Build
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import android.util.Log
import androidx.biometric.BiometricManager
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.automatethethings.xkey.ui.KeyDetailActivity
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeFalse
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.SignatureException
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey

/**
 * The production [KeystoreUserVerificationKey] against real Keystore hardware
 * (Codex review 7357 on PR #62).
 *
 * The JVM suites for `local.verifyUser` inject a software key and a
 * replacement prompt, so they stay green whatever the UVK's authorization
 * list says. The desktop's proof rests on exactly that list: a key that
 * cannot sign until a Class 3 biometric is presented for this one use. These
 * tests mint the real key -- [KeystoreUserVerificationKey], not a copy of its
 * spec -- and check what Keystore itself reports and attests about it, and
 * that it refuses to sign without a prompt.
 *
 * Keystore cannot mint a key bound to a biometric when none is enrolled, so
 * every test that needs the key is skipped on such a device, and
 * [withoutAClass3BiometricTheKeyIsRefusedAndNothingIsLeft] covers it instead.
 *
 * Each test mints under its own alias, never [KeystoreUserVerificationKey.ALIAS],
 * and deletes it in [tearDown]. Nothing here logs the chain, a signature or any
 * key material.
 *
 * Manual step, needs a person at the sensor: with a Class 3 biometric enrolled,
 * pair a desktop and run `local.verifyUser`; touching the sensor must return a
 * signature the desktop verifies, and cancelling the prompt must return the
 * user-cancelled error. An automated run cannot present a biometric.
 */
@RunWith(AndroidJUnit4::class)
class UserVerificationKeyDeviceTest {

    private lateinit var context: Context
    private lateinit var keyStore: KeyStore
    private val alias = "xkey_uvk_device_test_${System.nanoTime()}"

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    }

    @After
    fun tearDown() {
        if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
    }

    // ------------------------------------------------------- key properties

    /**
     * What Keystore reports about the minted key: bound to a strong biometric
     * for every single use, enforced in secure hardware, invalidated by a new
     * enrollment, an EC P-256 signing key.
     */
    @Test
    fun theKeyIsBoundToAStrongBiometricForEveryUse() {
        assumeStrongBiometricEnrolled()
        val chain = KeystoreUserVerificationKey(context, alias).chain()
        val info = keyInfo()

        assertTrue("the UVK must require user authentication", info.isUserAuthenticationRequired)
        assertTrue(
            "secure hardware, not the OS, must enforce the authentication requirement",
            info.isUserAuthenticationRequirementEnforcedBySecureHardware
        )
        assertTrue(
            "a new biometric enrollment must invalidate the UVK",
            info.isInvalidatedByBiometricEnrollment
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            assertEquals(
                "a timeout of 0 means one authentication per use",
                0,
                info.userAuthenticationValidityDurationSeconds
            )
        } else {
            assertTrue(
                "no authentication window: every use must be authenticated",
                info.userAuthenticationValidityDurationSeconds <= 0
            )
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            assertEquals(
                "only a Class 3 biometric may unlock the UVK, never a device credential",
                KeyProperties.AUTH_BIOMETRIC_STRONG,
                info.userAuthenticationType
            )
        }

        assertEquals(KeyProperties.PURPOSE_SIGN, info.purposes)
        assertEquals(256, info.keySize)
        assertTrue(info.digests.contains(KeyProperties.DIGEST_SHA256))
        val publicKey = chain.first().publicKey as ECPublicKey
        assertEquals(KeyProperties.KEY_ALGORITHM_EC, publicKey.algorithm)
        assertEquals("the UVK must be on P-256", P256_ORDER, publicKey.params.order)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            assertTrue(
                "the UVK must live in the TEE or StrongBox, got level ${info.securityLevel}",
                info.securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ||
                    info.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX
            )
        } else {
            @Suppress("DEPRECATION")
            assertTrue("the UVK must live in secure hardware", info.isInsideSecureHardware)
        }
    }

    /**
     * What the hardware attests, which is what the desktop actually checks:
     * the fixed challenge, and a hardware-enforced authorization list that
     * demands a biometric for every use. Read with the app's own attestation
     * parser.
     */
    @Test
    fun theAttestationCarriesTheChallengeAndTheBiometricAuthorization() {
        assumeStrongBiometricEnrolled()
        val leaf = KeystoreUserVerificationKey(context, alias).chain().first()
        val attestation = parseAttestation(leaf)

        assertArrayEquals(
            "the attestation challenge must be exactly the verify-user constant",
            "xkey-user-verification-v1".toByteArray(Charsets.US_ASCII),
            field(attestation, "challenge") as ByteArray?
        )
        assertFalse(
            "the hardware-enforced list must not carry noAuthRequired (503)",
            field(attestation, "noAuthRequired") as Boolean
        )
        // The parser names userAuthType (504) value 2, HardwareAuthenticatorType
        // FINGERPRINT -- the type every Class 3 biometric is attested as.
        assertEquals(
            "the hardware-enforced userAuthType (504) must be biometric (2)",
            "Fingerprint",
            field(attestation, "userAuthType")
        )
        val authTimeout = field(attestation, "authTimeout") as Int?
        assertTrue(
            "authTimeout (505) must be absent or 0, got $authTimeout",
            authTimeout == null || authTimeout == 0
        )
    }

    /** The chain is leaf first, each certificate signed by the next. */
    @Test
    fun theChainIsLeafFirstAndEachCertificateVerifiesUnderTheNext() {
        assumeStrongBiometricEnrolled()
        val chain = KeystoreUserVerificationKey(context, alias).chain()

        assertTrue("an attestation chain must reach past the leaf", chain.size >= 2)
        assertEquals(
            "the first certificate must be the UVK's own",
            keyStore.getCertificate(alias).publicKey,
            chain.first().publicKey
        )
        for (i in 0 until chain.size - 1) {
            try {
                chain[i].verify(chain[i + 1].publicKey)
            } catch (e: Exception) {
                fail("certificate $i does not verify under certificate ${i + 1}: ${e.javaClass.name}")
            }
        }
    }

    // ------------------------------------------- no signature without a finger

    /**
     * Driving the Keystore key directly, with no `BiometricPrompt`, Keystore
     * must refuse: [UserNotAuthenticatedException] at `initSign`, or a
     * [SignatureException] at `update` or `sign` (a per-use key begins its
     * operation and refuses when asked to process data).
     */
    @Test
    fun theKeystoreKeyRefusesToSignWithoutAuthentication() {
        assumeStrongBiometricEnrolled()
        KeystoreUserVerificationKey(context, alias).chain()
        val privateKey = keyStore.getKey(alias, null) as PrivateKey

        assertUnauthenticatedSignatureRefused {
            Signature.getInstance(SIGNATURE_ALGORITHM).apply { initSign(privateKey) }
        }
    }

    /**
     * The same refusal through [KeystoreUserVerificationKey.initSignature],
     * the signature the handler wraps in its `CryptoObject`: it is handed out
     * locked, and stays locked until the prompt succeeds.
     */
    @Test
    fun theSignatureTheHandlerPromptsWithIsLockedUntilAuthentication() {
        assumeStrongBiometricEnrolled()
        val uvk = KeystoreUserVerificationKey(context, alias)

        assertUnauthenticatedSignatureRefused { uvk.initSignature() }
    }

    // ------------------------------------------------------ no biometric

    /**
     * On a device with no Class 3 biometric the key cannot exist: the request
     * fails as a typed [BiometricUnavailableException] and leaves no alias.
     */
    @Test
    fun withoutAClass3BiometricTheKeyIsRefusedAndNothingIsLeft() {
        assumeFalse("a Class 3 biometric is enrolled", strongBiometricEnrolled())
        val uvk = KeystoreUserVerificationKey(context, alias)

        try {
            uvk.chain()
            fail("a UVK must not be minted without a Class 3 biometric")
        } catch (e: BiometricUnavailableException) {
            // expected
        }
        assertFalse(uvk.exists())
        assertFalse(keyStore.containsAlias(alias))
    }

    // ------------------------------------------------------------- helpers

    private fun keyInfo(): KeyInfo {
        val privateKey = keyStore.getKey(alias, null) as PrivateKey
        return KeyFactory.getInstance(privateKey.algorithm, ANDROID_KEYSTORE)
            .getKeySpec(privateKey, KeyInfo::class.java)
    }

    /**
     * Runs `initSign`, `update` and `sign` with no authentication and asserts
     * that one of them is refused for that reason. A signature is never
     * returned or printed: producing one is the failure.
     */
    private fun assertUnauthenticatedSignatureRefused(init: () -> Signature) {
        var step = "initSign"
        try {
            val signature = init()
            step = "update"
            signature.update(ByteArray(32))
            step = "sign"
            signature.sign()
        } catch (e: Exception) {
            Log.i(TAG, "unauthenticated $step refused with ${e.javaClass.name}")
            assertRefusedForWantOfAuthentication(step, e)
            return
        }
        fail("the UVK signed with no biometric authentication")
    }

    private fun assertRefusedForWantOfAuthentication(step: String, e: Exception) {
        when (step) {
            "initSign" -> {
                // initSignature wraps the platform's refusal in SigningException.
                val cause = if (e is SigningException) e.cause else e
                assertTrue(
                    "initSign must refuse with UserNotAuthenticatedException, got ${describe(e)}",
                    cause is UserNotAuthenticatedException
                )
            }
            else -> {
                assertTrue(
                    "$step must refuse with SignatureException or KeyStoreException, got ${describe(e)}",
                    e is SignatureException || e is java.security.KeyStoreException ||
                        e.javaClass.name == "android.security.KeyStoreException"
                )
                // From API 33 the Keystore cause says why; it must be the
                // missing authentication, not some other fault.
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    val keystoreCause = generateSequence(e as Throwable) { it.cause }
                        .filterIsInstance<android.security.KeyStoreException>()
                        .firstOrNull()
                    if (keystoreCause != null) {
                        assertEquals(
                            "Keystore must refuse for want of user authentication",
                            android.security.KeyStoreException.ERROR_USER_AUTHENTICATION_REQUIRED,
                            keystoreCause.numericErrorCode
                        )
                    }
                }
            }
        }
    }

    private fun describe(e: Throwable): String =
        generateSequence(e) { it.cause }.joinToString(" <- ") { it.javaClass.name }

    /**
     * The leaf's KeyDescription, read by `KeyDetailActivity`'s attestation
     * parser -- the app's only one that decodes the authorization list -- so
     * the test adds no ASN.1 parser of its own.
     */
    private fun parseAttestation(leaf: X509Certificate): Any {
        var activity: KeyDetailActivity? = null
        InstrumentationRegistry.getInstrumentation().runOnMainSync { activity = KeyDetailActivity() }
        val method = KeyDetailActivity::class.java.getDeclaredMethod(
            "parseAttestationExtension", X509Certificate::class.java
        )
        method.isAccessible = true
        val parsed = method.invoke(activity, leaf)
        assertNotNull("the UVK leaf must carry a parseable attestation extension", parsed)
        return parsed!!
    }

    private fun field(target: Any, name: String): Any? {
        val field = target.javaClass.getDeclaredField(name)
        field.isAccessible = true
        return field.get(target)
    }

    private fun assumeStrongBiometricEnrolled() {
        assumeTrue(
            "Keystore cannot mint a biometric-bound key without an enrolled Class 3 biometric",
            strongBiometricEnrolled()
        )
    }

    private fun strongBiometricEnrolled(): Boolean =
        BiometricManager.from(context)
            .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
            BiometricManager.BIOMETRIC_SUCCESS

    private companion object {
        const val TAG = "UvkDeviceTest"
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val SIGNATURE_ALGORITHM = "SHA256withECDSA"

        /** The order of the NIST P-256 group. */
        val P256_ORDER = BigInteger(
            "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16
        )
    }
}
