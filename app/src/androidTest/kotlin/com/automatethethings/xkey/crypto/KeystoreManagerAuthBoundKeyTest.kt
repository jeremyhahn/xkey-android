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
import androidx.biometric.BiometricManager
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.ui.MainActivity
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicReference

/**
 * [KeystoreManager] paths that only run when a key is bound to user
 * authentication, or when an operation is asked for something the key cannot
 * do.
 *
 * Every existing suite generates keys with `authDurationSeconds = -1` or
 * `requireBiometric = false`, because that is the only shape that can be used
 * afterwards without a finger on a sensor. The consequence is that the
 * authentication-policy arms of `generateKey`,
 * `generateKeyWithAuthDuration` and `applyAuthDuration` -- the arms that
 * decide whether a passkey is per-operation or time-windowed -- have never
 * been executed, and neither have the typed-failure paths that the protocol
 * layer's error codes depend on.
 *
 * An auth-bound key cannot be *used* here, but it can be *asked for*, and what
 * happens then is exactly what matters: on a device with no enrolled
 * authenticator the request must fail as a typed [KeyGenerationException] and
 * leave nothing behind, rather than surface a raw provider exception or a
 * half-made key. On a device that does have one the key must be created. The
 * suite decides which of the two it is from [BiometricManager], so it is
 * deterministic on either kind of device.
 *
 * Every alias is per-run and removed in [tearDown].
 */
@RunWith(AndroidJUnit4::class)
class KeystoreManagerAuthBoundKeyTest {

    private lateinit var context: Context
    private lateinit var keystoreManager: KeystoreManager

    private val credentialIds = mutableListOf<String>()
    private val generalKeyIds = mutableListOf<String>()

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        keystoreManager = KeystoreManager(context)
    }

    @After
    fun tearDown() {
        val dao = XKeyDatabase.getInstance(context).auditLogDao()
        (credentialIds + generalKeyIds).forEach { keyId ->
            runCatching { keystoreManager.deleteKey(keyId) }
            runCatching { keystoreManager.deleteGeneralKey(keyId) }
            runCatching { runBlocking { dao.deleteByKeyId(keyId) } }
        }
        credentialIds.clear()
        generalKeyIds.clear()
    }

    // ------------------------------------------------------ auth-bound keys

    /**
     * The FIDO2 path with `requireBiometric = true`, which is what a real
     * passkey registration asks for.
     */
    @Test
    fun aBiometricBoundCredentialIsEitherCreatedOrRefusedCleanly() {
        val credentialId = newCredentialId("biometric-bound")

        if (strongBiometricEnrolled()) {
            val cose = runBlocking { keystoreManager.generateKey(credentialId, requireBiometric = true) }
            assertTrue("a biometric-bound credential still exports a COSE key", cose.isNotEmpty())
            assertTrue(keystoreManager.keyExists(credentialId))
            return
        }

        val failure = failureFrom {
            runBlocking { keystoreManager.generateKey(credentialId, requireBiometric = true) }
        }
        assertTrue(
            "a device with nothing enrolled must refuse with a typed failure, got $failure",
            failure is KeyGenerationException
        )
        assertFalse(
            "a refused generation must not leave a half-made key behind",
            keystoreManager.keyExists(credentialId)
        )
    }

    /**
     * `authDurationSeconds = 0` is the PER_OPERATION policy: authentication is
     * required for every single use.
     */
    @Test
    fun aPerOperationCredentialIsEitherCreatedOrRefusedCleanly() {
        assertAuthDurationBehaviour(newCredentialId("per-operation"), authDurationSeconds = 0)
    }

    /**
     * A positive duration is the TIME_WINDOW policy: authentication stays
     * valid for N seconds. It is a different arm of the same `when`.
     */
    @Test
    fun aTimeWindowedCredentialIsEitherCreatedOrRefusedCleanly() {
        assertAuthDurationBehaviour(newCredentialId("time-window"), authDurationSeconds = 300)
    }

    /**
     * The general-key path reaches the policy through `applyAuthDuration`
     * rather than inline, so it is a separate arm again.
     */
    @Test
    fun aGeneralKeyBoundToAuthenticationIsEitherCreatedOrRefusedCleanly() {
        val keyId = newGeneralKeyId("auth-bound-ec")

        if (anyAuthenticatorEnrolled()) {
            val der = runBlocking {
                keystoreManager.generateKeyForAlgorithm(keyId, "ES256", 0, false)
            }
            assertTrue(der.isNotEmpty())
            return
        }

        val failure = failureFrom {
            runBlocking { keystoreManager.generateKeyForAlgorithm(keyId, "ES256", 0, false) }
        }
        assertTrue(
            "expected a typed key-generation failure, got $failure",
            failure is KeyGenerationException
        )
        assertFalse(keystoreManager.generalKeyExists(keyId))
    }

    @Test
    fun aTimeWindowedGeneralKeyTakesTheSamePolicyPath() {
        val keyId = newGeneralKeyId("windowed-ec")

        if (anyAuthenticatorEnrolled()) {
            assertTrue(
                runBlocking {
                    keystoreManager.generateKeyForAlgorithm(keyId, "ES256", 120, false)
                }.isNotEmpty()
            )
            return
        }

        val failure = failureFrom {
            runBlocking { keystoreManager.generateKeyForAlgorithm(keyId, "ES256", 120, false) }
        }
        assertTrue(
            "expected a typed key-generation failure, got $failure",
            failure is KeyGenerationException
        )
    }

    @Test
    fun anAuthBoundSymmetricKeyIsEitherCreatedOrRefusedCleanly() {
        val keyId = newGeneralKeyId("auth-bound-aes")

        if (anyAuthenticatorEnrolled()) {
            runBlocking { keystoreManager.generateSymmetricKey(keyId, 256, 0) }
            assertTrue(keystoreManager.generalKeyExists(keyId))
            return
        }

        val failure = failureFrom {
            runBlocking { keystoreManager.generateSymmetricKey(keyId, 256, 0) }
        }
        assertTrue(
            "expected a typed key-generation failure, got $failure",
            failure is KeyGenerationException
        )
        assertFalse(keystoreManager.generalKeyExists(keyId))
    }

    // -------------------------------------------- algorithm-name rejections

    /**
     * The `ES`/`RS` prefix decides which generator runs, but the suffix has to
     * name a curve or a key size. A prefix-valid, suffix-nonsense name must be
     * refused by the curve/size lookup rather than produce a key on some
     * arbitrary default.
     */
    @Test
    fun anEcAlgorithmWithNoSuchCurveIsRefused() {
        val keyId = newGeneralKeyId("es999")
        val failure = failureFrom {
            runBlocking { keystoreManager.generateKeyForAlgorithm(keyId, "ES999", -1, false) }
        }
        assertTrue(
            "expected a typed key-generation failure, got $failure",
            failure is KeyGenerationException
        )
        assertTrue(
            "the failure should name the algorithm it could not resolve",
            failure!!.message!!.contains("ES999")
        )
        assertFalse(keystoreManager.generalKeyExists(keyId))
    }

    @Test
    fun anRsaAlgorithmWithNoSuchKeySizeIsRefused() {
        val keyId = newGeneralKeyId("rs999")
        val failure = failureFrom {
            runBlocking { keystoreManager.generateKeyForAlgorithm(keyId, "RS999", -1, false) }
        }
        assertTrue(
            "expected a typed key-generation failure, got $failure",
            failure is KeyGenerationException
        )
        assertTrue(failure!!.message!!.contains("RS999"))
        assertFalse(keystoreManager.generalKeyExists(keyId))
    }

    // ------------------------------------------- operations a key cannot do

    /**
     * A COSE_Key is an EC2 structure; there is no COSE encoding here for an
     * RSA key, so asking for one must fail rather than emit something a
     * relying party would reject.
     */
    @Test
    fun anRsaKeyCannotBeExportedAsACoseKey() {
        val keyId = newGeneralKeyId("rsa-cose")
        runBlocking { keystoreManager.generateKeyForAlgorithm(keyId, "RS256", -1, false) }

        val failure = failureFrom { keystoreManager.getCOSEPublicKey(keyId) }
        assertTrue(
            "expected a typed failure for a non-EC key, got $failure",
            failure is KeyGenerationException
        )
    }

    /**
     * A symmetric key has no certificate, so every public-key export must
     * report "nothing to export" rather than throw.
     */
    @Test
    fun aSymmetricKeyHasNoPublicKeyToExportInAnyFormat() {
        val keyId = newGeneralKeyId("aes-export")
        runBlocking { keystoreManager.generateSymmetricKey(keyId, 256, -1) }

        assertNull("no DER", keystoreManager.getPublicKeyDER(keyId))
        assertNull("no PEM", keystoreManager.getPublicKeyPEM(keyId))
        assertNull("no OpenSSH form", keystoreManager.getPublicKeySSH(keyId))
        assertNull("no COSE form", keystoreManager.getCOSEPublicKey(keyId))
        assertNull("no public key object", keystoreManager.getPublicKey(keyId))
    }

    /**
     * The alias resolves, but the entry is a secret key rather than a private
     * key: signing has to report the identifier as unusable rather than cast
     * its way into a ClassCastException.
     */
    @Test
    fun signingWithASymmetricKeyReportsItAsNotFound() {
        val keyId = newGeneralKeyId("aes-sign")
        runBlocking { keystoreManager.generateSymmetricKey(keyId, 256, -1) }

        val failure = failureFrom {
            runBlocking { keystoreManager.signWithoutBiometric(keyId, ByteArray(32)) }
        }
        assertTrue(
            "expected KeyNotFoundException, got $failure",
            failure is KeyNotFoundException
        )
    }

    /**
     * `signWithoutBiometric` hardcodes ECDSA, so an RSA key reaches the
     * provider and is rejected there. That has to surface as a
     * [SigningException], because the protocol layer maps it to
     * SIGNING_FAILED.
     */
    @Test
    fun signingAnRsaKeyOnTheEcdsaPathIsATypedSigningFailure() {
        val keyId = newGeneralKeyId("rsa-ecdsa-path")
        runBlocking { keystoreManager.generateKeyForAlgorithm(keyId, "RS256", -1, false) }

        val failure = failureFrom {
            runBlocking { keystoreManager.signWithoutBiometric(keyId, randomBytes(32)) }
        }
        assertTrue(
            "expected SigningException, got $failure",
            failure is SigningException
        )
    }

    // ------------------------------------------------ prompt-bound refusals

    /**
     * [KeystoreManager.sign] takes a prompt helper, but it resolves the key
     * before it ever thinks about prompting. An unknown identifier fails with
     * no UI at all, which is the only part of the prompt-bound entry point an
     * automated run can reach -- and the part that must not hang a caller
     * waiting on a prompt that will never appear.
     */
    @Test
    fun thePromptBoundSignatureResolvesTheKeyBeforePrompting() {
        val helper = promptHelper()
        val unknown = "no-such-key-${System.nanoTime()}"

        val failure = failureFrom {
            runBlocking { keystoreManager.sign(unknown, ByteArray(32), helper, "t", "s") }
        }
        assertTrue("expected KeyNotFoundException, got $failure", failure is KeyNotFoundException)
        assertNull(keystoreManager.resolveKeystoreAlias(unknown))
    }

    /**
     * The same entry point, with an alias that resolves to something that
     * cannot sign: still no prompt, still a typed refusal.
     */
    @Test
    fun thePromptBoundSignatureRefusesAnEntryThatIsNotAPrivateKey() {
        val helper = promptHelper()
        val keyId = newGeneralKeyId("aes-prompt-sign")
        runBlocking { keystoreManager.generateSymmetricKey(keyId, 256, -1) }

        val failure = failureFrom {
            runBlocking { keystoreManager.sign(keyId, ByteArray(32), helper, "t", "s") }
        }
        assertTrue("expected KeyNotFoundException, got $failure", failure is KeyNotFoundException)
    }

    // ------------------------------------------------------------- helpers

    /**
     * Asserts the shared outcome of an auth-bound credential request: created
     * on a device that can verify a user, refused cleanly on one that cannot.
     */
    private fun assertAuthDurationBehaviour(credentialId: String, authDurationSeconds: Int) {
        if (anyAuthenticatorEnrolled()) {
            val cose = runBlocking {
                keystoreManager.generateKeyWithAuthDuration(credentialId, authDurationSeconds, false)
            }
            assertTrue(cose.isNotEmpty())
            assertTrue(keystoreManager.keyExists(credentialId))
            return
        }

        val failure = failureFrom {
            runBlocking {
                keystoreManager.generateKeyWithAuthDuration(credentialId, authDurationSeconds, false)
            }
        }
        assertTrue(
            "expected a typed key-generation failure, got $failure",
            failure is KeyGenerationException
        )
        assertFalse(
            "a refused generation must not leave a half-made key behind",
            keystoreManager.keyExists(credentialId)
        )
        assertTrue(
            "the failure must say which operation failed",
            failure!!.message!!.contains("auth duration")
        )
    }

    /**
     * A [BiometricHelper] bound to a real activity, for the entry points that
     * take one. Nothing here ever reaches the prompt itself.
     */
    private fun promptHelper(): BiometricHelper {
        val captured = AtomicReference<BiometricHelper?>(null)
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity -> captured.set(BiometricHelper(activity)) }
        }
        return captured.get() ?: throw AssertionError("no activity was available to build a helper")
    }

    /** True when a Class 3 biometric is enrolled and usable. */
    private fun strongBiometricEnrolled(): Boolean =
        BiometricManager.from(context)
            .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
            BiometricManager.BIOMETRIC_SUCCESS

    /**
     * True when either a Class 3 biometric or a device credential can verify
     * the user; the general-key and auth-duration paths accept both.
     */
    private fun anyAuthenticatorEnrolled(): Boolean {
        val manager = BiometricManager.from(context)
        val combined = manager.canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG or
                BiometricManager.Authenticators.DEVICE_CREDENTIAL
        )
        return combined == BiometricManager.BIOMETRIC_SUCCESS
    }

    private fun newCredentialId(label: String): String =
        "authbound-cred-$label-${System.nanoTime()}".also { credentialIds.add(it) }

    private fun newGeneralKeyId(label: String): String =
        "authbound-key-$label-${System.nanoTime()}".also { generalKeyIds.add(it) }

    private fun randomBytes(size: Int) = ByteArray(size).also { SecureRandom().nextBytes(it) }

    /** Runs [block] and returns whatever it threw, or null if it returned. */
    private fun failureFrom(block: () -> Unit): Throwable? {
        return try {
            block()
            null
        } catch (t: Throwable) {
            t
        }
    }
}
