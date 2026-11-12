/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
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
package com.automatethethings.xkey.ui

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricManager
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.auth.NotificationKeys
import com.automatethethings.xkey.auth.PromptOwnership
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.storage.XKeyDatabase
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.util.Base64
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * Instrumented tests for the signing half of [CryptoSigningActivity].
 *
 * `CryptoSigningActivityUiTest` stops at the requests the activity rejects
 * before it ever touches the Keystore. This suite provides real keys under the
 * credential alias the activity resolves, so the run gets as far as
 * `Signature.initSign` and the crypto-bound biometric prompt:
 *
 * - an EC key, which initialises cleanly and reaches `authenticate()`, where a
 *   device with no enrolled biometric refuses and the activity reports the
 *   system's error code rather than hanging;
 * - an RSA key, which the ECDSA signature object cannot accept, exercising the
 *   crypto-error branch;
 * - the show-over-lock-screen flag, which changes the window flags on the way in.
 *
 * The activity has no visible UI of its own, so every assertion is on the
 * [CryptoSigningActivity.ACTION_CRYPTO_SIGNING_RESULT] broadcast.
 *
 * The activity only serves a request whose signature entry the process
 * [PromptOwnership] holds ACTIVE, so each test holds that entry first, as the
 * launcher's request does, and lets go in `@After`.
 *
 * Both keys use a per-run id and are deleted in `@After`, along with the audit
 * rows key generation writes.
 */
@RunWith(AndroidJUnit4::class)
class CryptoSigningFlowTest {

    private val context: Context
        get() = ApplicationProvider.getApplicationContext()

    private val suffix = System.nanoTime()
    private val ecCredentialId = "cryptosign-ec-$suffix"
    private val rsaCredentialId = "cryptosign-rsa-$suffix"

    private lateinit var keystoreManager: KeystoreManager
    private var receiver: BroadcastReceiver? = null
    private val results: MutableList<Intent> = Collections.synchronizedList(mutableListOf())

    /** The prompt owner's entry this test holds ACTIVE, if any. */
    private var heldKey: String? = null

    @Before
    fun setUp() {
        keystoreManager = KeystoreManager(context)
        results.clear()
    }

    @After
    fun tearDown() {
        heldKey?.let { PromptOwnership.process.end(it) }
        heldKey = null
        receiver?.let { context.unregisterReceiver(it) }
        receiver = null

        keystoreManager.deleteKey(ecCredentialId)
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val rsaAlias = credentialAlias(rsaCredentialId)
        if (keyStore.containsAlias(rsaAlias)) keyStore.deleteEntry(rsaAlias)

        val auditLogDao = XKeyDatabase.getInstance(context).auditLogDao()
        runBlocking {
            auditLogDao.deleteByKeyId(ecCredentialId)
            auditLogDao.deleteByKeyId(rsaCredentialId)
        }
    }

    // ---------------------------------------------------------------
    // Reaching the biometric prompt
    // ---------------------------------------------------------------

    /**
     * With a usable EC credential the activity builds the signature, wraps it in
     * a `CryptoObject` and asks for biometric confirmation. No biometric is
     * enrolled on the test device, so the prompt refuses immediately and that
     * refusal has to come back to the caller as a failure result.
     *
     * Skipped on a device that *can* authenticate: there the prompt would wait
     * for a human.
     */
    @Test
    fun anEcCredentialReachesTheBiometricPromptAndReportsItsRefusal() {
        assumeNoEnrolledBiometric()
        runBlocking {
            keystoreManager.generateKey(credentialId = ecCredentialId, requireBiometric = false)
        }
        val requestId = "flow-ec-$suffix"
        holdTheScreen(requestId)

        awaitResultFor(
            CryptoSigningActivity.createIntent(
                context = context,
                requestId = requestId,
                credentialId = ecCredentialId,
                dataHashBase64 = encodedHash()
            )
        )

        val result = lastResult()
        assertFalse(
            "an unattended prompt cannot succeed",
            result.getBooleanExtra(CryptoSigningActivity.EXTRA_SUCCESS, true)
        )
        assertEquals(
            requestId,
            result.getStringExtra(CryptoSigningActivity.EXTRA_REQUEST_ID)
        )
        val errorCode = result.getIntExtra(
            CryptoSigningActivity.EXTRA_ERROR_CODE,
            Int.MIN_VALUE
        )
        assertFalse(
            "the key was found and the signature initialised, so the failure must " +
                "come from the prompt (was $errorCode)",
            errorCode == CryptoSigningActivity.ERROR_CODE_KEY_NOT_FOUND ||
                errorCode == CryptoSigningActivity.ERROR_CODE_INVALID_REQUEST ||
                errorCode == CryptoSigningActivity.ERROR_CODE_CRYPTO_ERROR
        )
        assertNotNull(
            "a failure result should explain itself",
            result.getStringExtra(CryptoSigningActivity.EXTRA_ERROR_MESSAGE)
        )
    }

    @Test
    fun theActivityFinishesOnceThePromptResolves() {
        assumeNoEnrolledBiometric()
        runBlocking {
            keystoreManager.generateKey(credentialId = ecCredentialId, requireBiometric = false)
        }
        val requestId = "flow-finish-$suffix"
        holdTheScreen(requestId)

        val scenario = awaitResultFor(
            CryptoSigningActivity.createIntent(
                context = context,
                requestId = requestId,
                credentialId = ecCredentialId,
                dataHashBase64 = encodedHash()
            )
        )

        val result = lastResult()
        assertEquals(requestId, result.getStringExtra(CryptoSigningActivity.EXTRA_REQUEST_ID))
        val errorCode = result.getIntExtra(CryptoSigningActivity.EXTRA_ERROR_CODE, Int.MIN_VALUE)
        assertFalse(
            "the run must resolve at the prompt, not before it (was $errorCode)",
            errorCode == CryptoSigningActivity.ERROR_CODE_KEY_NOT_FOUND ||
                errorCode == CryptoSigningActivity.ERROR_CODE_INVALID_REQUEST ||
                errorCode == CryptoSigningActivity.ERROR_CODE_CRYPTO_ERROR
        )
        val deadline = System.currentTimeMillis() + BROADCAST_TIMEOUT_SECONDS * 1_000
        while (System.currentTimeMillis() < deadline &&
            scenario.state != Lifecycle.State.DESTROYED
        ) {
            Thread.sleep(POLL_INTERVAL_MS)
        }
        assertEquals(
            "the transparent activity must not linger after the prompt resolves",
            Lifecycle.State.DESTROYED,
            scenario.state
        )
    }

    // ---------------------------------------------------------------
    // Signature initialisation failure
    // ---------------------------------------------------------------

    /**
     * The activity signs with SHA256withECDSA. A credential backed by an RSA key
     * cannot initialise that signature, which must be reported as a crypto
     * error instead of surfacing as a crash inside `onCreate`.
     */
    @Test
    fun anRsaCredentialIsReportedAsACryptoError() {
        generateRsaCredentialKey(rsaCredentialId)
        val requestId = "flow-rsa-$suffix"
        holdTheScreen(requestId)

        awaitResultFor(
            CryptoSigningActivity.createIntent(
                context = context,
                requestId = requestId,
                credentialId = rsaCredentialId,
                dataHashBase64 = encodedHash()
            )
        )

        val result = lastResult()
        assertEquals(requestId, result.getStringExtra(CryptoSigningActivity.EXTRA_REQUEST_ID))
        assertEquals(
            CryptoSigningActivity.ERROR_CODE_CRYPTO_ERROR,
            result.getIntExtra(CryptoSigningActivity.EXTRA_ERROR_CODE, Int.MIN_VALUE)
        )
    }

    // ---------------------------------------------------------------
    // Lock screen requests
    // ---------------------------------------------------------------

    /**
     * A service can ask for the prompt over the lock screen. The extra changes
     * the window setup only; the request itself is handled exactly as usual.
     */
    @Test
    fun aLockScreenRequestIsHandledLikeAnyOther() {
        val requestId = "flow-lock-$suffix"
        holdTheScreen(requestId)

        awaitResultFor(
            CryptoSigningActivity.createIntent(
                context = context,
                requestId = requestId,
                credentialId = "cryptosign-absent-$suffix",
                dataHashBase64 = encodedHash(),
                showOnLockScreen = true
            )
        )

        val result = lastResult()
        assertEquals(
            CryptoSigningActivity.ERROR_CODE_KEY_NOT_FOUND,
            result.getIntExtra(CryptoSigningActivity.EXTRA_ERROR_CODE, Int.MIN_VALUE)
        )
        assertEquals(requestId, result.getStringExtra(CryptoSigningActivity.EXTRA_REQUEST_ID))
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    /**
     * Skips the test when the device could actually authenticate.
     *
     * These tests rely on `authenticate()` failing without a human; on a phone
     * with an enrolled fingerprint it would instead wait for one.
     */
    private fun assumeNoEnrolledBiometric() {
        val status = BiometricManager.from(context)
            .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        assumeTrue(
            "requires a device with no enrolled biometric",
            status != BiometricManager.BIOMETRIC_SUCCESS
        )
    }

    private fun encodedHash(): String = Base64.getEncoder().encodeToString(ByteArray(32))

    private fun credentialAlias(credentialId: String) = "xkey_credential_$credentialId"

    /**
     * Creates an RSA key under the credential alias the activity resolves.
     *
     * [KeystoreManager] only mints EC credentials, so the key is generated here
     * with the same alias convention (`xkey_credential_<id>`).
     */
    private fun generateRsaCredentialKey(credentialId: String) {
        val spec = KeyGenParameterSpec.Builder(
            credentialAlias(credentialId),
            KeyProperties.PURPOSE_SIGN
        )
            .setKeySize(2048)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
            .setUserAuthenticationRequired(false)
            .build()

        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE).apply {
            initialize(spec)
            generateKeyPair()
        }
    }

    /**
     * Makes [requestId]'s signature entry ACTIVE in the process prompt owner,
     * as the launcher's request holds it while its prompt is up: the activity
     * refuses a request the owner does not hold ACTIVE. [tearDown] lets go.
     */
    private fun holdTheScreen(requestId: String) {
        val key = NotificationKeys.signature(requestId)
        PromptOwnership.process.enqueue(key, PromptOwnership.Kind.CRYPTO_SIGNING) {}
        heldKey = key
        assertEquals("nothing else holds the screen", key, PromptOwnership.process.activeKey)
    }

    /**
     * Registers a receiver for the signing-result broadcast, launches [intent],
     * and blocks until a result arrives or the timeout elapses.
     */
    private fun awaitResultFor(intent: Intent): ActivityScenario<CryptoSigningActivity> {
        val latch = CountDownLatch(1)
        val broadcastReceiver = object : BroadcastReceiver() {
            override fun onReceive(receivedContext: Context?, received: Intent?) {
                received?.let { results.add(it) }
                latch.countDown()
            }
        }
        receiver = broadcastReceiver
        ContextCompat.registerReceiver(
            context,
            broadcastReceiver,
            IntentFilter(CryptoSigningActivity.ACTION_CRYPTO_SIGNING_RESULT),
            ContextCompat.RECEIVER_NOT_EXPORTED
        )

        val scenario = ActivityScenario.launch<CryptoSigningActivity>(intent)

        assertTrue(
            "Expected a ${CryptoSigningActivity.ACTION_CRYPTO_SIGNING_RESULT} broadcast",
            latch.await(BROADCAST_TIMEOUT_SECONDS, TimeUnit.SECONDS)
        )
        return scenario
    }

    private fun lastResult(): Intent {
        val result = synchronized(results) { results.lastOrNull() }
        assertNotNull("No signing result broadcast was received", result)
        return result!!
    }

    private companion object {
        const val BROADCAST_TIMEOUT_SECONDS = 15L
        const val POLL_INTERVAL_MS = 50L
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
    }
}
