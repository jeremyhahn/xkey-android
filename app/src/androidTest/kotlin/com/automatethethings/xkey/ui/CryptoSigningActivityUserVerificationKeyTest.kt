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
import androidx.test.platform.app.InstrumentationRegistry
import com.automatethethings.xkey.crypto.KeystoreUserVerificationKey
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * The activity path `local.verifyUser` takes when a service, not an activity,
 * owns the request: [CryptoSigningActivity] launched with a full Keystore alias
 * ([CryptoSigningActivity.EXTRA_KEY_ALIAS]), against the real
 * [KeystoreUserVerificationKey] (Codex review 7357 on PR #62).
 *
 * The handler passes [KeystoreUserVerificationKey.ALIAS]; these tests mint the
 * same key under their own alias and pass that, so the user's key is never
 * touched. Nothing here fakes the key or the prompt: the activity resolves the
 * alias, initialises a `SHA256withECDSA` signature with the Keystore key, wraps
 * it in a `CryptoObject` and shows the system prompt. Each failure on that way
 * settles the request's [CryptoSigningController] with an error, so a
 * controller that is unsettled, with its prompt attached, shows every step
 * succeeded. A cancel through [CryptoSigningCancellations] must then dismiss
 * the prompt and deliver nothing.
 *
 * Manual step, needs a person at the sensor: with the prompt up, touching the
 * sensor must deliver a signature that verifies under the UVK's leaf; that
 * cannot be automated.
 *
 * Every alias is per-run and deleted in [tearDown].
 */
@RunWith(AndroidJUnit4::class)
class CryptoSigningActivityUserVerificationKeyTest {

    private val context: Context
        get() = ApplicationProvider.getApplicationContext()

    private val suffix = System.nanoTime()
    private val uvkAlias = "xkey_uvk_activity_test_$suffix"
    private val credentialId = "uvk-activity-test-$suffix"

    private lateinit var keyStore: KeyStore
    private var receiver: BroadcastReceiver? = null
    private val results: MutableList<Intent> = Collections.synchronizedList(mutableListOf())
    private val received = CountDownLatch(1)

    @Before
    fun setUp() {
        keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val broadcastReceiver = object : BroadcastReceiver() {
            override fun onReceive(receivedContext: Context?, intent: Intent?) {
                intent?.let { results.add(it) }
                received.countDown()
            }
        }
        receiver = broadcastReceiver
        ContextCompat.registerReceiver(
            context,
            broadcastReceiver,
            IntentFilter(CryptoSigningActivity.ACTION_CRYPTO_SIGNING_RESULT),
            ContextCompat.RECEIVER_NOT_EXPORTED
        )
    }

    @After
    fun tearDown() {
        receiver?.let { context.unregisterReceiver(it) }
        receiver = null
        listOf(uvkAlias, CREDENTIAL_PREFIX + credentialId).forEach { alias ->
            if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
        }
    }

    /**
     * The full alias resolves to the real UVK, the Keystore signature
     * initialises and the crypto-bound prompt goes up; a cancel for the
     * request then calls `cancelAuthentication()` on that prompt, finishes the
     * activity and delivers neither a signature nor an error.
     */
    @Test
    fun theUvkAliasReachesTheCryptoPromptAndACancelDismissesIt() {
        assumeTrue(
            "Keystore cannot mint a biometric-bound key without an enrolled Class 3 biometric",
            strongBiometricEnrolled()
        )
        KeystoreUserVerificationKey(context, uvkAlias).chain()
        val requestId = "uvk-activity-cancel-$suffix"
        val cancels = AtomicInteger()

        ActivityScenario.launch<CryptoSigningActivity>(intentFor(requestId, uvkAlias)).use { scenario ->
            assertNotEquals(
                "the activity finished before prompting: ${describe(results)}",
                Lifecycle.State.DESTROYED,
                scenario.state
            )
            scenario.onActivity { activity ->
                val controller = field(activity, "controller") as CryptoSigningController?
                assertNotNull("the request has no controller", controller)
                assertFalse(
                    "the alias, initSign or the prompt failed: ${describe(results)}",
                    field(controller!!, "settled") as Boolean
                )
                assertFalse(controller.isCancelled)
                assertNotNull("no BiometricPrompt was built", field(activity, "biometricPrompt"))
                val prompt = field(controller, "prompt") as CryptoSigningController.Prompt?
                assertNotNull("the prompt was never attached to the controller", prompt)
                // Observe the real prompt's cancel without replacing it.
                setField(controller, "prompt", CryptoSigningController.Prompt {
                    cancels.incrementAndGet()
                    prompt!!.cancelAuthentication()
                })
            }

            CryptoSigningCancellations.cancel(requestId)
            InstrumentationRegistry.getInstrumentation().waitForIdleSync()

            assertTrue(
                "the cancel must call cancelAuthentication() on the prompt",
                cancels.get() >= 1
            )
            awaitState(scenario, Lifecycle.State.DESTROYED)
        }

        // Anything the activity sent would have arrived within the window.
        received.await(QUIET_PERIOD_MS, TimeUnit.MILLISECONDS)
        assertTrue(
            "a cancelled request must deliver nothing, got ${describe(results)}",
            results.none { it.getStringExtra(CryptoSigningActivity.EXTRA_REQUEST_ID) == requestId }
        )
    }

    /**
     * The full alias replaces the credential alias rather than falling back to
     * it: with a usable key under `xkey_credential_<id>` and a full alias that
     * names nothing, the activity reports the key as not found. Needs no
     * biometric, so it runs on every device.
     */
    @Test
    fun theFullAliasWinsOverTheCredentialAlias() {
        generateCredentialKey()
        val requestId = "uvk-activity-alias-$suffix"

        ActivityScenario.launch<CryptoSigningActivity>(
            intentFor(requestId, "xkey_uvk_activity_missing_$suffix")
        ).use {
            assertTrue(
                "expected a signing result broadcast",
                received.await(BROADCAST_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            )
        }

        val result = results.last()
        assertEquals(requestId, result.getStringExtra(CryptoSigningActivity.EXTRA_REQUEST_ID))
        assertFalse(result.getBooleanExtra(CryptoSigningActivity.EXTRA_SUCCESS, true))
        assertEquals(
            CryptoSigningActivity.ERROR_CODE_KEY_NOT_FOUND,
            result.getIntExtra(CryptoSigningActivity.EXTRA_ERROR_CODE, Int.MIN_VALUE)
        )
    }

    // ------------------------------------------------------------- helpers

    private fun intentFor(requestId: String, keyAlias: String): Intent =
        CryptoSigningActivity.createIntent(
            context = context,
            requestId = requestId,
            credentialId = credentialId,
            dataHashBase64 = Base64.getEncoder().encodeToString(ByteArray(32)),
            keyAlias = keyAlias
        )

    /** A plain EC signing key under the credential alias the activity would derive. */
    private fun generateCredentialKey() {
        val spec = KeyGenParameterSpec.Builder(CREDENTIAL_PREFIX + credentialId, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(false)
            .build()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE).apply {
            initialize(spec)
            generateKeyPair()
        }
    }

    private fun awaitState(scenario: ActivityScenario<*>, state: Lifecycle.State) {
        val deadline = System.currentTimeMillis() + BROADCAST_TIMEOUT_SECONDS * 1000
        while (scenario.state != state && System.currentTimeMillis() < deadline) {
            Thread.sleep(POLL_INTERVAL_MS)
        }
        assertEquals("the cancelled activity must finish", state, scenario.state)
    }

    /** Result codes and messages only; a result never carries key material here. */
    private fun describe(intents: List<Intent>): String = synchronized(intents) {
        intents.joinToString { intent ->
            "success=${intent.getBooleanExtra(CryptoSigningActivity.EXTRA_SUCCESS, false)} " +
                "code=${intent.getIntExtra(CryptoSigningActivity.EXTRA_ERROR_CODE, 0)} " +
                "message=${intent.getStringExtra(CryptoSigningActivity.EXTRA_ERROR_MESSAGE)}"
        }.ifEmpty { "no result" }
    }

    private fun field(target: Any, name: String): Any? =
        target.javaClass.getDeclaredField(name).apply { isAccessible = true }.get(target)

    private fun setField(target: Any, name: String, value: Any?) {
        target.javaClass.getDeclaredField(name).apply { isAccessible = true }.set(target, value)
    }

    private fun strongBiometricEnrolled(): Boolean =
        BiometricManager.from(context)
            .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
            BiometricManager.BIOMETRIC_SUCCESS

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val CREDENTIAL_PREFIX = "xkey_credential_"
        const val BROADCAST_TIMEOUT_SECONDS = 15L
        const val QUIET_PERIOD_MS = 2_000L
        const val POLL_INTERVAL_MS = 50L
    }
}
