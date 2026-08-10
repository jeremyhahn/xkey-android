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
package com.automatethethings.xkey.crypto

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricPrompt
import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.ui.MainActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeFalse
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import javax.crypto.Cipher
import javax.crypto.KeyGenerator

/**
 * Instrumented tests for the failure half of [BiometricHelper.authenticate] and
 * [BiometricHelper.authenticateWithoutCrypto].
 *
 * A successful prompt needs a finger on a sensor and cannot be driven from a
 * test, but the branch that matters for correctness is the other one: when the
 * device cannot verify the user at all, the suspend function has to resume with
 * a typed [XKeyCryptoException] rather than hang forever. That is exactly the
 * state of a stock emulator -- no enrolled biometric -- so the prompt errors out
 * synchronously and `mapErrorToException` turns the framework error code into a
 * [BiometricUnavailableException].
 *
 * On a device that *does* have a usable biometric the prompt would sit waiting
 * for a real user, so those runs are skipped rather than left to time out.
 */
@RunWith(AndroidJUnit4::class)
class BiometricPromptFailureTest {

    /** Alias of the throwaway Keystore key backing [cryptoObject]; removed in @After. */
    private val keyAlias = "xkey_biometric_prompt_failure_${System.nanoTime()}"

    @After
    fun tearDown() {
        runCatching {
            KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }.deleteEntry(keyAlias)
        }
    }

    /**
     * An initialised cipher for a [BiometricPrompt.CryptoObject].
     *
     * The key has to live in the Android Keystore: `BiometricPrompt` rejects a
     * crypto object built on any other provider with
     * "Crypto primitive not backed by AndroidKeyStore provider" *before*
     * [BiometricHelper.authenticate] is ever reached, so a plain JCA cipher tests
     * the framework's argument checking rather than this project's error mapping.
     *
     * The key is deliberately not user-authentication-bound: this suite only runs
     * where nothing is enrolled, so an auth-bound key could not be generated at
     * all, and the binding has no bearing on the branch under test.
     */
    private fun cryptoObject(): BiometricPrompt.CryptoObject {
        val generator =
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                keyAlias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .build()
        )
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, generator.generateKey())
        return BiometricPrompt.CryptoObject(cipher)
    }

    /**
     * Runs [authenticate] on the main thread against a freshly launched activity
     * and returns whatever it threw, or null if it somehow succeeded.
     */
    private fun failureFrom(
        authenticate: suspend (BiometricHelper) -> Unit
    ): Throwable? {
        val outcome = AtomicReference<Throwable?>(null)
        val finished = CountDownLatch(1)

        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.moveToState(Lifecycle.State.RESUMED)

            val available = AtomicReference(false)
            scenario.onActivity { activity ->
                available.set(BiometricHelper(activity).isBiometricAvailable())
            }
            assumeFalse(
                "a device with an enrolled biometric would wait for a real user",
                available.get()
            )

            scenario.onActivity { activity ->
                val helper = BiometricHelper(activity)
                CoroutineScope(Dispatchers.Main).launch {
                    try {
                        authenticate(helper)
                    } catch (t: Throwable) {
                        outcome.set(t)
                    } finally {
                        finished.countDown()
                    }
                }
            }

            assertTrue(
                "the biometric prompt must resume its caller instead of hanging",
                finished.await(AWAIT_SECONDS, TimeUnit.SECONDS)
            )
        }
        return outcome.get()
    }

    @Test
    fun cryptoBoundAuthenticationFailsWhenTheUserCannotBeVerified() {
        val failure = failureFrom { helper ->
            helper.authenticate(
                cryptoObject = cryptoObject(),
                title = "xKey test",
                subtitle = "no authenticator is enrolled",
                description = "this prompt cannot succeed on this device"
            )
        }

        assertTrue(
            "expected a typed crypto failure, got $failure",
            failure is XKeyCryptoException
        )
    }

    @Test
    fun standaloneAuthenticationFailsWhenTheUserCannotBeVerified() {
        val failure = failureFrom { helper ->
            helper.authenticateWithoutCrypto(
                title = "xKey test",
                subtitle = "no authenticator is enrolled"
            )
        }

        assertTrue(
            "expected a typed crypto failure, got $failure",
            failure is XKeyCryptoException
        )
    }

    private companion object {
        const val AWAIT_SECONDS = 20L
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
    }
}
