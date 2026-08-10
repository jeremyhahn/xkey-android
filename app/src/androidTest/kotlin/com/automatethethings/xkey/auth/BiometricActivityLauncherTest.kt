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
package com.automatethethings.xkey.auth

import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import androidx.biometric.BiometricPrompt
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.crypto.BiometricException
import com.automatethethings.xkey.crypto.BiometricLockoutException
import com.automatethethings.xkey.crypto.KeyNotFoundException
import com.automatethethings.xkey.crypto.SigningException
import com.automatethethings.xkey.crypto.UserCancelledException
import com.automatethethings.xkey.ui.CryptoSigningActivity
import com.automatethethings.xkey.ui.TransparentBiometricActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.Base64
import java.util.Collections

/**
 * Instrumented tests for [BiometricActivityLauncher].
 *
 * The launcher is the bridge between a background service and a biometric
 * prompt: it starts an activity, waits on a broadcast, and turns the reply into
 * a typed exception. The broadcast half is what carries the risk, and it needs a
 * real `Context` -- `ContextCompat.registerReceiver` with `RECEIVER_NOT_EXPORTED`
 * has no JVM equivalent.
 *
 * The launcher is handed a [RecordingContext]: a wrapper whose only change is
 * that `startActivity` records the intent instead of launching it. That keeps
 * the suite deterministic -- no prompt appears, so the result does not depend on
 * whether the device has a fingerprint enrolled -- while leaving every line
 * under test untouched, including the intent the launcher builds. Results are
 * then delivered as genuine broadcasts, so the receivers are exercised for real
 * rather than invoked directly.
 */
@RunWith(AndroidJUnit4::class)
class BiometricActivityLauncherTest {

    /** A context that records launches instead of performing them. */
    private class RecordingContext(base: Context) : ContextWrapper(base) {
        val launched: MutableList<Intent> = Collections.synchronizedList(mutableListOf())

        override fun startActivity(intent: Intent) {
            launched.add(intent)
        }

        override fun startActivity(intent: Intent, options: android.os.Bundle?) {
            launched.add(intent)
        }
    }

    private lateinit var appContext: Context
    private lateinit var recordingContext: RecordingContext
    private lateinit var launcher: BiometricActivityLauncher
    private lateinit var scope: CoroutineScope

    @Before
    fun setUp() {
        appContext = ApplicationProvider.getApplicationContext()
        recordingContext = RecordingContext(appContext)
        launcher = BiometricActivityLauncher(recordingContext)
        scope = CoroutineScope(Dispatchers.Default + SupervisorJob())
    }

    @After
    fun tearDown() {
        launcher.unregister()
        scope.cancel()
    }

    // ------------------------------------------------------------- helpers

    private fun awaitLaunchedIntent(timeoutMs: Long = 10_000L): Intent {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            synchronized(recordingContext.launched) {
                recordingContext.launched.firstOrNull()
            }?.let { return it }
            Thread.sleep(10)
        }
        throw AssertionError("the launcher never started an activity")
    }

    private fun startAuthentication(): Deferred<Unit> = scope.async {
        launcher.requestAuthentication(
            title = "xKey Authentication",
            subtitle = "Sign in to example.test",
            description = "Test description"
        )
    }

    private fun startCryptoSignature(dataHash: ByteArray): Deferred<ByteArray> = scope.async {
        launcher.requestCryptoSignature(
            credentialId = "credential-${System.nanoTime()}",
            dataHash = dataHash,
            title = "xKey Signing",
            subtitle = "example.test"
        )
    }

    private fun sendBiometricResult(
        requestId: String,
        success: Boolean,
        errorCode: Int = 0,
        errorMessage: String? = null
    ) {
        val intent = Intent(TransparentBiometricActivity.ACTION_BIOMETRIC_RESULT).apply {
            setPackage(appContext.packageName)
            putExtra(TransparentBiometricActivity.EXTRA_REQUEST_ID, requestId)
            putExtra(TransparentBiometricActivity.EXTRA_SUCCESS, success)
            putExtra(TransparentBiometricActivity.EXTRA_ERROR_CODE, errorCode)
            errorMessage?.let { putExtra(TransparentBiometricActivity.EXTRA_ERROR_MESSAGE, it) }
        }
        appContext.sendBroadcast(intent)
    }

    private fun sendSigningResult(
        requestId: String,
        success: Boolean,
        signature: String? = null,
        errorCode: Int = 0,
        errorMessage: String? = null
    ) {
        val intent = Intent(CryptoSigningActivity.ACTION_CRYPTO_SIGNING_RESULT).apply {
            setPackage(appContext.packageName)
            putExtra(CryptoSigningActivity.EXTRA_REQUEST_ID, requestId)
            putExtra(CryptoSigningActivity.EXTRA_SUCCESS, success)
            signature?.let { putExtra(CryptoSigningActivity.EXTRA_SIGNATURE, it) }
            putExtra(CryptoSigningActivity.EXTRA_ERROR_CODE, errorCode)
            errorMessage?.let { putExtra(CryptoSigningActivity.EXTRA_ERROR_MESSAGE, it) }
        }
        appContext.sendBroadcast(intent)
    }

    private fun requestIdOf(intent: Intent): String =
        requireNotNull(intent.getStringExtra(TransparentBiometricActivity.EXTRA_REQUEST_ID)) {
            "the launched intent carried no request id"
        }

    /** Runs [block] and returns whatever it threw, or null if it completed. */
    private fun <T> failureOf(block: suspend () -> T): Throwable? = runBlocking {
        runCatching { withTimeout(15_000L) { block() } }.exceptionOrNull()
    }

    /** Drives one authentication that fails with [errorCode] and returns the throwable. */
    private fun authenticationFailure(errorCode: Int, message: String = "denied"): Throwable? {
        launcher.register()
        val deferred = startAuthentication()
        sendBiometricResult(requestIdOf(awaitLaunchedIntent()), false, errorCode, message)
        return failureOf { deferred.await() }
    }

    /** Drives one signing request that fails with [errorCode] and returns the throwable. */
    private fun signingFailure(errorCode: Int, message: String): Throwable? {
        launcher.register()
        val deferred = startCryptoSignature(ByteArray(32) { it.toByte() })
        sendSigningResult(requestIdOf(awaitLaunchedIntent()), false, null, errorCode, message)
        return failureOf { deferred.await() }
    }

    // ---------------------------------------------------------- registration

    @Test
    fun requestAuthentication_refusesBeforeRegistration() {
        val failure = failureOf {
            launcher.requestAuthentication(title = "t", subtitle = "s")
        }

        assertTrue("expected IllegalStateException, got $failure", failure is IllegalStateException)
        assertTrue(recordingContext.launched.isEmpty())
    }

    @Test
    fun requestCryptoSignature_refusesBeforeRegistration() {
        val failure = failureOf {
            launcher.requestCryptoSignature("credential", ByteArray(32), "t", "s")
        }

        assertTrue("expected IllegalStateException, got $failure", failure is IllegalStateException)
        assertTrue(recordingContext.launched.isEmpty())
    }

    @Test
    fun register_isIdempotent() {
        launcher.register()
        launcher.register()

        // A single unregister must still tear everything down; a double
        // registration would leave a receiver behind and throw on the next run.
        launcher.unregister()
        launcher.register()
        launcher.unregister()
    }

    @Test
    fun unregister_isSafeBeforeRegistration() {
        launcher.unregister()
        launcher.unregister()
    }

    // -------------------------------------------------------- authentication

    @Test
    fun requestAuthentication_buildsThePromptIntent() {
        launcher.register()

        val deferred = startAuthentication()

        val intent = awaitLaunchedIntent()
        assertEquals(
            TransparentBiometricActivity::class.java.name,
            intent.component?.className
        )
        assertEquals("xKey Authentication", intent.getStringExtra(TransparentBiometricActivity.EXTRA_TITLE))
        assertEquals(
            "Sign in to example.test",
            intent.getStringExtra(TransparentBiometricActivity.EXTRA_SUBTITLE)
        )
        assertNotNull(intent.getStringExtra(TransparentBiometricActivity.EXTRA_REQUEST_ID))
        assertTrue(intent.flags and Intent.FLAG_ACTIVITY_NEW_TASK != 0)

        sendBiometricResult(requestIdOf(intent), success = true)
        assertNull(failureOf { deferred.await() })
    }

    @Test
    fun requestAuthentication_returnsOnASuccessBroadcast() {
        launcher.register()
        val deferred = startAuthentication()

        sendBiometricResult(requestIdOf(awaitLaunchedIntent()), success = true)

        assertNull(failureOf { deferred.await() })
    }

    @Test
    fun userCancelled_becomesUserCancelledException() {
        val failure = authenticationFailure(BiometricPrompt.ERROR_USER_CANCELED)

        assertTrue("got $failure", failure is UserCancelledException)
    }

    @Test
    fun negativeButton_becomesUserCancelledException() {
        val failure = authenticationFailure(BiometricPrompt.ERROR_NEGATIVE_BUTTON)

        assertTrue("got $failure", failure is UserCancelledException)
    }

    @Test
    fun lockout_becomesATemporaryLockoutException() {
        val failure = authenticationFailure(BiometricPrompt.ERROR_LOCKOUT)

        assertTrue("got $failure", failure is BiometricLockoutException)
        assertFalse((failure as BiometricLockoutException).isPermanent)
    }

    @Test
    fun permanentLockout_becomesAPermanentLockoutException() {
        val failure = authenticationFailure(BiometricPrompt.ERROR_LOCKOUT_PERMANENT)

        assertTrue("got $failure", failure is BiometricLockoutException)
        assertTrue((failure as BiometricLockoutException).isPermanent)
    }

    @Test
    fun anUnmappedErrorCode_keepsItsCodeAndMessage() {
        val failure = authenticationFailure(BiometricPrompt.ERROR_HW_UNAVAILABLE, "sensor busy")

        assertTrue("got $failure", failure is BiometricException)
        assertTrue(failure!!.message!!.contains("sensor busy"))
    }

    @Test
    fun anErrorWithNoMessage_reportsAnUnknownError() {
        launcher.register()
        val deferred = startAuthentication()
        val intent = awaitLaunchedIntent()

        // No EXTRA_ERROR_MESSAGE at all, which is what a crashing prompt sends.
        sendBiometricResult(
            requestIdOf(intent),
            success = false,
            errorCode = BiometricPrompt.ERROR_VENDOR,
            errorMessage = null
        )

        val failure = failureOf { deferred.await() }
        assertTrue("got $failure", failure is BiometricException)
        assertTrue(failure!!.message!!.contains("Unknown error"))
    }

    @Test
    fun aResultForAnotherRequestIdIsIgnored() {
        launcher.register()
        val deferred = startAuthentication()
        val intent = awaitLaunchedIntent()

        sendBiometricResult("99999", success = false, errorCode = BiometricPrompt.ERROR_LOCKOUT)
        sendBiometricResult("not-a-number", success = true)
        // The real request is still pending, so it can still be resolved.
        sendBiometricResult(requestIdOf(intent), success = true)

        assertNull(failureOf { deferred.await() })
    }

    @Test
    fun unregister_cancelsAPendingRequest() {
        launcher.register()
        val deferred = startAuthentication()
        awaitLaunchedIntent()

        launcher.unregister()

        val failure = failureOf { deferred.await() }
        assertNotNull("the pending request should have been cancelled", failure)
    }

    // -------------------------------------------------------- crypto signing

    @Test
    fun requestCryptoSignature_buildsTheSigningIntent() {
        launcher.register()
        val dataHash = ByteArray(32) { (it * 7).toByte() }

        val deferred = startCryptoSignature(dataHash)

        val intent = awaitLaunchedIntent()
        assertEquals(
            CryptoSigningActivity::class.java.name,
            intent.component?.className
        )
        assertEquals(
            Base64.getEncoder().encodeToString(dataHash),
            intent.getStringExtra(CryptoSigningActivity.EXTRA_DATA_HASH)
        )
        assertNotNull(intent.getStringExtra(CryptoSigningActivity.EXTRA_CREDENTIAL_ID))

        sendSigningResult(
            requestIdOf(intent),
            success = true,
            signature = Base64.getEncoder().encodeToString(ByteArray(8))
        )
        assertNull(failureOf { deferred.await() })
    }

    @Test
    fun requestCryptoSignature_returnsTheDecodedSignature() {
        launcher.register()
        val signature = ByteArray(70) { (it + 1).toByte() }
        val deferred = startCryptoSignature(ByteArray(32))

        sendSigningResult(
            requestIdOf(awaitLaunchedIntent()),
            success = true,
            signature = Base64.getEncoder().encodeToString(signature)
        )

        val returned = runBlocking { withTimeout(15_000L) { deferred.await() } }
        assertArrayEquals(signature, returned)
    }

    @Test
    fun signingCancellation_becomesUserCancelledException() {
        val failure = signingFailure(BiometricPrompt.ERROR_USER_CANCELED, "cancelled")

        assertTrue("got $failure", failure is UserCancelledException)
    }

    @Test
    fun signingLockout_becomesALockoutException() {
        val failure = signingFailure(BiometricPrompt.ERROR_LOCKOUT_PERMANENT, "locked")

        assertTrue("got $failure", failure is BiometricLockoutException)
        assertTrue((failure as BiometricLockoutException).isPermanent)
    }

    @Test
    fun aMissingKey_becomesKeyNotFoundExceptionCarryingTheCredentialId() {
        val failure = signingFailure(
            CryptoSigningActivity.ERROR_CODE_KEY_NOT_FOUND,
            "Key not found for credential: abc-123"
        )

        assertTrue("got $failure", failure is KeyNotFoundException)
        assertEquals("abc-123", (failure as KeyNotFoundException).credentialId)
    }

    @Test
    fun aMissingKeyWithAnUnrecognisedMessage_reportsAnUnknownCredential() {
        val failure = signingFailure(
            CryptoSigningActivity.ERROR_CODE_KEY_NOT_FOUND,
            "the keystore is on fire"
        )

        assertTrue("got $failure", failure is KeyNotFoundException)
        assertEquals("unknown", (failure as KeyNotFoundException).credentialId)
    }

    @Test
    fun aSigningFailure_becomesSigningException() {
        val failure = signingFailure(
            CryptoSigningActivity.ERROR_CODE_SIGNING_FAILED,
            "signature rejected"
        )

        assertTrue("got $failure", failure is SigningException)
        assertEquals("signature rejected", (failure as SigningException).reason)
    }

    @Test
    fun aCryptoError_becomesSigningException() {
        val failure = signingFailure(
            CryptoSigningActivity.ERROR_CODE_CRYPTO_ERROR,
            "cipher unavailable"
        )

        assertTrue("got $failure", failure is SigningException)
    }

    @Test
    fun anUnmappedSigningErrorCode_becomesBiometricException() {
        val failure = signingFailure(BiometricPrompt.ERROR_TIMEOUT, "prompt timed out")

        assertTrue("got $failure", failure is BiometricException)
    }

    @Test
    fun unregister_cancelsAPendingSigningRequest() {
        launcher.register()
        val deferred = startCryptoSignature(ByteArray(32))
        awaitLaunchedIntent()

        launcher.unregister()

        assertNotNull(
            "the pending signing request should have been cancelled",
            failureOf { deferred.await() }
        )
    }
}
