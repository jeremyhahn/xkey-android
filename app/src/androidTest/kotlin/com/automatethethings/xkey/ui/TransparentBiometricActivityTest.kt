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
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * Instrumented tests for [TransparentBiometricActivity].
 *
 * The activity is headless: its layout is empty because the only thing the user
 * ever sees is the system biometric prompt, and every outcome is reported by a
 * package-scoped [TransparentBiometricActivity.ACTION_BIOMETRIC_RESULT]
 * broadcast rather than by anything on screen. These tests therefore register a
 * receiver and assert on that broadcast, exactly as the requesting service does.
 *
 * The emulator has no enrolled biometric, which is the branch worth covering:
 * the activity asks for `BIOMETRIC_STRONG` only, so the prompt fails
 * immediately, an error is broadcast, and the activity finishes without ever
 * blocking on user input. Nothing here depends on *which* error code the
 * platform picks (`ERROR_NO_BIOMETRICS` and `ERROR_HW_NOT_PRESENT` are both
 * legitimate) — only that it is not one of the activity's own sentinels and that
 * the caller's request id comes back so the result can be correlated.
 *
 * Coverage:
 * - [TransparentBiometricActivity.createIntent] wiring, defaults, and the
 *   optional description
 * - the missing-request-id guard, including the sentinel error code
 * - the unverifiable-device path, with and without the lock-screen flag and the
 *   optional description
 * - the activity tearing itself down after reporting
 */
@RunWith(AndroidJUnit4::class)
class TransparentBiometricActivityTest {

    private val context: Context
        get() = ApplicationProvider.getApplicationContext()

    private var receiver: BroadcastReceiver? = null

    @Before
    fun setUp() {
        results.clear()
    }

    @After
    fun tearDown() {
        receiver?.let { context.unregisterReceiver(it) }
        receiver = null
    }

    // ---------------------------------------------------------------
    // createIntent() factory
    // ---------------------------------------------------------------

    @Test
    fun createIntent_appliesTheDocumentedDefaults() {
        val intent = TransparentBiometricActivity.createIntent(context, requestId = "req-1")

        assertEquals(
            "req-1",
            intent.getStringExtra(TransparentBiometricActivity.EXTRA_REQUEST_ID)
        )
        assertEquals(
            "xKey Authentication",
            intent.getStringExtra(TransparentBiometricActivity.EXTRA_TITLE)
        )
        assertEquals(
            "Verify your identity",
            intent.getStringExtra(TransparentBiometricActivity.EXTRA_SUBTITLE)
        )
        assertFalse(
            intent.getBooleanExtra(
                TransparentBiometricActivity.EXTRA_SHOW_ON_LOCK_SCREEN,
                true
            )
        )
    }

    /** The description is optional, so the extra must be absent rather than null. */
    @Test
    fun createIntent_omitsTheDescriptionWhenNoneIsGiven() {
        val intent = TransparentBiometricActivity.createIntent(context, requestId = "req-1")

        assertFalse(intent.hasExtra(TransparentBiometricActivity.EXTRA_DESCRIPTION))
    }

    @Test
    fun createIntent_carriesEveryProvidedValue() {
        val intent = TransparentBiometricActivity.createIntent(
            context = context,
            requestId = "req-42",
            title = "Approve signature",
            subtitle = "example.com",
            description = "A desktop client asked to sign a challenge",
            showOnLockScreen = true
        )

        assertEquals(
            "req-42",
            intent.getStringExtra(TransparentBiometricActivity.EXTRA_REQUEST_ID)
        )
        assertEquals(
            "Approve signature",
            intent.getStringExtra(TransparentBiometricActivity.EXTRA_TITLE)
        )
        assertEquals(
            "example.com",
            intent.getStringExtra(TransparentBiometricActivity.EXTRA_SUBTITLE)
        )
        assertEquals(
            "A desktop client asked to sign a challenge",
            intent.getStringExtra(TransparentBiometricActivity.EXTRA_DESCRIPTION)
        )
        assertTrue(
            intent.getBooleanExtra(
                TransparentBiometricActivity.EXTRA_SHOW_ON_LOCK_SCREEN,
                false
            )
        )
    }

    // ---------------------------------------------------------------
    // Missing request id
    // ---------------------------------------------------------------

    @Test
    fun missingRequestId_reportsAnInvalidRequest() {
        awaitResultFor(Intent(context, TransparentBiometricActivity::class.java))

        val result = latestResult()
        assertEquals(
            TransparentBiometricActivity.ACTION_BIOMETRIC_RESULT,
            result.action
        )
        assertFalse(
            result.getBooleanExtra(TransparentBiometricActivity.EXTRA_SUCCESS, true)
        )
        assertEquals(
            TransparentBiometricActivity.ERROR_CODE_INVALID_REQUEST,
            result.getIntExtra(TransparentBiometricActivity.EXTRA_ERROR_CODE, Int.MIN_VALUE)
        )
        assertEquals(
            "Missing request ID",
            result.getStringExtra(TransparentBiometricActivity.EXTRA_ERROR_MESSAGE)
        )
    }

    @Test
    fun missingRequestId_finishesWithoutShowingAPrompt() {
        val scenario = ActivityScenario.launch<TransparentBiometricActivity>(
            Intent(context, TransparentBiometricActivity::class.java)
        )

        assertEquals(
            "onCreate finishes synchronously when the request id is missing",
            Lifecycle.State.DESTROYED,
            scenario.state
        )
    }

    // ---------------------------------------------------------------
    // No usable authenticator (the emulator's situation)
    // ---------------------------------------------------------------

    @Test
    fun withNoEnrolledAuthenticator_reportsThePromptErrorAndEchoesTheRequestId() {
        val requestId = newRequestId()

        awaitResultFor(TransparentBiometricActivity.createIntent(context, requestId))

        val result = latestResult()
        assertEquals(
            requestId,
            result.getStringExtra(TransparentBiometricActivity.EXTRA_REQUEST_ID)
        )
        assertFalse(
            "A device that cannot verify the user must not report success",
            result.getBooleanExtra(TransparentBiometricActivity.EXTRA_SUCCESS, true)
        )
        assertNotEquals(
            "The request was well-formed; the failure came from the prompt",
            TransparentBiometricActivity.ERROR_CODE_INVALID_REQUEST,
            result.getIntExtra(TransparentBiometricActivity.EXTRA_ERROR_CODE, Int.MIN_VALUE)
        )
        assertNotNull(
            result.getStringExtra(TransparentBiometricActivity.EXTRA_ERROR_MESSAGE)
        )
    }

    /** The lock-screen flag takes a different configuration path through onCreate. */
    @Test
    fun lockScreenRequest_stillReportsAResult() {
        val requestId = newRequestId()

        awaitResultFor(
            TransparentBiometricActivity.createIntent(
                context = context,
                requestId = requestId,
                showOnLockScreen = true
            )
        )

        val result = latestResult()
        assertEquals(
            requestId,
            result.getStringExtra(TransparentBiometricActivity.EXTRA_REQUEST_ID)
        )
        assertFalse(
            result.getBooleanExtra(TransparentBiometricActivity.EXTRA_SUCCESS, true)
        )
    }

    /** A description is added to the prompt builder only when one was supplied. */
    @Test
    fun aDescribedRequest_stillReportsAResult() {
        val requestId = newRequestId()

        awaitResultFor(
            TransparentBiometricActivity.createIntent(
                context = context,
                requestId = requestId,
                title = "Approve signature",
                subtitle = "example.com",
                description = "Signing a challenge from the desktop client"
            )
        )

        assertEquals(
            requestId,
            latestResult().getStringExtra(TransparentBiometricActivity.EXTRA_REQUEST_ID)
        )
    }

    @Test
    fun theActivityTearsItselfDownAfterReporting() {
        val scenario = ActivityScenario.launch<TransparentBiometricActivity>(
            TransparentBiometricActivity.createIntent(context, newRequestId())
        )

        awaitCondition("The prompt activity should finish once it has reported") {
            scenario.state == Lifecycle.State.DESTROYED
        }
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    /** A per-run id so results from one test can never be mistaken for another's. */
    private fun newRequestId(): String = "ui-test-" + UUID.randomUUID()

    /**
     * Registers a receiver for the biometric-result broadcast, launches [intent],
     * and blocks until a result arrives or the timeout elapses.
     */
    private fun awaitResultFor(intent: Intent) {
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
            IntentFilter(TransparentBiometricActivity.ACTION_BIOMETRIC_RESULT),
            ContextCompat.RECEIVER_NOT_EXPORTED
        )

        ActivityScenario.launch<TransparentBiometricActivity>(intent)

        assertTrue(
            "Expected a ${TransparentBiometricActivity.ACTION_BIOMETRIC_RESULT} broadcast",
            latch.await(BROADCAST_TIMEOUT_SECONDS, TimeUnit.SECONDS)
        )
    }

    private fun latestResult(): Intent {
        val result = results.lastOrNull()
        assertNotNull("No biometric result broadcast was received", result)
        return result!!
    }

    companion object {
        private const val BROADCAST_TIMEOUT_SECONDS = 15L

        /** Results captured by the registered receiver for the current test. */
        private val results = mutableListOf<Intent>()
    }
}
