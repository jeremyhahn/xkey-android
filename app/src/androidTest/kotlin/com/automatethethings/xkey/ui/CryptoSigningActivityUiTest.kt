/*
 * Copyright (c) 2025 Jeremy Hahn
 * Copyright (c) 2025 Automate The Things, LLC
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
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.Base64
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * Instrumented UI tests for [CryptoSigningActivity].
 *
 * CryptoSigningActivity is a transparent, headless activity: its layout
 * (activity_transparent_biometric) is intentionally empty because the only
 * visible UI is the system biometric prompt. Every failure path it can reach
 * without showing that prompt broadcasts a result instead of rendering
 * anything, so these tests register a receiver for
 * [CryptoSigningActivity.ACTION_CRYPTO_SIGNING_RESULT] and assert the broadcast
 * the activity emits, rather than asserting on views.
 *
 * Tests cover:
 * - [CryptoSigningActivity.createIntent] wiring the component and all extras
 * - Missing request id, credential id and data hash each ending the activity
 * - Undecodable data hash reported as an invalid request
 * - A credential with no keystore key reported as key-not-found, with the
 *   request id echoed back so the caller can correlate it
 */
@RunWith(AndroidJUnit4::class)
class CryptoSigningActivityUiTest {

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
    fun createIntent_targetsCryptoSigningActivity() {
        val intent = CryptoSigningActivity.createIntent(
            context = context,
            requestId = "req-1",
            credentialId = "cred-1",
            dataHashBase64 = "ZGF0YQ=="
        )

        assertEquals(
            CryptoSigningActivity::class.java.name,
            intent.component?.className
        )
    }

    @Test
    fun createIntent_includesAllProvidedExtras() {
        val intent = CryptoSigningActivity.createIntent(
            context = context,
            requestId = "req-42",
            credentialId = "cred-abc",
            dataHashBase64 = "ZGF0YQ==",
            title = "Custom Title",
            subtitle = "Custom Subtitle",
            showOnLockScreen = true
        )

        assertEquals("req-42", intent.getStringExtra(CryptoSigningActivity.EXTRA_REQUEST_ID))
        assertEquals("cred-abc", intent.getStringExtra(CryptoSigningActivity.EXTRA_CREDENTIAL_ID))
        assertEquals("ZGF0YQ==", intent.getStringExtra(CryptoSigningActivity.EXTRA_DATA_HASH))
        assertEquals("Custom Title", intent.getStringExtra(CryptoSigningActivity.EXTRA_TITLE))
        assertEquals("Custom Subtitle", intent.getStringExtra(CryptoSigningActivity.EXTRA_SUBTITLE))
        assertTrue(
            intent.getBooleanExtra(CryptoSigningActivity.EXTRA_SHOW_ON_LOCK_SCREEN, false)
        )
    }

    @Test
    fun createIntent_appliesDefaultTitleSubtitleAndLockScreen() {
        val intent = CryptoSigningActivity.createIntent(
            context = context,
            requestId = "req-1",
            credentialId = "cred-1",
            dataHashBase64 = "ZGF0YQ=="
        )

        assertEquals(
            "xKey Authentication",
            intent.getStringExtra(CryptoSigningActivity.EXTRA_TITLE)
        )
        assertEquals(
            "Verify your identity to sign",
            intent.getStringExtra(CryptoSigningActivity.EXTRA_SUBTITLE)
        )
        assertFalse(
            intent.getBooleanExtra(CryptoSigningActivity.EXTRA_SHOW_ON_LOCK_SCREEN, true)
        )
    }

    // ---------------------------------------------------------------
    // Launch behavior
    // ---------------------------------------------------------------

    @Test
    fun activity_finishesWhenLaunchedWithoutExtras() {
        val intent = Intent(context, CryptoSigningActivity::class.java)

        val scenario = ActivityScenario.launch<CryptoSigningActivity>(intent)

        // onCreate calls finish() synchronously when EXTRA_REQUEST_ID is missing.
        assertTrue(
            "Activity should finish when launched without required extras",
            scenario.state == Lifecycle.State.DESTROYED
        )
    }

    @Test
    fun missingCredentialId_reportsAnInvalidRequest() {
        awaitResultFor(
            Intent(context, CryptoSigningActivity::class.java).apply {
                putExtra(CryptoSigningActivity.EXTRA_REQUEST_ID, "req-missing-credential")
                putExtra(CryptoSigningActivity.EXTRA_DATA_HASH, encodedHash())
            }
        )

        assertErrorCode(CryptoSigningActivity.ERROR_CODE_INVALID_REQUEST)
    }

    @Test
    fun missingDataHash_reportsAnInvalidRequest() {
        awaitResultFor(
            Intent(context, CryptoSigningActivity::class.java).apply {
                putExtra(CryptoSigningActivity.EXTRA_REQUEST_ID, "req-missing-hash")
                putExtra(CryptoSigningActivity.EXTRA_CREDENTIAL_ID, "cred-1")
            }
        )

        assertErrorCode(CryptoSigningActivity.ERROR_CODE_INVALID_REQUEST)
    }

    @Test
    fun undecodableDataHash_reportsAnInvalidRequest() {
        awaitResultFor(
            CryptoSigningActivity.createIntent(
                context = context,
                requestId = "req-bad-hash",
                credentialId = "cred-1",
                dataHashBase64 = "!!!not-base64!!!"
            )
        )

        assertErrorCode(CryptoSigningActivity.ERROR_CODE_INVALID_REQUEST)
    }

    /**
     * A valid request whose credential has no key in the Android Keystore hits
     * the KEY_NOT_FOUND path and finishes WITHOUT showing a biometric prompt.
     */
    @Test
    fun missingSigningKey_reportsKeyNotFoundAndEchoesTheRequestId() {
        val requestId = "ui-test-" + UUID.randomUUID()

        awaitResultFor(
            CryptoSigningActivity.createIntent(
                context = context,
                requestId = requestId,
                credentialId = "ui-test-missing-" + UUID.randomUUID(),
                dataHashBase64 = encodedHash()
            )
        )

        assertErrorCode(CryptoSigningActivity.ERROR_CODE_KEY_NOT_FOUND)
        assertEquals(
            requestId,
            results.last().getStringExtra(CryptoSigningActivity.EXTRA_REQUEST_ID)
        )
    }

    @Test
    fun activity_finishesGracefullyWhenSigningKeyMissing() {
        val intent = CryptoSigningActivity.createIntent(
            context = context,
            requestId = "ui-test-" + UUID.randomUUID(),
            credentialId = "ui-test-missing-" + UUID.randomUUID(),
            dataHashBase64 = encodedHash()
        )

        val scenario = ActivityScenario.launch<CryptoSigningActivity>(intent)

        assertTrue(
            "Activity should finish gracefully when the signing key is missing",
            scenario.state == Lifecycle.State.DESTROYED
        )
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    private fun encodedHash(): String = Base64.getEncoder().encodeToString(ByteArray(32))

    /**
     * Registers a receiver for the signing-result broadcast, launches [intent],
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
            IntentFilter(CryptoSigningActivity.ACTION_CRYPTO_SIGNING_RESULT),
            ContextCompat.RECEIVER_NOT_EXPORTED
        )

        ActivityScenario.launch<CryptoSigningActivity>(intent)

        assertTrue(
            "Expected a ${CryptoSigningActivity.ACTION_CRYPTO_SIGNING_RESULT} broadcast",
            latch.await(BROADCAST_TIMEOUT_SECONDS, TimeUnit.SECONDS)
        )
    }

    private fun assertErrorCode(expected: Int) {
        val result = results.lastOrNull()
        assertNotNull("No signing result broadcast was received", result)
        assertFalse(
            "The broadcast should report failure",
            result!!.getBooleanExtra(CryptoSigningActivity.EXTRA_SUCCESS, true)
        )
        assertEquals(
            expected,
            result.getIntExtra(CryptoSigningActivity.EXTRA_ERROR_CODE, Int.MIN_VALUE)
        )
    }

    private companion object {
        const val BROADCAST_TIMEOUT_SECONDS = 10L

        /** Results captured by the registered receiver for the current test. */
        val results = mutableListOf<Intent>()
    }
}
