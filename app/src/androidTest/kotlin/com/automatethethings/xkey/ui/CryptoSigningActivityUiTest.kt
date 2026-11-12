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
import com.automatethethings.xkey.auth.NotificationKeys
import com.automatethethings.xkey.auth.PromptOwnership
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.Base64
import java.util.Collections
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
 * - A request the prompt owner does not hold ACTIVE finishing silently
 *
 * The activity only serves a request whose signature entry the process
 * [PromptOwnership] holds ACTIVE, so each test that expects a result holds that
 * entry first, as the launcher's request does, and lets go in [tearDown].
 */
@RunWith(AndroidJUnit4::class)
class CryptoSigningActivityUiTest {

    private val context: Context
        get() = ApplicationProvider.getApplicationContext()

    private var receiver: BroadcastReceiver? = null

    /** The prompt owner's entry this test holds ACTIVE, if any. */
    private var heldKey: String? = null

    @Before
    fun setUp() {
        results.clear()
    }

    @After
    fun tearDown() {
        heldKey?.let { PromptOwnership.process.end(it) }
        heldKey = null
        receiver?.let { context.unregisterReceiver(it) }
        receiver = null
    }

    // ---------------------------------------------------------------
    // createIntent() factory
    // ---------------------------------------------------------------

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
        val requestId = "req-missing-credential-" + UUID.randomUUID()
        holdTheScreen(requestId)
        awaitResultFor(
            Intent(context, CryptoSigningActivity::class.java).apply {
                putExtra(CryptoSigningActivity.EXTRA_REQUEST_ID, requestId)
                putExtra(CryptoSigningActivity.EXTRA_DATA_HASH, encodedHash())
            }
        )

        assertErrorCode(requestId, CryptoSigningActivity.ERROR_CODE_INVALID_REQUEST)
    }

    @Test
    fun missingDataHash_reportsAnInvalidRequest() {
        val requestId = "req-missing-hash-" + UUID.randomUUID()
        holdTheScreen(requestId)
        awaitResultFor(
            Intent(context, CryptoSigningActivity::class.java).apply {
                putExtra(CryptoSigningActivity.EXTRA_REQUEST_ID, requestId)
                putExtra(CryptoSigningActivity.EXTRA_CREDENTIAL_ID, "cred-1")
            }
        )

        assertErrorCode(requestId, CryptoSigningActivity.ERROR_CODE_INVALID_REQUEST)
    }

    @Test
    fun undecodableDataHash_reportsAnInvalidRequest() {
        val requestId = "req-bad-hash-" + UUID.randomUUID()
        holdTheScreen(requestId)
        awaitResultFor(
            CryptoSigningActivity.createIntent(
                context = context,
                requestId = requestId,
                credentialId = "cred-1",
                dataHashBase64 = "!!!not-base64!!!"
            )
        )

        assertErrorCode(requestId, CryptoSigningActivity.ERROR_CODE_INVALID_REQUEST)
    }

    /**
     * A credential with no Keystore key is reported as key-not-found, with the
     * request id echoed back, and the activity finishes.
     */
    @Test
    fun activity_finishesGracefullyWhenSigningKeyMissing() {
        val requestId = "ui-test-" + UUID.randomUUID()
        holdTheScreen(requestId)

        val scenario = awaitResultFor(
            CryptoSigningActivity.createIntent(
                context = context,
                requestId = requestId,
                credentialId = "ui-test-missing-" + UUID.randomUUID(),
                dataHashBase64 = encodedHash()
            )
        )

        assertErrorCode(requestId, CryptoSigningActivity.ERROR_CODE_KEY_NOT_FOUND)
        awaitDestroyed(scenario, "Activity should finish gracefully when the signing key is missing")
    }

    /**
     * A request the prompt owner does not hold ACTIVE never prompts and never
     * reports: the activity finishes and the owner's request keeps its say.
     */
    @Test
    fun aRequestWithoutAnActiveEntry_finishesWithoutABroadcast() {
        val requestId = "ui-test-unheld-" + UUID.randomUUID()

        val scenario = launchListening(
            CryptoSigningActivity.createIntent(
                context = context,
                requestId = requestId,
                credentialId = "ui-test-missing-" + UUID.randomUUID(),
                dataHashBase64 = encodedHash()
            )
        )

        awaitDestroyed(scenario, "an unheld request must finish")
        // Anything the activity sent would have arrived within the window.
        Thread.sleep(QUIET_PERIOD_MS)
        assertTrue(
            "an unheld request must deliver nothing",
            synchronized(results) {
                results.none { it.getStringExtra(CryptoSigningActivity.EXTRA_REQUEST_ID) == requestId }
            }
        )
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    private fun encodedHash(): String = Base64.getEncoder().encodeToString(ByteArray(32))

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
     * Registers a receiver for the signing-result broadcast and launches
     * [intent]; the returned latch opens on the first result.
     */
    private fun launchListening(
        intent: Intent,
        latch: CountDownLatch = CountDownLatch(1)
    ): ActivityScenario<CryptoSigningActivity> {
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

        return ActivityScenario.launch(intent)
    }

    /**
     * Launches [intent] listening for the signing-result broadcast, and blocks
     * until a result arrives or the timeout elapses.
     */
    private fun awaitResultFor(intent: Intent): ActivityScenario<CryptoSigningActivity> {
        val latch = CountDownLatch(1)
        val scenario = launchListening(intent, latch)

        assertTrue(
            "Expected a ${CryptoSigningActivity.ACTION_CRYPTO_SIGNING_RESULT} broadcast",
            latch.await(BROADCAST_TIMEOUT_SECONDS, TimeUnit.SECONDS)
        )
        return scenario
    }

    private fun awaitDestroyed(scenario: ActivityScenario<*>, message: String) {
        val deadline = System.currentTimeMillis() + BROADCAST_TIMEOUT_SECONDS * 1_000
        while (scenario.state != Lifecycle.State.DESTROYED && System.currentTimeMillis() < deadline) {
            Thread.sleep(POLL_INTERVAL_MS)
        }
        assertEquals(message, Lifecycle.State.DESTROYED, scenario.state)
    }

    private fun assertErrorCode(requestId: String, expected: Int) {
        val result = synchronized(results) { results.lastOrNull() }
        assertNotNull("No signing result broadcast was received", result)
        assertEquals(requestId, result!!.getStringExtra(CryptoSigningActivity.EXTRA_REQUEST_ID))
        assertFalse(
            "The broadcast should report failure",
            result.getBooleanExtra(CryptoSigningActivity.EXTRA_SUCCESS, true)
        )
        assertEquals(
            expected,
            result.getIntExtra(CryptoSigningActivity.EXTRA_ERROR_CODE, Int.MIN_VALUE)
        )
    }

    private companion object {
        const val BROADCAST_TIMEOUT_SECONDS = 10L
        const val QUIET_PERIOD_MS = 2_000L
        const val POLL_INTERVAL_MS = 50L

        /** Results captured by the registered receiver for the current test. */
        val results: MutableList<Intent> = Collections.synchronizedList(mutableListOf())
    }
}
