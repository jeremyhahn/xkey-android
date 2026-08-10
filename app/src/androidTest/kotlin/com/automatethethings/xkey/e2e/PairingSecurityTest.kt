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

package com.automatethethings.xkey.e2e

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.auth.SessionAuthManager
import com.automatethethings.xkey.ble.PairingConfirmationCallback
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.protocol.ErrorCodes
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.remote.BidirectionalMessageRouter
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.tcp.TcpHsmServer
import com.automatethethings.xkey.tcp.TcpHsmState
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Negative security tests for the pairing boundary.
 *
 * Completing a Noise XX handshake proves the peer holds *a* static key. It
 * does not prove the user approved that peer, and it does not let the peer
 * choose which identity it is. These tests assert both properties, which the
 * happy-path conformance suite cannot observe.
 */
@RunWith(AndroidJUnit4::class)
class PairingSecurityTest {

    private lateinit var context: Context
    private lateinit var server: TcpHsmServer
    private lateinit var pairedDeviceRepository: PairedDeviceRepository

    /** Set when the app would have shown a pairing prompt to the user. */
    private val promptShown = AtomicBoolean(false)

    /** Whether the simulated user approves. */
    private val userApproves = AtomicBoolean(true)

    private companion object {
        const val TEST_PORT = 18555
    }

    @Before
    fun startServer() {
        context = ApplicationProvider.getApplicationContext()
        pairedDeviceRepository = PairedDeviceRepository(context)

        val handler = RequestHandler(
            context = context,
            keystoreManager = KeystoreManager(context),
            biometricLauncher = null,
            sessionAuthManager = SessionAuthManager(),
            pairedDeviceRepository = pairedDeviceRepository
        )

        server = TcpHsmServer(
            requestHandler = handler,
            messageRouter = BidirectionalMessageRouter(handler),
            pairingCallback = object : PairingConfirmationCallback {
                override suspend fun onPairingConfirmationRequired(
                    deviceName: String,
                    publicKeyFingerprint: String
                ): Boolean {
                    promptShown.set(true)
                    return userApproves.get()
                }
            },
            pairedDeviceRepository = pairedDeviceRepository
        )
        server.start(context, TEST_PORT)
        runBlocking {
            withTimeout(5000) { server.state.first { it is TcpHsmState.Listening } }
        }
    }

    @After
    fun stopServer() {
        if (::server.isInitialized) server.stop()
    }

    /**
     * A peer that has completed the handshake but not pairing must not be able
     * to run privileged operations. Before this was enforced, any peer able to
     * reach the transport could list and use keys unapproved.
     */
    @Test
    fun privilegedMethodsAreRefusedBeforePairing() {
        val client = ProtocolTestClient(TEST_PORT)
        client.connect()
        try {
            // A representative spread: enumeration, key generation, signing,
            // and material export.
            val privilegedMethods = listOf(
                "local.listKeys" to JSONObject(),
                "local.getCapabilities" to JSONObject(),
                "local.generateKey" to JSONObject()
                    .put("keyId", "unpaired-attempt")
                    .put("keyType", "signing")
                    .put("algorithm", "ES256"),
                "local.sign" to JSONObject()
                    .put("keyId", "unpaired-attempt")
                    .put("data", "AAAA"),
                "local.importSharedKey" to JSONObject().put("key_id", "anything"),
                "local.pinStatus" to JSONObject()
            )

            for ((method, params) in privilegedMethods) {
                val error = client.callExpectingError(method, params)
                assertNotNull("$method must be refused before pairing", error)
                assertEquals(
                    "$method must be refused with PAIRING_REQUIRED",
                    ErrorCodes.PAIRING_REQUIRED,
                    error!!.code
                )
            }

            // The refusal must not have leaked a key into the store.
            val leaked = runBlocking {
                com.automatethethings.xkey.storage.XKeyDatabase.getInstance(context)
                    .keyDao().getByKeyId("unpaired-attempt")
            }
            assertNull("an unpaired peer must not create keys", leaked)
        } finally {
            client.close()
        }
    }

    /**
     * The peer does not get to choose its own identity. A peer that completes
     * the handshake with its own key but claims a previously-trusted key must
     * be rejected — otherwise it would inherit that device's trust and skip
     * the approval prompt entirely.
     */
    @Test
    fun pairingConfirmCannotClaimAnotherDevicesKey() {
        // A device the user previously trusted.
        val trustedKeyHex = "11".repeat(32)
        pairedDeviceRepository.addDevice(trustedKeyHex, "Previously Trusted Laptop")
        assertTrue(pairedDeviceRepository.isDeviceKnown(trustedKeyHex))

        promptShown.set(false)
        val client = ProtocolTestClient(TEST_PORT)
        client.connect()
        try {
            // The attacker's own handshake key differs from what it claims.
            assertFalse(
                "test precondition: attacker key must differ from the trusted key",
                client.publicKeyHex.equals(trustedKeyHex, ignoreCase = true)
            )

            val error = client.callExpectingError(
                "pairing.confirm",
                JSONObject()
                    .put("deviceName", "Previously Trusted Laptop")
                    .put("publicKeyHex", trustedKeyHex)
            )

            assertNotNull("claiming another device's key must be refused", error)
            assertEquals(ErrorCodes.PAIRING_REJECTED, error!!.code)
            assertFalse(
                "a spoofed claim must not silently auto-approve",
                promptShown.get()
            )

            // And the session must still be unpaired.
            val followUp = client.callExpectingError("local.listKeys", JSONObject())
            assertEquals(
                "session must remain unpaired after a rejected claim",
                ErrorCodes.PAIRING_REQUIRED,
                followUp!!.code
            )
        } finally {
            client.close()
            pairedDeviceRepository.removeDevice(trustedKeyHex)
        }
    }

    /**
     * The honest path still works: a peer pairing under its own authenticated
     * key is prompted, approved, and then allowed through.
     */
    @Test
    fun honestPairingIsPromptedThenAllowed() {
        promptShown.set(false)
        userApproves.set(true)

        val client = ProtocolTestClient(TEST_PORT)
        client.connect()
        try {
            val result = client.confirmPairing("Honest Desktop")
            assertTrue(result.optBoolean("confirmed"))
            assertTrue("an unknown device must prompt the user", promptShown.get())

            // Now privileged calls succeed.
            assertNotNull(client.call("local.listKeys", JSONObject()).getJSONArray("keys"))
        } finally {
            client.close()
            pairedDeviceRepository.removeDevice(client.publicKeyHex)
        }
    }

    /**
     * A device the user already approved must work on reconnect WITHOUT
     * sending `pairing.confirm` again.
     *
     * This is a compatibility requirement, not a convenience: the go-xkms
     * desktop only sends `pairing.confirm` during `xkey device pair`. Every
     * other command (`device attest`, `oath sync`, `piv phone-list`, the
     * xkmsd phone backend) reconnects and goes straight to its method, so
     * gating those on a fresh confirm returns PAIRING_REQUIRED for everything
     * and breaks the desktop outright.
     *
     * Security is preserved because the Noise handshake cryptographically
     * proves the peer holds the same static key the user approved.
     */
    @Test
    fun alreadyPairedPeerIsAcceptedWithoutResendingPairingConfirm() {
        val first = ProtocolTestClient(TEST_PORT)
        first.connect()
        val peerKeyHex = first.publicKeyHex
        try {
            promptShown.set(false)
            userApproves.set(true)
            assertTrue(first.confirmPairing("Desktop").optBoolean("confirmed"))
            assertTrue("first pairing must prompt", promptShown.get())
        } finally {
            first.close()
        }

        // Reconnect with the SAME static key, as the desktop does for every
        // command after the initial pair.
        promptShown.set(false)
        val second = ProtocolTestClient(TEST_PORT, reuseStaticKey = first.staticKey)
        second.connect()
        try {
            assertEquals(
                "reconnect must present the same authenticated identity",
                peerKeyHex,
                second.publicKeyHex
            )
            // Straight to a privileged method — no pairing.confirm.
            assertNotNull(second.call("local.listKeys", JSONObject()).getJSONArray("keys"))
            assertFalse("a known device must not re-prompt", promptShown.get())
        } finally {
            second.close()
            pairedDeviceRepository.removeDevice(peerKeyHex)
        }
    }

    /** A user who declines must leave the session unpaired. */
    @Test
    fun declinedPairingLeavesSessionUnpaired() {
        promptShown.set(false)
        userApproves.set(false)

        val client = ProtocolTestClient(TEST_PORT)
        client.connect()
        try {
            val error = client.callExpectingError(
                "pairing.confirm",
                JSONObject()
                    .put("deviceName", "Rejected Desktop")
                    .put("publicKeyHex", client.publicKeyHex)
            )
            assertNotNull("a declined pairing must return an error", error)
            assertEquals(ErrorCodes.PAIRING_REJECTED, error!!.code)

            val followUp = client.callExpectingError("local.listKeys", JSONObject())
            assertEquals(ErrorCodes.PAIRING_REQUIRED, followUp!!.code)
        } finally {
            client.close()
            userApproves.set(true)
        }
    }

    private fun assertNull(message: String, value: Any?) {
        org.junit.Assert.assertNull(message, value)
    }
}
