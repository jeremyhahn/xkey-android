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

package com.automatethethings.xkey.ble

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.automatethethings.xkey.protocol.ErrorCodes
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.storage.XKeyDatabase
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
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
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Pairing-boundary tests for the BLE transport, driven through
 * [BleLoopbackHarness].
 *
 * BLE is the app's primary transport and had no automated pairing coverage at
 * all: the same gate that `PairingSecurityTest` proves over TCP lives in
 * [GattServer] as a *separate* implementation (`interceptOrRoute` /
 * `rejectUnpaired` / `handlePairingConfirmIfNeeded`), so passing over TCP says
 * nothing about BLE. These tests assert it directly, over the real Noise
 * session and the real fragment protocol.
 */
@RunWith(AndroidJUnit4::class)
class BlePairingLoopbackTest {

    private lateinit var context: Context
    private lateinit var pairedDeviceRepository: PairedDeviceRepository
    private lateinit var harness: BleLoopbackHarness

    /** Set when the app would have shown the user a pairing prompt. */
    private val promptShown = AtomicBoolean(false)

    /** Whether the simulated user approves. */
    private val userApproves = AtomicBoolean(true)

    /** Keys this test registered in the paired-device store, removed in teardown. */
    private val pairedKeys = mutableListOf<String>()

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        pairedDeviceRepository = PairedDeviceRepository(context)
        promptShown.set(false)
        userApproves.set(true)

        harness = BleLoopbackHarness(
            context = context,
            pairedDeviceRepository = pairedDeviceRepository,
            pairingCallback = object : PairingConfirmationCallback {
                override suspend fun onPairingConfirmationRequired(
                    deviceName: String,
                    publicKeyFingerprint: String
                ): Boolean {
                    promptShown.set(true)
                    return userApproves.get()
                }
            }
        )
        runBlocking { harness.connect() }
        pairedKeys += harness.publicKeyHex
    }

    @After
    fun tearDown() {
        if (::harness.isInitialized) harness.close()
        pairedKeys.forEach { pairedDeviceRepository.removeDevice(it) }
        pairedKeys.clear()
    }

    // -----------------------------------------------------------------
    // The handshake itself
    // -----------------------------------------------------------------

    /**
     * The identity the server trusts must come from the Noise transcript, not
     * from anything the peer asserts. This is the property every other test
     * here depends on.
     */
    @Test
    fun handshakeAuthenticatesTheInitiatorsStaticKey() {
        assertTrue("the server must consider the session established", harness.server.isSessionEstablished())
        assertEquals(
            "the responder must authenticate the initiator's own static key",
            harness.publicKeyHex,
            harness.authenticatedPeerKeyHex
        )
        assertFalse("a fresh session must start unpaired", harness.isPairingConfirmed)
    }

    /** Transport encryption round-trips in both directions after the handshake. */
    @Test
    fun encryptedTransportRoundTripsThroughFragmentation(): Unit = runBlocking {
        val result = harness.confirmPairing("Fragmentation Probe").let {
            assertTrue(it.optBoolean("confirmed"))
            harness.call("local.getCapabilities")
        }
        assertTrue("a real response must come back over the loopback", result.length() > 0)
    }

    /**
     * A message split across many BLE fragments still arrives intact and is
     * refused by the same gate — proving the fragment layer, the Noise session
     * and the pairing gate compose.
     */
    @Test
    fun multiFragmentRequestIsReassembledAndStillGated(): Unit = runBlocking {
        val small = BleLoopbackHarness(
            context = context,
            pairedDeviceRepository = pairedDeviceRepository,
            pairingCallback = null,
            fragmentPayloadSize = 20
        )
        try {
            small.connect()
            val error = small.callExpectingError(
                "local.sign",
                JSONObject()
                    .put("keyId", "ble-multi-fragment")
                    .put("data", "A".repeat(4096))
            )
            assertNotNull("a fragmented request must still reach the gate", error)
            assertEquals(ErrorCodes.PAIRING_REQUIRED, error!!.code)
        } finally {
            small.close()
        }
    }

    // -----------------------------------------------------------------
    // The pairing gate
    // -----------------------------------------------------------------

    /**
     * Completing the handshake proves the peer holds a key, not that the user
     * approved it. Until `pairing.confirm` succeeds, every privileged method
     * must be refused.
     */
    @Test
    fun privilegedMethodsAreRefusedBeforePairing(): Unit = runBlocking {
        val privilegedMethods = listOf(
            "local.listKeys" to JSONObject(),
            "local.getCapabilities" to JSONObject(),
            "local.generateKey" to JSONObject()
                .put("keyId", UNPAIRED_KEY_ID)
                .put("keyType", "signing")
                .put("algorithm", "ES256"),
            "local.sign" to JSONObject()
                .put("keyId", UNPAIRED_KEY_ID)
                .put("data", "AAAA"),
            "local.importSharedKey" to JSONObject().put("key_id", "anything"),
            "local.syncPasswords" to JSONObject(),
            "local.pinStatus" to JSONObject()
        )

        for ((method, params) in privilegedMethods) {
            val error = harness.callExpectingError(method, params)
            assertNotNull("$method must be refused before pairing", error)
            assertEquals(
                "$method must be refused with PAIRING_REQUIRED",
                ErrorCodes.PAIRING_REQUIRED,
                error!!.code
            )
        }

        assertFalse("a refused peer must not become paired", harness.isPairingConfirmed)
        assertNull(
            "an unpaired peer must not create keys",
            XKeyDatabase.getInstance(context).keyDao().getByKeyId(UNPAIRED_KEY_ID)
        )
    }

    /**
     * The peer does not choose its own identity. A peer that handshakes with its
     * own key but claims a previously trusted one must be rejected outright —
     * otherwise it inherits that device's trust and skips the prompt.
     */
    @Test
    fun pairingConfirmCannotClaimAnotherDevicesKey(): Unit = runBlocking {
        val trustedKeyHex = "22".repeat(32)
        pairedDeviceRepository.addDevice(trustedKeyHex, "Previously Trusted BLE Laptop")
        pairedKeys += trustedKeyHex
        assertTrue(pairedDeviceRepository.isDeviceKnown(trustedKeyHex))
        assertFalse(
            "test precondition: the attacker key must differ from the trusted key",
            harness.publicKeyHex.equals(trustedKeyHex, ignoreCase = true)
        )

        val error = harness.callExpectingError(
            "pairing.confirm",
            JSONObject()
                .put("deviceName", "Previously Trusted BLE Laptop")
                .put("publicKeyHex", trustedKeyHex)
        )

        assertNotNull("claiming another device's key must be refused", error)
        assertEquals(ErrorCodes.PAIRING_REJECTED, error!!.code)
        assertFalse("a spoofed claim must not silently auto-approve", promptShown.get())
        assertFalse(harness.isPairingConfirmed)

        val followUp = harness.callExpectingError("local.listKeys", JSONObject())
        assertEquals(
            "the session must remain unpaired after a rejected claim",
            ErrorCodes.PAIRING_REQUIRED,
            followUp!!.code
        )
    }

    /** The honest path: an unknown peer prompts, is approved, and is let through. */
    @Test
    fun honestPairingIsPromptedThenAllowed(): Unit = runBlocking {
        val result = harness.confirmPairing("Honest BLE Desktop")

        assertTrue(result.optBoolean("confirmed"))
        assertTrue("an unknown device must prompt the user", promptShown.get())
        assertTrue(harness.isPairingConfirmed)
        assertTrue(
            "an approved device must be persisted under its authenticated key",
            pairedDeviceRepository.isDeviceKnown(harness.publicKeyHex)
        )

        assertNotNull(harness.call("local.listKeys").getJSONArray("keys"))
    }

    /** A user who declines leaves the session unpaired. */
    @Test
    fun declinedPairingLeavesSessionUnpaired(): Unit = runBlocking {
        userApproves.set(false)

        val error = harness.callExpectingError(
            "pairing.confirm",
            JSONObject()
                .put("deviceName", "Rejected BLE Desktop")
                .put("publicKeyHex", harness.publicKeyHex)
        )
        assertNotNull("a declined pairing must return an error", error)
        assertEquals(ErrorCodes.PAIRING_REJECTED, error!!.code)
        assertTrue("the user must actually have been asked", promptShown.get())
        assertFalse(harness.isPairingConfirmed)
        assertFalse(
            "a declined device must not be persisted",
            pairedDeviceRepository.isDeviceKnown(harness.publicKeyHex)
        )

        val followUp = harness.callExpectingError("local.listKeys", JSONObject())
        assertEquals(ErrorCodes.PAIRING_REQUIRED, followUp!!.code)
    }

    /** A device the user already approved pairs again without a second prompt. */
    @Test
    fun alreadyKnownDeviceIsAcceptedWithoutPrompting(): Unit = runBlocking {
        pairedDeviceRepository.addDevice(harness.publicKeyHex, "Returning BLE Desktop")
        promptShown.set(false)

        assertTrue(harness.confirmPairing("Returning BLE Desktop").optBoolean("confirmed"))
        assertFalse("a known device must not re-prompt", promptShown.get())
        assertTrue(harness.isPairingConfirmed)
    }

    // -----------------------------------------------------------------
    // Non-request traffic
    // -----------------------------------------------------------------

    /**
     * Responses to the phone's own outbound requests carry no method and must
     * pass the gate silently rather than being answered with an error — the
     * router owns them.
     */
    @Test
    fun responseShapedMessagesAreNotAnsweredBeforePairing(): Unit = runBlocking {
        val response = harness.exchange(
            JSONObject().put("id", 900001).put("result", JSONObject()).toString()
                .toByteArray(Charsets.UTF_8)
        )
        assertNull("a response envelope must not be answered", response)
    }

    /** Garbage that decrypts but is not JSON must be dropped, not answered. */
    @Test
    fun unparseableMessagesAreDroppedBeforePairing(): Unit = runBlocking {
        val response = harness.exchange("this is not json".toByteArray(Charsets.UTF_8))
        assertNull("an unparseable message must not be answered", response)
    }

    // -----------------------------------------------------------------
    // Prologue binding
    // -----------------------------------------------------------------

    /**
     * For a device the phone already knows, both sides bind the handshake to
     * `SHA256(initiator_pub || fingerprint || "xkey-v1")`. The responder side of
     * that formula lives in [GattServer] and the initiator side in
     * `BleClient.NoiseInitiatorSession`; if they ever diverge, every reconnect
     * to a known desktop breaks. The handshake completing is the proof.
     */
    @Test
    fun knownDeviceHandshakeBindsToTheSharedPrologue(): Unit = runBlocking {
        val fingerprint = MessageDigest.getInstance("SHA-256").digest("ble-prologue".toByteArray())
        val bound = BleLoopbackHarness(context, pairedDeviceRepository, null)
        try {
            bound.connect(knownDeviceFingerprint = fingerprint)
            assertTrue(bound.server.isSessionEstablished())
            assertArrayEquals(
                "the bound handshake must still authenticate the peer key",
                hexToBytes(bound.publicKeyHex),
                bound.responderViewOfPeerKey()
            )
        } finally {
            bound.close()
        }
    }

    /**
     * The binding must be real: a peer that computes its prologue from a
     * different fingerprint cannot complete the handshake, which is what stops a
     * relay from impersonating a known desktop.
     */
    @Test
    fun mismatchedPrologueFailsTheHandshake(): Unit = runBlocking {
        val responderFingerprint = MessageDigest.getInstance("SHA-256").digest("phone".toByteArray())
        val initiatorFingerprint = MessageDigest.getInstance("SHA-256").digest("impostor".toByteArray())
        val bound = BleLoopbackHarness(context, pairedDeviceRepository, null)
        var rejected = false
        try {
            bound.connect(
                knownDeviceFingerprint = responderFingerprint,
                initiatorFingerprintOverride = initiatorFingerprint
            )
        } catch (expected: Exception) {
            // A prologue mismatch changes the handshake hash used as AEAD
            // associated data, so the peer's static key fails to decrypt.
            rejected = true
        } finally {
            bound.close()
        }
        assertTrue("a mismatched prologue must not complete the handshake", rejected)
        assertFalse(
            "a failed handshake must leave the session unestablished",
            bound.server.isSessionEstablished()
        )
    }

    private fun hexToBytes(hex: String): ByteArray =
        ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    private companion object {
        const val UNPAIRED_KEY_ID = "ble-unpaired-attempt"
    }
}
