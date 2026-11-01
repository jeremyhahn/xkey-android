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
import android.util.Log
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import java.security.MessageDigest
import java.security.SecureRandom
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

/**
 * The Noise_XX_25519_ChaChaPoly_SHA256 session, driven end to end on the JVM.
 *
 * The app ships *two* independent Noise implementations: [NoiseSession] is the
 * responder the phone runs behind every transport, and [NoiseInitiatorSession]
 * (declared in `BleClient.kt`) is the initiator the phone runs when it dials a
 * desktop. Both re-implement `go-xkms/xkey/pkg/pairing` from scratch, so a
 * divergence between them — or against the Noise spec — is a silent wire break.
 *
 * Running the pair against each other proves the transcript rules they share:
 * message sizes, the prologue binding used for trusted-device pinning, AEAD
 * framing, and the nonce discipline of the transport phase. None of it needs a
 * radio, a Context, or Android Keystore:
 *
 *  - [NoiseInitiatorSession] is pure `java.security` / `javax.crypto`.
 *  - [NoiseSession.loadStaticKey] cannot reach `EncryptedSharedPreferences`
 *    off-device, and its documented fallback is to generate a fresh static key
 *    in-memory. That fallback is exactly what a unit test wants, and exercising
 *    it also covers the recovery path a device with a wiped keystore takes.
 *
 * Only `android.util.Log` has to be stubbed.
 */
class NoiseHandshakeTest {

    private companion object {
        /** The `<- e, ee, s, es` message: 32 + (32 + 16) + 16. */
        const val MSG2_SIZE = 96

        /** The `-> s, se` message: (32 + 16) + 16. */
        const val MSG3_SIZE = 64

        const val KEY_SIZE = 32

        fun randomBytes(size: Int): ByteArray =
            ByteArray(size).also { SecureRandom().nextBytes(it) }
    }

    /**
     * Only ever used to reach [NoiseSession.loadStaticKey]'s in-memory
     * fallback; no framework call on it is expected to succeed.
     */
    private lateinit var context: Context

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.v(any(), any<String>()) } returns 0
        every { Log.d(any(), any<String>()) } returns 0
        every { Log.i(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.e(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>(), any()) } returns 0
        every { Log.e(any(), any<String>(), any()) } returns 0
        context = mockk(relaxed = true)
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    // -----------------------------------------------------------------
    // The handshake
    // -----------------------------------------------------------------

    /**
     * The property everything else rests on: after XX, each side holds the
     * other's *authenticated* static key. The responder's copy is what
     * `GattServer` records as the peer identity, so if this ever drifts the
     * pairing gate is trusting the wrong key.
     */
    @Test
    fun fullHandshakeAuthenticatesBothStaticKeys() = runTest {
        val initiatorKey = randomBytes(KEY_SIZE)
        val initiator = NoiseInitiatorSession(initiatorKey)
        val responder = newResponder()

        handshake(initiator, responder)

        assertTrue("responder must complete", responder.isHandshakeComplete())
        assertTrue("initiator must complete", initiator.isHandshakeComplete())
        assertArrayEquals(
            "the responder must learn the initiator's own static key",
            initiator.getLocalStaticPublicKey(),
            responder.getRemoteStaticKey()
        )
        assertArrayEquals(
            "the initiator must learn the responder's own static key",
            responder.getStaticPublicKey(),
            initiator.getRemoteStaticKey()
        )
    }

    /**
     * Pins the three message sizes. The Go initiator slices these offsets
     * verbatim, so a change here breaks every desktop even though both Kotlin
     * sides would still agree with each other.
     */
    @Test
    fun handshakeMessageSizesMatchTheWireContract() = runTest {
        val initiator = NoiseInitiatorSession(randomBytes(KEY_SIZE))
        val responder = newResponder()

        val msg1 = initiator.createHandshakeMessage1()
        assertEquals("msg1 is a bare ephemeral public key", KEY_SIZE, msg1.size)

        val msg2 = responder.processHandshakeMessage(msg1)!!
        assertEquals("msg2 is e + encrypted s + encrypted empty payload", MSG2_SIZE, msg2.size)

        initiator.processHandshakeMessage2(msg2)
        val msg3 = initiator.createHandshakeMessage3()
        assertEquals("msg3 is encrypted s + encrypted empty payload", MSG3_SIZE, msg3.size)

        assertNull("the responder never replies to msg3", responder.processHandshakeMessage(msg3))
    }

    /** Two sessions must never derive the same ephemeral or transcript. */
    @Test
    fun everySessionUsesFreshEphemeralKeys() = runTest {
        val key = randomBytes(KEY_SIZE)
        val first = NoiseInitiatorSession(key).createHandshakeMessage1()
        val second = NoiseInitiatorSession(key).createHandshakeMessage1()

        assertFalse(
            "the same static key must not yield the same ephemeral",
            first.contentEquals(second)
        )
    }

    // -----------------------------------------------------------------
    // Identity exchange and the prologue binding
    // -----------------------------------------------------------------

    /** The 33-byte pre-handshake identity frame: version byte then the key. */
    @Test
    fun identityMessageIsVersionedAndCarriesTheStaticKey() {
        val initiator = NoiseInitiatorSession(randomBytes(KEY_SIZE))
        val message = initiator.createIdentityMessage()

        assertEquals(1 + KEY_SIZE, message.size)
        assertEquals("version byte", 0x01.toByte(), message[0])
        assertArrayEquals(
            initiator.getLocalStaticPublicKey(),
            message.copyOfRange(1, message.size)
        )
    }

    /**
     * A known-device ack binds the handshake to
     * `SHA256(initiator_pub || responder_fingerprint || "xkey-v1")`. Both sides
     * must derive it identically or the transcript hashes diverge.
     */
    @Test
    fun knownDeviceAckBindsBothSidesToTheSamePrologue() = runTest {
        val initiator = NoiseInitiatorSession(randomBytes(KEY_SIZE))
        val fingerprint = randomBytes(KEY_SIZE)

        initiator.processIdentityAck(byteArrayOf(0x01) + fingerprint)

        val responder = newResponder()
        responder.setPrologue(prologueOf(initiator.getLocalStaticPublicKey(), fingerprint))
        responder.reset()

        handshake(initiator, responder)
        assertTrue(responder.isHandshakeComplete())
    }

    /**
     * The binding is real: a responder that believes in a different fingerprint
     * produces a transcript the initiator cannot authenticate. This is what
     * stops a relay from substituting itself for a pinned desktop.
     */
    @Test
    fun aMismatchedPrologueBreaksTheHandshake() = runTest {
        val initiator = NoiseInitiatorSession(randomBytes(KEY_SIZE))
        initiator.processIdentityAck(byteArrayOf(0x01) + randomBytes(KEY_SIZE))

        val responder = newResponder()
        responder.setPrologue(prologueOf(initiator.getLocalStaticPublicKey(), randomBytes(KEY_SIZE)))
        responder.reset()

        val msg2 = responder.processHandshakeMessage(initiator.createHandshakeMessage1())!!
        try {
            initiator.processHandshakeMessage2(msg2)
            fail("a handshake bound to a different fingerprint must not authenticate")
        } catch (expected: Exception) {
            // AEAD authentication fails because the transcript hashes diverge.
        }
    }

    /** An unknown-device ack (`[0x00]`) leaves the prologue empty. */
    @Test
    fun unknownDeviceAckLeavesThePrologueEmpty() = runTest {
        val initiator = NoiseInitiatorSession(randomBytes(KEY_SIZE))
        initiator.processIdentityAck(byteArrayOf(0x00))

        handshake(initiator, newResponder())
        assertTrue(initiator.isHandshakeComplete())
    }

    /**
     * A truncated "known device" ack carries no usable fingerprint, so it is
     * treated as a new device rather than binding to garbage.
     */
    @Test
    fun truncatedKnownDeviceAckFallsBackToTheNewDevicePath() = runTest {
        val initiator = NoiseInitiatorSession(randomBytes(KEY_SIZE))
        initiator.processIdentityAck(byteArrayOf(0x01) + randomBytes(8))

        handshake(initiator, newResponder())
        assertTrue(initiator.isHandshakeComplete())
    }

    @Test
    fun emptyIdentityAckIsRejected() {
        val initiator = NoiseInitiatorSession(randomBytes(KEY_SIZE))
        try {
            initiator.processIdentityAck(ByteArray(0))
            fail("an empty identity acknowledgment must be rejected")
        } catch (expected: NoiseException) {
            // expected
        }
    }

    // -----------------------------------------------------------------
    // Malformed handshake input
    // -----------------------------------------------------------------

    /** msg1 is a bare 32-byte key; anything else is not a handshake. */
    @Test
    fun responderRejectsAnInitMessageOfTheWrongSize() = runTest {
        val responder = newResponder()
        try {
            responder.processHandshakeMessage(randomBytes(KEY_SIZE - 1))
            fail("expected an oversized/undersized init to be rejected")
        } catch (expected: NoiseException) {
            // expected
        }
    }

    @Test
    fun initiatorRejectsAShortSecondMessage() {
        val initiator = NoiseInitiatorSession(randomBytes(KEY_SIZE))
        initiator.createHandshakeMessage1()
        try {
            initiator.processHandshakeMessage2(randomBytes(MSG2_SIZE - 1))
            fail("expected a truncated msg2 to be rejected")
        } catch (expected: NoiseException) {
            // expected
        }
    }

    /** Once XX is complete the state machine accepts no further handshake frames. */
    @Test
    fun responderRefusesAFurtherHandshakeMessageAfterCompletion() = runTest {
        val responder = newResponder()
        handshake(NoiseInitiatorSession(randomBytes(KEY_SIZE)), responder)

        try {
            responder.processHandshakeMessage(randomBytes(KEY_SIZE))
            fail("expected a post-handshake frame to be refused")
        } catch (expected: NoiseException) {
            assertTrue(expected.message!!.contains("already complete"))
        }
    }

    /**
     * A responder that decrypts a corrupt msg3 must fail loudly rather than
     * splitting into transport keys neither side agrees on.
     */
    @Test
    fun responderRejectsACorruptFinalMessage() = runTest {
        val initiator = NoiseInitiatorSession(randomBytes(KEY_SIZE))
        val responder = newResponder()

        initiator.processHandshakeMessage2(
            responder.processHandshakeMessage(initiator.createHandshakeMessage1())!!
        )
        val msg3 = initiator.createHandshakeMessage3()
        msg3[0] = (msg3[0].toInt() xor 0x01).toByte()

        try {
            responder.processHandshakeMessage(msg3)
            fail("expected a tampered msg3 to fail authentication")
        } catch (expected: Exception) {
            assertFalse("the session must not be usable", responder.isHandshakeComplete())
        }
    }

    // -----------------------------------------------------------------
    // Transport phase
    // -----------------------------------------------------------------

    @Test
    fun transportRoundTripsInBothDirections() = runTest {
        val initiator = NoiseInitiatorSession(randomBytes(KEY_SIZE))
        val responder = newResponder()
        handshake(initiator, responder)

        val request = """{"id":1,"method":"local.getCapabilities"}""".toByteArray()
        assertArrayEquals(request, responder.decrypt(initiator.encrypt(request)))

        val response = """{"id":1,"result":{}}""".toByteArray()
        assertArrayEquals(response, initiator.decrypt(responder.encrypt(response)))
    }

    /** Each message must use a fresh nonce, so identical plaintext differs. */
    @Test
    fun everyTransportMessageUsesAFreshNonce() = runTest {
        val initiator = NoiseInitiatorSession(randomBytes(KEY_SIZE))
        val responder = newResponder()
        handshake(initiator, responder)

        val plaintext = "ping".toByteArray()
        val first = initiator.encrypt(plaintext)
        val second = initiator.encrypt(plaintext)

        assertFalse("nonce reuse would leak the keystream", first.contentEquals(second))
        assertArrayEquals(plaintext, responder.decrypt(first))
        assertArrayEquals(plaintext, responder.decrypt(second))
    }

    /** A flipped bit anywhere in the frame must fail the Poly1305 tag. */
    @Test
    fun tamperedTransportCiphertextIsRejected() = runTest {
        val initiator = NoiseInitiatorSession(randomBytes(KEY_SIZE))
        val responder = newResponder()
        handshake(initiator, responder)

        val ciphertext = initiator.encrypt("ping".toByteArray())
        ciphertext[ciphertext.size / 2] = (ciphertext[ciphertext.size / 2].toInt() xor 0x40).toByte()

        try {
            responder.decrypt(ciphertext)
            fail("expected the AEAD tag to reject a tampered frame")
        } catch (expected: Exception) {
            // expected
        }
    }

    /**
     * Documents the transport's ordering requirement. The counter is derived
     * from a local monotonic nonce with no replay window, so a frame that
     * arrives out of order cannot be decrypted — and, because the counter is
     * advanced before the AEAD runs, the receive direction stays desynchronised
     * afterwards. Anything that can drop or reorder a frame must tear the
     * session down rather than retry.
     */
    @Test
    fun transportFramesMustArriveInOrder() = runTest {
        val initiator = NoiseInitiatorSession(randomBytes(KEY_SIZE))
        val responder = newResponder()
        handshake(initiator, responder)

        val first = initiator.encrypt("first".toByteArray())
        val second = initiator.encrypt("second".toByteArray())

        try {
            responder.decrypt(second)
            fail("expected an out-of-order frame to fail")
        } catch (expected: Exception) {
            // expected
        }
        try {
            responder.decrypt(first)
            fail("the receive counter is not rewound, so recovery is impossible")
        } catch (expected: Exception) {
            // expected
        }
    }

    @Test
    fun transportIsRefusedBeforeTheHandshakeCompletes() = runTest {
        val responder = newResponder()
        assertFalse(responder.isHandshakeComplete())
        assertThrowsNoise { responder.encrypt("x".toByteArray()) }
        assertThrowsNoise { responder.decrypt(randomBytes(32)) }

        val initiator = NoiseInitiatorSession(randomBytes(KEY_SIZE))
        assertFalse(initiator.isHandshakeComplete())
        assertThrowsNoise { initiator.encrypt("x".toByteArray()) }
        assertThrowsNoise { initiator.decrypt(randomBytes(32)) }
    }

    // -----------------------------------------------------------------
    // Session reuse
    // -----------------------------------------------------------------

    /**
     * `reset()` is what a reconnect runs. It must drop the transport keys and
     * make the same responder usable for a brand new peer, while keeping the
     * device's long-term static identity.
     */
    @Test
    fun resetDropsTransportKeysAndAllowsAFreshPeer() = runTest {
        val responder = newResponder()
        handshake(NoiseInitiatorSession(randomBytes(KEY_SIZE)), responder)
        val staticKey = responder.getStaticPublicKey()!!.copyOf()

        responder.reset()

        assertFalse("the old session must be gone", responder.isHandshakeComplete())
        assertNull("the old peer identity must be gone", responder.getRemoteStaticKey())
        assertThrowsNoise { responder.encrypt("x".toByteArray()) }
        assertArrayEquals("the static identity must survive", staticKey, responder.getStaticPublicKey())

        val second = NoiseInitiatorSession(randomBytes(KEY_SIZE))
        handshake(second, responder)
        assertArrayEquals(second.getLocalStaticPublicKey(), responder.getRemoteStaticKey())
    }

    // -----------------------------------------------------------------
    // Static key storage
    // -----------------------------------------------------------------

    /**
     * `BleClient` asks for the stored static key so the phone dials out under
     * the same identity it answers on. When encrypted storage is unreachable
     * the contract is null — never a partially decoded key.
     */
    @Test
    fun storedStaticKeyPairIsNullWhenSecureStorageIsUnreachable() = runTest {
        assertNull(NoiseSession.getStoredStaticKeyPair(context))
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    /**
     * Builds the responder the phone would build. `loadStaticKey` falls back to
     * an in-memory key when encrypted storage is unavailable, which is the case
     * off-device — see the class KDoc.
     */
    private suspend fun newResponder(): NoiseSession =
        NoiseSession().also { it.loadStaticKey(context) }

    /** Runs the three XX messages between the two implementations. */
    private suspend fun handshake(initiator: NoiseInitiatorSession, responder: NoiseSession) {
        val msg2 = responder.processHandshakeMessage(initiator.createHandshakeMessage1())
            ?: throw AssertionError("the responder produced no msg2")
        initiator.processHandshakeMessage2(msg2)
        assertNull(
            "the responder must not reply to msg3",
            responder.processHandshakeMessage(initiator.createHandshakeMessage3())
        )
        initiator.finalizeHandshake()
    }

    /** The prologue formula both sides and `go-xkms` share. */
    private fun prologueOf(publicKey: ByteArray, fingerprint: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").run {
            update(publicKey)
            update(fingerprint)
            update("xkey-v1".toByteArray(Charsets.UTF_8))
            digest()
        }

    private fun assertThrowsNoise(block: () -> Unit) {
        try {
            block()
            fail("expected NoiseException")
        } catch (expected: NoiseException) {
            // expected
        }
    }
}
