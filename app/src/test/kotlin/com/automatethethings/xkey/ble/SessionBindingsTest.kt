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
import com.automatethethings.xkey.protocol.SessionBinding
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
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test

/**
 * The channel binding `local.attestDevice` signs over, read from real Noise
 * handshakes between the phone's two implementations: [NoiseSession] as the
 * responder and [NoiseInitiatorSession] as the initiator.
 *
 * The binding names keys by their handshake role, so the initiator's view and
 * the responder's view of one handshake must be the same value; if they were
 * not, a desktop could never verify an attestation made on the other path.
 */
class SessionBindingsTest {

    private companion object {
        const val KEY_SIZE = 32

        fun randomBytes(size: Int): ByteArray =
            ByteArray(size).also { SecureRandom().nextBytes(it) }
    }

    private lateinit var context: Context

    @Before
    fun setUp() {
        NoiseTestKeyStore.install()
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
    // No binding before the handshake completes
    // -----------------------------------------------------------------

    @Test
    fun responderHasNoBindingUntilTheFinalMessage() = runTest {
        val initiator = NoiseInitiatorSession(randomBytes(KEY_SIZE))
        val responder = newResponder()
        assertNull("a fresh responder has no channel to bind", responder.sessionBinding())

        val msg2 = responder.processHandshakeMessage(initiator.createHandshakeMessage1())!!
        assertNull("msg1 alone does not complete the responder", responder.sessionBinding())

        initiator.processHandshakeMessage2(msg2)
        assertNull("msg2 sent is not complete for the responder", responder.sessionBinding())

        responder.processHandshakeMessage(initiator.createHandshakeMessage3())
        assertNotNull("msg3 completes the responder", responder.sessionBinding())
    }

    @Test
    fun initiatorHasNoBindingUntilItFinalizes() = runTest {
        val initiator = NoiseInitiatorSession(randomBytes(KEY_SIZE))
        val responder = newResponder()
        assertNull("a fresh initiator has no channel to bind", initiator.sessionBinding())

        val msg2 = responder.processHandshakeMessage(initiator.createHandshakeMessage1())!!
        assertNull("msg1 sent does not complete the initiator", initiator.sessionBinding())

        initiator.processHandshakeMessage2(msg2)
        assertNull(
            "the responder's static key is known after msg2, but the handshake is not complete",
            initiator.sessionBinding()
        )

        responder.processHandshakeMessage(initiator.createHandshakeMessage3())
        assertNull("msg3 sent is not complete until the initiator finalizes", initiator.sessionBinding())

        initiator.finalizeHandshake()
        assertNotNull("finalizing completes the initiator", initiator.sessionBinding())
    }

    // -----------------------------------------------------------------
    // The binding of a completed handshake
    // -----------------------------------------------------------------

    @Test
    fun responderBindingNamesKeysByHandshakeRole() = runTest {
        val initiator = NoiseInitiatorSession(randomBytes(KEY_SIZE))
        val responder = newResponder()
        handshake(initiator, responder)

        val binding = responder.sessionBinding()!!
        assertArrayEquals(
            "the initiator key is the peer's: the desktop opened the handshake",
            initiator.getLocalStaticPublicKey(),
            binding.initiatorStaticPublicKey
        )
        assertArrayEquals(
            "the responder key is this phone's own",
            responder.getStaticPublicKey(),
            binding.responderStaticPublicKey
        )
        assertArrayEquals("a first pairing runs under an empty prologue", ByteArray(0), binding.prologue)
    }

    @Test
    fun initiatorBindingNamesKeysByHandshakeRoleNotDeviceRole() = runTest {
        val initiator = NoiseInitiatorSession(randomBytes(KEY_SIZE))
        val responder = newResponder()
        handshake(initiator, responder)

        val binding = initiator.sessionBinding()!!
        assertArrayEquals(
            "when the phone dials, its own key is the initiator's",
            initiator.getLocalStaticPublicKey(),
            binding.initiatorStaticPublicKey
        )
        assertArrayEquals(
            "and the desktop's key is the responder's",
            responder.getStaticPublicKey(),
            binding.responderStaticPublicKey
        )
        assertArrayEquals(ByteArray(0), binding.prologue)
    }

    @Test
    fun bothEndsOfAFirstPairingComputeTheSameBinding() = runTest {
        val initiator = NoiseInitiatorSession(randomBytes(KEY_SIZE))
        val responder = newResponder()
        handshake(initiator, responder)

        assertSameBinding(initiator.sessionBinding()!!, responder.sessionBinding()!!)
    }

    @Test
    fun bothEndsOfAKnownDeviceReconnectBindTheSamePrologue() = runTest {
        val initiator = NoiseInitiatorSession(randomBytes(KEY_SIZE))
        val fingerprint = randomBytes(KEY_SIZE)
        initiator.processIdentityAck(byteArrayOf(0x01) + fingerprint)
        val prologue = prologueOf(initiator.getLocalStaticPublicKey(), fingerprint)

        val responder = newResponder()
        responder.setPrologue(prologue)
        responder.reset()
        handshake(initiator, responder)

        val initiatorView = initiator.sessionBinding()!!
        val responderView = responder.sessionBinding()!!
        assertArrayEquals("the reconnect prologue is bound", prologue, responderView.prologue)
        assertSameBinding(initiatorView, responderView)
    }

    @Test
    fun aFirstPairingAndAReconnectOfTheSameKeysBindDifferently() = runTest {
        val key = randomBytes(KEY_SIZE)
        val first = NoiseInitiatorSession(key)
        val firstResponder = newResponder()
        handshake(first, firstResponder)

        val reconnect = NoiseInitiatorSession(key)
        val fingerprint = randomBytes(KEY_SIZE)
        reconnect.processIdentityAck(byteArrayOf(0x01) + fingerprint)
        val reconnectResponder = newResponder()
        reconnectResponder.setPrologue(prologueOf(reconnect.getLocalStaticPublicKey(), fingerprint))
        reconnectResponder.reset()
        handshake(reconnect, reconnectResponder)

        assertArrayEquals(
            first.sessionBinding()!!.initiatorStaticPublicKey,
            reconnect.sessionBinding()!!.initiatorStaticPublicKey
        )
        assertFalse(
            "the prologue keeps a first pairing and a reconnect apart",
            first.sessionBinding()!!.prologue.contentEquals(reconnect.sessionBinding()!!.prologue)
        )
    }

    // -----------------------------------------------------------------
    // copyOf
    // -----------------------------------------------------------------

    @Test
    fun copyOfDoesNotAliasTheOriginal() {
        val original = SessionBinding(randomBytes(KEY_SIZE), randomBytes(KEY_SIZE), randomBytes(KEY_SIZE))
        val initiatorKey = original.initiatorStaticPublicKey.copyOf()
        val responderKey = original.responderStaticPublicKey.copyOf()
        val prologue = original.prologue.copyOf()

        val copy = original.copyOf()
        assertNotSame(original.initiatorStaticPublicKey, copy.initiatorStaticPublicKey)
        assertNotSame(original.responderStaticPublicKey, copy.responderStaticPublicKey)
        assertNotSame(original.prologue, copy.prologue)
        assertSameBinding(original, copy)

        copy.initiatorStaticPublicKey.fill(0)
        copy.responderStaticPublicKey.fill(0)
        copy.prologue.fill(0)

        assertArrayEquals(initiatorKey, original.initiatorStaticPublicKey)
        assertArrayEquals(responderKey, original.responderStaticPublicKey)
        assertArrayEquals(prologue, original.prologue)
    }

    @Test
    fun copyOfAnEmptyPrologueIsEmpty() {
        val copy = SessionBinding(randomBytes(KEY_SIZE), randomBytes(KEY_SIZE), ByteArray(0)).copyOf()
        assertEquals(0, copy.prologue.size)
    }

    @Test
    fun mutatingACopyLeavesTheSessionsUnchanged() = runTest {
        val key = randomBytes(KEY_SIZE)
        val fingerprint = randomBytes(KEY_SIZE)
        val initiator = NoiseInitiatorSession(key)
        initiator.processIdentityAck(byteArrayOf(0x01) + fingerprint)
        val responder = newResponder()
        responder.setPrologue(prologueOf(initiator.getLocalStaticPublicKey(), fingerprint))
        responder.reset()
        handshake(initiator, responder)

        val initiatorBefore = snapshot(initiator.sessionBinding()!!)
        val responderBefore = snapshot(responder.sessionBinding()!!)

        for (copy in listOf(initiator.sessionBinding()!!.copyOf(), responder.sessionBinding()!!.copyOf())) {
            copy.initiatorStaticPublicKey.fill(0)
            copy.responderStaticPublicKey.fill(0)
            copy.prologue.fill(0)
        }

        assertSameBinding(initiatorBefore, initiator.sessionBinding()!!)
        assertSameBinding(responderBefore, responder.sessionBinding()!!)
    }

    /**
     * The responder's binding is built from copies of its keys; the initiator's
     * must be too. A binding that shares the session's own arrays lets a caller
     * that edits it rewrite the keys the session authenticated.
     */
    @Test
    fun initiatorBindingDoesNotAliasTheSessionKeys() = runTest {
        val initiator = NoiseInitiatorSession(randomBytes(KEY_SIZE))
        val responder = newResponder()
        handshake(initiator, responder)
        val localKey = initiator.getLocalStaticPublicKey().copyOf()
        val remoteKey = initiator.getRemoteStaticKey()!!.copyOf()

        val binding = initiator.sessionBinding()!!
        binding.initiatorStaticPublicKey.fill(0)
        binding.responderStaticPublicKey.fill(0)

        assertArrayEquals("the initiator's own key", localKey, initiator.getLocalStaticPublicKey())
        assertArrayEquals("the authenticated responder key", remoteKey, initiator.getRemoteStaticKey())
        assertArrayEquals(localKey, initiator.sessionBinding()!!.initiatorStaticPublicKey)
    }

    @Test
    fun responderBindingDoesNotAliasTheSessionKeys() = runTest {
        val initiator = NoiseInitiatorSession(randomBytes(KEY_SIZE))
        val responder = newResponder()
        handshake(initiator, responder)
        val localKey = responder.getStaticPublicKey()!!.copyOf()
        val remoteKey = responder.getRemoteStaticKey()!!.copyOf()

        val binding = responder.sessionBinding()!!
        binding.initiatorStaticPublicKey.fill(0)
        binding.responderStaticPublicKey.fill(0)

        assertArrayEquals(localKey, responder.getStaticPublicKey())
        assertArrayEquals(remoteKey, responder.getRemoteStaticKey())
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private suspend fun newResponder(): NoiseSession =
        NoiseSession().also { it.loadStaticKey(context) }

    /** Runs the three XX messages between the two implementations. */
    private suspend fun handshake(initiator: NoiseInitiatorSession, responder: NoiseSession) {
        val msg2 = responder.processHandshakeMessage(initiator.createHandshakeMessage1())
            ?: throw AssertionError("the responder produced no msg2")
        initiator.processHandshakeMessage2(msg2)
        assertNull(responder.processHandshakeMessage(initiator.createHandshakeMessage3()))
        initiator.finalizeHandshake()
    }

    /** The prologue formula both sides and the desktop share. */
    private fun prologueOf(publicKey: ByteArray, fingerprint: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").run {
            update(publicKey)
            update(fingerprint)
            update("xkey-v1".toByteArray(Charsets.UTF_8))
            digest()
        }

    private fun snapshot(binding: SessionBinding): SessionBinding =
        SessionBinding(
            binding.initiatorStaticPublicKey.copyOf(),
            binding.responderStaticPublicKey.copyOf(),
            binding.prologue.copyOf()
        )

    private fun assertSameBinding(expected: SessionBinding, actual: SessionBinding) {
        assertArrayEquals("initiator key", expected.initiatorStaticPublicKey, actual.initiatorStaticPublicKey)
        assertArrayEquals("responder key", expected.responderStaticPublicKey, actual.responderStaticPublicKey)
        assertArrayEquals("prologue", expected.prologue, actual.prologue)
    }
}
