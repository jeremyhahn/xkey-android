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
import java.security.SecureRandom
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * [NoiseSession] overwrites its key material before it lets go of it (#6).
 *
 * The session's live arrays are reached through
 * [NoiseSession.secretArraysForTest]; a test keeps the references, drives the
 * session past the point where it should release them, and checks that every
 * byte is zero. Zeroization on the JVM is best effort (see the class KDoc):
 * these tests prove the session overwrites the arrays it owns, nothing more.
 *
 * The rest of the harness is the one [NoiseHandshakeTest] uses: the responder
 * runs against [NoiseInitiatorSession], and `loadStaticKey` falls back to an
 * in-memory static key off-device.
 */
class NoiseSessionZeroizationTest {

    private companion object {
        const val KEY_SIZE = 32

        /** The handshake secrets a responder holds once it has answered msg1. */
        val HANDSHAKE_SECRETS = setOf("ephemeralPrivateKey", "chainingKey", "handshakeHash", "encryptionKey")

        /** The transport keys a responder holds once the handshake is complete. */
        val TRANSPORT_SECRETS = setOf("sendKey", "recvKey")

        fun randomBytes(size: Int): ByteArray =
            ByteArray(size).also { SecureRandom().nextBytes(it) }

        fun ByteArray.isAllZero(): Boolean = all { it == 0.toByte() }
    }

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

    // ---------------------------------------------------------------------
    // reset()
    // ---------------------------------------------------------------------

    /**
     * A reconnect in the middle of a handshake: every handshake secret the
     * responder held is zero after `reset()`.
     */
    @Test
    fun resetMidHandshakeOverwritesTheHandshakeSecrets() = runTest {
        val responder = newResponder()
        responder.processHandshakeMessage(NoiseInitiatorSession(randomBytes(KEY_SIZE)).createHandshakeMessage1())
        val held = responder.secretArraysForTest()
        assertTrue("the responder holds ${held.keys}", held.keys.containsAll(HANDSHAKE_SECRETS))

        responder.reset()

        assertAllZero(held - "staticPrivateKey")
    }

    /**
     * A reconnect after a completed session: every array the session held over
     * its lifetime, from msg1 through the transport keys, is zero after
     * `reset()`. The static private key is the device identity and survives.
     */
    @Test
    fun resetOverwritesEveryTransientSecretOfACompletedSession() = runTest {
        val responder = newResponder()
        val initiator = NoiseInitiatorSession(randomBytes(KEY_SIZE))
        val msg2 = responder.processHandshakeMessage(initiator.createHandshakeMessage1())
            ?: throw AssertionError("the responder produced no msg2")
        val duringHandshake = responder.secretArraysForTest()
        initiator.processHandshakeMessage2(msg2)
        responder.processHandshakeMessage(initiator.createHandshakeMessage3())
        initiator.finalizeHandshake()
        val afterHandshake = responder.secretArraysForTest()
        assertTrue("the responder holds ${afterHandshake.keys}", afterHandshake.keys.containsAll(TRANSPORT_SECRETS))

        val staticKey = afterHandshake.getValue("staticPrivateKey")
        val staticKeyBytes = staticKey.copyOf()

        responder.reset()

        assertAllZero(duringHandshake - "staticPrivateKey")
        assertAllZero(afterHandshake - "staticPrivateKey")
        assertArrayEquals("the static private key must survive a reset", staticKeyBytes, staticKey)
        assertFalse("the static private key must not be zero", staticKey.isAllZero())
    }

    /**
     * Split ends the handshake: the ephemeral private key, the chaining key and
     * the handshake encryption key are overwritten as soon as the transport
     * keys exist, without waiting for a reset.
     */
    @Test
    fun completingTheHandshakeOverwritesTheHandshakeKeys() = runTest {
        val responder = newResponder()
        val initiator = NoiseInitiatorSession(randomBytes(KEY_SIZE))
        val msg2 = responder.processHandshakeMessage(initiator.createHandshakeMessage1())
            ?: throw AssertionError("the responder produced no msg2")
        val ephemeralPrivateKey = responder.secretArraysForTest().getValue("ephemeralPrivateKey")
        initiator.processHandshakeMessage2(msg2)
        responder.processHandshakeMessage(initiator.createHandshakeMessage3())

        val held = responder.secretArraysForTest()
        assertTrue("the ephemeral private key must be zero", ephemeralPrivateKey.isAllZero())
        assertFalse("the ephemeral private key must be dropped", "ephemeralPrivateKey" in held)
        assertFalse("the handshake key must be dropped", "encryptionKey" in held)
        assertTrue("the chaining key must be zero", held.getValue("chainingKey").isAllZero())
        assertFalse("the send key must be live", held.getValue("sendKey").isAllZero())
        assertFalse("the receive key must be live", held.getValue("recvKey").isAllZero())
    }

    // ---------------------------------------------------------------------
    // The protocol still works
    // ---------------------------------------------------------------------

    // ---------------------------------------------------------------------
    // Keys handed out
    // ---------------------------------------------------------------------

    /**
     * A key a caller took from a getter is the caller's: a `reset()` cannot
     * zero it or swap it, and editing it cannot reach into the session.
     */
    @Test
    fun aKeyHandedOutByAGetterSurvivesAReset() = runTest {
        val responder = newResponder()
        val initiator = NoiseInitiatorSession(randomBytes(KEY_SIZE))
        handshake(initiator, responder)

        val remoteStatic = responder.getRemoteStaticKey()!!
        val localStatic = responder.getStaticPublicKey()!!
        val localStaticBytes = localStatic.copyOf()

        responder.reset()

        assertNull("the session must drop the peer identity", responder.getRemoteStaticKey())
        assertArrayEquals(initiator.getLocalStaticPublicKey(), remoteStatic)
        assertArrayEquals(localStaticBytes, localStatic)

        localStatic.fill(0)
        assertArrayEquals(
            "editing a handed-out key must not reach the session",
            localStaticBytes,
            responder.getStaticPublicKey()
        )
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

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

    private fun assertAllZero(arrays: Map<String, ByteArray>) {
        arrays.forEach { (name, array) ->
            assertTrue("$name must be all zeros", array.isAllZero())
        }
    }
}
