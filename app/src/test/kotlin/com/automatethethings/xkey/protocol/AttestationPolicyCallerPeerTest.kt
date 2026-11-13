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

package com.automatethethings.xkey.protocol

import android.app.KeyguardManager
import android.app.NotificationManager
import android.content.Context
import android.os.Looper
import android.util.Log
import com.automatethethings.xkey.auth.BiometricActivityLauncher
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.settings.AttestationBiometricPolicy
import com.automatethethings.xkey.settings.BiometricSettingsData
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.storage.XKeyDatabase
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import java.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.withContext
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The attestation biometric policy answers to the peer of the session a
 * request arrived on (PR #42).
 *
 * A phone-initiated session passes its own peer through
 * [RequestHandler.handleRawRequest]; the transport-installed peer belongs to
 * whichever desktop the phone is *serving*. Under `PAIRED_DEVICES_SKIP` the
 * prompt used to be decided by that installed peer, so re-attesting a paired
 * desktop prompted whenever no incoming session existed, and an unrelated
 * incoming session's trust decided it when one did.
 *
 * This drives the real handler, not a stand-in. Only its Android edges are
 * mocked: the database, the keyguard and notification services, the main
 * looper and the biometric launcher, whose `requestAuthentication` call *is*
 * the prompt. With no AndroidKeyStore on the JVM, the attestation fails after
 * the policy is applied, so these tests count prompts and never assert a
 * successful attestation.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class AttestationPolicyCallerPeerTest {

    private lateinit var biometricLauncher: BiometricActivityLauncher
    private lateinit var handler: RequestHandler

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

        // BiometricNotificationHelper builds a Handler on the main looper.
        mockkStatic(Looper::class)
        every { Looper.getMainLooper() } returns mockk(relaxed = true)

        // The handler's DAOs come from the Room singleton.
        mockkObject(XKeyDatabase.Companion)
        every { XKeyDatabase.getInstance(any()) } returns mockk(relaxed = true)

        Dispatchers.setMain(UnconfinedTestDispatcher())

        val context = mockk<Context>(relaxed = true)
        // A relaxed KeyguardManager reports the screen unlocked, so no
        // lock-screen notification is raised around a prompt.
        every { context.getSystemService(Context.KEYGUARD_SERVICE) } returns
            mockk<KeyguardManager>(relaxed = true)
        every { context.getSystemService(NotificationManager::class.java) } returns
            mockk<NotificationManager>(relaxed = true)

        val pairedDevices = mockk<PairedDeviceRepository>()
        every { pairedDevices.isDeviceKnown(any()) } answers { firstArg<String>() == PAIRED_PEER }

        biometricLauncher = mockk(relaxed = true)
        handler = RequestHandler(
            context = context,
            keystoreManager = mockk<KeystoreManager>(relaxed = true),
            biometricLauncher = biometricLauncher,
            sessionAuthManager = null,
            pairedDeviceRepository = pairedDevices
        )
        handler.updateSettings(
            BiometricSettingsData(attestationBiometricPolicy = AttestationBiometricPolicy.PAIRED_DEVICES_SKIP)
        )
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
        unmockkAll()
    }

    // -----------------------------------------------------------------
    // A caller session: the outgoing peer decides
    // -----------------------------------------------------------------

    /** A paired desktop, re-attested with nothing incoming. */
    @Test
    fun aPairedOutgoingPeerWithNoIncomingSessionIsNotPrompted() = runTest {
        handler.handleRawRequest(attestRequest(), outgoingBinding, PAIRED_PEER)

        assertPrompts(0)
    }

    @Test
    fun anUnpairedOutgoingPeerIsPrompted() = runTest {
        handler.handleRawRequest(attestRequest(), outgoingBinding, UNPAIRED_PEER)

        assertPrompts(1)
    }

    /**
     * An incoming session to a different, unpaired desktop must not lend the
     * outgoing call its trust, or its lack of it.
     */
    @Test
    fun anUnpairedIncomingPeerDoesNotDecideAPairedOutgoingCall() = runTest {
        serveIncomingSession(UNPAIRED_PEER)

        handler.handleRawRequest(attestRequest(), outgoingBinding, PAIRED_PEER)

        assertPrompts(0)
    }

    /** The same mix-up in the other direction: an exemption borrowed, not earned. */
    @Test
    fun aPairedIncomingPeerDoesNotExemptAnUnpairedOutgoingCall() = runTest {
        serveIncomingSession(PAIRED_PEER)

        handler.handleRawRequest(attestRequest(), outgoingBinding, UNPAIRED_PEER)

        assertPrompts(1)
    }

    /**
     * A caller session with no peer is refused outright. The paired incoming
     * peer is there to prove it is not used to fill the gap.
     */
    @Test
    fun aCallerSessionWithAnEmptyPeerIsRefusedWithoutAPrompt() = runTest {
        serveIncomingSession(PAIRED_PEER)

        val response = handler.handleRawRequest(attestRequest(), outgoingBinding, "")

        assertErrorCode(ErrorCodes.ATTESTATION_FAILED, response)
        assertPrompts(0)
    }

    /** A null peer is the same refusal as an empty one. */
    @Test
    fun aCallerSessionWithANullPeerIsRefusedWithoutAPrompt() = runTest {
        serveIncomingSession(PAIRED_PEER)

        val response = handler.handleRawRequest(attestRequest(), outgoingBinding, null)

        assertErrorCode(ErrorCodes.ATTESTATION_FAILED, response)
        assertPrompts(0)
    }

    /**
     * The peer is resolved before the policy is read, so `ALWAYS`, which
     * never consults it, still refuses a session that has none rather than
     * prompting for it.
     */
    @Test
    fun anEmptyCallerPeerIsRefusedUnderEveryPolicy() = runTest {
        handler.updateSettings(
            BiometricSettingsData(attestationBiometricPolicy = AttestationBiometricPolicy.ALWAYS)
        )

        val response = handler.handleRawRequest(attestRequest(), outgoingBinding, "")

        assertErrorCode(ErrorCodes.ATTESTATION_FAILED, response)
        assertPrompts(0)
    }

    // -----------------------------------------------------------------
    // A served connection: its own peer decides
    // -----------------------------------------------------------------

    @Test
    fun aPairedServedPeerIsNotPrompted() = runTest {
        onServedConnection(PAIRED_PEER) { handler.handleRawRequest(attestRequest()) }

        assertPrompts(0)
    }

    @Test
    fun anUnpairedServedPeerIsPrompted() = runTest {
        onServedConnection(UNPAIRED_PEER) { handler.handleRawRequest(attestRequest()) }

        assertPrompts(1)
    }

    /**
     * The global served peer is whichever desktop connected last; a
     * connection's own peer decides, never that one.
     */
    @Test
    fun anotherConnectionsPairedPeerDoesNotExemptThisOne() = runTest {
        handler.setConnectedDevicePublicKeyHex(PAIRED_PEER)

        onServedConnection(UNPAIRED_PEER) { handler.handleRawRequest(attestRequest()) }

        assertPrompts(1)
    }

    /** A served connection that authenticated no peer: prompt, never assume. */
    @Test
    fun aServedConnectionWithNoPeerIsStillPrompted() = runTest {
        handler.setConnectedDevicePublicKeyHex(PAIRED_PEER)

        onServedConnection(null) { handler.handleRawRequest(attestRequest()) }

        assertPrompts(1)
    }

    /**
     * A request on no connection has no channel to bind to: it is refused
     * before the policy is read, and the served peer lends it nothing.
     */
    @Test
    fun aRequestOnNoConnectionIsRefusedWithoutAPrompt() = runTest {
        handler.setConnectedDevicePublicKeyHex(PAIRED_PEER)

        val response = handler.handleRawRequest(attestRequest())

        assertEquals(ErrorCodes.ATTESTATION_FAILED, Response.fromJson(response).error?.code)
        assertPrompts(0)
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    /** The desktop this phone last served: a peer no other session may borrow. */
    private fun serveIncomingSession(peerPublicKeyHex: String) {
        handler.setConnectedDevicePublicKeyHex(peerPublicKeyHex)
    }

    /** Runs [block] as the transport routes a request from a served connection. */
    private suspend fun <T> onServedConnection(peerPublicKeyHex: String?, block: suspend () -> T): T =
        withContext(RequestHandler.servedConnection(incomingBinding, peerPublicKeyHex, "test:connection")) { block() }

    private fun attestRequest(): ByteArray {
        val nonce = ByteArray(AttestTranscript.BINDING_SIZE) { (it + 1).toByte() }
        val params = JSONObject()
            .put("protocolVersion", AttestTranscript.PROTOCOL_VERSION)
            .put("purpose", AttestTranscript.PURPOSE_REATTEST)
            .put("nonce", Base64.getEncoder().encodeToString(nonce))
        return Request(id = 1, method = MethodNames.LOCAL_ATTEST_DEVICE, params = params).toJson()
    }

    private fun assertPrompts(expected: Int) {
        coVerify(exactly = expected) {
            biometricLauncher.requestAuthentication(any(), any(), any(), any(), any())
        }
    }

    private fun assertErrorCode(expected: Int, response: ByteArray) {
        val error = Response.fromJson(response).error
        assertNotNull("expected an error response", error)
        assertEquals(expected, error!!.code)
        assertTrue(
            "the refusal must name the missing peer: ${error.message}",
            error.message.contains("no authenticated peer")
        )
    }

    private companion object {
        const val PAIRED_PEER = "aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11"
        const val UNPAIRED_PEER = "bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22"

        /** Distinct keys per session, so a binding mix-up could never pass silently. */
        val outgoingBinding = SessionBindingProvider {
            SessionBinding(ByteArray(32) { 1 }, ByteArray(32) { 2 }, ByteArray(0))
        }
        val incomingBinding = SessionBindingProvider {
            SessionBinding(ByteArray(32) { 3 }, ByteArray(32) { 4 }, ByteArray(0))
        }
    }
}
