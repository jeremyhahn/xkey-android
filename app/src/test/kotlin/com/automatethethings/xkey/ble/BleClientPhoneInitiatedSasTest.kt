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
package com.automatethethings.xkey.ble

import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothProfile
import android.util.Log
import com.automatethethings.xkey.protocol.AttestTranscript
import com.automatethethings.xkey.protocol.MethodNames
import com.automatethethings.xkey.protocol.SasTestVectors
import com.automatethethings.xkey.protocol.SessionBindingProvider
import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import java.security.SecureRandom
import java.util.concurrent.CopyOnWriteArrayList
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

/**
 * The SAS on a session the *phone* opened (#137).
 *
 * The sessions the phone accepts show the user the `NNNN-NNNN-NNNN` code before
 * they are trusted; one the phone dials must too, or a machine in the middle
 * goes unnoticed. [BleClient] derives the code from the session's own
 * binding — the value the desktop derives from the same transcript, pinned by
 * [SasTestVectors] — asks through [PairingConfirmationCallback], and trusts the
 * session only on a yes.
 */
class BleClientPhoneInitiatedSasTest {

    private var harness: BleClientHarness? = null

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
    }

    @After
    fun tearDown() {
        harness?.close()
        harness = null
        unmockkAll()
    }

    private fun harness(
        handler: PhoneInitiatedRequestHandler?,
        confirmation: PairingConfirmationCallback?
    ): BleClientHarness =
        BleClientHarness(inboundRequests = handler, pairingConfirmation = confirmation).also { harness = it }

    /** The code the client shows is the shared vector's for the shared binding. */
    @Test
    fun theCodeForTheSharedBindingIsThePinnedVector() {
        assertEquals(SasTestVectors.FIXED_BINDING_SAS, BleClient.shortAuthStringFor(SasTestVectors.fixedBinding()))
    }

    /** Confirm: the user sees the desktop's code and key, and the session is up. */
    @Test
    fun aConfirmedSasTrustsTheSession(): Unit = runBlocking {
        val confirmation = RecordingConfirmation { true }
        val h = harness(RecordingHandler(), confirmation)

        assertTrue(h.client.connect(h.address, randomKey()))

        assertEquals("the user must be asked once", 1, confirmation.asked.size)
        val (name, fingerprint, sas) = confirmation.asked[0]
        assertEquals(
            "the phone must show the code the desktop derives from this transcript",
            AttestTranscript.shortAuthString(h.responder.sessionBinding()), sas
        )
        assertEquals(hex(h.responder.getStaticPublicKey()!!).take(16), fingerprint)
        assertEquals(h.deviceName, name)
        assertTrue(h.client.isConnected())
    }

    /** Reject: the connection is refused and the desktop's request never reaches the handler. */
    @Test
    fun aRejectedSasAbortsAndAnswersNothing(): Unit = runBlocking {
        val handler = RecordingHandler()
        lateinit var h: BleClientHarness
        val confirmation = RecordingConfirmation {
            h.desktopSends(attestRequest(id = 7))
            delay(200)
            false
        }
        h = harness(handler, confirmation)

        try {
            h.client.connect(h.address, randomKey())
            fail("a rejected SAS must abort the connection")
        } catch (e: BleClientException) {
            // expected
        }

        delay(200)
        assertEquals(1, confirmation.asked.size)
        assertTrue("nothing may be served on a rejected session", handler.requests.isEmpty())
        assertTrue("nothing may be answered on a rejected session", h.receivedResponses.isEmpty())
        assertFalse(h.client.isConnected())
        assertEquals(null, h.client.getRemoteStaticKey())
    }

    /** The desktop asks `local.attestDevice` at once; the answer waits for the user. */
    @Test
    fun theDesktopsAttestationWaitsForTheUser(): Unit = runBlocking {
        val handler = RecordingHandler()
        lateinit var h: BleClientHarness
        var servedBeforeTheAnswer = -1
        val confirmation = RecordingConfirmation {
            h.desktopSends(attestRequest(id = 9))
            delay(300)
            servedBeforeTheAnswer = handler.requests.size
            true
        }
        h = harness(handler, confirmation)

        h.client.connect(h.address, randomKey())

        assertEquals("the handler must wait for the user's answer", 0, servedBeforeTheAnswer)
        val answer = JSONObject(String(h.awaitResponses(1)[0], Charsets.UTF_8))
        assertEquals(9L, answer.getLong("id"))
        assertEquals(1, handler.requests.size)
    }

    /** No one to ask: the session is refused, never trusted unattended. */
    @Test
    fun withNoConfirmationTheSessionIsRefused(): Unit = runBlocking {
        val h = harness(RecordingHandler(), null)

        try {
            h.client.connect(h.address, randomKey())
            fail("a session nobody confirmed must not be trusted")
        } catch (e: BleClientException) {
            // expected
        }
        assertFalse(h.client.isConnected())
    }

    /** The link drops while the user compares: the prompt ends and nothing is trusted. */
    @Test
    fun aTransportDisconnectEndsThePendingPrompt(): Unit = runBlocking {
        val prompt = PendingPrompt()
        val h = harness(RecordingHandler(), prompt.confirmation)

        val connecting = async { h.client.connect(h.address, randomKey()) }
        prompt.awaitShown()
        h.probe.gattCallback.onConnectionStateChange(
            h.gatt, BluetoothGatt.GATT_SUCCESS, BluetoothProfile.STATE_DISCONNECTED
        )

        assertFalse("a session whose link dropped must not be reported up", withTimeout(5_000) { connecting.await() })
        assertTrue("the disconnect must end the prompt", prompt.cancelled.await())
        assertFalse(h.client.isConnected())
    }

    /** disconnect() while the user compares ends the prompt; it does not wait for the answer. */
    @Test
    fun disconnectEndsThePendingPrompt(): Unit = runBlocking {
        val prompt = PendingPrompt()
        val h = harness(RecordingHandler(), prompt.confirmation)

        val connecting = async { h.client.connect(h.address, randomKey()) }
        prompt.awaitShown()
        h.client.disconnect()

        assertFalse(withTimeout(5_000) { connecting.await() })
        assertTrue("disconnect() must end the prompt", withTimeout(5_000) { prompt.cancelled.await() })
        assertFalse(h.client.isConnected())
    }

    /** destroy() returns while the prompt is pending, and ends it. */
    @Test
    fun destroyReturnsWhileThePromptIsPending(): Unit = runBlocking {
        val prompt = PendingPrompt()
        val h = harness(RecordingHandler(), prompt.confirmation)

        val connecting = async {
            try {
                h.client.connect(h.address, randomKey())
            } catch (e: BleClientException) {
                false
            }
        }
        prompt.awaitShown()
        // Off this test's job: destroy() tears down NonCancellable, so a
        // timeout around it could not end a destroy() that hangs.
        val destroyed = CompletableDeferred<Unit>()
        CoroutineScope(Dispatchers.Default).launch { h.client.destroy(); destroyed.complete(Unit) }
        withTimeout(5_000) { destroyed.await() }

        assertTrue("destroy() must end the prompt", withTimeout(5_000) { prompt.cancelled.await() })
        assertFalse(withTimeout(5_000) { connecting.await() })
        assertFalse(h.client.isConnected())
    }

    /** An Allow that lands after the disconnect trusts nothing and reports nothing up. */
    @Test
    fun anAllowAfterTheDisconnectTrustsNothing(): Unit = runBlocking {
        val handler = RecordingHandler()
        val shown = CompletableDeferred<Unit>()
        val allow = CompletableDeferred<Unit>()
        lateinit var h: BleClientHarness
        val confirmation = RecordingConfirmation {
            h.desktopSends(attestRequest(id = 11))
            shown.complete(Unit)
            // A dialog that answers even though the session is gone.
            withContext(NonCancellable) { allow.await() }
            true
        }
        h = harness(handler, confirmation)

        val connecting = async { h.client.connect(h.address, randomKey()) }
        withTimeout(5_000) { shown.await() }
        h.client.disconnect()
        delay(300)
        allow.complete(Unit)

        assertFalse("an Allow for a retired session must not report it up", withTimeout(5_000) { connecting.await() })
        delay(200)
        assertFalse(h.client.isConnected())
        assertTrue("nothing may be served on a retired session", handler.requests.isEmpty())
        assertTrue("nothing may be answered on a retired session", h.receivedResponses.isEmpty())
    }

    /**
     * The link drops after the user said yes, between the ownership check and
     * the trust publication: the retired connection is not trusted, its
     * desktop request is never served, and connect() reports no session.
     */
    @Test
    fun aDisconnectAtTheTrustPublicationTrustsNothing(): Unit = runBlocking {
        val handler = RecordingHandler()
        lateinit var h: BleClientHarness
        val confirmation = RecordingConfirmation {
            h.desktopSends(attestRequest(id = 13))
            delay(200)
            true
        }
        h = harness(handler, confirmation)
        var dropped: Any? = null
        h.client.sasTrustHook = {
            h.client.sasTrustHook = null
            dropped = connectionOf(h.client)
            h.probe.gattCallback.onConnectionStateChange(
                h.gatt, BluetoothGatt.GATT_SUCCESS, BluetoothProfile.STATE_DISCONNECTED
            )
        }

        val connected = withTimeout(5_000) { h.client.connect(h.address, randomKey()) }

        assertFalse("connect() must not report a dropped link as up", connected)
        val retired = dropped ?: throw AssertionError("the seam was never reached")
        assertFalse("a retired connection must not be trusted", fieldOf(retired, "trusted") as Boolean)
        val answer = fieldOf(retired, "sasConfirmed") as CompletableDeferred<*>
        assertTrue(answer.isCompleted)
        assertEquals(false, answer.await())
        delay(300)
        assertFalse(h.client.isConnected())
        assertTrue("nothing may be served on a retired session", handler.requests.isEmpty())
        assertTrue("nothing may be answered on a retired session", h.receivedResponses.isEmpty())
    }

    private fun connectionOf(client: BleClient): Any? =
        BleClient::class.java.getDeclaredField("connection").apply { isAccessible = true }.get(client)

    private fun fieldOf(target: Any, name: String): Any? =
        target.javaClass.getDeclaredField(name).apply { isAccessible = true }.get(target)

    /** A prompt that stays open until it is cancelled, and says whether it was. */
    private class PendingPrompt {
        private val shown = CompletableDeferred<Unit>()
        val cancelled = CompletableDeferred<Boolean>()
        val confirmation = RecordingConfirmation {
            shown.complete(Unit)
            try {
                CompletableDeferred<Boolean>().await()
            } catch (e: CancellationException) {
                cancelled.complete(true)
                throw e
            }
        }

        suspend fun awaitShown() = withTimeout(5_000) { shown.await() }
    }

    private class RecordingConfirmation(
        private val answer: suspend () -> Boolean
    ) : PairingConfirmationCallback {
        val asked = CopyOnWriteArrayList<Triple<String, String, String>>()

        override suspend fun onPairingConfirmationRequired(deviceName: String, publicKeyFingerprint: String): Boolean {
            throw AssertionError("a phone-initiated session must show the SAS")
        }

        override suspend fun onPairingConfirmationRequired(
            deviceName: String,
            publicKeyFingerprint: String,
            shortAuthString: String
        ): Boolean {
            asked += Triple(deviceName, publicKeyFingerprint, shortAuthString)
            return answer()
        }
    }

    private class RecordingHandler : PhoneInitiatedRequestHandler {
        val requests = CopyOnWriteArrayList<ByteArray>()

        override suspend fun handle(
            request: ByteArray,
            binding: SessionBindingProvider,
            peerPublicKeyHex: String?
        ): ByteArray {
            requests += request
            val id = JSONObject(String(request, Charsets.UTF_8)).optLong("id", -1)
            return """{"jsonrpc":"2.0","id":$id,"result":{"attested":true}}""".toByteArray()
        }
    }

    private fun attestRequest(id: Long): ByteArray =
        """{"jsonrpc":"2.0","id":$id,"method":"${MethodNames.LOCAL_ATTEST_DEVICE}","params":{"purpose":"pair"}}"""
            .toByteArray()

    private fun randomKey(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }

    private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }
}
