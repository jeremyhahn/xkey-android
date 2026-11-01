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

import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothProfile
import android.util.Log
import com.automatethethings.xkey.protocol.AttestTranscript
import com.automatethethings.xkey.protocol.ErrorCodes
import com.automatethethings.xkey.protocol.MethodNames
import com.automatethethings.xkey.protocol.SessionBinding
import com.automatethethings.xkey.protocol.SessionBindingProvider
import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import java.security.SecureRandom
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * `local.attestDevice` on a session the *phone* opened.
 *
 * go-xkms (#1306) sends it right after the Noise handshake on every
 * phone-initiated session and refuses the session without a verified answer.
 * On the sessions the phone accepts, [RequestHandler] answers it behind the
 * transport; here [BleClient] has to hand it to the same handler, bound to this
 * session's keys, and get the answer back out while its own request may still
 * be waiting.
 *
 * The handler is a fake: what is under test is the dispatch — which session
 * the binding describes, which methods reach the handler, and that the answer
 * reaches the desktop. `runBlocking`, for the reason [BleClientConnectionTest]
 * gives.
 */
class BleClientPhoneInitiatedAttestTest {

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

    private fun harness(handler: PhoneInitiatedRequestHandler?): BleClientHarness =
        BleClientHarness(inboundRequests = handler).also { harness = it }

    // -----------------------------------------------------------------
    // The answer
    // -----------------------------------------------------------------

    /**
     * The desktop's request reaches the handler verbatim, bound to *this*
     * session with the Noise roles as they ran: the phone dialled, so its
     * static key is the initiator's and the desktop's the responder's.
     */
    @Test
    fun anAttestDeviceRequestIsAnsweredByTheHandlerBoundToThisSession(): Unit = runBlocking {
        val handler = RecordingHandler()
        val h = harness(handler)
        h.client.connect(h.address, randomKey())
        val request = attestRequest(id = 41)

        h.desktopSends(request)

        val answer = JSONObject(String(h.awaitResponses(1)[0], Charsets.UTF_8))
        assertEquals(41L, answer.getLong("id"))
        assertTrue("the handler's result must reach the desktop", answer.getJSONObject("result").getBoolean("attested"))
        assertEquals(1, handler.requests.size)
        assertArrayEquals("the handler must see the request verbatim", request, handler.requests[0])

        val binding = handler.binding ?: throw AssertionError("the handler must be given a binding")
        assertArrayEquals(
            "the phone dialled, so it is the initiator",
            h.responder.getRemoteStaticKey(), binding.initiatorStaticPublicKey
        )
        assertArrayEquals(
            "the desktop answered, so it is the responder",
            h.responder.getStaticPublicKey(), binding.responderStaticPublicKey
        )
        assertArrayEquals(h.responder.getPrologue(), binding.prologue)
        assertEquals(hex(h.responder.getStaticPublicKey()!!), handler.peerPublicKeyHex)
    }

    /** The binding the phone signs over is the one the desktop derives, so the SAS agrees too. */
    @Test
    fun theBindingYieldsTheSameCodeTheDesktopComputes(): Unit = runBlocking {
        val handler = RecordingHandler()
        val h = harness(handler)
        h.client.connect(h.address, randomKey())

        h.desktopSends(attestRequest(id = 1))
        h.awaitResponses(1)

        assertEquals(
            AttestTranscript.shortAuthString(h.responder.sessionBinding()),
            AttestTranscript.shortAuthString(handler.binding)
        )
    }

    /**
     * go-xkms sends the request the moment it reads message 3. The client used
     * to derive its transport keys only after that write returned, so a request
     * this quick could land while it still looked like handshake traffic.
     */
    @Test
    fun aRequestSentInReplyToMessageThreeIsAnswered(): Unit = runBlocking {
        val handler = RecordingHandler()
        val h = harness(handler)
        h.requestOnHandshake = attestRequest(id = 3)

        h.client.connect(h.address, randomKey())

        val answer = JSONObject(String(h.awaitResponses(1)[0], Charsets.UTF_8))
        assertEquals(3L, answer.getLong("id"))
        assertEquals(1, handler.requests.size)
        assertTrue(h.client.isConnected())
    }

    /**
     * The request can be notified before the stack acknowledges message 3's
     * write. Message 3 holds the client's write lock until that
     * acknowledgement, so the answer waits for it. Without the lock the answer
     * took the single write-completion slot and wrote into a busy stack: the
     * stack refused it, and message 3's acknowledgement then found no one
     * waiting, so the handshake hung and the attestation was lost.
     */
    @Test
    fun aRequestNotifiedBeforeMessageThreeIsAcknowledgedWaitsForIt(): Unit = runBlocking {
        val handler = RecordingHandler()
        val h = harness(handler)
        h.requestOnHandshake = attestRequest(id = 4)
        h.replyBeforeWriteAck = true

        val connected = try {
            withTimeout(REPLY_TIMEOUT_MS) { h.client.connect(h.address, randomKey()) }
        } catch (e: Exception) {
            false
        }

        assertEquals("the answer was written over message 3", 0, h.overlappingWrites.get())
        assertTrue("message 3's acknowledgement must reach the handshake", connected)
        val answer = JSONObject(String(h.awaitResponses(1)[0], Charsets.UTF_8))
        assertEquals(4L, answer.getLong("id"))
        assertEquals(1, handler.requests.size)
    }

    /**
     * The desktop may attest the phone before it answers the phone's own
     * request. [BleClient.sendRequest] holds its state lock while it waits, so
     * the answer has to go out without it — serialised with the request's
     * write by the client's write lock instead — or the two deadlock until the
     * request times out.
     */
    @Test
    fun anAttestationIsAnsweredWhileTheClientsOwnRequestIsWaiting(): Unit = runBlocking {
        val handler = RecordingHandler()
        val h = harness(handler)
        h.client.connect(h.address, randomKey())
        // The desktop answers the phone's request with a request of its own.
        h.responseFor = { attestRequest(id = 99) }
        val request = """{"jsonrpc":"2.0","id":7,"method":"local.listKeys"}""".toByteArray()

        val call = async(Dispatchers.Default) { h.client.sendRequest(request) }

        val answer = JSONObject(String(h.awaitResponses(1)[0], Charsets.UTF_8))
        assertEquals(99L, answer.getLong("id"))
        val reply = """{"jsonrpc":"2.0","id":7,"result":{"keys":[]}}""".toByteArray()
        h.desktopSends(reply)
        assertArrayEquals(
            "the waiting request must still get its own reply",
            reply, withTimeout(REPLY_TIMEOUT_MS) { call.await() }
        )
    }

    /**
     * An attestation waits for the user's approval. A disconnect cancels the
     * worker answering it, with the connection, rather than leaving it to
     * finish on whatever connection comes next.
     */
    @Test
    fun aDisconnectCancelsTheWorkerWaitingForApproval(): Unit = runBlocking {
        val handler = ApprovalHandler(ignoresCancellation = false)
        val h = harness(handler)
        h.client.connect(h.address, randomKey())
        h.desktopSends(attestRequest(id = 5))
        withTimeout(REPLY_TIMEOUT_MS) { handler.entered.await() }

        h.probe.disconnectInternal()

        withTimeout(REPLY_TIMEOUT_MS) { handler.cancelled.await() }
    }

    /**
     * A worker whose handler cannot be interrupted is approved only after the
     * client has reconnected. Its answer is the old session's ciphertext, so
     * it must not reach the new connection: it is dropped, under the write
     * lock, because its session is no longer the client's.
     */
    @Test
    fun anAnswerApprovedAfterAReconnectIsNotWrittenToTheNewConnection(): Unit = runBlocking {
        val handler = ApprovalHandler(ignoresCancellation = true)
        val h = harness(handler)
        h.client.connect(h.address, randomKey())
        h.desktopSends(attestRequest(id = 6))
        withTimeout(REPLY_TIMEOUT_MS) { handler.entered.await() }

        h.probe.disconnectInternal()
        // Reconnected: a new GATT connection carrying a new session.
        val newGatt = h.nextConnection()
        assertTrue(h.client.connect(h.address, randomKey()))
        val handshakeWrites = h.writesOn(newGatt)
        val oldWrites = h.writesOn(h.gatt)
        val dropped = answerDropped()

        handler.approve()

        withTimeout(REPLY_TIMEOUT_MS) { dropped.await() }
        assertEquals("the old answer reached the new connection", handshakeWrites, h.writesOn(newGatt))
        assertEquals("the old answer was written at all", oldWrites, h.writesOn(h.gatt))
        assertTrue("the new connection must stay up", h.client.isConnected())
        assertTrue("nothing may reach the desktop either", h.receivedResponses.isEmpty())
    }

    /**
     * A worker past its session check when the client reconnects. Its job is
     * cancelled with the old connection, but a cancelled continuation still
     * runs the write's block: the write must be refused there, before it
     * reaches the stack or takes the completion of the write the new
     * connection's handshake has outstanding.
     */
    @Test
    fun aWorkerPausedPastItsSessionCheckDoesNotWriteOnTheNextConnection(): Unit = runBlocking {
        val h = harness(RecordingHandler())
        h.client.connect(h.address, randomKey())
        val paused = WritePause(h.client, BleClient.WriteStep.SESSION_CHECKED)
        h.desktopSends(attestRequest(id = 9))
        paused.awaitPaused()
        val oldWrites = h.writesOn(h.gatt)

        h.probe.disconnectInternal()
        val newGatt = h.nextConnection()
        h.holdWrites = true
        val reconnect = async(Dispatchers.Default) { h.client.connect(h.address, randomKey()) }
        awaitUntil("the reconnection's identity write") { h.heldWrites == 1 }
        val handshakeWrite = h.probe.writeCompletion.get()
        val dropped = answerDropped()

        paused.resume()

        withTimeout(REPLY_TIMEOUT_MS) { dropped.await() }
        assertEquals("the old session's ciphertext reached the new connection", 1, h.writesOn(newGatt))
        assertEquals("the old session's ciphertext was written at all", oldWrites, h.writesOn(h.gatt))
        assertSame("the handshake's write lost its completion", handshakeWrite, h.probe.writeCompletion.get())
        assertTrue("the reconnection must still be under way", reconnect.isActive)

        h.releaseHeldWrites()
        assertTrue(withTimeout(REPLY_TIMEOUT_MS) { reconnect.await() })
        assertTrue("nothing may reach the desktop", h.receivedResponses.isEmpty())
    }

    /**
     * A write admitted to the connection holds it until it has reached the
     * stack: the disconnect that replaces the connection waits, so the write
     * goes out whole on the connection it was admitted to, never on the next.
     */
    @Test
    fun aDisconnectWaitsForAWriteAlreadyAdmittedToTheConnection(): Unit = runBlocking {
        val h = harness(RecordingHandler())
        h.client.connect(h.address, randomKey())
        val paused = WritePause(h.client, BleClient.WriteStep.WRITE_ADMITTED)
        h.desktopSends(attestRequest(id = 10))
        paused.awaitPaused()

        val disconnecting = thread(name = "disconnect") { h.probe.disconnectInternal() }
        awaitUntil("the disconnect to block or finish") {
            disconnecting.state == Thread.State.BLOCKED || !disconnecting.isAlive
        }
        assertTrue("the connection was replaced under an admitted write", disconnecting.isAlive)

        paused.resume()

        disconnecting.join(REPLY_TIMEOUT_MS)
        assertFalse("the disconnect must finish once the write is out", disconnecting.isAlive)
        val answer = JSONObject(String(h.awaitResponses(1)[0], Charsets.UTF_8))
        assertEquals(10L, answer.getLong("id"))
        val newGatt = h.nextConnection()
        assertTrue(h.client.connect(h.address, randomKey()))
        assertTrue(h.client.isConnected())
        assertEquals("only the first connection carried the answer", 1, h.receivedResponses.size)
        assertTrue(h.writesOn(newGatt) > 0)
    }

    /**
     * A writer nothing cancels -- this one is not a request worker -- that
     * outlives its connection is refused at its next fragment because that
     * connection is no longer the client's, not because it was cancelled.
     */
    @Test
    fun aWriterThatOutlivesItsConnectionIsRefusedAtItsNextFragment(): Unit = runBlocking {
        val h = harness(null)
        h.client.connect(h.address, randomKey())
        val session = h.probe.noiseSession ?: throw AssertionError("a connected client must hold a session")
        val paused = WritePause(h.client, BleClient.WriteStep.SESSION_CHECKED)
        val oldWrites = h.writesOn(h.gatt)
        val message = """{"jsonrpc":"2.0","id":11,"result":{}}""".toByteArray()
        val writer = async(Dispatchers.Default) { runCatching { h.probe.sendEncrypted(session, message) } }
        paused.awaitPaused()

        h.probe.disconnectInternal()
        val newGatt = h.nextConnection()
        h.holdWrites = true
        val reconnect = async(Dispatchers.Default) { h.client.connect(h.address, randomKey()) }
        awaitUntil("the reconnection's identity write") { h.heldWrites == 1 }
        val handshakeWrite = h.probe.writeCompletion.get()

        paused.resume()

        val refusal = withTimeout(REPLY_TIMEOUT_MS) { writer.await() }.exceptionOrNull()
        assertTrue("the writer must be refused, not cancelled: $refusal", refusal is BleClientException)
        assertEquals("the old session's ciphertext was written at all", oldWrites, h.writesOn(h.gatt))
        assertEquals("the old session's ciphertext reached the new connection", 1, h.writesOn(newGatt))
        assertSame("the handshake's write lost its completion", handshakeWrite, h.probe.writeCompletion.get())

        h.releaseHeldWrites()
        assertTrue(withTimeout(REPLY_TIMEOUT_MS) { reconnect.await() })
    }

    /**
     * The old GATT object reports its disconnect after the client has
     * reconnected. It is not the connection's: it must neither fail the write
     * the new connection has outstanding nor tear the new connection down.
     */
    @Test
    fun aLateDisconnectFromTheOldConnectionLeavesTheNewOneUp(): Unit = runBlocking {
        val h = harness(null)
        h.client.connect(h.address, randomKey())
        h.probe.disconnectInternal()
        val newGatt = h.nextConnection()
        assertTrue(h.client.connect(h.address, randomKey()))
        h.holdWrites = true
        val request = """{"jsonrpc":"2.0","id":1,"method":"local.listKeys"}""".toByteArray()
        val call = async(Dispatchers.Default) { h.client.sendRequest(request) }
        awaitUntil("the request's write") { h.heldWrites == 1 }
        val requestWrite = h.probe.writeCompletion.get()

        h.probe.gattCallback.onConnectionStateChange(
            h.gatt, BluetoothGatt.GATT_SUCCESS, BluetoothProfile.STATE_DISCONNECTED
        )

        assertSame("the old link's disconnect failed the new connection's write", requestWrite, h.probe.writeCompletion.get())
        h.releaseHeldWrites()
        assertArrayEquals(h.responseFor(request), withTimeout(REPLY_TIMEOUT_MS) { call.await() })
        assertSame("the old link's disconnect tore down the new one", newGatt, h.probe.gattConnection)
        assertTrue(h.client.isConnected())
    }

    /**
     * Codex review 6601: the desktop answers the phone's request with an
     * attestation, which waits for approval while the request waits for its
     * reply, holding stateMutex. The link's own disconnect cancels the worker
     * in the callback, not once the teardown gets that mutex, so nothing is
     * signed or written for it after the link has gone.
     */
    @Test
    fun aDisconnectWhileARequestAwaitsItsReplyCancelsTheWorkerWaitingForApproval(): Unit = runBlocking {
        val handler = ApprovalHandler(ignoresCancellation = false)
        val h = harness(handler)
        h.client.connect(h.address, randomKey())
        h.responseFor = { attestRequest(id = 12) }
        val request = """{"jsonrpc":"2.0","id":7,"method":"local.listKeys"}""".toByteArray()
        val call = async(Dispatchers.Default) { runCatching { h.client.sendRequest(request) } }
        withTimeout(REPLY_TIMEOUT_MS) { handler.entered.await() }
        val writes = h.writesOn(h.gatt)

        h.probe.gattCallback.onConnectionStateChange(
            h.gatt, BluetoothGatt.GATT_SUCCESS, BluetoothProfile.STATE_DISCONNECTED
        )

        withTimeout(REPLY_TIMEOUT_MS) { handler.cancelled.await() }
        val failure = withTimeout(REPLY_TIMEOUT_MS) { call.await() }.exceptionOrNull()
        assertTrue("the request must be failed, not left waiting: $failure", failure is BleClientException)
        awaitUntil("the link to be torn down") {
            h.client.connectionState.value == ClientConnectionState.Disconnected
        }
        handler.approve()
        assertEquals("a write was attempted for the cancelled worker", writes, h.writesOn(h.gatt))
        assertTrue("nothing may reach the desktop", h.receivedResponses.isEmpty())
    }

    /**
     * The old GATT object reports its disconnect while the new connection's
     * request waits for its reply and its worker for approval. It ends,
     * cancels and wakes nothing of the new connection's: the worker is
     * answered and the request gets its own reply.
     */
    @Test
    fun aLateDisconnectFromTheOldConnectionLeavesTheNewOnesWaitersAlone(): Unit = runBlocking {
        val handler = ApprovalHandler(ignoresCancellation = false)
        val h = harness(handler)
        h.client.connect(h.address, randomKey())
        h.probe.disconnectInternal()
        val newGatt = h.nextConnection()
        assertTrue(h.client.connect(h.address, randomKey()))
        h.responseFor = { attestRequest(id = 14) }
        val request = """{"jsonrpc":"2.0","id":8,"method":"local.listKeys"}""".toByteArray()
        val call = async(Dispatchers.Default) { h.client.sendRequest(request) }
        withTimeout(REPLY_TIMEOUT_MS) { handler.entered.await() }

        h.probe.gattCallback.onConnectionStateChange(
            h.gatt, BluetoothGatt.GATT_SUCCESS, BluetoothProfile.STATE_DISCONNECTED
        )

        assertFalse("the old link's disconnect cancelled the new connection's worker", handler.cancelled.isCompleted)
        assertTrue("the old link's disconnect woke the new connection's request", call.isActive)
        handler.approve()
        val answer = JSONObject(String(h.awaitResponses(1)[0], Charsets.UTF_8))
        assertEquals(14L, answer.getLong("id"))
        val reply = """{"jsonrpc":"2.0","id":8,"result":{"keys":[]}}""".toByteArray()
        h.desktopSends(reply)
        assertArrayEquals(
            "the new connection's request must get its own reply",
            reply, withTimeout(REPLY_TIMEOUT_MS) { call.await() }
        )
        assertSame("the old link's disconnect tore down the new one", newGatt, h.probe.gattConnection)
        assertTrue(h.client.isConnected())
    }

    // -----------------------------------------------------------------
    // Refusals
    // -----------------------------------------------------------------

    /** The phone dialled out to ask; the desktop does not get to drive it. */
    @Test
    fun aMethodOtherThanAttestDeviceIsRefusedWithoutReachingTheHandler(): Unit = runBlocking {
        val handler = RecordingHandler()
        val h = harness(handler)
        h.client.connect(h.address, randomKey())

        h.desktopSends("""{"jsonrpc":"2.0","id":5,"method":"local.listKeys"}""".toByteArray())

        val answer = JSONObject(String(h.awaitResponses(1)[0], Charsets.UTF_8))
        assertEquals(5L, answer.getLong("id"))
        assertEquals(ErrorCodes.METHOD_NOT_FOUND, answer.getJSONObject("error").getInt("code"))
        assertTrue("the handler must not see it", handler.requests.isEmpty())
    }

    /** Without a handler the desktop is told no, rather than left to time out. */
    @Test
    fun withNoHandlerTheAttestationIsRefused(): Unit = runBlocking {
        val h = harness(null)
        h.client.connect(h.address, randomKey())

        h.desktopSends(attestRequest(id = 6))

        val answer = JSONObject(String(h.awaitResponses(1)[0], Charsets.UTF_8))
        assertEquals(6L, answer.getLong("id"))
        assertEquals(ErrorCodes.METHOD_NOT_FOUND, answer.getJSONObject("error").getInt("code"))
    }

    // -----------------------------------------------------------------
    // The receive nonce
    // -----------------------------------------------------------------

    /**
     * Every post-handshake message is now decrypted, stray ones included. A
     * failed decrypt that still advanced the nonce would make every later
     * message, the attestation request among them, undecryptable.
     */
    @Test
    fun bytesThatFailToDecryptDoNotDesynchroniseTheSession(): Unit = runBlocking {
        val handler = RecordingHandler()
        val h = harness(handler)
        h.client.connect(h.address, randomKey())

        h.probe.handleCompleteMessage(ByteArray(64).also { SecureRandom().nextBytes(it) })
        h.desktopSends(attestRequest(id = 8))

        val answer = JSONObject(String(h.awaitResponses(1)[0], Charsets.UTF_8))
        assertEquals(8L, answer.getLong("id"))
        assertEquals(1, handler.requests.size)
    }


    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    /** Records what reached it and answers with a canned attestation result. */
    private class RecordingHandler : PhoneInitiatedRequestHandler {
        val requests = CopyOnWriteArrayList<ByteArray>()

        @Volatile
        var binding: SessionBinding? = null

        @Volatile
        var peerPublicKeyHex: String? = null

        override suspend fun handle(
            request: ByteArray,
            binding: SessionBindingProvider,
            peerPublicKeyHex: String?
        ): ByteArray {
            this.binding = binding.binding()
            this.peerPublicKeyHex = peerPublicKeyHex
            requests += request
            val id = JSONObject(String(request, Charsets.UTF_8)).optLong("id", -1)
            return """{"jsonrpc":"2.0","id":$id,"result":{"attested":true}}""".toByteArray()
        }
    }

    /**
     * Holds the attestation until [approve], as a handler waiting for the
     * user's biometric does. With [ignoresCancellation] it blocks its thread,
     * as a callback nothing can interrupt would; otherwise it suspends, and
     * records being cancelled in [cancelled].
     */
    private class ApprovalHandler(private val ignoresCancellation: Boolean) : PhoneInitiatedRequestHandler {
        val entered = CompletableDeferred<Unit>()
        val cancelled = CompletableDeferred<Unit>()
        private val approval = CompletableDeferred<Unit>()
        private val approvalLatch = CountDownLatch(1)

        fun approve() {
            approvalLatch.countDown()
            approval.complete(Unit)
        }

        override suspend fun handle(
            request: ByteArray,
            binding: SessionBindingProvider,
            peerPublicKeyHex: String?
        ): ByteArray {
            entered.complete(Unit)
            if (ignoresCancellation) {
                approvalLatch.await(REPLY_TIMEOUT_MS, TimeUnit.MILLISECONDS)
            } else {
                try {
                    approval.await()
                } catch (e: CancellationException) {
                    cancelled.complete(Unit)
                    throw e
                }
            }
            val id = JSONObject(String(request, Charsets.UTF_8)).optLong("id", -1)
            return """{"jsonrpc":"2.0","id":$id,"result":{"attested":true}}""".toByteArray()
        }
    }

    /**
     * Holds the first writer to reach [step] there, on its own thread, until
     * [resume]: the window in which a test changes the connection under it.
     */
    private class WritePause(client: BleClient, private val step: BleClient.WriteStep) {
        private val reached = CountDownLatch(1)
        private val released = CountDownLatch(1)
        private val armed = AtomicBoolean(true)

        init {
            client.writeStepHook = { at ->
                if (at == step && armed.compareAndSet(true, false)) {
                    reached.countDown()
                    released.await(REPLY_TIMEOUT_MS, TimeUnit.MILLISECONDS)
                }
            }
        }

        fun awaitPaused() {
            assertTrue("no writer reached $step", reached.await(REPLY_TIMEOUT_MS, TimeUnit.MILLISECONDS))
        }

        fun resume() = released.countDown()
    }

    /** Completes once a worker reports that its answer could not be sent. */
    private fun answerDropped(): CompletableDeferred<Unit> {
        val dropped = CompletableDeferred<Unit>()
        every { Log.w(any(), match<String> { it.startsWith("Could not send the answer") }, any()) } answers {
            dropped.complete(Unit)
            0
        }
        return dropped
    }

    private fun awaitUntil(what: String, condition: () -> Boolean) {
        val deadline = System.currentTimeMillis() + REPLY_TIMEOUT_MS
        while (!condition()) {
            if (System.currentTimeMillis() > deadline) throw AssertionError("timed out waiting for $what")
            Thread.sleep(2)
        }
    }

    private fun attestRequest(id: Long): ByteArray =
        """{"jsonrpc":"2.0","id":$id,"method":"${MethodNames.LOCAL_ATTEST_DEVICE}","params":{"purpose":"pair"}}"""
            .toByteArray()

    private fun randomKey(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }

    private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

    private companion object {
        const val REPLY_TIMEOUT_MS = 5_000L
    }
}
