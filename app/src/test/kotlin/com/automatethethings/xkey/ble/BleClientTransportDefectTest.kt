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
import android.util.Log
import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import java.security.SecureRandom
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
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
 * The three ways [BleClient]'s transport used to strand its caller, each pinned
 * by a test that fails against the previous behaviour.
 *
 * All of them are silent in production. A link is either dead before Noise
 * starts, or a reply is discarded and the request waits out its full
 * sixty-second timeout — nothing reaches a log the user will ever read, and
 * "Payload size must be at least 20 bytes" is what a failed MTU negotiation
 * used to look like from the outside.
 *
 * `runBlocking` rather than `runTest`, for the reason [BleClientConnectionTest]
 * gives: the client's scope and its `withTimeout` guards are real, so virtual
 * time would step straight through them.
 */
class BleClientTransportDefectTest {

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

    private fun harness(mtu: Int = 247): BleClientHarness =
        BleClientHarness(mtu = mtu).also { harness = it }

    // -----------------------------------------------------------------
    // A link that cannot carry a fragment
    // -----------------------------------------------------------------

    /**
     * A negotiation the stack will not even start leaves the BLE default of 23,
     * which budgets `min(23 - 3, 512) - 7 = 13` bytes per fragment — below
     * [Fragmenter.MIN_PAYLOAD_SIZE]. The client used to carry on and let the
     * fragmenter's `require` fire on the identity frame, three layers below the
     * cause, so the user was told the payload size was wrong when the real
     * problem was the link.
     */
    @Test
    fun anMtuNegotiationTheStackWontStartIsRefusedWithItsRealCause(): Unit = runBlocking {
        val h = harness()
        h.mtuRequestStarts = false

        assertMtuRefusal(assertConnectFails(h))
        assertEquals("nothing may be written on an unusable link", 0, h.writeCount)
        assertNull("no identity frame was ever sent", h.receivedIdentity)
    }

    /** The same dead end, reached through a failure status instead. */
    @Test
    fun anMtuFailureStatusIsRefusedTheSameWay(): Unit = runBlocking {
        val h = harness()
        h.mtuStatus = BluetoothGatt.GATT_FAILURE

        assertMtuRefusal(assertConnectFails(h))
        assertEquals(0, h.writeCount)
    }

    /** One byte under the floor is still a link that can carry nothing. */
    @Test
    fun anMtuOneByteUnderTheFloorIsRefused(): Unit = runBlocking {
        val h = harness(mtu = BleClient.MIN_USABLE_MTU - 1)

        assertMtuRefusal(assertConnectFails(h))
    }

    /**
     * The floor itself has to work, or the constant is simply wrong: at
     * [BleClient.MIN_USABLE_MTU] every message — identity frame, both handshake
     * steps, and the reply coming back — is split across several fragments of
     * exactly [Fragmenter.MIN_PAYLOAD_SIZE] bytes.
     */
    @Test
    fun theSmallestUsableMtuStillCarriesAWholeSession(): Unit = runBlocking {
        val h = harness(mtu = BleClient.MIN_USABLE_MTU)

        assertTrue(h.client.connect(h.address, randomKey()))

        val request = """{"jsonrpc":"2.0","id":1,"method":"local.getCapabilities"}""".toByteArray()
        assertArrayEquals(h.responseFor(request), h.client.sendRequest(request))
        assertArrayEquals(request, h.receivedRequests[0])
    }

    // -----------------------------------------------------------------
    // Inbound fragment ordering
    // -----------------------------------------------------------------

    /**
     * The stack notifies in order on one thread, but a coroutine launched per
     * notification does not *run* in order. [FragmentReassembler] resets its
     * buffer whenever a first fragment lands on a non-empty one, so a single
     * reordered pair discards the whole message and the request that is waiting
     * blocks until its timeout.
     *
     * Many multi-fragment messages back to back is what makes that visible: one
     * reordering anywhere in the run and the await below never returns.
     */
    @Test
    fun aBurstOfFragmentsIsReassembledInArrivalOrder(): Unit = runBlocking {
        val h = harness()
        h.client.connect(h.address, randomKey())

        repeat(MESSAGE_ROUNDS) { round ->
            // Sized so its ciphertext fills exactly FRAGMENTS_PER_MESSAGE
            // fragments. The client authenticates every message once the
            // handshake is done, so the burst is what the desktop really
            // sends: the responder's ciphertext, in nonce order.
            val payload = ByteArray(FRAGMENTS_PER_MESSAGE * Fragmenter.MIN_PAYLOAD_SIZE - NOISE_TAG_SIZE) {
                (round + it).toByte()
            }
            val pending = CompletableDeferred<ByteArray>()
            h.probe.pendingResponse = pending
            val fragments = Fragmenter(Fragmenter.MIN_PAYLOAD_SIZE).fragment(h.responder.encrypt(payload))
            assertEquals(FRAGMENTS_PER_MESSAGE, fragments.size)

            // Delivered as fast as the stack delivers them: no pause, no
            // acknowledgement, nothing to serialise them but the client.
            for (fragment in fragments) {
                h.probe.gattCallback.onCharacteristicChanged(
                    h.gatt, h.responseCharacteristic, fragment
                )
            }

            assertArrayEquals(
                "round $round was reassembled out of order",
                payload,
                withTimeout(REASSEMBLY_TIMEOUT_MS) { pending.await() }
            )
        }
    }

    /** A notification racing teardown must be dropped, not crash the drain. */
    @Test
    fun aFragmentArrivingAfterDestroyIsDropped(): Unit = runBlocking {
        val h = harness()
        h.client.connect(h.address, randomKey())
        h.client.destroy()

        h.probe.gattCallback.onCharacteristicChanged(
            h.gatt, h.responseCharacteristic, firstOfTwoFragments()
        )

        awaitScopeFinished(h.client)
        assertEquals(0, h.probe.fragmentReassembler.getFragmentCount())
    }

    // -----------------------------------------------------------------
    // Which request a reply belongs to
    // -----------------------------------------------------------------

    /**
     * The reply had been *completed* into the waiter without clearing it, so a
     * deferred that a later request had already superseded stayed installed and
     * reachable. Taking it is what makes the handover single-shot.
     */
    @Test
    fun aSatisfiedWaiterIsRemovedRatherThanLeftInstalled(): Unit = runBlocking {
        val h = harness()
        h.client.connect(h.address, randomKey())
        val waiter = CompletableDeferred<ByteArray>()
        h.probe.pendingResponse = waiter
        val payload = "the-response".toByteArray()

        h.probe.handleCompleteMessage(h.responder.encrypt(payload))

        assertArrayEquals(payload, withTimeout(REASSEMBLY_TIMEOUT_MS) { waiter.await() })
        assertNull("a satisfied waiter must not stay installed", h.probe.pendingResponse)
    }

    /** With nothing in flight there is no one to hand a reply to. */
    @Test
    fun aReplyWithNoRequestWaitingIsDiscarded(): Unit = runBlocking {
        val h = harness()
        h.client.connect(h.address, randomKey())
        assertNull("the connect must leave nothing waiting", h.probe.pendingResponse)

        h.probe.handleCompleteMessage("unsolicited".toByteArray())

        val next = CompletableDeferred<ByteArray>()
        h.probe.pendingResponse = next
        // handleCompleteMessage settles the stray reply on this thread, so
        // there is nothing left to wait for before the check.
        assertFalse("a stray reply must not satisfy the next request", next.isCompleted)
    }

    /**
     * A request installs its own waiter. Whatever it displaces has to be
     * *failed* — leaving it pending strands whoever was awaiting it for the
     * full request timeout.
     */
    @Test
    fun aNewRequestFailsTheWaiterItDisplaces(): Unit = runBlocking {
        val h = harness()
        h.client.connect(h.address, randomKey())
        val displaced = CompletableDeferred<ByteArray>()
        h.probe.pendingResponse = displaced

        h.client.sendRequest("""{"id":1,"method":"local.getCapabilities"}""".toByteArray())

        assertTrue("a displaced waiter must be failed, not stranded", displaced.isCancelled)
    }

    /** A stray reply between requests must not corrupt the next exchange. */
    @Test
    fun aStrayReplyBetweenRequestsLeavesTheNextOneIntact(): Unit = runBlocking {
        val h = harness()
        h.client.connect(h.address, randomKey())

        h.probe.handleCompleteMessage("stray".toByteArray())

        val request = """{"id":7,"method":"local.listKeys"}""".toByteArray()
        assertArrayEquals(h.responseFor(request), h.client.sendRequest(request))
    }

    // -----------------------------------------------------------------
    // Which write an acknowledgement belongs to
    // -----------------------------------------------------------------

    /**
     * PR #42: the ack invoked the write's completion and
     * only then cleared the slot. Invoking it resumes the writer, and the
     * writer's next fragment installs its own completion — so a callback still
     * running when that happened cleared the *next* write's completion, and the
     * next ack found nothing to resume. The request then hung with `writeMutex`
     * and `stateMutex` held.
     *
     * The harness keeps each callback open until the next write has started,
     * across a request of [MULTI_FRAGMENT_WRITES] fragments, and the timeout
     * turns that hang into a failure.
     */
    @Test
    fun aWriteStartedInsideThePreviousAckIsAcknowledgedToItsOwnWriter(): Unit = runBlocking {
        val h = harness()
        h.client.connect(h.address, randomKey())
        h.ackAfterTheNextWriteStarts = true
        val writesBefore = h.writeCount
        val request = (
            """{"jsonrpc":"2.0","id":2,"method":"local.getCapabilities","pad":"""" +
                "x".repeat(MULTI_FRAGMENT_PAD) + "\"}"
            ).toByteArray()

        val response = withTimeout(REASSEMBLY_TIMEOUT_MS) { h.client.sendRequest(request) }

        assertArrayEquals(h.responseFor(request), response)
        assertArrayEquals(request, h.receivedRequests.last())
        assertEquals(MULTI_FRAGMENT_WRITES, h.writeCount - writesBefore)
        assertEquals(
            "every write but the last must start inside the previous ack, or nothing raced",
            MULTI_FRAGMENT_WRITES - 1,
            h.acksOutlivedByTheNextWrite.get()
        )
        assertFalse("no completion may outlive its write", h.probe.hasWriteInFlight)
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private fun randomKey(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }

    /** Fragment 0 of a 2-fragment message: buffered, never completing. */
    private fun firstOfTwoFragments(): ByteArray =
        Fragmenter(Fragmenter.MIN_PAYLOAD_SIZE).fragment(ByteArray(40) { it.toByte() })[0]

    private fun assertMtuRefusal(failure: BleClientException) {
        val message = failure.message!!
        assertTrue(
            "the MTU has to be named as the cause: $message",
            message.contains("carry a fragment") || message.contains("per fragment")
        )
        assertTrue(
            "the caller has to be told what would work: $message",
            message.contains("${BleClient.MIN_USABLE_MTU}")
        )
        assertFalse(
            "the fragmenter's require must never be what reports this: $message",
            message.contains("Payload size must be at least")
        )
    }

    private suspend fun assertConnectFails(h: BleClientHarness): BleClientException {
        try {
            h.client.connect(h.address, randomKey())
        } catch (expected: BleClientException) {
            assertEquals(
                "a failed connect must not leave the UI showing a connection",
                ClientConnectionState.Disconnected,
                h.client.connectionState.value
            )
            return expected
        }
        fail("expected the connection to fail")
        error("unreachable")
    }

    private companion object {
        const val MESSAGE_ROUNDS = 40
        const val FRAGMENTS_PER_MESSAGE = 8
        const val REASSEMBLY_TIMEOUT_MS = 5_000L

        /** ChaChaPoly's tag, which every transport message carries. */
        const val NOISE_TAG_SIZE = 16

        /**
         * Padding that puts the request's ciphertext — 681 bytes — into
         * [MULTI_FRAGMENT_WRITES] fragments of the 237 bytes an MTU of 247
         * carries.
         */
        const val MULTI_FRAGMENT_PAD = 600
        const val MULTI_FRAGMENT_WRITES = 3
    }
}
