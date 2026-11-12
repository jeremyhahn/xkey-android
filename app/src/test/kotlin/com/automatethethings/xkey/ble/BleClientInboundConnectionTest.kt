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

import android.util.Log
import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import java.security.SecureRandom
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * What the client received on a connection that has since ended, driven
 * through [BleClientHarness].
 *
 * Fragments are queued from the stack's callback thread and drained by one
 * consumer, so a fragment of one connection can still be draining when the
 * client has disconnected it and dialled the next. It must neither reach the
 * next connection's reassembly nor be routed by the next connection's state.
 */
class BleClientInboundConnectionTest {

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

    /**
     * The old connection's fragment -- a whole identity acknowledgement -- is
     * taken by the consumer, which is held there while the client disconnects
     * and dials the next connection. The next handshake opens by waiting for
     * that same acknowledgement, so had the old one reached it, the handshake
     * would read its own acknowledgement as message 2 and fail.
     */
    @Test
    fun aFragmentQueuedBeforeItsConnectionEndedDoesNotReachTheNextHandshake(): Unit = runBlocking {
        val h = harness()
        h.client.connect(h.address, randomKey())
        val paused = ConsumerPause(h)
        h.probe.gattCallback.onCharacteristicChanged(
            h.gatt, h.responseCharacteristic, singleFragment(byteArrayOf(0x00))
        )
        paused.awaitPaused()

        h.probe.disconnectInternal()
        val newGatt = h.nextConnection()
        val reconnect = async(Dispatchers.Default) { h.client.connect(h.address, randomKey()) }
        h.awaitUntil("the next connection's identity frame") { h.writesOn(newGatt) >= 1 }
        paused.resume()

        assertTrue(
            "the next handshake must read only its own connection's messages",
            withTimeout(TIMEOUT_MS) { reconnect.await() }
        )
        assertArrayEquals(h.responseFor(REQUEST), withTimeout(TIMEOUT_MS) { h.client.sendRequest(REQUEST) })
    }

    /**
     * A whole message of the ended connection drains once the next one is up
     * and has a request waiting. It is the desktop's genuine reply on the next
     * connection, so had the next session been asked to decrypt it, the
     * request would complete before the desktop's own copy arrives.
     */
    @Test
    fun aMessageFromAnEndedConnectionIsNotDecryptedByTheNext(): Unit = runBlocking {
        val h = harness()
        h.client.connect(h.address, randomKey())
        val ended = h.probe.connection ?: throw AssertionError("the first connection is not up")
        h.probe.disconnectInternal()
        h.nextConnection()
        h.client.connect(h.address, randomKey())
        h.holdWrites = true
        val call = async(Dispatchers.Default) { h.client.sendRequest(REQUEST) }
        h.awaitUntil("the request's write") { h.heldWrites == 1 }
        val reply = h.heldReplies.single() ?: throw AssertionError("the desktop did not reply")

        h.probe.handleCompleteMessage(ended, reply)

        // Routed on this thread: had the next session decrypted the message,
        // it would have taken the request's waiter before the call returned.
        assertNotNull("the next connection's session decrypted the ended connection's message", h.probe.pendingResponse)
        assertFalse("the next connection's session decrypted the ended connection's message", call.isCompleted)
        h.releaseHeldWrites()
        assertArrayEquals(h.responseFor(REQUEST), withTimeout(TIMEOUT_MS) { call.await() })
    }


    /** Holds the inbound consumer on the first fragment it takes, until [resume]. */
    private class ConsumerPause(harness: BleClientHarness) {
        private val paused = CountDownLatch(1)
        private val released = CountDownLatch(1)
        private val first = AtomicBoolean(true)

        init {
            harness.onInboundEvent = {
                if (first.getAndSet(false)) {
                    paused.countDown()
                    released.await(TIMEOUT_MS, TimeUnit.MILLISECONDS)
                }
            }
        }

        fun awaitPaused() {
            assertTrue("the consumer never took the fragment", paused.await(TIMEOUT_MS, TimeUnit.MILLISECONDS))
        }

        fun resume() = released.countDown()
    }

    private fun singleFragment(message: ByteArray): ByteArray =
        Fragmenter(Fragmenter.MIN_PAYLOAD_SIZE).fragment(message).single()

    private fun randomKey(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }

    private companion object {
        const val TIMEOUT_MS = 5_000L
        val REQUEST = """{"jsonrpc":"2.0","id":1,"method":"local.listKeys"}""".toByteArray()
    }
}
