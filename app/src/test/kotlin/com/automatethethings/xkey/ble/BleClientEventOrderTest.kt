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

import android.bluetooth.BluetoothProfile
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
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The client, as BLE central, handles a notification and the stack's
 * disconnect in the order they arrived (#63): a reply the desktop notified
 * before it disconnected reaches its request, and only then is a request
 * still waiting woken.
 *
 * The inbound consumer is held on the reply while the disconnect is
 * delivered from another thread; the old disconnect woke the waiting request
 * at once and dropped the queued reply.
 */
class BleClientEventOrderTest {

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

    private fun harness(): BleClientHarness = BleClientHarness(mtu = 247).also { harness = it }

    /** The #63 regression on the central: the reply notified before the disconnect is the request's answer. */
    @Test
    fun aReplyNotifiedBeforeTheDisconnectReachesItsRequest(): Unit = runBlocking {
        val h = harness()
        h.client.connect(h.address, randomKey())
        h.holdWrites = true
        val call = async(Dispatchers.Default) { runCatching { h.client.sendRequest(REQUEST) } }
        h.awaitUntil("the request's write") { h.heldWrites == 1 }
        val paused = ConsumerPause(h)

        h.releaseHeldWrites()
        paused.awaitPaused()
        onThread { disconnect(h) }
        // The callback has returned. Had it woken the request itself, ahead
        // of the reply, it would have taken the request's waiter in doing so.
        assertNotNull("the disconnect woke the request ahead of the reply", h.probe.pendingResponse)
        assertFalse("the request is not woken before the reply ahead of the disconnect", call.isCompleted)
        paused.resume()

        val reply = withTimeout(TIMEOUT_MS) { call.await() }
        assertArrayEquals(h.responseFor(REQUEST), reply.getOrThrow())
    }

    /** A request the desktop sent before it disconnected is not run, and nothing is written for it. */
    @Test
    fun aDesktopRequestQueuedBeforeTheDisconnectIsNotAnswered(): Unit = runBlocking {
        val h = harness()
        h.client.connect(h.address, randomKey())
        val paused = ConsumerPause(h)
        val writesBefore = h.writesOn(h.gatt)
        val takenBefore = h.inboundEventsTaken

        h.desktopSends(DESKTOP_REQUEST)
        paused.awaitPaused()
        onThread { disconnect(h) }
        paused.resume()

        // The request's one fragment, then the disconnect queued behind it:
        // once the consumer takes the disconnect, the request is handled.
        h.awaitInboundEventsTaken(takenBefore + 2)
        assertTrue("no answer goes out on an ended connection", h.receivedResponses.isEmpty())
        assertEquals(writesBefore, h.writesOn(h.gatt))
    }

    private fun disconnect(h: BleClientHarness) {
        h.probe.gattCallback.onConnectionStateChange(h.gatt, 0, BluetoothProfile.STATE_DISCONNECTED)
    }

    /** Runs [block] on a thread of its own, as the stack delivers a callback, and waits for it to return. */
    private fun onThread(block: () -> Unit) {
        var failure: Throwable? = null
        val thread = Thread { runCatching(block).onFailure { failure = it } }
        thread.start()
        thread.join(TIMEOUT_MS)
        failure?.let { throw it }
    }

    /** Holds the inbound consumer on the first event it takes, until [resume]. */
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
            assertTrue("the consumer never took the event", paused.await(TIMEOUT_MS, TimeUnit.MILLISECONDS))
        }

        fun resume() = released.countDown()
    }

    private fun randomKey(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }

    private companion object {
        const val TIMEOUT_MS = 5_000L

        val REQUEST = """{"jsonrpc":"2.0","id":1,"method":"local.listKeys"}""".toByteArray()
        val DESKTOP_REQUEST = """{"jsonrpc":"2.0","id":5,"method":"remote.ping","params":{}}""".toByteArray()
    }
}
