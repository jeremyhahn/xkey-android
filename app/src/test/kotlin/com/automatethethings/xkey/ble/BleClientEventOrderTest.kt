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
        awaitUntil("the request's write") { h.heldWrites == 1 }
        val paused = ConsumerPause(h.client)

        h.releaseHeldWrites()
        paused.awaitPaused()
        onThread { disconnect(h) }
        Thread.sleep(SETTLE_MS)
        assertFalse("the request is not woken before the reply ahead of the disconnect", call.isCompleted)
        paused.resume()

        val reply = withTimeout(TIMEOUT_MS) { call.await() }
        assertArrayEquals(h.responseFor(REQUEST), reply.getOrThrow())
    }

    /** With no reply queued, the disconnect still wakes the waiting request at once, not at a deadline. */
    @Test
    fun aDisconnectWithNoReplyQueuedFailsTheRequestAtOnce(): Unit = runBlocking {
        val h = harness()
        h.client.connect(h.address, randomKey())
        h.holdWrites = true
        val call = async(Dispatchers.Default) { runCatching { h.client.sendRequest(REQUEST) } }
        awaitUntil("the request's write") { h.heldWrites == 1 }

        onThread { disconnect(h) }

        val failed = withTimeout(QUICK_MS) { call.await() }
        assertTrue("the request fails with the connection", failed.isFailure)
    }

    /** A request the desktop sent before it disconnected is not run, and nothing is written for it. */
    @Test
    fun aDesktopRequestQueuedBeforeTheDisconnectIsNotAnswered(): Unit = runBlocking {
        val h = harness()
        h.client.connect(h.address, randomKey())
        val paused = ConsumerPause(h.client)
        val writesBefore = h.writesOn(h.gatt)

        h.desktopSends(DESKTOP_REQUEST)
        paused.awaitPaused()
        onThread { disconnect(h) }
        paused.resume()

        Thread.sleep(SETTLE_MS)
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
    private class ConsumerPause(client: BleClient) {
        private val paused = CountDownLatch(1)
        private val released = CountDownLatch(1)
        private val first = AtomicBoolean(true)

        init {
            client.inboundFragmentHook = {
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

    private fun awaitUntil(what: String, condition: () -> Boolean) {
        val deadline = System.currentTimeMillis() + TIMEOUT_MS
        while (System.currentTimeMillis() < deadline) {
            if (condition()) return
            Thread.sleep(5)
        }
        throw AssertionError("timed out waiting for $what")
    }

    private fun randomKey(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }

    private companion object {
        const val TIMEOUT_MS = 5_000L

        // Well inside BleClient.DRAIN_DEADLINE_MS.
        const val QUICK_MS = 2_000L

        // Long enough for a disconnect handled out of order to have woken the request.
        const val SETTLE_MS = 300L

        val REQUEST = """{"jsonrpc":"2.0","id":1,"method":"local.listKeys"}""".toByteArray()
        val DESKTOP_REQUEST = """{"jsonrpc":"2.0","id":5,"method":"remote.ping","params":{}}""".toByteArray()
    }
}
