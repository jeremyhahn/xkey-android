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
import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mockk.verify
import java.security.SecureRandom
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * A GATT callback from a connection the client has moved on from, driven
 * through [BleClientHarness].
 *
 * The stack reports a link's disconnect on a binder thread, on its own
 * schedule: the client may already have disconnected that link and be
 * dialling, or be up on, the next one. Such a callback must complete or fail
 * nothing of the next connection's -- not its dial, not the write it has
 * outstanding -- while a disconnect from the connection's own GATT object
 * still fails its write and tears it down.
 */
class BleClientStaleCallbackTest {

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

    private fun harness(): BleClientHarness = BleClientHarness().also { harness = it }

    /**
     * The old link's disconnect has passed its identity
     * check -- it was still the connection's -- when the client disconnects
     * it and reconnects. By the time the callback goes on, the new connection
     * has a write outstanding. What the callback fails is what it took with
     * the check, so the new connection's write completes and it stays up.
     */
    @Test
    fun aDisconnectPausedPastItsCheckDoesNotFailTheNextConnectionsWrite(): Unit = runBlocking {
        val h = harness()
        h.client.connect(h.address, randomKey())
        val paused = StateChangePause(h.client, BluetoothProfile.STATE_DISCONNECTED)
        val lateDisconnect = thread(name = "old-link-disconnect") {
            h.probe.gattCallback.onConnectionStateChange(
                h.gatt, BluetoothGatt.GATT_SUCCESS, BluetoothProfile.STATE_DISCONNECTED
            )
        }
        paused.awaitPaused()

        h.probe.disconnectInternal()
        val newGatt = h.nextConnection()
        assertTrue(h.client.connect(h.address, randomKey()))
        h.holdWrites = true
        val call = async(Dispatchers.Default) { h.client.sendRequest(REQUEST) }
        awaitUntil("the request's write") { h.heldWrites == 1 }
        val requestWrite = h.probe.writeCompletion.get()

        paused.resume()
        lateDisconnect.join(TIMEOUT_MS)

        assertFalse("the old link's callback must return", lateDisconnect.isAlive)
        assertSame("the old link's disconnect failed the new connection's write", requestWrite, h.probe.writeCompletion.get())
        h.releaseHeldWrites()
        assertArrayEquals(h.responseFor(REQUEST), withTimeout(TIMEOUT_MS) { call.await() })
        // Queued behind the teardown the old callback launched, so that has
        // run, and left the new connection alone, before this returns.
        assertArrayEquals(h.responseFor(REQUEST), withTimeout(TIMEOUT_MS) { h.client.sendRequest(REQUEST) })
        assertSame("the old link's disconnect tore down the new one", newGatt, h.probe.gattConnection)
        assertTrue(h.client.isConnected())
    }

    /**
     * The old link reports its disconnect while the next connection is being
     * dialled -- before the client even holds that connection's GATT object
     * -- and again while its handshake has a write outstanding. Neither may
     * fail the dial or the handshake's write.
     */
    @Test
    fun aLateDisconnectWhileTheNextConnectionIsDialledLeavesItAlone(): Unit = runBlocking {
        val h = harness()
        h.client.connect(h.address, randomKey())
        h.probe.disconnectInternal()
        val newGatt = h.nextConnection()
        h.whileDialling = {
            h.probe.gattCallback.onConnectionStateChange(
                h.gatt, BluetoothGatt.GATT_SUCCESS, BluetoothProfile.STATE_DISCONNECTED
            )
        }
        h.holdWrites = true
        val reconnect = async(Dispatchers.Default) { h.client.connect(h.address, randomKey()) }
        awaitUntil("the reconnection's identity write") { h.heldWrites == 1 }
        val handshakeWrite = h.probe.writeCompletion.get()

        h.probe.gattCallback.onConnectionStateChange(
            h.gatt, BluetoothGatt.GATT_SUCCESS, BluetoothProfile.STATE_DISCONNECTED
        )

        assertSame("the old link's disconnect failed the handshake's write", handshakeWrite, h.probe.writeCompletion.get())
        assertTrue("the reconnection must still be under way", reconnect.isActive)
        h.releaseHeldWrites()
        assertTrue(withTimeout(TIMEOUT_MS) { reconnect.await() })
        assertSame(newGatt, h.probe.gattConnection)
        assertTrue(h.client.isConnected())
    }

    /** The connection's own disconnect still fails its write and tears it down. */
    @Test
    fun aDisconnectFromTheCurrentConnectionFailsItsWriteAndTearsItDown(): Unit = runBlocking {
        val h = harness()
        h.client.connect(h.address, randomKey())
        h.holdWrites = true
        val call = async(Dispatchers.Default) { runCatching { h.client.sendRequest(REQUEST) } }
        awaitUntil("the request's write") { h.heldWrites == 1 }

        h.probe.gattCallback.onConnectionStateChange(
            h.gatt, BluetoothGatt.GATT_SUCCESS, BluetoothProfile.STATE_DISCONNECTED
        )

        // At once, not at a deadline.
        val failure = withTimeout(QUICK_MS) { call.await() }.exceptionOrNull()
        assertTrue("the write must be failed, not left waiting: $failure", failure is BleClientException)
        awaitUntil("the link to be torn down") {
            h.client.connectionState.value == ClientConnectionState.Disconnected
        }
        assertNull(h.probe.gattConnection)
        assertFalse(h.client.isConnected())
        verify { h.gatt.close() }
    }

    /**
     * A request that has written and waits for its reply
     * holds stateMutex, which the teardown waits for, and has no write left
     * to fail. The connection's own disconnect wakes it in the callback, so
     * it fails at once rather than at the 60-second response timeout, and
     * the teardown runs once it has let go of the mutex.
     */
    @Test
    fun aDisconnectWhileARequestAwaitsItsReplyFailsItBeforeTheTeardown(): Unit = runBlocking {
        val h = harness()
        h.client.connect(h.address, randomKey())
        // The desktop answers with a request of its own, which the client
        // refuses, and never with the reply.
        h.responseFor = { DESKTOP_REQUEST }
        val call = async(Dispatchers.Default) { runCatching { h.client.sendRequest(REQUEST) } }
        h.awaitResponses(1)
        assertTrue("the request must be waiting for its reply", call.isActive)

        h.probe.gattCallback.onConnectionStateChange(
            h.gatt, BluetoothGatt.GATT_SUCCESS, BluetoothProfile.STATE_DISCONNECTED
        )

        val failure = withTimeout(TIMEOUT_MS) { call.await() }.exceptionOrNull()
        assertTrue("the request must be failed, not left waiting: $failure", failure is BleClientException)
        awaitUntil("the link to be torn down") {
            h.client.connectionState.value == ClientConnectionState.Disconnected
        }
        assertNull(h.probe.gattConnection)
        assertNull("no waiter may be left behind", h.probe.pendingResponse)
        assertFalse(h.client.isConnected())
        verify { h.gatt.close() }
    }

    /**
     * Parks the first state change of [newState] in [BleClient.stateChangeHook],
     * just after its GATT object was checked, until [resume].
     */
    private class StateChangePause(client: BleClient, private val newState: Int) {
        private val reached = CountDownLatch(1)
        private val released = CountDownLatch(1)
        private val armed = AtomicBoolean(true)

        init {
            client.stateChangeHook = { state ->
                if (state == newState && armed.compareAndSet(true, false)) {
                    reached.countDown()
                    released.await(TIMEOUT_MS, TimeUnit.MILLISECONDS)
                }
            }
        }

        fun awaitPaused() {
            assertTrue("no state change reached the hook", reached.await(TIMEOUT_MS, TimeUnit.MILLISECONDS))
        }

        fun resume() = released.countDown()
    }

    private fun awaitUntil(what: String, condition: () -> Boolean) {
        val deadline = System.currentTimeMillis() + TIMEOUT_MS
        while (!condition()) {
            if (System.currentTimeMillis() > deadline) throw AssertionError("timed out waiting for $what")
            Thread.sleep(2)
        }
    }

    private fun randomKey(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }

    private companion object {
        const val TIMEOUT_MS = 5_000L

        // Well inside BleClient.DRAIN_DEADLINE_MS.
        const val QUICK_MS = 2_000L

        val REQUEST = """{"jsonrpc":"2.0","id":1,"method":"local.listKeys"}""".toByteArray()

        /** Not served on a phone-initiated session: the client answers it with an error. */
        val DESKTOP_REQUEST = """{"jsonrpc":"2.0","id":99,"method":"local.listKeys"}""".toByteArray()
    }
}
