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
import io.mockk.verify
import java.security.SecureRandom
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

/**
 * What [BleClient] does when a request or a teardown goes wrong, driven through
 * [BleClientHarness].
 *
 * [BleClientConnectionTest] covers the connect ladder and the happy request
 * loop by calling the *internal* teardown directly. Three things it never
 * reaches are asserted here, and each is a way the client can strand its
 * caller rather than fail it:
 *
 *  - the public `disconnect()`, which is what the UI calls. It is fire and
 *    forget — the work happens on the client's own scope — so a caller has no
 *    return value to check and a broken one would simply never tear down;
 *  - a request whose write the stack refuses. The response deferred must be
 *    cancelled on the way out, or the *next* request inherits a dead one and
 *    waits the full sixty-second timeout for a reply that can never arrive;
 *  - a `close()` that throws during teardown, which must not stop the rest of
 *    the state being cleared.
 */
class BleClientTeardownTest {

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

    // -----------------------------------------------------------------
    // The public teardown
    // -----------------------------------------------------------------

    /**
     * `disconnect()` returns before the work is done, so the only thing a
     * caller can rely on is that it eventually happens.
     */
    @Test
    fun thePublicDisconnectEventuallyClosesTheLink(): Unit = runBlocking {
        val h = harness()
        h.client.connect(h.address, randomKey())
        assertTrue(h.client.isConnected())

        h.client.disconnect()

        // The teardown clears the link before it closes the GATT object, and
        // the harness signals each close.
        h.awaitUntil("the link to be torn down") { h.probe.gattConnection == null }
        assertNull("the session must not outlive the link", h.probe.noiseSession)
        assertFalse(h.client.isConnected())
        verify { h.gatt.close() }
    }

    /** A stack that throws on close must not leave half-cleared state behind. */
    @Test
    fun aCloseThatThrowsStillClearsTheConnection(): Unit = runBlocking {
        val h = harness()
        h.client.connect(h.address, randomKey())
        every { h.gatt.close() } throws IllegalStateException("stack already gone")

        h.probe.disconnectInternal()

        assertNull(h.probe.gattConnection)
        assertNull(h.probe.connectedDevice)
        assertNull(h.probe.noiseSession)
        assertEquals("the MTU falls back to the BLE minimum", 23, h.probe.negotiatedMtu)
    }

    // -----------------------------------------------------------------
    // Requests that cannot be sent
    // -----------------------------------------------------------------

    /**
     * A request the stack will not even start must fail immediately and leave
     * nothing waiting behind it.
     */
    @Test
    fun aRequestTheStackRefusesToWriteFailsAndClearsThePendingResponse(): Unit = runBlocking {
        val h = harness()
        h.client.connect(h.address, randomKey())
        h.writeStarts = false

        try {
            h.client.sendRequest("""{"id":1,"method":"local.getCapabilities"}""".toByteArray())
            fail("a write the stack refuses must fail the request")
        } catch (expected: BleClientException) {
            assertTrue(expected.message!!.contains("Request failed"))
        }

        assertNull(
            "a dead deferred must not be left for the next request to await",
            h.probe.pendingResponse
        )
        assertTrue("the session itself is still up", h.client.isConnected())
    }

    /**
     * A session can outlive the characteristics — discovery state is cleared on
     * disconnect. Sending then has nowhere to write, and must say so rather
     * than encrypt a message into nothing.
     */
    @Test
    fun aRequestWithoutAControlPointIsRefused(): Unit = runBlocking {
        val h = harness()
        h.client.connect(h.address, randomKey())
        h.probe.controlPointCharacteristic = null

        try {
            h.client.sendRequest("ping".toByteArray())
            fail("a request with nowhere to write must be refused")
        } catch (expected: BleClientException) {
            assertTrue(expected.message!!.contains("control point"))
        }
    }

    // -----------------------------------------------------------------
    // Connection state
    // -----------------------------------------------------------------


    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private fun randomKey(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }
}
