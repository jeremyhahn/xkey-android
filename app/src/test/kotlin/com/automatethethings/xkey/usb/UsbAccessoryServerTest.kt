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
package com.automatethethings.xkey.usb

import android.content.Context
import android.hardware.usb.UsbAccessory
import android.hardware.usb.UsbManager
import android.util.Log
import com.automatethethings.xkey.protocol.RequestHandler
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mockk.verify
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.IOException

/**
 * Unit tests for [UsbAccessoryServer]'s lifecycle and failure handling.
 *
 * The accessory lifecycle is driven entirely by system callbacks, so the states
 * a user can end up stuck in are the ones worth pinning: a refused
 * `openAccessory` must surface as [UsbAccessoryState.Error] rather than leaving
 * the UI showing "handshaking" forever, and it must not consume the connection
 * slot — otherwise the retry that Android delivers on the next attach would be
 * silently dropped.
 *
 * The handshake itself belongs to `StreamPairingSession` and is covered by its
 * own suites; here it only matters that nothing is sent before one exists.
 */
class UsbAccessoryServerTest {

    private lateinit var context: Context
    private lateinit var usbManager: UsbManager
    private lateinit var accessory: UsbAccessory
    private lateinit var server: UsbAccessoryServer

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.v(any(), any()) } returns 0
        every { Log.d(any(), any()) } returns 0
        every { Log.i(any(), any()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>(), any()) } returns 0
        every { Log.e(any(), any()) } returns 0
        every { Log.e(any(), any(), any()) } returns 0

        usbManager = mockk()
        context = mockk()
        every { context.getSystemService(Context.USB_SERVICE) } returns usbManager

        accessory = mockk(relaxed = true)
        every { accessory.manufacturer } returns "Automate The Things"
        every { accessory.model } returns "xKey"

        server = UsbAccessoryServer(requestHandler = mockk(relaxed = true))
    }

    @After
    fun tearDown() {
        server.disconnect()
        unmockkAll()
    }

    // -------------------------------------------------------------------------
    // Initial state
    // -------------------------------------------------------------------------

    @Test
    fun `a fresh server reports itself disconnected`() {
        assertEquals(UsbAccessoryState.Disconnected, server.state.value)
    }

    @Test
    fun `a fresh server has nothing to send on`() = runTest {
        val error = try {
            server.sendEncryptedMessage(byteArrayOf(1, 2, 3))
            null
        } catch (e: IOException) {
            e
        }

        assertEquals("No active Noise session", error?.message)
    }

    // -------------------------------------------------------------------------
    // A refused accessory
    // -------------------------------------------------------------------------

    @Test
    fun `a refused accessory surfaces as an error rather than a stuck handshake`() {
        every { usbManager.openAccessory(accessory) } returns null

        server.connect(context, accessory)

        val state = server.state.value
        assertTrue(state is UsbAccessoryState.Error)
        assertEquals("Failed to open USB accessory", (state as UsbAccessoryState.Error).message)
    }

    @Test
    fun `a refused accessory leaves the connection slot free for a retry`() {
        every { usbManager.openAccessory(accessory) } returns null

        server.connect(context, accessory)
        server.connect(context, accessory)

        // Both attach events reached the USB manager; the first failure did not
        // latch the server into a state where later attaches are ignored.
        verify(exactly = 2) { usbManager.openAccessory(accessory) }
    }

    // -------------------------------------------------------------------------
    // Disconnect
    // -------------------------------------------------------------------------

    @Test
    fun `disconnect is idempotent`() {
        server.disconnect()
        server.disconnect()

        assertEquals(UsbAccessoryState.Disconnected, server.state.value)
    }

    @Test
    fun `disconnect clears a previous error state`() {
        every { usbManager.openAccessory(accessory) } returns null
        server.connect(context, accessory)
        assertTrue(server.state.value is UsbAccessoryState.Error)

        server.disconnect()

        assertEquals(UsbAccessoryState.Disconnected, server.state.value)
    }
}
