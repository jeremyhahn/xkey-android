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
import android.os.ParcelFileDescriptor
import android.util.Log
import com.automatethethings.xkey.protocol.RequestHandler
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mockk.verify
import kotlinx.coroutines.Job
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.io.IOException
import java.io.RandomAccessFile

/**
 * Unit tests for [UsbAccessoryServer]'s lifecycle and failure handling.
 *
 * The accessory lifecycle is driven entirely by system callbacks, so the states
 * a user can end up stuck in are the ones worth pinning: a refused
 * `openAccessory` must surface as [UsbAccessoryState.Error] rather than leaving
 * the UI showing "handshaking" forever, and it must not consume the connection
 * slot — otherwise the retry that Android delivers on the next attach would be
 * silently dropped. The same holds for a pulled cable: the detach must close
 * the accessory and free the slot, so the next attach serves again (#134).
 *
 * The handshake itself belongs to `StreamPairingSession` and is covered by its
 * own suites; here it only matters that nothing is sent before one exists.
 */
class UsbAccessoryServerTest {

    private lateinit var context: Context
    private lateinit var usbManager: UsbManager
    private lateinit var accessory: UsbAccessory
    private lateinit var server: UsbAccessoryServer
    private lateinit var watcher: FakeDetachWatcher
    private var detachedCalls = 0
    private val openFiles = mutableListOf<RandomAccessFile>()
    private val sessions = mutableListOf<Job>()

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

        watcher = FakeDetachWatcher()
        detachedCalls = 0
        server = UsbAccessoryServer(
            requestHandler = mockk<RequestHandler>(relaxed = true),
            detachWatcher = watcher,
            onDetached = { detachedCalls++ },
        )
    }

    @After
    fun tearDown() {
        server.disconnect()
        // A session logs as it ends; let every one end before Log is unmocked.
        runBlocking { withTimeout(5_000) { sessions.forEach { it.join() } } }
        sessions.clear()
        openFiles.forEach { it.close() }
        openFiles.clear()
        unmockkAll()
    }

    /** Delivers an attach of the accessory, keeping the session it starts to join in [tearDown]. */
    private fun attach() {
        server.connect(context, accessory)
        server.sessionJob?.let { job -> if (job !in sessions) sessions += job }
    }

    /** Records the detach watcher's lifecycle; [detach] plays the system broadcast. */
    private class FakeDetachWatcher : AccessoryDetachWatcher {
        var starts = 0
        var stops = 0
        var onDetach: ((UsbAccessory?) -> Unit)? = null

        override fun start(context: Context, onDetach: (UsbAccessory?) -> Unit) {
            starts++
            this.onDetach = onDetach
        }

        override fun stop() {
            stops++
            onDetach = null
        }

        fun detach(accessory: UsbAccessory?) {
            val callback = onDetach
            assertNotNull("no detach receiver is registered", callback)
            callback!!(accessory)
        }
    }

    /**
     * A descriptor the accessory opens to: an empty temporary file, so a
     * session that gets as far as reading sees end of stream, as when the host
     * has gone.
     */
    private fun openableDescriptor(): ParcelFileDescriptor {
        val file = File.createTempFile("usb-accessory", ".bin").apply { deleteOnExit() }
        val raf = RandomAccessFile(file, "rw").also { openFiles += it }
        val pfd = mockk<ParcelFileDescriptor>(relaxed = true)
        every { pfd.fileDescriptor } returns raf.fd
        return pfd
    }

    /** Waits up to [timeoutMs] for [condition], polling. */
    private fun awaitTrue(timeoutMs: Long = 5_000, condition: () -> Boolean): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (condition()) return true
            Thread.sleep(10)
        }
        return condition()
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

        attach()

        val state = server.state.value
        assertTrue(state is UsbAccessoryState.Error)
        assertEquals("Failed to open USB accessory", (state as UsbAccessoryState.Error).message)
    }

    @Test
    fun `a refused accessory leaves the connection slot free for a retry`() {
        every { usbManager.openAccessory(accessory) } returns null

        attach()
        attach()

        // Both attach events reached the USB manager; the first failure did not
        // latch the server into a state where later attaches are ignored.
        verify(exactly = 2) { usbManager.openAccessory(accessory) }
    }

    @Test
    fun `a refused accessory registers no detach receiver`() {
        every { usbManager.openAccessory(accessory) } returns null

        attach()

        assertEquals(0, watcher.starts)
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
        attach()
        assertTrue(server.state.value is UsbAccessoryState.Error)

        server.disconnect()

        assertEquals(UsbAccessoryState.Disconnected, server.state.value)
    }

    // -------------------------------------------------------------------------
    // Detach and reattach (#134)
    // -------------------------------------------------------------------------

    @Test
    fun `an open accessory registers a detach receiver until it disconnects`() {
        every { usbManager.openAccessory(accessory) } returns openableDescriptor()

        attach()
        assertEquals(1, watcher.starts)
        assertNotNull(watcher.onDetach)

        server.disconnect()
        assertTrue(watcher.stops >= 1)
        assertEquals(null, watcher.onDetach)
    }

    @Test
    fun `a detach closes the accessory and its session and tells the owner`() {
        val pfd = openableDescriptor()
        every { usbManager.openAccessory(accessory) } returns pfd

        attach()
        watcher.detach(accessory)

        verify { pfd.close() }
        assertFalse(server.isOpen)
        assertEquals(UsbAccessoryState.Disconnected, server.state.value)
        assertEquals(1, detachedCalls)
        assertEquals(null, watcher.onDetach)
    }

    @Test
    fun `a detach that names no accessory still closes the open one`() {
        val pfd = openableDescriptor()
        every { usbManager.openAccessory(accessory) } returns pfd

        attach()
        watcher.detach(null)

        verify { pfd.close() }
        assertEquals(1, detachedCalls)
    }

    @Test
    fun `a detach of another accessory leaves the open one alone`() {
        val pfd = openableDescriptor()
        every { usbManager.openAccessory(accessory) } returns pfd
        val other = mockk<UsbAccessory>(relaxed = true)

        attach()
        watcher.detach(other)

        assertEquals(0, detachedCalls)
        assertNotNull(watcher.onDetach)
    }

    @Test
    fun `after a detach a later attach serves again on the same server`() {
        every { usbManager.openAccessory(accessory) } returnsMany listOf(openableDescriptor(), openableDescriptor())

        attach()
        watcher.detach(accessory)
        attach()

        verify(exactly = 2) { usbManager.openAccessory(accessory) }
        assertEquals(2, watcher.starts)

        watcher.detach(accessory)
        assertEquals(2, detachedCalls)
    }

    @Test
    fun `a session that ends by itself frees the connection slot`() {
        every { usbManager.openAccessory(accessory) } returnsMany listOf(openableDescriptor(), openableDescriptor())

        attach()
        // The session cannot complete a handshake over an empty stream (nor
        // load a key from a mock context), so it ends on its own.
        assertTrue("the session never ended", awaitTrue { !server.isOpen })

        attach()

        verify(exactly = 2) { usbManager.openAccessory(accessory) }
    }
}
