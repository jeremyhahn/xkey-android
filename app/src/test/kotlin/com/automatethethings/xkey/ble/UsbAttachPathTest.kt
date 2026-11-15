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

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.hardware.usb.UsbAccessory
import android.hardware.usb.UsbManager
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.content.IntentCompat
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.remote.BidirectionalMessageRouter
import com.automatethethings.xkey.usb.BroadcastAccessoryDetachWatcher
import com.automatethethings.xkey.usb.UsbAccessoryServer
import com.automatethethings.xkey.usb.UsbAccessoryServerSlot
import com.automatethethings.xkey.usb.UsbAccessoryState
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.io.RandomAccessFile
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The service's USB attach path (#134): an attach that resumes late, after
 * its server closed and a replacement attached, must not take the desktop
 * session's observer away from the replacement.
 *
 * The slot, the servers and the detach receiver are the production ones; only
 * the receiver's registration and the accessory are faked, as in
 * UsbAccessoryServerSlotTest.
 */
class UsbAttachPathTest {

    private lateinit var context: Context
    private lateinit var accessory: UsbAccessory
    private lateinit var handler: RequestHandler
    private lateinit var slot: UsbAccessoryServerSlot
    private lateinit var scope: CoroutineScope
    private val receivers = mutableListOf<BroadcastReceiver>()
    private val opened = mutableListOf<UsbAccessoryServer>()
    private val openFiles = mutableListOf<RandomAccessFile>()

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

        // Sessions wait in their key load (Handshaking) until cancelled.
        mockkConstructor(NoiseSession::class)
        coEvery { anyConstructed<NoiseSession>().loadStaticKey(any()) } coAnswers { awaitCancellation() }

        val usbManager = mockk<UsbManager>()
        context = mockk(relaxed = true)
        every { context.applicationContext } returns context
        every { context.getSystemService(Context.USB_SERVICE) } returns usbManager
        every { usbManager.openAccessory(any()) } answers { openableDescriptor() }

        accessory = mockk(relaxed = true)
        handler = mockk(relaxed = true)
        slot = UsbAccessoryServerSlot(
            newDetachWatcher = { BroadcastAccessoryDetachWatcher { _, receiver -> receivers += receiver } },
        )
        scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    }

    @After
    fun tearDown() {
        scope.cancel()
        slot.clear()
        synchronized(opened) { opened.forEach { it.disconnect() } }
        runBlocking { withTimeout(5_000) { opened.forEach { it.sessionJob?.join() } } }
        openFiles.forEach { it.close() }
        unmockkAll()
    }

    private fun openableDescriptor(): ParcelFileDescriptor {
        val file = File.createTempFile("usb-accessory", ".bin").apply { deleteOnExit() }
        val raf = RandomAccessFile(file, "rw").also { openFiles += it }
        val pfd = mockk<ParcelFileDescriptor>(relaxed = true)
        every { pfd.fileDescriptor } returns raf.fd
        return pfd
    }

    /** The service's call: open the accessory through the slot. */
    private suspend fun UsbAttachPath.attachAccessory(): UsbAccessoryServer? = attach {
        open(
            context = context,
            accessory = accessory,
            requestHandler = handler,
            router = mockk<BidirectionalMessageRouter>(relaxed = true),
        )
    }?.also { synchronized(opened) { opened += it } }

    private fun waitFor(timeoutMs: Long, condition: () -> Boolean): Boolean {
        val end = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < end) {
            if (condition()) return true
            Thread.sleep(10)
        }
        return condition()
    }

    /** Plays the system's USB_ACCESSORY_DETACHED broadcast to the last registered receiver. */
    private fun broadcastDetach() {
        val intent = mockk<Intent>()
        every { intent.action } returns UsbManager.ACTION_USB_ACCESSORY_DETACHED
        mockkStatic(IntentCompat::class)
        every {
            IntentCompat.getParcelableExtra(intent, UsbManager.EXTRA_ACCESSORY, UsbAccessory::class.java)
        } returns accessory
        receivers.last().onReceive(context, intent)
    }

    @Test
    fun `an attach paused after its open does not take the observer from the replacement`() {
        // Ready while the slot's current server is in its handshake.
        val tracker = DesktopSessionTracker.ofDesktop {
            slot.current()?.takeIf { it.first.state.value is UsbAccessoryState.Handshaking }?.let { (_, router) ->
                com.automatethethings.xkey.remote.ConnectedDesktop(
                    "00", io.mockk.mockk<com.automatethethings.xkey.remote.SessionSender>(relaxed = true), router
                )
            }
        }
        val aOpened = CompletableDeferred<UsbAccessoryServer>()
        val releaseA = CompletableDeferred<Unit>()
        val firstAttach = AtomicBoolean(true)
        val path = UsbAttachPath(slot, tracker, scope, afterOpen = { server ->
            if (firstAttach.getAndSet(false)) {
                aOpened.complete(server)
                releaseA.await()
            }
        })

        // Attach A opens, then pauses before the rest of its attach path.
        val attachA = scope.async { path.attachAccessory() }
        val a = runBlocking { withTimeout(5_000) { aOpened.await() } }

        // A's cable is pulled while A's attach is paused; B attaches.
        broadcastDetach()
        runBlocking { withTimeout(5_000) { a.sessionJob?.join() } }
        val b = runBlocking { withTimeout(10_000) { path.attachAccessory() } }
        assertNotNull("the replacement attach was refused", b)
        assertNotSame(a, b)
        assertTrue("B's handshake did not refresh the session", waitFor(5_000) { tracker.session.value != null })

        // A's attach resumes late.
        releaseA.complete(Unit)
        runBlocking { withTimeout(5_000) { attachA.await() } }

        // B's transitions must still reach the desktop session.
        broadcastDetach()
        assertTrue(
            "B's detach did not refresh the desktop session: a late attach took its observer",
            waitFor(5_000) { tracker.session.value == null },
        )
    }
}
