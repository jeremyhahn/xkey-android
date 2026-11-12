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

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.hardware.usb.UsbAccessory
import android.hardware.usb.UsbManager
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.content.IntentCompat
import com.automatethethings.xkey.auth.SessionAuthManager
import com.automatethethings.xkey.ble.NoiseSession
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.remote.BidirectionalMessageRouter
import com.automatethethings.xkey.settings.BiometricAuthMode
import com.automatethethings.xkey.settings.BiometricSettingsData
import com.automatethethings.xkey.settings.UserVerificationPolicy
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mockk.verify
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.io.RandomAccessFile
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread

/**
 * The service's USB server slot (#134): a detach delivered through the
 * production [BroadcastAccessoryDetachWatcher] receiver reaches the slot's
 * close wiring, the slot drops its closed server, and the next attach starts
 * a new one without a service restart.
 *
 * Only the receiver's registration is swapped (the unit-test android.jar has
 * no IntentFilter); the receiver itself, the server and the slot are the
 * production ones.
 */
class UsbAccessoryServerSlotTest {

    private lateinit var context: Context
    private lateinit var usbManager: UsbManager
    private lateinit var accessory: UsbAccessory
    private lateinit var slot: UsbAccessoryServerSlot
    private val receivers = mutableListOf<BroadcastReceiver>()
    private val opened = mutableListOf<UsbAccessoryServer>()
    private val openFiles = mutableListOf<RandomAccessFile>()

    /** One handler shared by every attach, as the service shares its RequestHandler. */
    private lateinit var handler: RequestHandler
    @Volatile private var sessionId: String? = null
    @Volatile private var peerKeyHex: String? = null

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

        // Sessions wait in their key load until cancelled, so only a close ends one.
        mockkConstructor(NoiseSession::class)
        coEvery { anyConstructed<NoiseSession>().loadStaticKey(any()) } coAnswers { awaitCancellation() }

        usbManager = mockk()
        context = mockk(relaxed = true)
        every { context.applicationContext } returns context
        every { context.getSystemService(Context.USB_SERVICE) } returns usbManager
        every { usbManager.openAccessory(any()) } answers { openableDescriptor() }

        accessory = mockk(relaxed = true)
        every { accessory.manufacturer } returns "Automate The Things"
        every { accessory.model } returns "xKey"

        handler = mockk(relaxed = true)
        every { handler.setSessionId(any()) } answers { sessionId = firstArg() }
        every { handler.setConnectedDevicePublicKeyHex(any()) } answers { peerKeyHex = firstArg() }

        slot = UsbAccessoryServerSlot(
            newDetachWatcher = { BroadcastAccessoryDetachWatcher { _, receiver -> receivers += receiver } },
        )
    }

    @After
    fun tearDown() {
        slot.clear()
        opened.forEach { it.disconnect() }
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

    private fun attach(): UsbAccessoryServer? = runBlocking {
        slot.open(
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
    private fun broadcastDetach(detached: UsbAccessory) {
        val intent = mockk<Intent>()
        every { intent.action } returns UsbManager.ACTION_USB_ACCESSORY_DETACHED
        mockkStatic(IntentCompat::class)
        every {
            IntentCompat.getParcelableExtra(intent, UsbManager.EXTRA_ACCESSORY, UsbAccessory::class.java)
        } returns detached
        receivers.last().onReceive(context, intent)
    }

    @Test
    fun `a detach broadcast drops the closed server and the next attach starts a new one`() {
        val first = attach()
        assertNotNull(first)
        assertSame(first, slot.current()?.first)
        assertEquals(1, receivers.size)

        broadcastDetach(accessory)

        assertFalse(first!!.isOpen)
        assertNull("the slot kept the closed server", slot.current())

        val second = attach()
        assertNotNull("the attach after the detach was ignored", second)
        assertNotSame(first, second)
        assertSame(second, slot.current()?.first)
        assertEquals(true, second!!.isOpen)
        verify(exactly = 2) { usbManager.openAccessory(accessory) }
    }

    @Test
    fun `an attach while a server is active is ignored`() {
        val first = attach()
        assertNotNull(first)

        assertNull(attach())
        assertSame(first, slot.current()?.first)
    }

    @Test
    fun `a per-session approval does not carry over a detach and reattach`() {
        val auth = SessionAuthManager()
        val perSession = BiometricSettingsData(
            uvPolicy = UserVerificationPolicy.REQUIRED,
            authMode = BiometricAuthMode.PER_SESSION,
        )

        assertNotNull(attach())
        // The user approves once in this USB session, as a local.sign prompt does.
        assertTrue(auth.isBiometricRequired(perSession, sessionId))
        auth.recordAuthentication(sessionId)
        assertFalse(auth.isBiometricRequired(perSession, sessionId))

        broadcastDetach(accessory)
        assertNotNull(attach())

        assertTrue(
            "the approval of the detached USB session was reused",
            auth.isBiometricRequired(perSession, sessionId),
        )
    }

    @Test
    fun `a slow teardown of the detached session keeps the new peer identity`() {
        val oldTeardown = CompletableDeferred<Unit>()
        val sessions = AtomicInteger()
        coEvery { anyConstructed<NoiseSession>().loadStaticKey(any()) } coAnswers {
            if (sessions.incrementAndGet() == 1) {
                handler.setConnectedDevicePublicKeyHex("old-peer")
                try {
                    awaitCancellation()
                } finally {
                    // The pairing session's teardown clears the shared peer identity.
                    withContext(NonCancellable) {
                        oldTeardown.await()
                        handler.setConnectedDevicePublicKeyHex(null)
                    }
                }
            } else {
                handler.setConnectedDevicePublicKeyHex("new-peer")
                awaitCancellation()
            }
        }

        val first = attach()
        assertNotNull(first)
        assertTrue(waitFor(5_000) { peerKeyHex == "old-peer" })

        broadcastDetach(accessory)
        var second: UsbAccessoryServer? = null
        val reattach = thread { second = attach() }
        waitFor(1_000) { peerKeyHex == "new-peer" }

        oldTeardown.complete(Unit)
        reattach.join(5_000)
        runBlocking { withTimeout(5_000) { first!!.sessionJob?.join() } }
        assertNotNull("the reattach was ignored", second)
        assertTrue(waitFor(5_000) { sessions.get() == 2 })
        waitFor(2_000) { peerKeyHex == "new-peer" }

        assertEquals("the old session's teardown cleared the new peer", "new-peer", peerKeyHex)
    }

    @Test
    fun `an open that throws leaves the slot empty and stops the detach watcher`() {
        every { usbManager.openAccessory(any()) } throws SecurityException("no USB permission") andThenAnswer {
            openableDescriptor()
        }

        val thrown = runCatching { attach() }.exceptionOrNull()
        assertTrue(thrown is SecurityException)
        assertNull(slot.current())
        assertFalse(slot.isActive)
        assertEquals(1, receivers.size)
        verify(exactly = 1) { context.unregisterReceiver(receivers[0]) }

        val next = attach()
        assertNotNull(next)
        assertSame(next, slot.current()?.first)
    }

    @Test
    fun `a connect that throws after the open closes the descriptor`() {
        val descriptors = mutableListOf<ParcelFileDescriptor>()
        every { usbManager.openAccessory(any()) } answers { openableDescriptor().also { descriptors += it } }
        every { handler.setSessionId(any()) } throws IllegalStateException("session id refused") andThenAnswer {
            sessionId = firstArg()
        }

        val thrown = runCatching { attach() }.exceptionOrNull()
        assertTrue(thrown is IllegalStateException)
        assertNull(slot.current())
        verify(exactly = 1) { descriptors[0].close() }
        verify(exactly = 1) { context.unregisterReceiver(receivers[0]) }

        val next = attach()
        assertNotNull(next)
        assertSame(next, slot.current()?.first)
        assertEquals(2, descriptors.size)
    }
}
