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

import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.remote.BidirectionalMessageRouter
import com.automatethethings.xkey.remote.ConnectedDesktop
import com.automatethethings.xkey.remote.RemoteKeyClient
import com.automatethethings.xkey.remote.ScriptedMessageSender
import com.automatethethings.xkey.remote.TEST_PEER_KEY_HEX
import com.automatethethings.xkey.remote.desktopOf
import com.automatethethings.xkey.remote.stubAndroidLog
import com.automatethethings.xkey.usb.UsbAccessoryState
import io.mockk.mockk
import io.mockk.unmockkAll
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Before
import org.junit.Test

/**
 * The service's desktop session as the USB transport drives it: a USB
 * accessory counts as a desktop only once its session is Connected, and the
 * client is dropped as soon as that session ends, even if the accessory is
 * never detached.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class DesktopSessionTrackerTest {

    private lateinit var router: BidirectionalMessageRouter
    private lateinit var sender: ScriptedMessageSender

    @Before
    fun setUp() {
        stubAndroidLog()
        router = BidirectionalMessageRouter(mockk<RequestHandler>())
        sender = ScriptedMessageSender(router)
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    /** The USB desktop as UsbAccessoryServer hands it out: only while Connected. */
    private fun usbDesktop(state: UsbAccessoryState, peer: String = TEST_PEER_KEY_HEX): ConnectedDesktop? =
        if (state is UsbAccessoryState.Connected) desktopOf(sender, router, peer) else null

    @Test
    fun `the USB session publishes the client on Connected and drops it when it ends`() = runTest {
        val usbState = MutableStateFlow<UsbAccessoryState>(UsbAccessoryState.Handshaking)
        val tracker = DesktopSessionTracker.ofDesktop { usbDesktop(usbState.value) }
        val seen = mutableListOf<RemoteKeyClient?>()
        backgroundScope.launch(UnconfinedTestDispatcher(testScheduler)) { tracker.session.toList(seen) }
        tracker.follow(backgroundScope, usbState)
        runCurrent()

        // Connecting: no desktop yet.
        assertNull(tracker.session.value)
        assertNull(tracker.client())

        usbState.value = UsbAccessoryState.Connected("acc")
        runCurrent()
        val first = tracker.session.value
        assertNotNull(first)
        assertSame(first, tracker.client())

        // The session ends without a detach: the client goes with it.
        usbState.value = UsbAccessoryState.Disconnected
        runCurrent()
        assertNull(tracker.session.value)
        assertNull(tracker.client())

        // A new session on the same accessory gets a fresh client.
        usbState.value = UsbAccessoryState.Connected("acc")
        runCurrent()
        assertNotNull(tracker.session.value)
        assertNotSame(first, tracker.session.value)

        usbState.value = UsbAccessoryState.Error("cable")
        runCurrent()
        assertNull(tracker.session.value)

        // The PIV screens saw every transition: none, ready, lost, ready, lost.
        assertEquals(5, seen.size)
    }

    @Test
    fun `another desktop on the same router gets its own client`() {
        var peer = "aa01"
        val tracker = DesktopSessionTracker.ofDesktop { desktopOf(sender, router, peer) }
        val first = tracker.client()
        assertSame(first, tracker.client())
        peer = "bb02"
        assertNotSame(first, tracker.client())
    }
}
