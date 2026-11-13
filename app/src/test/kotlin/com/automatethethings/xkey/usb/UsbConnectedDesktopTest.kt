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
import com.automatethethings.xkey.oath.OathCredentialEntity
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.remote.BidirectionalMessageRouter
import com.automatethethings.xkey.remote.SessionSender
import com.automatethethings.xkey.remote.stubAndroidLog
import com.automatethethings.xkey.transport.StreamSessionHarness
import com.automatethethings.xkey.ui.DesktopOathLinks
import com.automatethethings.xkey.ui.OathDesktopActions
import io.mockk.every
import io.mockk.mockk
import io.mockk.unmockkAll
import java.io.IOException
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

/**
 * A USB accessory is a desktop for the `remote.*` clients only while its
 * session is [UsbAccessoryState.Connected]: the server object outlives the
 * handshake, a refused open and the end of a session.
 */
class UsbConnectedDesktopTest {

    private lateinit var server: UsbAccessoryServer
    private lateinit var router: BidirectionalMessageRouter
    private var secretReads = 0

    @Before
    fun setUp() {
        stubAndroidLog()
        router = BidirectionalMessageRouter(mockk<RequestHandler>())
        server = UsbAccessoryServer(requestHandler = mockk(relaxed = true), messageRouter = router)
    }

    @After
    fun tearDown() {
        server.disconnect()
        unmockkAll()
    }

    private fun actions() = OathDesktopActions(
        desktop = { server.connectedDesktop(router) },
        links = object : DesktopOathLinks {
            override fun get(peerKeyHex: String, oathId: String): String? = "desk-7"
            override fun put(peerKeyHex: String, oathId: String, desktopId: String) = Unit
        },
        secretOf = { _ -> secretReads++; ByteArray(10) }
    )

    private fun entity() = OathCredentialEntity(
        oathId = "GitHub:alice",
        oathType = "TOTP",
        algorithm = "SHA1",
        digits = 6,
        periodSeconds = 30,
        counter = 0,
        issuer = "GitHub",
        accountName = "alice",
        secretEncrypted = ByteArray(4),
        createdAt = 0L
    )

    private fun assertNoDesktop() = runTest {
        assertNull(server.connectedDesktop(router))
        val a = actions()
        assertFalse(a.isConnected())
        assertTrue(a.menuEntries(entity()).isEmpty())
        assertEquals(OathDesktopActions.Outcome.NotConnected, a.copyToDesktop(entity()))
        assertEquals(0, secretReads)
    }

    @Test
    fun `a disconnected server is no desktop`() {
        assertEquals(UsbAccessoryState.Disconnected, server.state.value)
        assertNoDesktop()
    }

    @Test
    fun `a refused accessory is no desktop`() {
        val usbManager = mockk<UsbManager>()
        val context = mockk<Context>()
        val accessory = mockk<UsbAccessory>(relaxed = true)
        every { context.getSystemService(Context.USB_SERVICE) } returns usbManager
        every { usbManager.openAccessory(accessory) } returns null

        server.connect(context, accessory)

        assertTrue(server.state.value is UsbAccessoryState.Error)
        assertNoDesktop()
    }

    @Test
    fun `an ended session is no desktop`() {
        server.disconnect()
        assertNoDesktop()
    }

    @Test
    fun `only a connected session with an authenticated peer is a desktop`() {
        for (state in listOf(
            UsbAccessoryState.Disconnected,
            UsbAccessoryState.Handshaking,
            UsbAccessoryState.Error("Failed to open USB accessory")
        )) {
            assertNull(state.toString(), server.connectedDesktop(state, PEER to bound, router))
        }
        assertNull(server.connectedDesktop(UsbAccessoryState.Connected("acc"), null, router))
        assertNull(server.connectedDesktop(UsbAccessoryState.Connected("acc"), PEER to bound, null))

        val desktop = server.connectedDesktop(UsbAccessoryState.Connected("acc"), PEER to bound, router)
        assertNotNull(desktop)
        assertEquals(PEER, desktop!!.peerKeyHex)
        assertTrue("the sender is the session's, never the server", desktop.sender === bound)
        assertTrue(desktop.router === router)
    }

    /**
     * The USB desktop is built from the stream session's bound sender: once
     * desktop A's connection is replaced by paired desktop B's, a send
     * captured for A fails and B receives nothing.
     */
    @Test
    fun `a send captured for desktop A fails once B replaces it and B receives nothing`() = runBlocking {
        StreamSessionHarness().use { harness ->
            val a = harness.connectPaired()
            val captured = server.connectedDesktop(UsbAccessoryState.Connected("acc"), harness.pairing.boundSender(), router)
            assertEquals(a.publicKeyHex, captured!!.peerKeyHex)

            val b = harness.connectPaired()
            assertEquals(b.publicKeyHex, harness.pairing.boundSender()!!.first)
            // A is still paired: only the connection binding refuses its send.
            assertTrue(
                "A stays paired",
                harness.repo.getAllDevices().any { it.publicKeyHex == a.publicKeyHex },
            )

            try {
                captured.sender.sendEncryptedMessage(REQUEST)
                fail("a send captured for A must not go out once B replaced it")
            } catch (e: IOException) {
                // A's connection is no longer the session's.
            }
            b.assertNoFrame()
        }
    }

    private val bound = object : SessionSender {
        override suspend fun sendEncryptedMessage(data: ByteArray) = Unit
    }

    private companion object {
        const val PEER = "aa01"
        val REQUEST = """{"jsonrpc":"2.0","id":9,"method":"remote.oathAdd","params":{}}""".toByteArray()
    }
}
