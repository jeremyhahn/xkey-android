// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under AGPL-3.0 (see LICENSE) or a commercial license.
// Contact licensing@automatethethings.com for commercial licensing options.

package com.automatethethings.xkey.ui

import com.automatethethings.xkey.oath.OathCredentialEntity
import com.automatethethings.xkey.protocol.MethodNames
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.remote.BidirectionalMessageRouter
import com.automatethethings.xkey.remote.ScriptedMessageSender
import com.automatethethings.xkey.remote.desktopOf
import com.automatethethings.xkey.remote.stubAndroidLog
import io.mockk.mockk
import io.mockk.spyk
import io.mockk.unmockkAll
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class OathDesktopActionsTest {

    private lateinit var router: BidirectionalMessageRouter
    private lateinit var sender: ScriptedMessageSender
    private val links = MapLinks()
    private val secrets = mutableListOf<ByteArray>()
    private var connected = true
    private var peer = PEER_A

    @Before
    fun setUp() {
        stubAndroidLog()
        router = spyk(BidirectionalMessageRouter(mockk<RequestHandler>()))
        sender = ScriptedMessageSender(router)
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    private fun actions() = OathDesktopActions(
        desktop = { if (connected) desktopOf(sender, router, peer) else null },
        links = links,
        secretOf = { _ ->
            // "Hello!\xde\xad\xbe\xef" = JBSWY3DPEHPK3PXP
            byteArrayOf(0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0xde.toByte(), 0xad.toByte(), 0xbe.toByte(), 0xef.toByte())
                .also { secrets += it }
        }
    )

    private fun entity(type: String = "TOTP") = OathCredentialEntity(
        oathId = "GitHub:alice",
        oathType = type,
        algorithm = "SHA1",
        digits = 6,
        periodSeconds = 30,
        counter = 3,
        issuer = "GitHub",
        accountName = "alice",
        secretEncrypted = ByteArray(4),
        createdAt = 0L
    )

    @Test
    fun `copy to desktop sends remote oathAdd and stores the link`() = runTest {
        sender.succeedWith("""{"success":true,"credential_id":"desk-7"}""")

        val outcome = actions().copyToDesktop(entity())

        assertEquals(OathDesktopActions.Outcome.Copied("desk-7"), outcome)
        val req = sender.lastRequest
        assertEquals(MethodNames.REMOTE_OATH_ADD, req.method)
        val cred = req.params!!.getJSONObject("credential")
        assertEquals("GitHub:alice", cred.getString("name"))
        assertEquals("totp", cred.getString("type"))
        assertEquals("JBSWY3DPEHPK3PXP", cred.getString("secret"))
        assertEquals("desk-7", links.get(PEER_A, "GitHub:alice"))
        assertTrue(secrets.single().all { it == 0.toByte() })
    }

    @Test
    fun `copy of an hotp credential carries its counter`() = runTest {
        sender.succeedWith("""{"success":true,"credential_id":"desk-8"}""")

        actions().copyToDesktop(entity(type = "HOTP"))

        val cred = sender.lastRequest.params!!.getJSONObject("credential")
        assertEquals("hotp", cred.getString("type"))
        assertEquals(3L, cred.getLong("counter"))
    }

    @Test
    fun `copy failure reports and stores no link`() = runTest {
        sender.failWith(-32603, "store locked")

        val outcome = actions().copyToDesktop(entity())

        assertTrue(outcome is OathDesktopActions.Outcome.Failed)
        assertNull(links.get(PEER_A, "GitHub:alice"))
        assertTrue(secrets.single().all { it == 0.toByte() })
    }

    @Test
    fun `desktop code sends remote oathGenerate and returns code and expiry`() = runTest {
        links.put(PEER_A, "GitHub:alice", "desk-7")
        sender.succeedWith("""{"code":"492039","expires_in":21}""")

        val outcome = actions().desktopCode(entity())

        assertEquals(OathDesktopActions.Outcome.Code("492039", 21), outcome)
        assertEquals(MethodNames.REMOTE_OATH_GENERATE, sender.lastRequest.method)
        assertEquals("desk-7", sender.lastRequest.params!!.getString("credential_id"))
    }

    @Test
    fun `desktop code without a link sends nothing`() = runTest {
        val outcome = actions().desktopCode(entity())

        assertEquals(OathDesktopActions.Outcome.NotOnDesktop, outcome)
        assertTrue(sender.sent.isEmpty())
    }

    @Test
    fun `malformed desktop code reply is a failure`() = runTest {
        links.put(PEER_A, "GitHub:alice", "desk-7")
        sender.succeedWith("""{"code":"abc"}""")

        assertTrue(actions().desktopCode(entity()) is OathDesktopActions.Outcome.Failed)
    }

    @Test
    fun `no desktop connected sends nothing and offers nothing`() = runTest {
        connected = false
        links.put(PEER_A, "GitHub:alice", "desk-7")
        val a = actions()

        assertFalse(a.isConnected())
        assertTrue(a.menuEntries(entity()).isEmpty())
        assertEquals(OathDesktopActions.Outcome.NotConnected, a.copyToDesktop(entity()))
        assertEquals(OathDesktopActions.Outcome.NotConnected, a.desktopCode(entity()))
        assertTrue(sender.sent.isEmpty())
        assertTrue(secrets.isEmpty())
    }

    @Test
    fun `menu offers copy and, once linked, the desktop code`() {
        val a = actions()
        assertEquals(listOf(OathDesktopActions.Entry.COPY), a.menuEntries(entity()))

        links.put(PEER_A, "GitHub:alice", "desk-7")
        assertEquals(
            listOf(OathDesktopActions.Entry.COPY, OathDesktopActions.Entry.DESKTOP_CODE),
            a.menuEntries(entity())
        )
    }

    @Test
    fun `a link belongs to the desktop it was copied to`() = runTest {
        sender.succeedWith("""{"success":true,"credential_id":"desk-7"}""")
        val a = actions()
        assertEquals(OathDesktopActions.Outcome.Copied("desk-7"), a.copyToDesktop(entity()))

        peer = PEER_B
        sender.sent.clear()
        assertEquals(listOf(OathDesktopActions.Entry.COPY), a.menuEntries(entity()))
        assertEquals(OathDesktopActions.Outcome.NotOnDesktop, a.desktopCode(entity()))
        assertTrue(sender.sent.isEmpty())

        sender.succeedWith("""{"success":true,"credential_id":"desk-9"}""")
        assertEquals(OathDesktopActions.Outcome.Copied("desk-9"), a.copyToDesktop(entity()))
        assertEquals("desk-7", links.get(PEER_A, "GitHub:alice"))
        assertEquals("desk-9", links.get(PEER_B, "GitHub:alice"))

        peer = PEER_A
        assertEquals(
            listOf(OathDesktopActions.Entry.COPY, OathDesktopActions.Entry.DESKTOP_CODE),
            a.menuEntries(entity())
        )
        sender.succeedWith("""{"code":"492039","expires_in":21}""")
        a.desktopCode(entity())
        assertEquals("desk-7", sender.lastRequest.params!!.getString("credential_id"))
    }

    @Test
    fun `a menu action goes to the desktop present when the menu opened`() = runTest {
        links.put(PEER_A, "GitHub:alice", "desk-7")
        val a = actions()
        val menu = a.openMenu(entity())
        assertEquals(
            listOf(OathDesktopActions.Entry.COPY, OathDesktopActions.Entry.DESKTOP_CODE),
            menu.entries
        )

        // Desktop B replaces A while the menu is open.
        peer = PEER_B
        sender.succeedWith("""{"code":"492039","expires_in":21}""")
        assertEquals(OathDesktopActions.Outcome.Code("492039", 21), menu.desktopCode())
        assertEquals("desk-7", sender.lastRequest.params!!.getString("credential_id"))

        sender.succeedWith("""{"success":true,"credential_id":"desk-9"}""")
        assertEquals(OathDesktopActions.Outcome.Copied("desk-9"), menu.copyToDesktop())
        assertEquals("the link is A's, the desktop the menu opened on", "desk-9", links.get(PEER_A, "GitHub:alice"))
        assertNull("B inherits nothing from A's menu", links.get(PEER_B, "GitHub:alice"))
    }

    @Test
    fun `a menu opened with no desktop sends nothing once one connects`() = runTest {
        connected = false
        val menu = actions().openMenu(entity())
        assertTrue(menu.entries.isEmpty())

        connected = true
        assertEquals(OathDesktopActions.Outcome.NotConnected, menu.copyToDesktop())
        assertEquals(OathDesktopActions.Outcome.NotConnected, menu.desktopCode())
        assertTrue(sender.sent.isEmpty())
        assertTrue(secrets.isEmpty())
    }

    private class MapLinks : DesktopOathLinks {
        private val map = mutableMapOf<Pair<String, String>, String>()
        override fun get(peerKeyHex: String, oathId: String): String? = map[peerKeyHex to oathId]
        override fun put(peerKeyHex: String, oathId: String, desktopId: String) {
            map[peerKeyHex to oathId] = desktopId
        }
    }

    private companion object {
        const val PEER_A = "aa01"
        const val PEER_B = "bb02"
    }
}
