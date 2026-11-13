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
package com.automatethethings.xkey.ui

import com.automatethethings.xkey.protocol.ErrorCodes
import com.automatethethings.xkey.protocol.ProtocolException
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.remote.BidirectionalMessageRouter
import com.automatethethings.xkey.remote.RemoteKeyClient
import com.automatethethings.xkey.remote.ScriptedMessageSender
import com.automatethethings.xkey.remote.stubAndroidLog
import io.mockk.mockk
import io.mockk.unmockkAll
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.util.Base64

/**
 * Unit tests for the desktop half of the PIV screens: [DesktopPivSlots] (the
 * slot list on [PivActivity]) and [DesktopPivSlotActions] (certificate detail
 * and test sign on [PivSlotDetailActivity]).
 */
class DesktopPivSlotsTest {

    private lateinit var router: BidirectionalMessageRouter
    private lateinit var sender: ScriptedMessageSender
    private lateinit var client: RemoteKeyClient

    @Before
    fun setUp() {
        stubAndroidLog()
        router = BidirectionalMessageRouter(mockk<RequestHandler>())
        sender = ScriptedMessageSender(router)
        client = RemoteKeyClient(sender, router, requestTimeoutMs = 5_000L)
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `no connected desktop gives no desktop slots and sends nothing`() = runTest {
        val slots = DesktopPivSlots { null }.load()

        assertTrue(slots.isEmpty())
        assertTrue(sender.sent.isEmpty())
    }

    @Test
    fun `a desktop error gives no desktop slots instead of throwing`() = runTest {
        sender.failWith(ErrorCodes.PIV_SLOT_NOT_FOUND, "PIV not configured")

        assertTrue(DesktopPivSlots { client }.load().isEmpty())
    }

    @Test
    fun `a malformed desktop reply gives no desktop slots instead of throwing`() = runTest {
        sender.succeedWith("""{"slots":"nope"}""")

        assertTrue(DesktopPivSlots { client }.load().isEmpty())
    }

    @Test
    fun `a silent desktop gives no desktop slots instead of throwing`() = runTest {
        sender.neverReply()

        assertTrue(DesktopPivSlots { client }.load().isEmpty())
    }

    @Test
    fun `the desktop's slots load through remote_pivListSlots`() = runTest {
        sender.succeedWith(
            """{"slots":[{"slot":"9c","algorithm":"ECDSA-P256","has_key":true,
                "has_certificate":false}]}"""
        )

        val slots = DesktopPivSlots { client }.load()

        assertEquals("remote.pivListSlots", sender.lastRequest.method)
        assertEquals(listOf("9c"), slots.map { it.slot })
    }

    @Test
    fun `a desktop slot certificate comes from remote_pivGetCert`() = runTest {
        sender.succeedWith("""{"certificate_der":"$TEST_CERT_B64","subject":"CN=alice"}""")

        val cert = DesktopPivSlotActions(client).certificate("9a")

        assertEquals("remote.pivGetCert", sender.lastRequest.method)
        assertEquals("9a", requireNotNull(sender.lastRequest.params).getString("slot"))
        assertEquals("CN=alice", cert?.subject)
    }

    @Test
    fun `a desktop slot without a certificate shows none`() = runTest {
        sender.failWith(ErrorCodes.PIV_SLOT_NOT_FOUND, "no certificate")

        assertNull(DesktopPivSlotActions(client).certificate("9a"))
    }

    @Test
    fun `any other certificate failure reaches the caller`() = runTest {
        sender.failWith(ErrorCodes.INTERNAL_ERROR, "boom")

        try {
            DesktopPivSlotActions(client).certificate("9a")
            fail("expected a ProtocolException")
        } catch (e: ProtocolException) {
            assertEquals(ErrorCodes.INTERNAL_ERROR, e.errorCode)
        }
    }

    @Test
    fun `a desktop slot test sign sends remote_pivSign`() = runTest {
        sender.succeedWith("""{"signature":"AQID","algorithm":"ECDSA-P256"}""")

        val result = DesktopPivSlotActions(client).signTest("9c")

        val request = sender.lastRequest
        assertEquals("remote.pivSign", request.method)
        val params = requireNotNull(request.params)
        assertEquals("9c", params.getString("slot"))
        assertArrayEquals(
            DesktopPivSlotActions.TEST_DATA,
            Base64.getDecoder().decode(params.getString("data"))
        )
        assertArrayEquals(byteArrayOf(1, 2, 3), result.signature)
    }

    private companion object {
        /** Self-signed P-256 certificate, shared with RemoteKeyClientTest. */
        const val TEST_CERT_B64 =
            "MIIBlzCCAT2gAwIBAgIUa7dyC68C+loNkjRl2ObjpoqPaeIwCgYIKoZIzj0EAwIwIDEeMBwGA1UE" +
                "AwwVeGtleS10ZXN0LWF0dGVzdGF0aW9uMCAXDTI2MDgwNDE3MzIxMVoYDzIxMjYwNzExMTczMjEx" +
                "WjAgMR4wHAYDVQQDDBV4a2V5LXRlc3QtYXR0ZXN0YXRpb24wWTATBgcqhkjOPQIBBggqhkjOPQMB" +
                "BwNCAARjknCWu53trpHuN0P50IiHFjLNKu2vTKueeQnV3PvVaZe/+ItshGBaPeJNyt71yGUEp/Zu" +
                "qBQWdzu6Nvr461Nyo1MwUTAdBgNVHQ4EFgQUIaADDAgqBqCh3alUo7UKCx9iJygwHwYDVR0jBBgw" +
                "FoAUIaADDAgqBqCh3alUo7UKCx9iJygwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBF" +
                "AiEAgyiW6kWusYtA/2vL7azz04PiUqfHHbM3gjvfDw+fvgECIGlYmitwnnoYi0BeksCPjlpC034V" +
                "/QdkZ5F8cJpT75x4"
    }
}
