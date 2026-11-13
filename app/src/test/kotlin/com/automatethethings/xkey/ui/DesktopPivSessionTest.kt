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

import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.remote.BidirectionalMessageRouter
import com.automatethethings.xkey.remote.RemoteKeyClient
import com.automatethethings.xkey.remote.RemotePivSlot
import com.automatethethings.xkey.remote.ScriptedMessageSender
import com.automatethethings.xkey.remote.desktopOf
import com.automatethethings.xkey.remote.stubAndroidLog
import io.mockk.mockk
import io.mockk.unmockkAll
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.IOException

/**
 * The desktop session as the PIV screens see it: [desktopPivSlots] for the
 * slot list and [desktopPivSlotDetail] for one slot's detail, both driven by
 * the service's desktop session flow (a client while a desktop is connected,
 * null when it is lost).
 */
@OptIn(ExperimentalCoroutinesApi::class)
class DesktopPivSessionTest {

    private lateinit var router: BidirectionalMessageRouter
    private lateinit var sender: ScriptedMessageSender
    private lateinit var client: RemoteKeyClient

    @Before
    fun setUp() {
        stubAndroidLog()
        router = BidirectionalMessageRouter(mockk<RequestHandler>())
        sender = ScriptedMessageSender(router)
        client = RemoteKeyClient(desktopOf(sender, router), requestTimeoutMs = 5_000L)
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    // --- slot ids travel verbatim -----------------------------------------

    @Test
    fun `a lowercase desktop slot id reaches remote_pivGetCert as listed`() = runTest {
        sender.succeedWith("""{"certificate_der":"$TEST_CERT_B64","subject":"CN=alice"}""")

        val detail = desktopPivSlotDetail(flowOf(client), "9a").first()

        assertEquals("9a", requireNotNull(sender.lastRequest.params).getString("slot"))
        val loaded = detail as DesktopPivSlotDetail.Loaded
        assertEquals("CN=alice", loaded.certificate?.subject)
    }

    @Test
    fun `an uppercase desktop slot id is not folded either`() = runTest {
        sender.succeedWith("""{"certificate_der":"$TEST_CERT_B64"}""")

        desktopPivSlotDetail(flowOf(client), "9A").first()

        assertEquals("9A", requireNotNull(sender.lastRequest.params).getString("slot"))
    }

    @Test
    fun `a desktop slot outside the phone's slot set still loads`() = runTest {
        sender.succeedWith("""{"certificate_der":"$TEST_CERT_B64"}""")

        val detail = desktopPivSlotDetail(flowOf(client), "custom-1").first()

        assertEquals("custom-1", requireNotNull(sender.lastRequest.params).getString("slot"))
        assertEquals("custom-1", (detail as DesktopPivSlotDetail.Loaded).slotId)
    }

    @Test
    fun `the detail test sign sends the listed slot id verbatim`() = runTest {
        sender.succeedWith("""{"certificate_der":"$TEST_CERT_B64"}""")
        val loaded = desktopPivSlotDetail(flowOf(client), "9c").first() as DesktopPivSlotDetail.Loaded
        sender.succeedWith("""{"signature":"AQID","algorithm":"ECDSA-P256"}""")

        val outcome = loaded.actions.trySignTest(loaded.slotId)

        assertEquals("remote.pivSign", sender.lastRequest.method)
        assertEquals("9c", requireNotNull(sender.lastRequest.params).getString("slot"))
        assertTrue(outcome is DesktopSignTestOutcome.Signed)
    }

    // --- transport failures -----------------------------------------------

    @Test
    fun `a missing session while fetching the certificate shows a failure`() = runTest {
        sender.replyWith { throw IOException("no Noise session") }

        val detail = desktopPivSlotDetail(flowOf(client), "9a").first()

        assertEquals("no Noise session", (detail as DesktopPivSlotDetail.Failed).message)
    }

    @Test
    fun `a missing session during the test sign is a failed outcome`() = runTest {
        sender.replyWith { throw IOException("no Noise session") }

        val outcome = DesktopPivSlotActions(client).trySignTest("9c")

        assertEquals("no Noise session", (outcome as DesktopSignTestOutcome.Failed).message)
    }

    @Test
    fun `cancelling the test sign is not turned into a failure`() = runTest {
        sender.neverReply()
        var outcome: DesktopSignTestOutcome? = null

        val job = launch { outcome = DesktopPivSlotActions(client).trySignTest("9c") }
        runCurrent()
        job.cancel()
        job.join()

        assertTrue(job.isCancelled)
        assertNull(outcome)
    }

    // --- malformed slot ids -----------------------------------------------

    @Test
    fun `a blank slot id in the detail is a failure, not a crash`() = runTest {
        sender.succeedWith("""{"certificate_der":"$TEST_CERT_B64"}""")

        val detail = desktopPivSlotDetail(flowOf(client), " ").first()

        assertTrue(detail is DesktopPivSlotDetail.Failed)
        assertTrue(sender.sent.isEmpty())
    }

    @Test
    fun `a blank slot id in the test sign is a failed outcome`() = runTest {
        val outcome = DesktopPivSlotActions(client).trySignTest(" ")

        assertTrue(outcome is DesktopSignTestOutcome.Failed)
        assertTrue(sender.sent.isEmpty())
    }

    @Test
    fun `a desktop listing a whitespace slot id shows no slots`() = runTest {
        sender.succeedWith("""{"slots":[{"slot":" ","has_key":false,"has_certificate":false}]}""")

        assertTrue(desktopPivSlots(flowOf(client)).first().isEmpty())
    }

    // --- session ready / lost ---------------------------------------------

    @Test
    fun `a desktop that connects while the list is visible shows its slots`() = runTest {
        sender.succeedWith(SLOTS_JSON)
        val sessions = MutableStateFlow<RemoteKeyClient?>(null)
        val seen = mutableListOf<List<RemotePivSlot>>()
        backgroundScope.launch(UnconfinedTestDispatcher(testScheduler)) {
            desktopPivSlots(sessions).toList(seen)
        }

        assertEquals(listOf(emptyList<RemotePivSlot>()), seen)
        assertTrue(sender.sent.isEmpty())

        sessions.value = client
        runCurrent()

        assertEquals(listOf("9c"), seen.last().map { it.slot })
    }

    @Test
    fun `a desktop lost after its slots load clears them`() = runTest {
        sender.succeedWith(SLOTS_JSON)
        val sessions = MutableStateFlow<RemoteKeyClient?>(client)
        val seen = mutableListOf<List<RemotePivSlot>>()
        backgroundScope.launch(UnconfinedTestDispatcher(testScheduler)) {
            desktopPivSlots(sessions).toList(seen)
        }
        runCurrent()
        assertEquals(1, seen.last().size)

        sessions.value = null
        runCurrent()

        assertTrue(seen.last().isEmpty())
    }

    @Test
    fun `a desktop that connects while the detail is visible loads the certificate`() = runTest {
        sender.succeedWith("""{"certificate_der":"$TEST_CERT_B64"}""")
        val sessions = MutableStateFlow<RemoteKeyClient?>(null)
        val seen = mutableListOf<DesktopPivSlotDetail>()
        backgroundScope.launch(UnconfinedTestDispatcher(testScheduler)) {
            desktopPivSlotDetail(sessions, "9a").toList(seen)
        }
        assertEquals(listOf<DesktopPivSlotDetail>(DesktopPivSlotDetail.NotConnected), seen)

        sessions.value = client
        runCurrent()

        assertTrue(seen.last() is DesktopPivSlotDetail.Loaded)
    }

    @Test
    fun `a desktop lost after the detail loads drops its certificate`() = runTest {
        sender.succeedWith("""{"certificate_der":"$TEST_CERT_B64"}""")
        val sessions = MutableStateFlow<RemoteKeyClient?>(client)
        val seen = mutableListOf<DesktopPivSlotDetail>()
        backgroundScope.launch(UnconfinedTestDispatcher(testScheduler)) {
            desktopPivSlotDetail(sessions, "9a").toList(seen)
        }
        runCurrent()
        assertTrue(seen.last() is DesktopPivSlotDetail.Loaded)

        sessions.value = null
        runCurrent()

        assertEquals(DesktopPivSlotDetail.NotConnected, seen.last())
    }

    private companion object {
        const val SLOTS_JSON =
            """{"slots":[{"slot":"9c","algorithm":"ECDSA-P256","has_key":true,"has_certificate":false}]}"""

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
