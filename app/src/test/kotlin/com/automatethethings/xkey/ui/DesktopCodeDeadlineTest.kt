// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under AGPL-3.0 (see LICENSE) or a commercial license.
// Contact licensing@automatethethings.com for commercial licensing options.

package com.automatethethings.xkey.ui

import com.automatethethings.xkey.oath.OathCredentialEntity
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
import java.lang.reflect.Modifier

/**
 * A desktop OATH code is shown only through [DesktopCodeDeadline]: the
 * deadline starts from the reply's expires_in on a monotonic clock, and once
 * it passes the code is gone while the dialog is still open.
 */
class DesktopCodeDeadlineTest {

    private lateinit var router: BidirectionalMessageRouter
    private lateinit var sender: ScriptedMessageSender
    private val links = MapLinks()
    private var now = 50_000L
    private val clock = MonotonicClock { now }

    @Before
    fun setUp() {
        stubAndroidLog()
        router = spyk(BidirectionalMessageRouter(mockk<RequestHandler>()))
        sender = ScriptedMessageSender(router)
        links.put(PEER, "GitHub:alice", "desk-7")
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    private fun actions() = OathDesktopActions(
        desktop = { desktopOf(sender, router, PEER) },
        links = links,
        secretOf = { ByteArray(10) },
        clock = clock
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

    private suspend fun codeReply(json: String): DesktopCodeDeadline {
        sender.succeedWith(json)
        val outcome = actions().desktopCode(entity())
        return (outcome as OathDesktopActions.Outcome.Code).deadline
    }

    @Test
    fun `a code with expires_in 2 is gone after 2 s with the dialog still open`() = runTest {
        val deadline = codeReply("""{"code":"492039","expires_in":2}""")

        assertEquals(DesktopCodeDeadline.View.Live("492039", 2), deadline.view())
        now += 1_000
        assertEquals(DesktopCodeDeadline.View.Live("492039", 1), deadline.view())
        now += 999
        assertEquals(DesktopCodeDeadline.View.Live("492039", 1), deadline.view())
        now += 1
        assertEquals(DesktopCodeDeadline.View.Expired, deadline.view())
        now += 60_000
        assertEquals(DesktopCodeDeadline.View.Expired, deadline.view())
        assertFalse("an expired deadline keeps no code", deadline.toString().contains("492039"))
    }

    @Test
    fun `the remaining seconds count from the reply, not from when the dialog shows`() = runTest {
        val deadline = codeReply("""{"code":"492039","expires_in":21}""")
        now += 20_500
        assertEquals(DesktopCodeDeadline.View.Live("492039", 1), deadline.view())
        now += 500
        assertEquals(DesktopCodeDeadline.View.Expired, deadline.view())
    }

    @Test
    fun `expires_in 0 is expired at once`() = runTest {
        val deadline = codeReply("""{"code":"492039","expires_in":0}""")
        assertEquals(DesktopCodeDeadline.View.Expired, deadline.view())
        assertNull(deadline.millisUntilChange())
    }

    @Test
    fun `the dialog is told when the shown seconds next change`() = runTest {
        val deadline = codeReply("""{"code":"492039","expires_in":2}""")
        assertEquals(1_000L, deadline.millisUntilChange())
        now += 300
        assertEquals(700L, deadline.millisUntilChange())
        now += 1_700
        assertNull(deadline.millisUntilChange())
    }

    @Test
    fun `a counter-based code has no deadline`() = runTest {
        val deadline = codeReply("""{"code":"492039"}""")
        assertEquals(DesktopCodeDeadline.View.NoExpiry("492039"), deadline.view())
        now += 3_600_000
        assertEquals(DesktopCodeDeadline.View.NoExpiry("492039"), deadline.view())
        assertNull(deadline.millisUntilChange())
    }

    @Test
    fun `a desktop code reaches the screen only through its deadline`() = runTest {
        val outcome = run {
            sender.succeedWith("""{"code":"492039","expires_in":2}""")
            actions().desktopCode(entity())
        }
        assertFalse("Code must not print its code", outcome.toString().contains("492039"))

        // Neither the outcome nor the deadline hands out the code as a String
        // other than through view(), which applies the deadline.
        for (type in listOf(OathDesktopActions.Outcome.Code::class.java, DesktopCodeDeadline::class.java)) {
            val leaks = type.methods.filter {
                Modifier.isPublic(it.modifiers) && it.name != "toString" &&
                    (it.returnType == String::class.java || it.returnType == CharSequence::class.java)
            }
            assertTrue("${type.simpleName} exposes the code without the deadline: $leaks", leaks.isEmpty())
        }
    }

    private class MapLinks : DesktopOathLinks {
        private val map = mutableMapOf<Pair<String, String>, String>()
        override fun get(peerKeyHex: String, oathId: String): String? = map[peerKeyHex to oathId]
        override fun put(peerKeyHex: String, oathId: String, desktopId: String) {
            map[peerKeyHex to oathId] = desktopId
        }
    }

    private companion object {
        const val PEER = "aa01"
    }
}
