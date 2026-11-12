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
package com.automatethethings.xkey.remote

import com.automatethethings.xkey.crypto.SoftwareKey
import com.automatethethings.xkey.protocol.MethodNames
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import io.mockk.mockk
import io.mockk.unmockkAll
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The outbound share honours the phone's `local.*` sharing rules: a key the
 * rules refuse, or material that is not exportable, never reaches the wire.
 * The rules are checked against the peer confirmed on the session the key is
 * sent on, and nothing is sent once that session has been replaced.
 */
class DesktopKeyShareTest {

    private lateinit var router: BidirectionalMessageRouter
    private lateinit var sender: ScriptedMessageSender
    private lateinit var share: DesktopKeyShare

    private val peer = "ab".repeat(32)
    private val pem = "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----\n"
    private val listed = mutableSetOf<Pair<String, String>>()
    private val isShared: suspend (String, String) -> Boolean = { k, p -> (k to p) in listed }
    private val accepted = """{"accepted":true,"import_id":"shared-k","backend":"software"}"""

    @Before
    fun setUp() {
        stubAndroidLog()
        router = BidirectionalMessageRouter(mockk<RequestHandler>())
        sender = ScriptedMessageSender(router)
        sender.succeedWith(accepted)
        share = DesktopKeyShare(session(sender, router, peer), 200)
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    private fun session(
        s: MessageSender,
        r: BidirectionalMessageRouter,
        peerHex: String?,
        stillCurrent: (ShareSession) -> Boolean = { true }
    ): ShareSession = ShareSession.of(listOf(ShareSession.Transport(s, r)), peerHex, stillCurrent)!!

    private fun entity(
        policy: SharingPolicyType,
        exportable: Boolean = false,
        shareable: Boolean = false
    ) = KeyEntity(
        keyId = "k",
        keyType = "signing",
        algorithm = "EC",
        label = "label",
        keySizeBits = 256,
        exportable = exportable,
        shareable = shareable,
        sharingPolicy = policy,
        source = "local"
    )

    private fun software(exportable: Boolean, shareable: Boolean) = SoftwareKey(
        keyId = "k",
        algorithm = "AES",
        keyType = "symmetric",
        keySize = 256,
        exportable = exportable,
        shareable = shareable,
        material = ByteArray(32) { 5 }
    )

    @Test
    fun `hardware key with an admitting policy sends only the public half`() = runTest {
        val out = share.send(entity(SharingPolicyType.ALL_PEERS), null, pem, null, isShared)
        assertTrue(out is DesktopKeyShare.Outcome.Sent)
        assertEquals(1, sender.sent.size)
        assertEquals(MethodNames.REMOTE_SHARE_PUBLIC_KEY, sender.lastRequest.method)
        assertFalse(sender.lastRequest.params!!.has("wrapped_key"))
    }

    @Test
    fun `private key never reaches the wire`() = runTest {
        val out = share.send(entity(SharingPolicyType.PRIVATE), null, pem, null, isShared)
        assertEquals(DesktopKeyShare.Outcome.Refused(DesktopShareDecision.POLICY_DENIED), out)
        assertTrue(sender.sent.isEmpty())
    }

    @Test
    fun `selected peers admits only a listed peer`() = runTest {
        val e = entity(SharingPolicyType.SELECTED_PEERS)
        assertEquals(
            DesktopKeyShare.Outcome.Refused(DesktopShareDecision.POLICY_DENIED),
            share.send(e, null, pem, null, isShared)
        )
        assertTrue(sender.sent.isEmpty())
        listed += "k" to peer
        assertTrue(share.send(e, null, pem, null, isShared) is DesktopKeyShare.Outcome.Sent)
    }

    @Test
    fun `no confirmed peer or no key record never reaches the wire`() = runTest {
        val unconfirmed = DesktopKeyShare(session(sender, router, null), 200)
        assertEquals(
            DesktopKeyShare.Outcome.Refused(DesktopShareDecision.NO_PEER),
            unconfirmed.send(entity(SharingPolicyType.ALL_PEERS), null, pem, null, isShared)
        )
        assertEquals(
            DesktopKeyShare.Outcome.Refused(DesktopShareDecision.POLICY_DENIED),
            share.send(null, null, pem, null, isShared)
        )
        assertTrue(sender.sent.isEmpty())
    }

    @Test
    fun `non-exportable software key never reaches the wire and is zeroed`() = runTest {
        for ((e, s) in listOf(
            entity(SharingPolicyType.ALL_PEERS, exportable = false, shareable = true) to software(true, true),
            entity(SharingPolicyType.ALL_PEERS, exportable = true, shareable = false) to software(true, true),
            entity(SharingPolicyType.ALL_PEERS, exportable = true, shareable = true) to software(false, true),
            entity(SharingPolicyType.ALL_PEERS, exportable = true, shareable = true) to software(true, false)
        )) {
            assertEquals(DesktopKeyShare.Outcome.Refused(DesktopShareDecision.NOT_EXPORTABLE), share.send(e, s, null, null, isShared))
            assertTrue(s.material.all { it == 0.toByte() })
        }
        assertTrue(sender.sent.isEmpty())
    }

    @Test
    fun `exportable symmetric key is held back while no wrap path matches the desktop`() = runTest {
        val s = software(true, true)
        val out = share.send(entity(SharingPolicyType.ALL_PEERS, true, true), s, null, null, isShared)
        assertFalse(DesktopShareGate.SYMMETRIC_WRAP_PATH_MATCHES)
        assertEquals(DesktopKeyShare.Outcome.Refused(DesktopShareDecision.SYMMETRIC_NO_WRAP_PATH), out)
        assertTrue(sender.sent.isEmpty())
        assertTrue(s.material.all { it == 0.toByte() })
    }

    @Test
    fun `hardware key without a public half is not sent`() = runTest {
        assertEquals(
            DesktopKeyShare.Outcome.Refused(DesktopShareDecision.NOT_FOUND),
            share.send(entity(SharingPolicyType.ALL_PEERS), null, null, null, isShared)
        )
        assertTrue(sender.sent.isEmpty())
    }

    // --- The authorization is bound to the session that receives the key ---

    @Test
    fun `a key granted only to the peer confirmed on another transport is refused`() = runTest {
        val peerB = "bb".repeat(32)
        listed += "k" to peerB
        val routerA = BidirectionalMessageRouter(mockk<RequestHandler>())
        val senderA = ScriptedMessageSender(routerA).apply { succeedWith(accepted) }
        val routerB = BidirectionalMessageRouter(mockk<RequestHandler>())
        val senderB = ScriptedMessageSender(routerB).apply { succeedWith(accepted) }

        // A is the active transport; the one confirmed identity the phone
        // holds is B's, from the other session.
        val s = ShareSession.of(
            listOf(ShareSession.Transport(senderA, routerA), ShareSession.Transport(senderB, routerB)),
            peerB
        ) { true }!!
        assertSame(senderA, s.sender)
        assertNull(s.peerPublicKeyHex)

        val out = DesktopKeyShare(s, 200).send(entity(SharingPolicyType.SELECTED_PEERS), null, pem, null, isShared)
        assertEquals(DesktopKeyShare.Outcome.Refused(DesktopShareDecision.NO_PEER), out)
        assertTrue(senderA.sent.isEmpty())
        assertTrue(senderB.sent.isEmpty())
    }

    @Test
    fun `the peer confirmed on the only live session is the one checked`() = runTest {
        val peerB = "bb".repeat(32)
        listed += "k" to peerB
        val s = session(sender, router, peerB)
        assertEquals(peerB, s.peerPublicKeyHex)
        val out = DesktopKeyShare(s, 200).send(entity(SharingPolicyType.SELECTED_PEERS), null, pem, null, isShared)
        assertTrue(out is DesktopKeyShare.Outcome.Sent)
        assertEquals(1, sender.sent.size)
    }

    @Test
    fun `no live transport is no session`() {
        assertNull(ShareSession.of(emptyList(), peer) { true })
    }

    @Test
    fun `a session replaced after the decision sends nothing and zeroes the material`() = runTest {
        val s = software(true, true)
        val replaced = DesktopKeyShare(session(sender, router, peer) { false }, 200)
        assertEquals(
            DesktopKeyShare.Outcome.SessionChanged,
            replaced.send(entity(SharingPolicyType.ALL_PEERS), null, pem, null, isShared)
        )
        assertEquals(
            DesktopKeyShare.Outcome.SessionChanged,
            replaced.send(entity(SharingPolicyType.ALL_PEERS, true, true), s, null, null, isShared)
        )
        assertTrue(sender.sent.isEmpty())
        assertTrue(s.material.all { it == 0.toByte() })
    }

    @Test
    fun `a session replaced just before encryption never reaches the transport`() = runTest {
        // Current when the share is decided, replaced by the time the bytes
        // would be handed to the transport for encryption.
        var checks = 0
        val racing = DesktopKeyShare(session(sender, router, peer) { checks++ == 0 }, 200)
        assertEquals(
            DesktopKeyShare.Outcome.SessionChanged,
            racing.send(entity(SharingPolicyType.ALL_PEERS), null, pem, null, isShared)
        )
        assertTrue(sender.sent.isEmpty())
    }

    @Test
    fun `sessions are the same only for the same transport and peer`() {
        val other = ScriptedMessageSender(router)
        val a = session(sender, router, peer)
        assertTrue(a.sameAs(session(sender, router, peer)))
        assertFalse(a.sameAs(session(sender, router, null)))
        assertFalse(a.sameAs(session(other, router, peer)))
        assertFalse(a.sameAs(null))
    }

    // --- accepted=false is a failed import ---

    @Test
    fun `a reply with accepted false is a declined import, never sent`() = runTest {
        sender.succeedWith("""{"accepted":false,"import_id":"","backend":"software"}""")
        val out = share.send(entity(SharingPolicyType.ALL_PEERS), null, pem, null, isShared)
        assertFalse(out is DesktopKeyShare.Outcome.Sent)
        assertEquals(
            DesktopKeyShare.Outcome.Declined(RemoteShareClient.ShareResult(false, "", "software")),
            out
        )
    }

    @Test
    fun `a reply with accepted true is sent`() = runTest {
        val out = share.send(entity(SharingPolicyType.ALL_PEERS), null, pem, null, isShared)
        assertEquals(DesktopKeyShare.Outcome.Sent(RemoteShareClient.ShareResult(true, "shared-k", "software")), out)
    }
}
