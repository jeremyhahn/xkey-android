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
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.protocol.SharePermission
import com.automatethethings.xkey.settings.InMemorySharedPreferences
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.storage.dao.KeySharingPolicyDao
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import io.mockk.coEvery
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.runs
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
 * The rules are checked against the peer confirmed on the very connection the
 * key is sent on, never the handler-wide peer key, and nothing is sent once
 * that connection has been replaced.
 */
class DesktopKeyShareTest {

    private lateinit var router: BidirectionalMessageRouter
    private lateinit var sender: ScriptedMessageSender
    private lateinit var share: DesktopKeyShare

    private val peer = "ab".repeat(32)
    private val pem = "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----\n"
    private val listed = mutableSetOf<Pair<String, String>>()
    private val grants = mockk<KeySharingPolicyDao> {
        coEvery { isKeySharedWithPeer(any(), any()) } answers { (firstArg<String>() to secondArg<String>()) in listed }
    }
    private val paired = PairedDeviceRepository(InMemorySharedPreferences())
    private val permission = SharePermission(grants, paired)
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

    /** The session on [s], with [peerHex] confirmed on [s]'s own connection. */
    private fun session(
        s: ScriptedMessageSender,
        r: BidirectionalMessageRouter,
        peerHex: String?,
        stillCurrent: (ShareSession) -> Boolean = { true }
    ): ShareSession {
        s.confirmedPeer = peerHex
        return ShareSession.of(listOf(ShareSession.Transport(s, r)), stillCurrent)!!
    }

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
        val out = share.send(entity(SharingPolicyType.ALL_PEERS), null, pem, null, permission)
        assertTrue(out is DesktopKeyShare.Outcome.Sent)
        assertEquals(1, sender.sent.size)
        assertEquals(MethodNames.REMOTE_SHARE_PUBLIC_KEY, sender.lastRequest.method)
        assertFalse(sender.lastRequest.params!!.has("wrapped_key"))
    }

    @Test
    fun `private key never reaches the wire`() = runTest {
        val out = share.send(entity(SharingPolicyType.PRIVATE), null, pem, null, permission)
        assertEquals(DesktopKeyShare.Outcome.Refused(DesktopShareDecision.POLICY_DENIED), out)
        assertTrue(sender.sent.isEmpty())
    }

    @Test
    fun `selected peers admits only a listed peer`() = runTest {
        val e = entity(SharingPolicyType.SELECTED_PEERS)
        assertEquals(
            DesktopKeyShare.Outcome.Refused(DesktopShareDecision.POLICY_DENIED),
            share.send(e, null, pem, null, permission)
        )
        assertTrue(sender.sent.isEmpty())
        listed += "k" to peer
        assertTrue(share.send(e, null, pem, null, permission) is DesktopKeyShare.Outcome.Sent)
    }

    /**
     * The desktop was unpaired and re-paired with the same static key while
     * its grant cleanup lags: its old row still allows the key, but the
     * revocation is pending, so the gate refuses it, as the inbound handler
     * does, and nothing reaches the wire.
     */
    @Test
    fun `a re-paired peer with a pending revocation and a stale allowed row is refused`() = runTest {
        mockkObject(AuditLogger)
        every { AuditLogger.logDeviceUnpaired(any(), any()) } just runs
        val e = entity(SharingPolicyType.SELECTED_PEERS)
        listed += "k" to peer
        paired.addDevice(peer, "desktop")
        paired.removeDevice(peer)
        paired.addDevice(peer, "desktop")
        assertTrue(paired.isRevocationPending(peer))

        assertEquals(
            DesktopShareDecision.POLICY_DENIED,
            DesktopShareGate.decide(e, null, pem, peer, permission)
        )
        assertEquals(
            DesktopKeyShare.Outcome.Refused(DesktopShareDecision.POLICY_DENIED),
            share.send(e, null, pem, null, permission)
        )
        assertTrue(sender.sent.isEmpty())

        // Control: once the cleanup acknowledges the revocation (it deletes
        // the old rows first), a fresh grant admits the peer again.
        paired.completeRevocation(peer, paired.pendingRevocationGeneration(peer)!!)
        assertTrue(share.send(e, null, pem, null, permission) is DesktopKeyShare.Outcome.Sent)
    }

    @Test
    fun `no confirmed peer or no key record never reaches the wire`() = runTest {
        // Another transport whose connection confirms no one.
        val unconfirmed = DesktopKeyShare(session(ScriptedMessageSender(router), router, null), 200)
        assertEquals(
            DesktopKeyShare.Outcome.Refused(DesktopShareDecision.NO_PEER),
            unconfirmed.send(entity(SharingPolicyType.ALL_PEERS), null, pem, null, permission)
        )
        assertEquals(
            DesktopKeyShare.Outcome.Refused(DesktopShareDecision.POLICY_DENIED),
            share.send(null, null, pem, null, permission)
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
            assertEquals(DesktopKeyShare.Outcome.Refused(DesktopShareDecision.NOT_EXPORTABLE), share.send(e, s, null, null, permission))
            assertTrue(s.material.all { it == 0.toByte() })
        }
        assertTrue(sender.sent.isEmpty())
    }

    @Test
    fun `exportable symmetric key is held back while no wrap path matches the desktop`() = runTest {
        val s = software(true, true)
        val out = share.send(entity(SharingPolicyType.ALL_PEERS, true, true), s, null, null, permission)
        assertFalse(DesktopShareGate.SYMMETRIC_WRAP_PATH_MATCHES)
        assertEquals(DesktopKeyShare.Outcome.Refused(DesktopShareDecision.SYMMETRIC_NO_WRAP_PATH), out)
        assertTrue(sender.sent.isEmpty())
        assertTrue(s.material.all { it == 0.toByte() })
    }

    @Test
    fun `hardware key without a public half is not sent`() = runTest {
        assertEquals(
            DesktopKeyShare.Outcome.Refused(DesktopShareDecision.NOT_FOUND),
            share.send(entity(SharingPolicyType.ALL_PEERS), null, null, null, permission)
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
        val senderB = ScriptedMessageSender(routerB).apply { succeedWith(accepted); confirmedPeer = peerB }

        // A is the active transport and confirms no one; B is confirmed only
        // on the other session.
        val s = ShareSession.of(
            listOf(ShareSession.Transport(senderA, routerA), ShareSession.Transport(senderB, routerB))
        ) { true }!!
        assertSame(senderA, s.sender)
        assertNull(s.peerPublicKeyHex)

        val out = DesktopKeyShare(s, 200).send(entity(SharingPolicyType.SELECTED_PEERS), null, pem, null, permission)
        assertEquals(DesktopKeyShare.Outcome.Refused(DesktopShareDecision.NO_PEER), out)
        assertTrue(senderA.sent.isEmpty())
        assertTrue(senderB.sent.isEmpty())
    }

    @Test
    fun `TCP peer A plus a revoked BLE session of B never authorizes a key granted only to B`() = runTest {
        val peerA = "aa".repeat(32)
        val peerB = "bb".repeat(32)
        listed += "k" to peerB
        val bleRouter = BidirectionalMessageRouter(mockk<RequestHandler>())
        val ble = ScriptedMessageSender(bleRouter).apply { succeedWith(accepted); confirmedPeer = peerB }
        val tcpRouter = BidirectionalMessageRouter(mockk<RequestHandler>())
        val tcp = ScriptedMessageSender(tcpRouter).apply { succeedWith(accepted); confirmedPeer = peerA }

        // B's BLE session is revoked and its teardown deferred: the
        // handler-wide peer key still names B, but B's connection confirms no
        // one and is no longer live. TCP is the only live transport.
        ble.confirmedPeer = null
        val s = ShareSession.of(listOf(ShareSession.Transport(tcp, tcpRouter))) { true }!!
        assertSame(tcp, s.sender)
        assertEquals(peerA, s.peerPublicKeyHex)

        val out = DesktopKeyShare(s, 200).send(entity(SharingPolicyType.SELECTED_PEERS), null, pem, null, permission)
        assertEquals(DesktopKeyShare.Outcome.Refused(DesktopShareDecision.POLICY_DENIED), out)
        assertTrue(tcp.sent.isEmpty())
        assertTrue(ble.sent.isEmpty())

        // An unconfirmed TCP connection is no peer at all, whatever B was.
        tcp.confirmedPeer = null
        val unconfirmed = ShareSession.of(listOf(ShareSession.Transport(tcp, tcpRouter))) { true }!!
        assertEquals(
            DesktopKeyShare.Outcome.Refused(DesktopShareDecision.NO_PEER),
            DesktopKeyShare(unconfirmed, 200).send(entity(SharingPolicyType.SELECTED_PEERS), null, pem, null, permission)
        )
        assertTrue(tcp.sent.isEmpty())
    }

    @Test
    fun `a connection replaced after the decision is no longer current, even for the same peer`() = runTest {
        val s = session(sender, router, peer)
        assertTrue(s.isCurrent())
        // The desktop reconnects: same transport and peer, another connection.
        sender.connection = Any()
        assertFalse(s.isCurrent())
        assertFalse(s.sameAs(session(sender, router, peer)))

        val held = session(sender, router, peer)
        sender.confirmedPeer = null
        assertEquals(
            DesktopKeyShare.Outcome.SessionChanged,
            DesktopKeyShare(held, 200).send(entity(SharingPolicyType.ALL_PEERS), null, pem, null, permission)
        )
        assertTrue(sender.sent.isEmpty())
    }

    @Test
    fun `the peer confirmed on the only live session is the one checked`() = runTest {
        val peerB = "bb".repeat(32)
        listed += "k" to peerB
        val s = session(sender, router, peerB)
        assertEquals(peerB, s.peerPublicKeyHex)
        val out = DesktopKeyShare(s, 200).send(entity(SharingPolicyType.SELECTED_PEERS), null, pem, null, permission)
        assertTrue(out is DesktopKeyShare.Outcome.Sent)
        assertEquals(1, sender.sent.size)
    }

    @Test
    fun `no live transport is no session`() {
        assertNull(ShareSession.of(emptyList()) { true })
    }

    @Test
    fun `a session replaced after the decision sends nothing and zeroes the material`() = runTest {
        val s = software(true, true)
        val replaced = DesktopKeyShare(session(sender, router, peer) { false }, 200)
        assertEquals(
            DesktopKeyShare.Outcome.SessionChanged,
            replaced.send(entity(SharingPolicyType.ALL_PEERS), null, pem, null, permission)
        )
        assertEquals(
            DesktopKeyShare.Outcome.SessionChanged,
            replaced.send(entity(SharingPolicyType.ALL_PEERS, true, true), s, null, null, permission)
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
            racing.send(entity(SharingPolicyType.ALL_PEERS), null, pem, null, permission)
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
        val out = share.send(entity(SharingPolicyType.ALL_PEERS), null, pem, null, permission)
        assertFalse(out is DesktopKeyShare.Outcome.Sent)
        assertEquals(
            DesktopKeyShare.Outcome.Declined(RemoteShareClient.ShareResult(false, "", "software")),
            out
        )
    }

    @Test
    fun `a reply with accepted true is sent`() = runTest {
        val out = share.send(entity(SharingPolicyType.ALL_PEERS), null, pem, null, permission)
        assertEquals(DesktopKeyShare.Outcome.Sent(RemoteShareClient.ShareResult(true, "shared-k", "software")), out)
    }
}
