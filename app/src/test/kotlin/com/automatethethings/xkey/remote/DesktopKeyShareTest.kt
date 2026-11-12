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
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The outbound share honours the phone's `local.*` sharing rules: a key the
 * rules refuse, or material that is not exportable, never reaches the wire.
 */
class DesktopKeyShareTest {

    private lateinit var sender: ScriptedMessageSender
    private lateinit var share: DesktopKeyShare

    private val peer = "ab".repeat(32)
    private val pem = "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----\n"
    private val listed = mutableSetOf<Pair<String, String>>()
    private val isShared: suspend (String, String) -> Boolean = { k, p -> (k to p) in listed }

    @Before
    fun setUp() {
        stubAndroidLog()
        val router = BidirectionalMessageRouter(mockk<RequestHandler>())
        sender = ScriptedMessageSender(router)
        sender.succeedWith("""{"accepted":true,"import_id":"shared-k","backend":"software"}""")
        share = DesktopKeyShare(RemoteShareClient(sender, router, 200))
    }

    @After
    fun tearDown() {
        unmockkAll()
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
        val out = share.send(entity(SharingPolicyType.ALL_PEERS), null, pem, null, peer, isShared)
        assertTrue(out is DesktopKeyShare.Outcome.Sent)
        assertEquals(1, sender.sent.size)
        assertEquals(MethodNames.REMOTE_SHARE_PUBLIC_KEY, sender.lastRequest.method)
        assertFalse(sender.lastRequest.params!!.has("wrapped_key"))
    }

    @Test
    fun `private key never reaches the wire`() = runTest {
        val out = share.send(entity(SharingPolicyType.PRIVATE), null, pem, null, peer, isShared)
        assertEquals(DesktopKeyShare.Outcome.Refused(DesktopShareDecision.POLICY_DENIED), out)
        assertTrue(sender.sent.isEmpty())
    }

    @Test
    fun `selected peers admits only a listed peer`() = runTest {
        val e = entity(SharingPolicyType.SELECTED_PEERS)
        assertEquals(
            DesktopKeyShare.Outcome.Refused(DesktopShareDecision.POLICY_DENIED),
            share.send(e, null, pem, null, peer, isShared)
        )
        assertTrue(sender.sent.isEmpty())
        listed += "k" to peer
        assertTrue(share.send(e, null, pem, null, peer, isShared) is DesktopKeyShare.Outcome.Sent)
    }

    @Test
    fun `no confirmed peer or no key record never reaches the wire`() = runTest {
        assertEquals(
            DesktopKeyShare.Outcome.Refused(DesktopShareDecision.NO_PEER),
            share.send(entity(SharingPolicyType.ALL_PEERS), null, pem, null, null, isShared)
        )
        assertEquals(
            DesktopKeyShare.Outcome.Refused(DesktopShareDecision.POLICY_DENIED),
            share.send(null, null, pem, null, peer, isShared)
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
            assertEquals(DesktopKeyShare.Outcome.Refused(DesktopShareDecision.NOT_EXPORTABLE), share.send(e, s, null, null, peer, isShared))
            assertTrue(s.material.all { it == 0.toByte() })
        }
        assertTrue(sender.sent.isEmpty())
    }

    @Test
    fun `exportable symmetric key is held back while no wrap path matches the desktop`() = runTest {
        val s = software(true, true)
        val out = share.send(entity(SharingPolicyType.ALL_PEERS, true, true), s, null, null, peer, isShared)
        assertFalse(DesktopShareGate.SYMMETRIC_WRAP_PATH_MATCHES)
        assertEquals(DesktopKeyShare.Outcome.Refused(DesktopShareDecision.SYMMETRIC_NO_WRAP_PATH), out)
        assertTrue(sender.sent.isEmpty())
        assertTrue(s.material.all { it == 0.toByte() })
    }

    @Test
    fun `hardware key without a public half is not sent`() = runTest {
        assertEquals(
            DesktopKeyShare.Outcome.Refused(DesktopShareDecision.NOT_FOUND),
            share.send(entity(SharingPolicyType.ALL_PEERS), null, null, null, peer, isShared)
        )
        assertTrue(sender.sent.isEmpty())
    }
}
