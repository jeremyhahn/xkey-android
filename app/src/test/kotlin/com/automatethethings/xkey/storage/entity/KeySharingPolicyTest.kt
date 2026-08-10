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
package com.automatethethings.xkey.storage.entity

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for [KeySharingPolicy].
 *
 * A row in this table is the only thing standing between a peer and a key whose
 * [SharingPolicyType] is `SELECTED_PEERS`, so the two facts that matter are
 * pinned here: the composite identity is (key, peer), and a policy defaults to
 * *allowed* — which means a row's presence alone grants access and revocation
 * has to flip [KeySharingPolicy.allowed] rather than rely on the default.
 */
class KeySharingPolicyTest {

    private fun policy(
        keyId: String = "key-1",
        peer: String = "04a1b2c3",
        allowed: Boolean = true
    ) = KeySharingPolicy(
        keyId = keyId,
        peerPublicKeyHex = peer,
        allowed = allowed,
        createdAt = 1_700_000_000_000L
    )

    @Test
    fun `a new policy grants access by default`() {
        val entity = KeySharingPolicy(keyId = "key-1", peerPublicKeyHex = "04a1")

        assertTrue(entity.allowed)
    }

    @Test
    fun `a new policy stamps its own creation time`() {
        val before = System.currentTimeMillis()
        val entity = KeySharingPolicy(keyId = "key-1", peerPublicKeyHex = "04a1")
        val after = System.currentTimeMillis()

        assertTrue(entity.createdAt in before..after)
    }

    @Test
    fun `a revoked policy keeps the row but denies the peer`() {
        val revoked = policy().copy(allowed = false)

        assertFalse(revoked.allowed)
        assertEquals("key-1", revoked.keyId)
        assertEquals("04a1b2c3", revoked.peerPublicKeyHex)
    }

    @Test
    fun `two policies with the same fields are equal and hash alike`() {
        assertEquals(policy(), policy())
        assertEquals(policy().hashCode(), policy().hashCode())
    }

    @Test
    fun `the composite identity is the key and the peer together`() {
        val base = policy()

        assertNotEquals(base, base.copy(keyId = "key-2"))
        assertNotEquals(base, base.copy(peerPublicKeyHex = "04ffffff"))
    }

    @Test
    fun `policies differing in allowed or createdAt are not equal`() {
        val base = policy()

        assertNotEquals(base, base.copy(allowed = false))
        assertNotEquals(base, base.copy(createdAt = 1L))
    }

    @Test
    fun `a policy is never equal to an unrelated value`() {
        assertFalse(policy().equals("key-1"))
    }

    @Test
    fun `a policy destructures in declaration order`() {
        val (keyId, peer, allowed, createdAt) = policy()

        assertEquals("key-1", keyId)
        assertEquals("04a1b2c3", peer)
        assertTrue(allowed)
        assertEquals(1_700_000_000_000L, createdAt)
    }

    @Test
    fun `toString renders the fields`() {
        val rendered = policy().toString()

        assertTrue(rendered.contains("keyId=key-1"))
        assertTrue(rendered.contains("peerPublicKeyHex=04a1b2c3"))
        assertTrue(rendered.contains("allowed=true"))
    }
}
