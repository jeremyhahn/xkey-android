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
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for [KeySharingPolicy].
 *
 * A row in this table is the only thing standing between a peer and a key whose
 * [SharingPolicyType] is `SELECTED_PEERS`, so the fact that matters is pinned
 * here: a policy defaults to *allowed* — which means a row's presence alone
 * grants access and revocation has to flip [KeySharingPolicy.allowed] rather
 * than rely on the default.
 */
class KeySharingPolicyTest {

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
        val revoked = KeySharingPolicy(keyId = "key-1", peerPublicKeyHex = "04a1b2c3")
            .copy(allowed = false)

        assertFalse(revoked.allowed)
        assertEquals("key-1", revoked.keyId)
        assertEquals("04a1b2c3", revoked.peerPublicKeyHex)
    }
}
