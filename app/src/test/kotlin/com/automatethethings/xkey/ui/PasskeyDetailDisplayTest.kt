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

import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Tests for the KeyEntity FIDO2 fields shown by PasskeyDetailActivity.
 */
class PasskeyDetailDisplayTest {

    // -------------------------------------------------------------------------
    // KeyEntity FIDO2 Fields
    // -------------------------------------------------------------------------

    @Test
    fun `fido2 key entity has correct keyType`() {
        val key = createFido2Key()
        assertEquals("fido2", key.keyType)
    }

    @Test
    fun `fido2 key entity has correct key size`() {
        val key = createFido2Key()
        assertEquals(256, key.keySizeBits)
    }

    private fun createFido2Key() = KeyEntity(
        keyId = "test-key-id",
        keyType = "fido2",
        algorithm = "ES256",
        label = "Test RP",
        keySizeBits = 256,
        source = "local",
        rpName = "Test RP",
        rpId = "test.example.com",
        userName = "testuser",
        userDisplayName = "Test User",
        sharingPolicy = SharingPolicyType.PRIVATE
    )
}
