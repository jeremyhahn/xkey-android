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
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests for PasskeyAdapter DiffUtil callback and display name resolution.
 *
 * Verifies that the adapter correctly identifies item changes and that
 * the display name fallback chain works as expected.
 */
class PasskeyAdapterTest {

    private val diffCallback = PasskeyAdapter.PasskeyDiffCallback()

    // -------------------------------------------------------------------------
    // DiffUtil: areItemsTheSame
    // -------------------------------------------------------------------------

    @Test
    fun `areItemsTheSame returns true for same keyId`() {
        val old = createFido2Key(keyId = "abc123")
        val new = createFido2Key(keyId = "abc123", rpName = "Updated RP")

        assertTrue(diffCallback.areItemsTheSame(old, new))
    }

    @Test
    fun `areItemsTheSame returns false for different keyId`() {
        val old = createFido2Key(keyId = "abc123")
        val new = createFido2Key(keyId = "xyz789")

        assertFalse(diffCallback.areItemsTheSame(old, new))
    }

    // -------------------------------------------------------------------------
    // DiffUtil: areContentsTheSame
    // -------------------------------------------------------------------------

    @Test
    fun `areContentsTheSame returns true when all tracked fields match`() {
        val old = createFido2Key(
            keyId = "abc123",
            rpName = "GitHub",
            userName = "user@example.com",
            lastUsedAt = 1000L,
            useCount = 5
        )
        val new = createFido2Key(
            keyId = "abc123",
            rpName = "GitHub",
            userName = "user@example.com",
            lastUsedAt = 1000L,
            useCount = 5
        )

        assertTrue(diffCallback.areContentsTheSame(old, new))
    }

    @Test
    fun `areContentsTheSame returns false when rpName changes`() {
        val old = createFido2Key(keyId = "abc123", rpName = "GitHub")
        val new = createFido2Key(keyId = "abc123", rpName = "GitLab")

        assertFalse(diffCallback.areContentsTheSame(old, new))
    }

    @Test
    fun `areContentsTheSame returns false when userName changes`() {
        val old = createFido2Key(keyId = "abc123", userName = "old@example.com")
        val new = createFido2Key(keyId = "abc123", userName = "new@example.com")

        assertFalse(diffCallback.areContentsTheSame(old, new))
    }

    @Test
    fun `areContentsTheSame returns false when lastUsedAt changes`() {
        val old = createFido2Key(keyId = "abc123", lastUsedAt = 1000L)
        val new = createFido2Key(keyId = "abc123", lastUsedAt = 2000L)

        assertFalse(diffCallback.areContentsTheSame(old, new))
    }

    @Test
    fun `areContentsTheSame returns false when useCount changes`() {
        val old = createFido2Key(keyId = "abc123", useCount = 5)
        val new = createFido2Key(keyId = "abc123", useCount = 6)

        assertFalse(diffCallback.areContentsTheSame(old, new))
    }

    @Test
    fun `areContentsTheSame ignores non-tracked field changes`() {
        val old = createFido2Key(keyId = "abc123", signCount = 10)
        val new = createFido2Key(keyId = "abc123", signCount = 20)

        // signCount is not tracked by DiffUtil, so contents are "same"
        assertTrue(diffCallback.areContentsTheSame(old, new))
    }

    // -------------------------------------------------------------------------
    // Display Name Resolution
    // -------------------------------------------------------------------------

    @Test
    fun `display name prefers rpName`() {
        val key = createFido2Key(rpName = "GitHub", rpId = "github.com", label = "My Key")
        val displayName = key.rpName ?: key.rpId ?: key.label
        assertEquals("GitHub", displayName)
    }

    @Test
    fun `display name falls back to rpId when rpName is null`() {
        val key = createFido2Key(rpName = null, rpId = "github.com", label = "My Key")
        val displayName = key.rpName ?: key.rpId ?: key.label
        assertEquals("github.com", displayName)
    }

    @Test
    fun `display name falls back to label when rpName and rpId are null`() {
        val key = createFido2Key(rpName = null, rpId = null, label = "My Key")
        val displayName = key.rpName ?: key.rpId ?: key.label
        assertEquals("My Key", displayName)
    }

    @Test
    fun `initial letter is uppercase first char of rpName`() {
        val key = createFido2Key(rpName = "github.com")
        val displayName = key.rpName ?: key.rpId ?: key.label
        val initial = displayName.firstOrNull()?.uppercaseChar()?.toString() ?: "?"
        assertEquals("G", initial)
    }

    @Test
    fun `initial letter uses question mark for empty name`() {
        val key = createFido2Key(rpName = "", rpId = null, label = "")
        val displayName = key.rpName ?: key.rpId ?: key.label
        val initial = displayName.firstOrNull()?.uppercaseChar()?.toString() ?: "?"
        assertEquals("?", initial)
    }

    @Test
    fun `username prefers userName over userDisplayName`() {
        val key = createFido2Key(userName = "user@example.com", userDisplayName = "John Doe")
        val userName = key.userName ?: key.userDisplayName
        assertEquals("user@example.com", userName)
    }

    @Test
    fun `username falls back to userDisplayName`() {
        val key = createFido2Key(userName = null, userDisplayName = "John Doe")
        val userName = key.userName ?: key.userDisplayName
        assertEquals("John Doe", userName)
    }

    // -------------------------------------------------------------------------
    // Helper
    // -------------------------------------------------------------------------

    private fun createFido2Key(
        keyId: String = "test-key-id",
        rpName: String? = "Test RP",
        rpId: String? = "test.example.com",
        userName: String? = "testuser",
        userDisplayName: String? = "Test User",
        label: String = rpName ?: rpId ?: "Test Key",
        lastUsedAt: Long = 0,
        useCount: Long = 0,
        signCount: Long = 0
    ) = KeyEntity(
        keyId = keyId,
        keyType = "fido2",
        algorithm = "ES256",
        label = label,
        keySizeBits = 256,
        source = "local",
        rpName = rpName,
        rpId = rpId,
        userName = userName,
        userDisplayName = userDisplayName,
        lastUsedAt = lastUsedAt,
        useCount = useCount,
        signCount = signCount,
        isDiscoverable = true,
        sharingPolicy = SharingPolicyType.PRIVATE
    )
}
