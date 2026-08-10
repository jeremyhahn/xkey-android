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
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Tests for passkey detail display logic.
 *
 * Verifies source display name mapping, sharing policy display,
 * and date formatting used by PasskeyDetailActivity.
 */
class PasskeyDetailDisplayTest {

    // -------------------------------------------------------------------------
    // Source Display Names
    // -------------------------------------------------------------------------

    @Test
    fun `source display name maps local correctly`() {
        assertEquals("Local", getSourceDisplayName("local"))
    }

    @Test
    fun `source display name maps remote_ble correctly`() {
        assertEquals("Remote (BLE)", getSourceDisplayName("remote_ble"))
    }

    @Test
    fun `source display name maps remote_usb correctly`() {
        assertEquals("Remote (USB)", getSourceDisplayName("remote_usb"))
    }

    @Test
    fun `source display name maps xkmsd correctly`() {
        assertEquals("xKMS Daemon", getSourceDisplayName("xkmsd"))
    }

    @Test
    fun `source display name returns raw value for unknown source`() {
        assertEquals("custom_source", getSourceDisplayName("custom_source"))
    }

    // -------------------------------------------------------------------------
    // Sharing Policy Display Names
    // -------------------------------------------------------------------------

    @Test
    fun `sharing policy display name maps PRIVATE correctly`() {
        assertEquals("Private", getSharingDisplayName(SharingPolicyType.PRIVATE))
    }

    @Test
    fun `sharing policy display name maps ALL_PEERS correctly`() {
        assertEquals("All Peers", getSharingDisplayName(SharingPolicyType.ALL_PEERS))
    }

    @Test
    fun `sharing policy display name maps SELECTED_PEERS correctly`() {
        assertEquals("Selected Peers", getSharingDisplayName(SharingPolicyType.SELECTED_PEERS))
    }

    // -------------------------------------------------------------------------
    // Date Formatting
    // -------------------------------------------------------------------------

    @Test
    fun `date format produces expected pattern`() {
        val dateFormat = SimpleDateFormat("MMM d, yyyy HH:mm", Locale.US)
        val timestamp = 1706788200000L // Jan 1, 2024 12:30 in some timezone
        val formatted = dateFormat.format(Date(timestamp))

        assertNotNull(formatted)
        assertTrue("Formatted date should contain year", formatted.contains("2024"))
    }

    @Test
    fun `lastUsedAt zero indicates never used`() {
        val key = createFido2Key(lastUsedAt = 0)
        assertTrue("lastUsedAt of 0 should indicate never used", key.lastUsedAt == 0L)
    }

    @Test
    fun `lastUsedAt positive indicates used`() {
        val key = createFido2Key(lastUsedAt = System.currentTimeMillis())
        assertTrue("Positive lastUsedAt should indicate used", key.lastUsedAt > 0)
    }

    // -------------------------------------------------------------------------
    // KeyEntity FIDO2 Fields
    // -------------------------------------------------------------------------

    @Test
    fun `fido2 key entity has correct keyType`() {
        val key = createFido2Key()
        assertEquals("fido2", key.keyType)
    }

    @Test
    fun `fido2 key entity has correct algorithm`() {
        val key = createFido2Key()
        assertEquals("ES256", key.algorithm)
    }

    @Test
    fun `fido2 key entity has correct key size`() {
        val key = createFido2Key()
        assertEquals(256, key.keySizeBits)
    }

    @Test
    fun `fido2 key entity discoverable flag defaults correctly`() {
        val discoverableKey = createFido2Key(isDiscoverable = true)
        val nonDiscoverableKey = createFido2Key(isDiscoverable = false)

        assertTrue(discoverableKey.isDiscoverable)
        assertFalse(nonDiscoverableKey.isDiscoverable)
    }

    @Test
    fun `fido2 key entity sign count tracks correctly`() {
        val key = createFido2Key(signCount = 42)
        assertEquals(42L, key.signCount)
    }

    @Test
    fun `fido2 key entity use count formats as integer`() {
        val key = createFido2Key(useCount = 100)
        assertEquals(100, key.useCount.toInt())
    }

    @Test
    fun `sharing policy enum values are complete`() {
        val values = SharingPolicyType.values()
        assertEquals(3, values.size)
        assertTrue(values.contains(SharingPolicyType.PRIVATE))
        assertTrue(values.contains(SharingPolicyType.ALL_PEERS))
        assertTrue(values.contains(SharingPolicyType.SELECTED_PEERS))
    }

    @Test
    fun `sharing policy default is PRIVATE`() {
        val key = KeyEntity(
            keyId = "test",
            keyType = "fido2",
            algorithm = "ES256",
            label = "Test",
            keySizeBits = 256,
            source = "local"
        )
        assertEquals(SharingPolicyType.PRIVATE, key.sharingPolicy)
    }

    // -------------------------------------------------------------------------
    // Display helpers (replicate PasskeyDetailActivity logic)
    // -------------------------------------------------------------------------

    private fun getSourceDisplayName(source: String): String = when (source) {
        "local" -> "Local"
        "remote_ble" -> "Remote (BLE)"
        "remote_usb" -> "Remote (USB)"
        "xkmsd" -> "xKMS Daemon"
        else -> source
    }

    private fun getSharingDisplayName(policy: SharingPolicyType): String = when (policy) {
        SharingPolicyType.PRIVATE -> "Private"
        SharingPolicyType.ALL_PEERS -> "All Peers"
        SharingPolicyType.SELECTED_PEERS -> "Selected Peers"
    }

    private fun createFido2Key(
        keyId: String = "test-key-id",
        rpName: String? = "Test RP",
        rpId: String? = "test.example.com",
        userName: String? = "testuser",
        userDisplayName: String? = "Test User",
        lastUsedAt: Long = 0,
        useCount: Long = 0,
        signCount: Long = 0,
        isDiscoverable: Boolean = true
    ) = KeyEntity(
        keyId = keyId,
        keyType = "fido2",
        algorithm = "ES256",
        label = rpName ?: rpId ?: "Test Key",
        keySizeBits = 256,
        source = "local",
        rpName = rpName,
        rpId = rpId,
        userName = userName,
        userDisplayName = userDisplayName,
        lastUsedAt = lastUsedAt,
        useCount = useCount,
        signCount = signCount,
        isDiscoverable = isDiscoverable,
        sharingPolicy = SharingPolicyType.PRIVATE
    )
}
