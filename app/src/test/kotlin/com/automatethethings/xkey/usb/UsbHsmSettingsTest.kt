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
package com.automatethethings.xkey.usb

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for [UsbHsmSettingsData].
 *
 * Verifies default values, equality, copy semantics, and the
 * nativeUsbEnabled property for Native USB Accessory Mode.
 */
class UsbHsmSettingsTest {

    @Test
    fun `default settings have native USB disabled`() {
        val settings = UsbHsmSettingsData()
        assertFalse(settings.nativeUsbEnabled)
    }

    @Test
    fun `can create settings with native USB enabled`() {
        val settings = UsbHsmSettingsData(nativeUsbEnabled = true)
        assertTrue(settings.nativeUsbEnabled)
    }

    @Test
    fun `copy preserves all fields`() {
        val original = UsbHsmSettingsData(nativeUsbEnabled = true)
        val copy = original.copy()
        assertEquals(original, copy)
    }

    @Test
    fun `copy allows changing individual fields`() {
        val original = UsbHsmSettingsData()
        val withNativeUsb = original.copy(nativeUsbEnabled = true)

        assertFalse(original.nativeUsbEnabled)
        assertTrue(withNativeUsb.nativeUsbEnabled)
    }

    @Test
    fun `equality considers all fields`() {
        val a = UsbHsmSettingsData(nativeUsbEnabled = false)
        val b = UsbHsmSettingsData(nativeUsbEnabled = false)
        val c = UsbHsmSettingsData(nativeUsbEnabled = true)

        assertEquals(a, b)
        assertNotEquals(a, c)
    }

    @Test
    fun `hashCode is consistent with equality`() {
        val a = UsbHsmSettingsData(nativeUsbEnabled = true)
        val b = UsbHsmSettingsData(nativeUsbEnabled = true)
        assertEquals(a.hashCode(), b.hashCode())
    }

    @Test
    fun `toString contains all field values`() {
        val settings = UsbHsmSettingsData(nativeUsbEnabled = true)
        val str = settings.toString()
        assertTrue(str.contains("nativeUsbEnabled=true"))
    }
}
