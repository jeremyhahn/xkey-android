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

import org.junit.Assert.assertFalse
import org.junit.Test

/**
 * Unit tests for [UsbHsmSettingsData].
 *
 * Verifies that Native USB Accessory Mode is off by default.
 */
class UsbHsmSettingsTest {

    @Test
    fun `default settings have native USB disabled`() {
        val settings = UsbHsmSettingsData()
        assertFalse(settings.nativeUsbEnabled)
    }
}
