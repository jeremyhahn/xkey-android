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
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for [UsbAccessoryState].
 *
 * UsbAccessoryServerTest drives the server's state transitions; Handshaking
 * and Connected need a live accessory, so they are checked here.
 */
class UsbAccessoryStateTest {

    @Test
    fun `Handshaking is a singleton`() {
        val a = UsbAccessoryState.Handshaking
        val b = UsbAccessoryState.Handshaking
        assertTrue(a === b)
    }

    @Test
    fun `Connected carries accessory info`() {
        val state = UsbAccessoryState.Connected("Pixel 8 Pro USB")
        assertEquals("Pixel 8 Pro USB", state.accessoryInfo)
    }
}
