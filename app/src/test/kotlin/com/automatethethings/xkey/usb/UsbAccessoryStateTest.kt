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
 * Unit tests for [UsbAccessoryState] sealed class hierarchy.
 *
 * Verifies all state variants, their properties, equality semantics,
 * and exhaustive pattern-matching compatibility.
 */
class UsbAccessoryStateTest {

    @Test
    fun `Disconnected is a singleton`() {
        val a = UsbAccessoryState.Disconnected
        val b = UsbAccessoryState.Disconnected
        assertTrue(a === b)
    }

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

    @Test
    fun `Connected equality checks accessory info`() {
        val a = UsbAccessoryState.Connected("Device A")
        val b = UsbAccessoryState.Connected("Device A")
        val c = UsbAccessoryState.Connected("Device B")

        assertEquals(a, b)
        assertNotEquals(a, c)
    }

    @Test
    fun `Error carries message`() {
        val state = UsbAccessoryState.Error("Failed to open USB accessory")
        assertEquals("Failed to open USB accessory", state.message)
    }

    @Test
    fun `Error equality checks message`() {
        val a = UsbAccessoryState.Error("error1")
        val b = UsbAccessoryState.Error("error1")
        val c = UsbAccessoryState.Error("error2")

        assertEquals(a, b)
        assertNotEquals(a, c)
    }

    @Test
    fun `all states are UsbAccessoryState subtype`() {
        val states: List<UsbAccessoryState> = listOf(
            UsbAccessoryState.Disconnected,
            UsbAccessoryState.Handshaking,
            UsbAccessoryState.Connected("test"),
            UsbAccessoryState.Error("test")
        )
        states.forEach { state ->
            assertTrue(
                "${state::class.simpleName} should be UsbAccessoryState",
                state is UsbAccessoryState
            )
        }
    }

    @Test
    fun `states are distinguishable via when expression`() {
        val states = listOf(
            UsbAccessoryState.Disconnected,
            UsbAccessoryState.Handshaking,
            UsbAccessoryState.Connected("info"),
            UsbAccessoryState.Error("err")
        )

        val labels = states.map { state ->
            when (state) {
                is UsbAccessoryState.Disconnected -> "disconnected"
                is UsbAccessoryState.Handshaking -> "handshaking"
                is UsbAccessoryState.Connected -> "connected"
                is UsbAccessoryState.Error -> "error"
            }
        }

        assertEquals(listOf("disconnected", "handshaking", "connected", "error"), labels)
    }

    @Test
    fun `different state types are not equal`() {
        assertNotEquals(
            UsbAccessoryState.Disconnected as UsbAccessoryState,
            UsbAccessoryState.Handshaking as UsbAccessoryState
        )
        assertNotEquals(
            UsbAccessoryState.Connected("test") as UsbAccessoryState,
            UsbAccessoryState.Error("test") as UsbAccessoryState
        )
    }
}
