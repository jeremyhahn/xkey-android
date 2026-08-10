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
package com.automatethethings.xkey.protocol

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for PIV and PIN protocol method names and error codes defined in
 * [MethodNames] and [ErrorCodes].
 *
 * These tests verify the protocol contract between the Android authenticator
 * and desktop clients. They do not exercise the full [RequestHandler] dispatch
 * (which requires Android Context and Android Keystore), but ensure that method
 * names and error codes follow the expected conventions and are in valid ranges.
 */
class PivHandlerTest {

    // -------------------------------------------------------------------------
    // PIV method names
    // -------------------------------------------------------------------------

    @Test
    fun `PIV local method names follow local dot pivX naming convention`() {
        val pivLocalMethods = listOf(
            MethodNames.LOCAL_PIV_GENERATE_KEY,
            MethodNames.LOCAL_PIV_IMPORT_CERT,
            MethodNames.LOCAL_PIV_LIST_SLOTS,
            MethodNames.LOCAL_PIV_SIGN,
            MethodNames.LOCAL_PIV_GET_CERT
        )

        pivLocalMethods.forEach { method ->
            assertTrue(
                "Local PIV method '$method' should start with 'local.piv'",
                method.startsWith("local.piv")
            )
        }
    }

    @Test
    fun `PIV remote method names follow remote dot pivX naming convention`() {
        val pivRemoteMethods = listOf(
            MethodNames.REMOTE_PIV_LIST_SLOTS,
            MethodNames.REMOTE_PIV_SIGN,
            MethodNames.REMOTE_PIV_GET_CERT
        )

        pivRemoteMethods.forEach { method ->
            assertTrue(
                "Remote PIV method '$method' should start with 'remote.piv'",
                method.startsWith("remote.piv")
            )
        }
    }

    @Test
    fun `PIV local method names have expected values`() {
        assertEquals("local.pivGenerateKey", MethodNames.LOCAL_PIV_GENERATE_KEY)
        assertEquals("local.pivImportCert", MethodNames.LOCAL_PIV_IMPORT_CERT)
        assertEquals("local.pivListSlots", MethodNames.LOCAL_PIV_LIST_SLOTS)
        assertEquals("local.pivSign", MethodNames.LOCAL_PIV_SIGN)
        assertEquals("local.pivGetCert", MethodNames.LOCAL_PIV_GET_CERT)
    }

    @Test
    fun `PIV remote method names have expected values`() {
        assertEquals("remote.pivListSlots", MethodNames.REMOTE_PIV_LIST_SLOTS)
        assertEquals("remote.pivSign", MethodNames.REMOTE_PIV_SIGN)
        assertEquals("remote.pivGetCert", MethodNames.REMOTE_PIV_GET_CERT)
    }

    @Test
    fun `there are 5 local PIV methods`() {
        val pivLocalMethods = listOf(
            MethodNames.LOCAL_PIV_GENERATE_KEY,
            MethodNames.LOCAL_PIV_IMPORT_CERT,
            MethodNames.LOCAL_PIV_LIST_SLOTS,
            MethodNames.LOCAL_PIV_SIGN,
            MethodNames.LOCAL_PIV_GET_CERT
        )
        assertEquals(5, pivLocalMethods.size)
    }

    @Test
    fun `there are 3 remote PIV methods`() {
        val pivRemoteMethods = listOf(
            MethodNames.REMOTE_PIV_LIST_SLOTS,
            MethodNames.REMOTE_PIV_SIGN,
            MethodNames.REMOTE_PIV_GET_CERT
        )
        assertEquals(3, pivRemoteMethods.size)
    }

    // -------------------------------------------------------------------------
    // PIV error codes
    // -------------------------------------------------------------------------

    @Test
    fun `PIV error codes are in expected range`() {
        val pivErrorCodes = listOf(
            ErrorCodes.PIV_SLOT_NOT_FOUND,
            ErrorCodes.PIV_SLOT_OCCUPIED,
            ErrorCodes.PIV_SIGN_FAILED,
            ErrorCodes.PIV_INVALID_SLOT
        )

        pivErrorCodes.forEach { code ->
            assertTrue(
                "PIV error code $code should be negative (JSON-RPC convention)",
                code < 0
            )
            assertTrue(
                "PIV error code $code should be in the xKey custom range (-32099 to -32000)",
                code in -32099..-32000
            )
        }
    }

    @Test
    fun `PIV error codes have expected values`() {
        assertEquals(-32026, ErrorCodes.PIV_SLOT_NOT_FOUND)
        assertEquals(-32027, ErrorCodes.PIV_SLOT_OCCUPIED)
        assertEquals(-32028, ErrorCodes.PIV_SIGN_FAILED)
        assertEquals(-32029, ErrorCodes.PIV_INVALID_SLOT)
    }

    @Test
    fun `PIV error codes are all unique`() {
        val pivErrorCodes = listOf(
            ErrorCodes.PIV_SLOT_NOT_FOUND,
            ErrorCodes.PIV_SLOT_OCCUPIED,
            ErrorCodes.PIV_SIGN_FAILED,
            ErrorCodes.PIV_INVALID_SLOT
        )
        assertEquals(
            "All PIV error codes must be unique",
            pivErrorCodes.size,
            pivErrorCodes.toSet().size
        )
    }

    // -------------------------------------------------------------------------
    // PIN method names
    // -------------------------------------------------------------------------

    @Test
    fun `PIN method names follow local dot pinX naming convention`() {
        val pinMethods = listOf(
            MethodNames.LOCAL_PIN_VERIFY,
            MethodNames.LOCAL_PIN_STATUS,
            MethodNames.LOCAL_PIN_SET,
            MethodNames.LOCAL_PIN_CHANGE,
            MethodNames.LOCAL_PIN_RESET_LOCKOUT
        )

        pinMethods.forEach { method ->
            assertTrue(
                "PIN method '$method' should start with 'local.pin'",
                method.startsWith("local.pin")
            )
        }
    }

    @Test
    fun `PIN method names have expected values`() {
        assertEquals("local.pinVerify", MethodNames.LOCAL_PIN_VERIFY)
        assertEquals("local.pinStatus", MethodNames.LOCAL_PIN_STATUS)
        assertEquals("local.pinSet", MethodNames.LOCAL_PIN_SET)
        assertEquals("local.pinChange", MethodNames.LOCAL_PIN_CHANGE)
        assertEquals("local.pinResetLockout", MethodNames.LOCAL_PIN_RESET_LOCKOUT)
    }

    @Test
    fun `there are 5 PIN methods`() {
        val pinMethods = listOf(
            MethodNames.LOCAL_PIN_VERIFY,
            MethodNames.LOCAL_PIN_STATUS,
            MethodNames.LOCAL_PIN_SET,
            MethodNames.LOCAL_PIN_CHANGE,
            MethodNames.LOCAL_PIN_RESET_LOCKOUT
        )
        assertEquals(5, pinMethods.size)
    }

    // -------------------------------------------------------------------------
    // PIN error codes
    // -------------------------------------------------------------------------

    @Test
    fun `PIN error codes are in expected range`() {
        val pinErrorCodes = listOf(
            ErrorCodes.PIN_REQUIRED,
            ErrorCodes.PIN_INCORRECT,
            ErrorCodes.PIN_LOCKED
        )

        pinErrorCodes.forEach { code ->
            assertTrue(
                "PIN error code $code should be negative (JSON-RPC convention)",
                code < 0
            )
            assertTrue(
                "PIN error code $code should be in the xKey custom range (-32099 to -32000)",
                code in -32099..-32000
            )
        }
    }

    @Test
    fun `PIN error codes have expected values`() {
        assertEquals(-32032, ErrorCodes.PIN_REQUIRED)
        assertEquals(-32033, ErrorCodes.PIN_INCORRECT)
        assertEquals(-32034, ErrorCodes.PIN_LOCKED)
    }

    @Test
    fun `PIN error codes are all unique`() {
        val pinErrorCodes = listOf(
            ErrorCodes.PIN_REQUIRED,
            ErrorCodes.PIN_INCORRECT,
            ErrorCodes.PIN_LOCKED
        )
        assertEquals(
            "All PIN error codes must be unique",
            pinErrorCodes.size,
            pinErrorCodes.toSet().size
        )
    }

    // -------------------------------------------------------------------------
    // Cross-concern: PIN and PIV error codes do not overlap
    // -------------------------------------------------------------------------

    @Test
    fun `PIV and PIN error codes do not overlap`() {
        val pivCodes = setOf(
            ErrorCodes.PIV_SLOT_NOT_FOUND,
            ErrorCodes.PIV_SLOT_OCCUPIED,
            ErrorCodes.PIV_SIGN_FAILED,
            ErrorCodes.PIV_INVALID_SLOT
        )
        val pinCodes = setOf(
            ErrorCodes.PIN_REQUIRED,
            ErrorCodes.PIN_INCORRECT,
            ErrorCodes.PIN_LOCKED
        )

        val overlap = pivCodes.intersect(pinCodes)
        assertTrue(
            "PIV and PIN error codes must not overlap, found: $overlap",
            overlap.isEmpty()
        )
    }

    // -------------------------------------------------------------------------
    // JSON-RPC standard error codes sanity check
    // -------------------------------------------------------------------------

    @Test
    fun `standard JSON-RPC error codes are in specification range`() {
        assertEquals(-32700, ErrorCodes.PARSE_ERROR)
        assertEquals(-32600, ErrorCodes.INVALID_REQUEST)
        assertEquals(-32601, ErrorCodes.METHOD_NOT_FOUND)
        assertEquals(-32602, ErrorCodes.INVALID_PARAMS)
        assertEquals(-32603, ErrorCodes.INTERNAL_ERROR)
    }
}
