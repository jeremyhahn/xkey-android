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
import org.junit.Test

/**
 * Unit tests for PIV and PIN protocol method names and error codes defined in
 * [MethodNames] and [ErrorCodes].
 *
 * These tests verify the protocol contract between the Android authenticator
 * and desktop clients. They do not exercise the full [RequestHandler] dispatch
 * (which requires Android Context and Android Keystore), but pin the wire
 * values of the PIV and PIN method names and error codes. Uniqueness and
 * range of every error code are checked in [ProtocolConstantsTest].
 */
class PivHandlerTest {

    // -------------------------------------------------------------------------
    // PIV method names
    // -------------------------------------------------------------------------

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

    // -------------------------------------------------------------------------
    // PIV error codes
    // -------------------------------------------------------------------------

    @Test
    fun `PIV error codes have expected values`() {
        assertEquals(-32026, ErrorCodes.PIV_SLOT_NOT_FOUND)
        assertEquals(-32027, ErrorCodes.PIV_SLOT_OCCUPIED)
        assertEquals(-32028, ErrorCodes.PIV_SIGN_FAILED)
        assertEquals(-32029, ErrorCodes.PIV_INVALID_SLOT)
    }

    // -------------------------------------------------------------------------
    // PIN method names
    // -------------------------------------------------------------------------

    @Test
    fun `PIN method names have expected values`() {
        assertEquals("local.pinVerify", MethodNames.LOCAL_PIN_VERIFY)
        assertEquals("local.pinStatus", MethodNames.LOCAL_PIN_STATUS)
        assertEquals("local.pinSet", MethodNames.LOCAL_PIN_SET)
        assertEquals("local.pinChange", MethodNames.LOCAL_PIN_CHANGE)
        assertEquals("local.pinResetLockout", MethodNames.LOCAL_PIN_RESET_LOCKOUT)
    }

    // -------------------------------------------------------------------------
    // PIN error codes
    // -------------------------------------------------------------------------

    @Test
    fun `PIN error codes have expected values`() {
        assertEquals(-32032, ErrorCodes.PIN_REQUIRED)
        assertEquals(-32033, ErrorCodes.PIN_INCORRECT)
        assertEquals(-32034, ErrorCodes.PIN_LOCKED)
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
