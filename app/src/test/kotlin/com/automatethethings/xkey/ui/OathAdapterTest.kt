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

import com.automatethethings.xkey.oath.OathCredentialEntity
import com.automatethethings.xkey.oath.OathCredentialWithCode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests for [OathAdapter] DiffUtil callback and code formatting.
 *
 * Verifies that [OathAdapter.OathDiffCallback] correctly identifies item
 * identity and content changes, and that [OathAdapter.formatCode] splits
 * codes at the midpoint.
 */
class OathAdapterTest {

    private val diffCallback = OathAdapter.OathDiffCallback()

    // -------------------------------------------------------------------------
    // DiffUtil: areItemsTheSame
    // -------------------------------------------------------------------------

    @Test
    fun `areItemsTheSame returns true for same oathId`() {
        val old = createOathItem(oathId = "issuer:alice@example.com")
        val new = createOathItem(oathId = "issuer:alice@example.com", code = "999999")

        assertTrue(diffCallback.areItemsTheSame(old, new))
    }

    @Test
    fun `areItemsTheSame returns false for different oathId`() {
        val old = createOathItem(oathId = "issuer:alice@example.com")
        val new = createOathItem(oathId = "issuer:bob@example.com")

        assertFalse(diffCallback.areItemsTheSame(old, new))
    }

    // -------------------------------------------------------------------------
    // DiffUtil: areContentsTheSame
    // -------------------------------------------------------------------------

    @Test
    fun `areContentsTheSame returns false when code changes`() {
        val old = createOathItem(oathId = "github:user", code = "123456")
        val new = createOathItem(oathId = "github:user", code = "654321")

        assertFalse(diffCallback.areContentsTheSame(old, new))
    }

    @Test
    fun `areContentsTheSame returns false when countdown changes`() {
        val old = createOathItem(oathId = "github:user", secondsRemaining = 25)
        val new = createOathItem(oathId = "github:user", secondsRemaining = 10)

        assertFalse(diffCallback.areContentsTheSame(old, new))
    }

    // -------------------------------------------------------------------------
    // formatCode
    // -------------------------------------------------------------------------

    @Test
    fun `formatCode splits 6-digit code at midpoint`() {
        assertEquals("123 456", OathAdapter.formatCode("123456"))
    }

    @Test
    fun `formatCode splits 7-digit code at midpoint`() {
        assertEquals("123 4567", OathAdapter.formatCode("1234567"))
    }

    // -------------------------------------------------------------------------
    // Helper
    // -------------------------------------------------------------------------

    private fun createOathItem(
        oathId: String = "github:user@example.com",
        issuer: String? = "GitHub",
        accountName: String = "user@example.com",
        code: String = "123456",
        secondsRemaining: Int = 30,
        oathType: String = "TOTP",
        algorithm: String = "SHA1",
        digits: Int = 6,
        periodSeconds: Int = 30
    ) = OathCredentialWithCode(
        credential = OathCredentialEntity(
            oathId = oathId,
            oathType = oathType,
            algorithm = algorithm,
            digits = digits,
            periodSeconds = periodSeconds,
            issuer = issuer,
            accountName = accountName,
            secretEncrypted = byteArrayOf(0x00),
            createdAt = System.currentTimeMillis()
        ),
        code = code,
        secondsRemaining = secondsRemaining
    )
}
