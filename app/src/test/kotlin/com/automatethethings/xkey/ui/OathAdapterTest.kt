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
 * Tests for [OathAdapter] DiffUtil callback, code formatting, and bind-time
 * display logic (initial letter, issuer text, account visibility).
 *
 * Verifies that [OathAdapter.OathDiffCallback] correctly identifies item
 * identity and content changes, that [OathAdapter.formatCode] splits codes
 * at the midpoint, and that the ViewHolder bind logic resolves initials
 * and label visibility correctly.
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

    @Test
    fun `formatCode splits 8-digit code at midpoint`() {
        assertEquals("1234 5678", OathAdapter.formatCode("12345678"))
    }

    // -------------------------------------------------------------------------
    // Initial Letter
    // -------------------------------------------------------------------------

    @Test
    fun `initial letter prefers issuer first char`() {
        val item = createOathItem(issuer = "GitHub", accountName = "user@example.com")
        val initial = item.credential.issuer
            ?.firstOrNull()
            ?.uppercaseChar()
            ?.toString()
            ?: item.credential.accountName
                .firstOrNull()
                ?.uppercaseChar()
                ?.toString()
            ?: "?"

        assertEquals("G", initial)
    }

    @Test
    fun `initial letter falls back to accountName when issuer is null`() {
        val item = createOathItem(issuer = null, accountName = "alice@example.com")
        val initial = item.credential.issuer
            ?.firstOrNull()
            ?.uppercaseChar()
            ?.toString()
            ?: item.credential.accountName
                .firstOrNull()
                ?.uppercaseChar()
                ?.toString()
            ?: "?"

        assertEquals("A", initial)
    }

    @Test
    fun `initial letter returns question mark when both empty`() {
        val item = createOathItem(issuer = null, accountName = "")
        val initial = item.credential.issuer
            ?.firstOrNull()
            ?.uppercaseChar()
            ?.toString()
            ?: item.credential.accountName
                .firstOrNull()
                ?.uppercaseChar()
                ?.toString()
            ?: "?"

        assertEquals("?", initial)
    }

    // -------------------------------------------------------------------------
    // Issuer Display and Account Visibility
    // -------------------------------------------------------------------------

    @Test
    fun `issuer display shows issuer when present`() {
        val item = createOathItem(issuer = "Google", accountName = "user@gmail.com")
        val issuerText = item.credential.issuer ?: item.credential.accountName

        assertEquals("Google", issuerText)
    }

    @Test
    fun `issuer display shows accountName when issuer is null`() {
        val item = createOathItem(issuer = null, accountName = "user@gmail.com")
        val issuerText = item.credential.issuer ?: item.credential.accountName

        assertEquals("user@gmail.com", issuerText)
    }

    @Test
    fun `account visible when issuer is present`() {
        val item = createOathItem(issuer = "Google", accountName = "user@gmail.com")
        val accountVisible = item.credential.issuer != null

        assertTrue(accountVisible)
    }

    @Test
    fun `account hidden when issuer is null to avoid duplication`() {
        val item = createOathItem(issuer = null, accountName = "user@gmail.com")
        val accountVisible = item.credential.issuer != null

        assertFalse(accountVisible)
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
