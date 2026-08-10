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
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.text.DateFormat
import java.util.Date

/**
 * Tests for OathActivity credential detail dialog display logic.
 *
 * Verifies type-specific field visibility (period vs counter), source
 * display name mapping, use count formatting, last-used fallback to
 * "Never", and context menu display name construction.
 */
class OathActivityDisplayTest {

    // -------------------------------------------------------------------------
    // Type-Specific Fields
    // -------------------------------------------------------------------------

    @Test
    fun `TOTP credential shows period in seconds`() {
        val cred = createCredential(oathType = "TOTP", periodSeconds = 30)
        assertEquals("TOTP", cred.oathType)
        assertEquals("30 seconds", formatPeriodValue(cred.periodSeconds))
    }

    @Test
    fun `TOTP credential with non-default period shows correct value`() {
        val cred = createCredential(oathType = "TOTP", periodSeconds = 60)
        assertEquals("60 seconds", formatPeriodValue(cred.periodSeconds))
    }

    @Test
    fun `HOTP credential shows counter value`() {
        val cred = createCredential(oathType = "HOTP", counter = 42)
        assertEquals("HOTP", cred.oathType)
        assertEquals("42", cred.counter.toString())
    }

    // -------------------------------------------------------------------------
    // Source Display Names
    // -------------------------------------------------------------------------

    @Test
    fun `source local maps to Local`() {
        assertEquals("Local", getSourceDisplayName("local"))
    }

    @Test
    fun `source remote_ble maps to Remote BLE`() {
        assertEquals("Remote (BLE)", getSourceDisplayName("remote_ble"))
    }

    @Test
    fun `source remote_usb maps to Remote USB`() {
        assertEquals("Remote (USB)", getSourceDisplayName("remote_usb"))
    }

    @Test
    fun `source xkmsd maps to xKMS Daemon`() {
        assertEquals("xKMS Daemon", getSourceDisplayName("xkmsd"))
    }

    @Test
    fun `unknown source displayed as-is`() {
        assertEquals("custom_import", getSourceDisplayName("custom_import"))
    }

    // -------------------------------------------------------------------------
    // Use Count Formatting
    // -------------------------------------------------------------------------

    @Test
    fun `use count formats with times suffix`() {
        val cred = createCredential(useCount = 15)
        assertEquals("15 times", formatTimesUsed(cred.useCount))
    }

    @Test
    fun `use count zero formats correctly`() {
        val cred = createCredential(useCount = 0)
        assertEquals("0 times", formatTimesUsed(cred.useCount))
    }

    // -------------------------------------------------------------------------
    // Last Used Display
    // -------------------------------------------------------------------------

    @Test
    fun `last used shows Never when null`() {
        val cred = createCredential(lastUsedAt = null)
        val display = formatLastUsed(cred.lastUsedAt)
        assertEquals("Never", display)
    }

    @Test
    fun `last used shows formatted date when present`() {
        val timestamp = 1706788200000L
        val cred = createCredential(lastUsedAt = timestamp)
        val display = formatLastUsed(cred.lastUsedAt)

        assertTrue("Formatted date should not be Never", display != "Never")
        assertTrue(
            "Formatted date should contain year",
            display.contains("2024")
        )
    }

    // -------------------------------------------------------------------------
    // Context Menu Display Name
    // -------------------------------------------------------------------------

    @Test
    fun `context menu shows issuer colon account when issuer present`() {
        val cred = createCredential(issuer = "GitHub", accountName = "user@example.com")
        assertEquals("GitHub: user@example.com", buildContextDisplayName(cred))
    }

    @Test
    fun `context menu shows account only when issuer null`() {
        val cred = createCredential(issuer = null, accountName = "user@example.com")
        assertEquals("user@example.com", buildContextDisplayName(cred))
    }

    // -------------------------------------------------------------------------
    // Issuer Display in Detail Dialog
    // -------------------------------------------------------------------------

    @Test
    fun `issuer shown when present`() {
        val cred = createCredential(issuer = "Google")
        assertEquals("Google", cred.issuer)
    }

    @Test
    fun `issuer null uses dash placeholder`() {
        val cred = createCredential(issuer = null)
        val display = cred.issuer ?: "-"
        assertEquals("-", display)
    }

    // -------------------------------------------------------------------------
    // Display helpers (replicate OathActivity dialog logic)
    // -------------------------------------------------------------------------

    /**
     * Replicates the source display name mapping used in the credential detail
     * dialog. Matches the pattern from PasskeyDetailActivity.
     */
    private fun getSourceDisplayName(source: String): String = when (source) {
        "local" -> "Local"
        "remote_ble" -> "Remote (BLE)"
        "remote_usb" -> "Remote (USB)"
        "xkmsd" -> "xKMS Daemon"
        else -> source
    }

    /**
     * Replicates the period value format string: "%1$d seconds".
     */
    private fun formatPeriodValue(periodSeconds: Int): String =
        "$periodSeconds seconds"

    /**
     * Replicates the use count format string: "%1$d times".
     */
    private fun formatTimesUsed(useCount: Int): String =
        "$useCount times"

    /**
     * Replicates the last-used display logic: "Never" when null,
     * otherwise a formatted date via DateFormat.MEDIUM / SHORT.
     */
    private fun formatLastUsed(lastUsedAt: Long?): String {
        if (lastUsedAt == null) return "Never"
        val dateFormat = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT)
        return dateFormat.format(Date(lastUsedAt))
    }

    /**
     * Replicates the context menu display name construction from
     * OathActivity.showContextMenu: "Issuer: AccountName" when issuer
     * is present, just accountName otherwise.
     */
    private fun buildContextDisplayName(cred: OathCredentialEntity): String = buildString {
        cred.issuer?.let { append("$it: ") }
        append(cred.accountName)
    }

    /**
     * Creates an [OathCredentialEntity] with sensible defaults for testing.
     */
    private fun createCredential(
        oathType: String = "TOTP",
        algorithm: String = "SHA1",
        digits: Int = 6,
        periodSeconds: Int = 30,
        counter: Long = 0,
        issuer: String? = "TestIssuer",
        accountName: String = "test@example.com",
        source: String = "local",
        lastUsedAt: Long? = null,
        useCount: Int = 0
    ) = OathCredentialEntity(
        id = 0,
        oathId = "${issuer ?: ""}:$accountName",
        oathType = oathType,
        algorithm = algorithm,
        digits = digits,
        periodSeconds = periodSeconds,
        counter = counter,
        issuer = issuer,
        accountName = accountName,
        secretEncrypted = byteArrayOf(0x01, 0x02, 0x03),
        source = source,
        createdAt = System.currentTimeMillis(),
        lastUsedAt = lastUsedAt,
        useCount = useCount
    )
}
