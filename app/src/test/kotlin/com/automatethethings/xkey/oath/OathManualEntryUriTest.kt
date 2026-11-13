package com.automatethethings.xkey.oath

import java.net.URI
import java.net.URLDecoder
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The manual-entry round trip: [otpauthUri] writes the label the way
 * [parseStructuredOathLabel] reads it back, so the persisted issuer and
 * account are the values typed in (#156); an external import keeps the
 * separator split of third-party labels.
 */
class OathManualEntryUriTest {

    @Test
    fun `an issuer and an account round trip apart`() {
        assertEquals(
            OathLabel("GitHub", "alice@example.com"),
            roundTrip(issuer = "GitHub", account = "alice@example.com")
        )
    }

    @Test
    fun `an issuer containing a colon keeps both fields`() {
        assertEquals(
            OathLabel("Corp:EU", "alice@example.com"),
            roundTrip(issuer = "Corp:EU", account = "alice@example.com")
        )
    }

    @Test
    fun `an account containing a colon stays whole`() {
        assertEquals(
            OathLabel("Corp", "host:user"),
            roundTrip(issuer = "Corp", account = "host:user")
        )
    }

    @Test
    fun `an account with no issuer is all account`() {
        assertEquals(OathLabel(null, "host:user"), roundTrip(issuer = null, account = "host:user"))
    }

    @Test
    fun `uri punctuation in the issuer and the account round trips`() {
        assertEquals(
            OathLabel("A&B=C?D#E 50%", "a+b&c@example.com"),
            roundTrip(issuer = "A&B=C?D#E 50%", account = "a+b&c@example.com")
        )
    }

    @Test
    fun `the label uses a literal colon separator`() {
        val uri = otpauthUri("totp", "Corp:EU", "alice", "JBSWY3DPEHPK3PXP", "SHA1", 6, 30, null)
        assertEquals("/Corp%3AEU:alice", URI(uri).rawPath)
    }

    @Test
    fun `an imported encoded separator with no issuer parameter keeps the issuer`() {
        assertEquals(
            OathLabel("GitHub", "alice"),
            read("otpauth://totp/GitHub%3Aalice?secret=JBSWY3DPEHPK3PXP", structured = false)
        )
    }

    @Test
    fun `an imported literal separator with no issuer parameter keeps the issuer`() {
        assertEquals(
            OathLabel("GitHub", "alice"),
            read("otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP", structured = false)
        )
    }

    @Test
    fun `an imported issuer parameter matching the label prefix strips it`() {
        assertEquals(
            OathLabel("GitHub", "alice"),
            read("otpauth://totp/GitHub%3Aalice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub", structured = false)
        )
    }

    @Test
    fun `an imported issuer parameter differing from the label prefix is kept as given`() {
        assertEquals(
            OathLabel("GitHub", "alice"),
            read("otpauth://totp/Other%3Aalice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub", structured = false)
        )
    }

    /** Build the manual-entry URI, then read it back on the structured path. */
    private fun roundTrip(issuer: String?, account: String): OathLabel =
        read(otpauthUri("totp", issuer, account, "JBSWY3DPEHPK3PXP", "SHA1", 6, 30, null), structured = true)

    /**
     * Read [uriString] as `OathRepository.importFromUri` does: the
     * still-encoded path through [parseStructuredOathLabel] or
     * [parseOathLabel], with the `issuer` parameter winning for the issuer.
     */
    private fun read(uriString: String, structured: Boolean): OathLabel {
        val uri = URI(uriString)
        val issuerParam = uri.rawQuery.split("&")
            .map { it.split("=", limit = 2) }
            .firstOrNull { it[0] == "issuer" }
            ?.let { URLDecoder.decode(it[1], Charsets.UTF_8.name()) }
        val encodedLabel = uri.rawPath.removePrefix("/")
        val label = if (structured) {
            parseStructuredOathLabel(encodedLabel)
        } else {
            parseOathLabel(encodedLabel, issuerParam)
        }
        return OathLabel(issuerParam ?: label.issuer, label.account)
    }
}
