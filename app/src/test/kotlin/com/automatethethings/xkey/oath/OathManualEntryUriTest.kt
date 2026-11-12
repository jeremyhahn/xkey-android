package com.automatethethings.xkey.oath

import java.net.URI
import java.net.URLDecoder
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The manual-entry round trip: [manualOtpauthUri] writes the label the way
 * [parseOathLabel] reads it back, so the persisted issuer and account are the
 * values typed in (#156).
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
        val uri = manualOtpauthUri("Corp:EU", "alice", "JBSWY3DPEHPK3PXP", "TOTP", "SHA1", 6, 30)
        assertEquals("/Corp%3AEU:alice", URI(uri).rawPath)
    }

    /**
     * Build the URI, then read it as `OathRepository.importFromUri` does: the
     * still-encoded path through [parseOathLabel], with the `issuer`
     * parameter winning for the issuer.
     */
    private fun roundTrip(issuer: String?, account: String): OathLabel {
        val uri = URI(manualOtpauthUri(issuer, account, "JBSWY3DPEHPK3PXP", "TOTP", "SHA1", 6, 30))
        val issuerParam = uri.rawQuery.split("&")
            .map { it.split("=", limit = 2) }
            .firstOrNull { it[0] == "issuer" }
            ?.let { URLDecoder.decode(it[1], Charsets.UTF_8.name()) }
        val label = parseOathLabel(uri.rawPath.removePrefix("/"), issuerParam)
        return OathLabel(issuerParam ?: label.issuer, label.account)
    }
}
