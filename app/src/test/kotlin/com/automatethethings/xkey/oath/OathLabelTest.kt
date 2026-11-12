package com.automatethethings.xkey.oath

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The otpauth label split of [parseOathLabel]: the label is split on its
 * first literal `:` before percent-decoding, so an encoded `%3A` in either
 * part stays in that part (#156). With no literal `:`, an imported label
 * splits on an encoded one, as third-party codes write it; a structured label
 * (manual entry, sync) does not.
 */
class OathLabelTest {

    @Test
    fun `an issuer with an encoded colon keeps its account name`() {
        assertEquals(
            OathLabel("Corp:EU", "user@example.com"),
            parseOathLabel("Corp%3AEU:user@example.com")
        )
    }

    @Test
    fun `an account with an encoded colon stays whole`() {
        assertEquals(
            OathLabel("Corp", "host:user"),
            parseOathLabel("Corp:host%3Auser")
        )
    }

    @Test
    fun `an issuer and an account both with encoded colons`() {
        assertEquals(
            OathLabel("Corp:EU", "host:user"),
            parseOathLabel("Corp%3AEU:host%3Auser")
        )
    }

    @Test
    fun `a label with no issuer is all account`() {
        assertEquals(OathLabel(null, "user@example.com"), parseOathLabel("user%40example.com"))
    }

    @Test
    fun `an imported label with only an encoded colon splits there`() {
        assertEquals(OathLabel("GitHub", "alice"), parseOathLabel("GitHub%3Aalice"))
    }

    @Test
    fun `an imported label with a literal colon and no issuer parameter splits there`() {
        assertEquals(OathLabel("GitHub", "alice"), parseOathLabel("GitHub:alice"))
    }

    @Test
    fun `a structured label with only an encoded colon has no issuer`() {
        assertEquals(OathLabel(null, "host:user"), parseStructuredOathLabel("host%3Auser"))
    }

    @Test
    fun `a structured label splits on a literal colon`() {
        assertEquals(OathLabel("Corp:EU", "host:user"), parseStructuredOathLabel("Corp%3AEU:host%3Auser"))
    }

    @Test
    fun `an empty issuer is absent`() {
        assertEquals(OathLabel(null, "user@example.com"), parseOathLabel(":user@example.com"))
    }

    @Test
    fun `both parts are decoded and trimmed`() {
        assertEquals(
            OathLabel("Big Corp", "first.last@example.com"),
            parseOathLabel("%20Big%20Corp%20:%20first.last%40example.com%20")
        )
    }

    @Test
    fun `a percent sign that starts no escape is literal`() {
        assertEquals(OathLabel("50% off", "user"), parseOathLabel("50% off:user"))
    }

    @Test
    fun `a malformed escape is kept as written`() {
        assertEquals(OathLabel("%zz", "user"), parseOathLabel("%zz:user"))
        assertEquals(OathLabel(null, "user%"), parseOathLabel("user%"))
    }

    @Test
    fun `an encoded colon after the issuer parameter separates the label`() {
        assertEquals(
            OathLabel("GitHub", "alice@example.com"),
            parseOathLabel("GitHub%3Aalice%40example.com", issuerParam = "GitHub")
        )
    }

    @Test
    fun `an encoded colon after an issuer parameter containing a colon separates the label`() {
        assertEquals(
            OathLabel("Corp:EU", "alice"),
            parseOathLabel("Corp%3AEU%3Aalice", issuerParam = "Corp:EU")
        )
    }

    @Test
    fun `an imported label prefix that differs from the issuer parameter is still split off`() {
        // importFromUri keeps the parameter as the issuer, as main did.
        assertEquals(OathLabel("Other", "alice"), parseOathLabel("Other%3Aalice", issuerParam = "GitHub"))
    }

    @Test
    fun `a literal colon separates the label whatever the issuer parameter`() {
        assertEquals(
            OathLabel("Corp", "host:user"),
            parseOathLabel("Corp:host%3Auser", issuerParam = "Corp:host")
        )
    }

    @Test
    fun `a plus sign in the path is literal`() {
        assertEquals(OathLabel("A+B", "user+tag@example.com"), parseOathLabel("A+B:user+tag@example.com"))
    }
}
