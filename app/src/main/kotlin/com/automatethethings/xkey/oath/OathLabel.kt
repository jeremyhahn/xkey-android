package com.automatethethings.xkey.oath

import java.net.URLDecoder

/**
 * The two parts of an otpauth label: `issuer:account` or just `account`.
 *
 * @property issuer The label's issuer prefix, or null when absent or empty.
 * @property account The account name.
 */
internal data class OathLabel(val issuer: String?, val account: String)

/**
 * Parse an otpauth label into its issuer and account name.
 *
 * The label is split on its first literal `:` before it is percent-decoded,
 * so an encoded `%3A` (as `otpauthUri` writes a colon) stays inside the
 * issuer or the account (#156).
 *
 * @param encodedLabel The label as it appears in the URI path, still
 *        percent-encoded, without the leading `/`.
 * @return The [OathLabel]; both parts are decoded and trimmed.
 */
internal fun parseOathLabel(encodedLabel: String): OathLabel {
    val colonIndex = encodedLabel.indexOf(':')
    return if (colonIndex >= 0) {
        val issuer = decodeLabelPart(encodedLabel.substring(0, colonIndex)).trim()
        val account = decodeLabelPart(encodedLabel.substring(colonIndex + 1)).trim()
        OathLabel(issuer.ifEmpty { null }, account)
    } else {
        OathLabel(null, decodeLabelPart(encodedLabel).trim())
    }
}

/** Percent-decode (UTF-8) one label part; a `+` in a URI path is literal. */
private fun decodeLabelPart(part: String): String =
    URLDecoder.decode(part.replace("+", "%2B"), Charsets.UTF_8.name())
