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
internal fun parseOathLabel(encodedLabel: String, issuerParam: String? = null): OathLabel {
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

/**
 * Assemble the `otpauth://` URI the importer parses from hand-entered values.
 *
 * Every value is percent-encoded, so an issuer or account containing `&`,
 * `?`, `#` or `=` is not read back as URI structure.
 */
internal fun manualOtpauthUri(
    issuer: String?,
    accountName: String,
    secret: String,
    type: String,
    algorithm: String,
    digits: Int,
    period: Int
): String = buildString {
    val label = if (issuer != null) "$issuer:$accountName" else accountName
    append("otpauth://${type.lowercase()}/")
    append(encodeUriComponent(label))
    append("?secret=${encodeUriComponent(secret)}")
    if (issuer != null) append("&issuer=${encodeUriComponent(issuer)}")
    append("&algorithm=${encodeUriComponent(algorithm)}")
    append("&digits=$digits")
    append("&period=$period")
}

/** Percent-encode (UTF-8) a URI component; a space is `%20`, never `+`. */
private fun encodeUriComponent(value: String): String =
    java.net.URLEncoder.encode(value, Charsets.UTF_8.name()).replace("+", "%20")
