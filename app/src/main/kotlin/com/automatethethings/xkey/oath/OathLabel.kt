package com.automatethethings.xkey.oath

import java.io.ByteArrayOutputStream
import java.net.URLEncoder

/**
 * The two parts of an otpauth label: `issuer:account` or just `account`.
 *
 * @property issuer The label's issuer prefix, or null when absent or empty.
 * @property account The account name.
 */
internal data class OathLabel(val issuer: String?, val account: String)

/** An encoded colon, as `otpauthUri` writes one inside a label part. */
private const val ENCODED_COLON = "%3A"

/**
 * Parse an otpauth label into its issuer and account name.
 *
 * A literal `:` separates the issuer and the account, and a `:` inside
 * either is written `%3A` (#156). The label is split before it is
 * percent-decoded, so that `%3A` stays in its part. With no literal `:`, an
 * encoded `%3A` separates the label only where the decoded prefix is the
 * `issuer` query parameter (older manual-entry URIs and other generators
 * encode the separator); otherwise the label is all account, so an
 * issuerless `host%3Auser` stays whole.
 *
 * @param encodedLabel The label as it appears in the URI path, still
 *        percent-encoded, without the leading `/`.
 * @param issuerParam The URI's decoded `issuer` query parameter, if any.
 * @return The [OathLabel]; both parts are decoded and trimmed.
 */
internal fun parseOathLabel(encodedLabel: String, issuerParam: String? = null): OathLabel {
    val colonIndex = encodedLabel.indexOf(':')
    if (colonIndex >= 0) {
        return splitLabel(encodedLabel, colonIndex, 1)
    }
    val issuer = issuerParam?.trim()
    if (!issuer.isNullOrEmpty()) {
        var index = encodedLabel.indexOf(ENCODED_COLON, ignoreCase = true)
        while (index >= 0) {
            if (decodeLabelPart(encodedLabel.substring(0, index)).trim() == issuer) {
                return splitLabel(encodedLabel, index, ENCODED_COLON.length)
            }
            index = encodedLabel.indexOf(ENCODED_COLON, index + 1, ignoreCase = true)
        }
    }
    return OathLabel(null, decodeLabelPart(encodedLabel).trim())
}

/** Split [label] around the [length]-char separator at [index], then decode. */
private fun splitLabel(label: String, index: Int, length: Int): OathLabel {
    val issuer = decodeLabelPart(label.substring(0, index)).trim()
    val account = decodeLabelPart(label.substring(index + length)).trim()
    return OathLabel(issuer.ifEmpty { null }, account)
}

/**
 * Percent-decode (UTF-8) one label part leniently, as `Uri.getPath` did: a
 * `%` that starts no two-hex-digit escape is kept as written, and a `+` in a
 * URI path is literal.
 */
private fun decodeLabelPart(part: String): String {
    if ('%' !in part) return part
    val bytes = ByteArrayOutputStream()
    var i = 0
    while (i < part.length) {
        val hi = if (part[i] == '%' && i + 2 < part.length) Character.digit(part[i + 1], 16) else -1
        val lo = if (hi >= 0) Character.digit(part[i + 2], 16) else -1
        if (lo >= 0) {
            bytes.write(hi * 16 + lo)
            i += 3
        } else {
            val end = i + Character.charCount(part.codePointAt(i))
            bytes.write(part.substring(i, end).toByteArray(Charsets.UTF_8))
            i = end
        }
    }
    return bytes.toString(Charsets.UTF_8.name())
}

/**
 * Assemble the `otpauth://` URI the importer parses from hand-entered values.
 *
 * Every value is percent-encoded, so an issuer or account containing `&`,
 * `?`, `#`, `=` or `:` is not read back as URI structure. The issuer and the
 * account are joined by a literal `:`, the separator [parseOathLabel] reads
 * (#156).
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
    append("otpauth://${type.lowercase()}/")
    if (issuer != null) append("${encodeUriComponent(issuer)}:")
    append(encodeUriComponent(accountName))
    append("?secret=${encodeUriComponent(secret)}")
    if (issuer != null) append("&issuer=${encodeUriComponent(issuer)}")
    append("&algorithm=${encodeUriComponent(algorithm)}")
    append("&digits=$digits")
    append("&period=$period")
}

/** Percent-encode (UTF-8) a URI component; a space is `%20`, never `+`. */
private fun encodeUriComponent(value: String): String =
    URLEncoder.encode(value, Charsets.UTF_8.name()).replace("+", "%20")
