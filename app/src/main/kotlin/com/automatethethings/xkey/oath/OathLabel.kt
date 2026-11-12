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
 * @param encodedLabel The label as it appears in the URI path, still
 *        percent-encoded, without the leading `/`.
 * @return The [OathLabel]; both parts are trimmed.
 */
internal fun parseOathLabel(encodedLabel: String): OathLabel {
    val label = URLDecoder.decode(encodedLabel.replace("+", "%2B"), Charsets.UTF_8.name())
    val colonIndex = label.indexOf(':')
    return if (colonIndex >= 0) {
        val issuer = label.substring(0, colonIndex).trim()
        val account = label.substring(colonIndex + 1).trim()
        OathLabel(issuer.ifEmpty { null }, account)
    } else {
        OathLabel(null, label.trim())
    }
}
