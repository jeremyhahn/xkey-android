/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
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
package com.automatethethings.xkey.crypto

import java.security.spec.ECParameterSpec

/** Stub: parses nothing yet. */
object ContactKeyParser {

    class ParsedContactKey(val der: ByteArray, val algorithm: String, val fingerprint: String)

    fun parse(bytes: ByteArray): ParsedContactKey? = null

    fun decodePem(text: String): ByteArray? = null

    fun fingerprint(der: ByteArray): String = ""

    fun resolveAlgorithm(hint: String?, detected: String): String =
        hint?.takeIf { it.isNotBlank() } ?: detected

    internal fun curveAlgorithm(params: ECParameterSpec): String? = null
}
