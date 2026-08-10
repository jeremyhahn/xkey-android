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
package com.automatethethings.xkey.util

import org.json.JSONObject

/**
 * Extension functions for JSONObject to handle Kotlin/Java interop issues.
 *
 * The standard `optString(key, null)` method has type inference issues in Kotlin
 * where the compiler infers `Nothing?` instead of `String?`. These extension
 * functions provide type-safe alternatives.
 */

/**
 * Returns the string value for [key], or null if the key doesn't exist or the value is null.
 */
fun JSONObject.getStringOrNull(key: String): String? =
    if (has(key) && !isNull(key)) getString(key) else null

/**
 * Returns the string value for [key], or [default] if the key doesn't exist,
 * the value is null, or the value is an empty string.
 */
fun JSONObject.getStringOrDefault(key: String, default: String): String {
    if (!has(key) || isNull(key)) return default
    val value = getString(key)
    return if (value.isEmpty()) default else value
}
