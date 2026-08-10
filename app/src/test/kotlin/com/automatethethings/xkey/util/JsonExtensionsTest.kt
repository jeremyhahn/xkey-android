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
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Unit tests for the [JSONObject] string extensions.
 *
 * These two helpers stand between every wire message and the fields the
 * protocol layer reads out of it, so the distinctions they draw matter:
 * an absent key, an explicit JSON `null` and an empty string are three
 * different things, and only [getStringOrDefault] folds the last one in
 * with the other two.
 */
class JsonExtensionsTest {

    // -------------------------------------------------------------------------
    // getStringOrNull
    // -------------------------------------------------------------------------

    @Test
    fun `getStringOrNull returns the value for a present key`() {
        val json = JSONObject("""{"method":"local.sign"}""")

        assertEquals("local.sign", json.getStringOrNull("method"))
    }

    @Test
    fun `getStringOrNull returns null for an absent key`() {
        val json = JSONObject("""{"method":"local.sign"}""")

        assertNull(json.getStringOrNull("params"))
    }

    @Test
    fun `getStringOrNull returns null for an explicit JSON null`() {
        val json = JSONObject("""{"method":null}""")

        assertNull(json.getStringOrNull("method"))
    }

    @Test
    fun `getStringOrNull keeps an empty string rather than folding it to null`() {
        val json = JSONObject("""{"method":""}""")

        assertEquals("", json.getStringOrNull("method"))
    }

    /**
     * A non-string value is NOT portable: Android's `org.json` coerces it to
     * its string form, while the JVM artifact these unit tests run against
     * throws `JSONException`. The helper inherits whichever it is running on,
     * so nothing may depend on coercion — the wire contract with go-xkms sends
     * every one of these fields as a JSON string.
     */
    @Test
    fun `getStringOrNull does not promise coercion of a non-string value`() {
        val json = JSONObject("""{"id":42}""")

        val coercedOrThrew = runCatching { json.getStringOrNull("id") }
        if (coercedOrThrew.isSuccess) {
            assertEquals("42", coercedOrThrew.getOrNull())
        }
    }

    @Test
    fun `getStringOrNull returns null on an empty document`() {
        assertNull(JSONObject().getStringOrNull("anything"))
    }

    @Test
    fun `getStringOrNull preserves whitespace and unicode exactly`() {
        val json = JSONObject().put("label", "  ünïcödé ✓  ")

        assertEquals("  ünïcödé ✓  ", json.getStringOrNull("label"))
    }

    // -------------------------------------------------------------------------
    // getStringOrDefault
    // -------------------------------------------------------------------------

    @Test
    fun `getStringOrDefault returns the value for a present non-empty key`() {
        val json = JSONObject("""{"source":"local"}""")

        assertEquals("local", json.getStringOrDefault("source", "remote"))
    }

    @Test
    fun `getStringOrDefault falls back for an absent key`() {
        val json = JSONObject("""{"source":"local"}""")

        assertEquals("remote", json.getStringOrDefault("origin", "remote"))
    }

    @Test
    fun `getStringOrDefault falls back for an explicit JSON null`() {
        val json = JSONObject("""{"source":null}""")

        assertEquals("remote", json.getStringOrDefault("source", "remote"))
    }

    @Test
    fun `getStringOrDefault falls back for an empty string`() {
        val json = JSONObject("""{"source":""}""")

        assertEquals("remote", json.getStringOrDefault("source", "remote"))
    }

    @Test
    fun `getStringOrDefault keeps a blank-but-not-empty string`() {
        val json = JSONObject("""{"source":"   "}""")

        assertEquals("   ", json.getStringOrDefault("source", "remote"))
    }

    @Test
    fun `getStringOrDefault accepts an empty default`() {
        val json = JSONObject()

        assertEquals("", json.getStringOrDefault("missing", ""))
    }

    /** Same portability caveat as the getStringOrNull case above. */
    @Test
    fun `getStringOrDefault does not promise coercion of a non-string value`() {
        val json = JSONObject("""{"count":0}""")

        val coercedOrThrew = runCatching { json.getStringOrDefault("count", "fallback") }
        if (coercedOrThrew.isSuccess) {
            assertEquals("0", coercedOrThrew.getOrNull())
        }
    }
}
