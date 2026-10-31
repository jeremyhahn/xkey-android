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
package com.automatethethings.xkey.credential.handler

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests for BrowserAllowlist privileged browser configuration.
 *
 * Verifies that the allowlist JSON is well-formed and contains the expected
 * browser entries with valid SHA-256 certificate fingerprints.
 */
class BrowserAllowlistTest {

    @Test
    fun `allowlist JSON is valid`() {
        val json = JSONObject(BrowserAllowlist.PRIVILEGED_BROWSERS)
        assertEquals("android", json.getString("type"))
        assertTrue("Must have 'apps' array", json.has("apps"))
        assertTrue("Apps array must not be empty", json.getJSONArray("apps").length() > 0)
    }

    @Test
    fun `allowlist contains Chrome stable`() {
        assertBrowserPresent("com.android.chrome")
    }

    @Test
    fun `allowlist contains Chrome Beta`() {
        assertBrowserPresent("com.chrome.beta")
    }

    @Test
    fun `allowlist contains Chrome Dev`() {
        assertBrowserPresent("com.chrome.dev")
    }

    @Test
    fun `allowlist contains Chrome Canary`() {
        assertBrowserPresent("com.chrome.canary")
    }

    @Test
    fun `allowlist contains Firefox`() {
        assertBrowserPresent("org.mozilla.firefox")
    }

    @Test
    fun `allowlist contains Firefox Beta`() {
        assertBrowserPresent("org.mozilla.firefox_beta")
    }

    @Test
    fun `allowlist contains Firefox Nightly`() {
        assertBrowserPresent("org.mozilla.fenix")
    }

    @Test
    fun `allowlist contains Samsung Internet`() {
        assertBrowserPresent("com.sec.android.app.sbrowser")
    }

    @Test
    fun `allowlist contains Microsoft Edge`() {
        assertBrowserPresent("com.microsoft.emmx")
    }

    @Test
    fun `allowlist contains Vanadium`() {
        assertBrowserPresent("app.vanadium.browser")
    }

    @Test
    fun `all entries have valid SHA-256 fingerprints`() {
        val json = JSONObject(BrowserAllowlist.PRIVILEGED_BROWSERS)
        val apps = json.getJSONArray("apps")

        for (i in 0 until apps.length()) {
            val app = apps.getJSONObject(i)
            val info = app.getJSONObject("info")
            val packageName = info.getString("package_name")
            val signatures = info.getJSONArray("signatures")

            assertTrue("$packageName must have at least one signature", signatures.length() > 0)

            for (j in 0 until signatures.length()) {
                val sig = signatures.getJSONObject(j)
                val fingerprint = sig.getString("cert_fingerprint_sha256")
                assertEquals(
                    "$packageName fingerprint must be 64 hex chars (SHA-256)",
                    64, fingerprint.length
                )
                assertTrue(
                    "$packageName fingerprint must be uppercase hex",
                    fingerprint.matches(Regex("[0-9A-F]{64}"))
                )
            }
        }
    }

    @Test
    fun `all entries have type android`() {
        val json = JSONObject(BrowserAllowlist.PRIVILEGED_BROWSERS)
        val apps = json.getJSONArray("apps")

        for (i in 0 until apps.length()) {
            val app = apps.getJSONObject(i)
            assertEquals("Each app entry must have type 'android'", "android", app.getString("type"))
        }
    }

    @Test
    fun `Chrome stable has correct fingerprint`() {
        val fingerprint = getFingerprintForPackage("com.android.chrome")
        assertEquals(
            "F0FD6C5B410F25CB25C3B53346C8972FAE30F8EE7411DF910480AD6B2D60DB83",
            fingerprint
        )
    }

    @Test
    fun `Vanadium has correct fingerprint`() {
        val fingerprint = getFingerprintForPackage("app.vanadium.browser")
        assertEquals(
            "C6ADB8B83C6D4C17D292AFDE56FD488A51D316FF8F2C11C5410223BFF8A7DBB3",
            fingerprint
        )
    }

    // --- Helpers ---

    private fun assertBrowserPresent(packageName: String) {
        val json = JSONObject(BrowserAllowlist.PRIVILEGED_BROWSERS)
        val apps = json.getJSONArray("apps")
        var found = false
        for (i in 0 until apps.length()) {
            val app = apps.getJSONObject(i)
            val info = app.getJSONObject("info")
            if (info.getString("package_name") == packageName) {
                found = true
                break
            }
        }
        assertTrue("Allowlist must contain $packageName", found)
    }

    private fun getFingerprintForPackage(packageName: String): String {
        val json = JSONObject(BrowserAllowlist.PRIVILEGED_BROWSERS)
        val apps = json.getJSONArray("apps")
        for (i in 0 until apps.length()) {
            val app = apps.getJSONObject(i)
            val info = app.getJSONObject("info")
            if (info.getString("package_name") == packageName) {
                return info.getJSONArray("signatures")
                    .getJSONObject(0)
                    .getString("cert_fingerprint_sha256")
            }
        }
        throw AssertionError("Package $packageName not found in allowlist")
    }
}
