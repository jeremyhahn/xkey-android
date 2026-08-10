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

/**
 * Browser privileged allowlist for CredentialProvider origin resolution.
 *
 * When a browser calls the CredentialProvider via CredentialManager,
 * [CallingAppInfo.getOrigin] needs this allowlist to identify the browser
 * as a privileged caller and return the correct web origin.
 *
 * Certificate fingerprints sourced from Google's official allowlist:
 * https://www.gstatic.com/gpm-passkeys-privileged-apps/apps.json
 */
object BrowserAllowlist {

    /**
     * JSON allowlist of privileged browser apps with their SHA-256
     * signing certificate fingerprints.
     *
     * Includes: Chrome (all channels), Firefox, Samsung Internet,
     * Microsoft Edge, and Vanadium (GrapheneOS).
     */
    val PRIVILEGED_BROWSERS: String = buildAllowlistJson()

    private fun buildAllowlistJson(): String {
        val apps = listOf(
            // Chrome stable
            browserEntry("com.android.chrome",
                "F0FD6C5B410F25CB25C3B53346C8972FAE30F8EE7411DF910480AD6B2D60DB83"),
            // Chrome Beta
            browserEntry("com.chrome.beta",
                "DA633D34B69E63AE2103B49D53CE052FC5F7F3C53AAB94FDC2A208BDFD14249C"),
            // Chrome Dev
            browserEntry("com.chrome.dev",
                "9044EE5FEE4BBC5E21DD44665431C4EB1F1F71A32716A0BC927BCBB39233CABF"),
            // Chrome Canary
            browserEntry("com.chrome.canary",
                "2019DFA1FB23EFBF70C5BCD1443C5BEAB04F3F2FF4366E9AC1E3457639A24CFC"),
            // Firefox
            browserEntry("org.mozilla.firefox",
                "A78B62A5165B4494B2FEAD9E76A280D22D937FEE6251AECE599446B2EA319B04"),
            // Firefox Beta
            browserEntry("org.mozilla.firefox_beta",
                "A78B62A5165B4494B2FEAD9E76A280D22D937FEE6251AECE599446B2EA319B04"),
            // Firefox Nightly (Fenix)
            browserEntry("org.mozilla.fenix",
                "5004779088E7F988D5BC5CC5F8798FEBF4F8CD084A1B2A46EFD4C8EE4AEAF211"),
            // Samsung Internet
            browserEntry("com.sec.android.app.sbrowser",
                "C8A2E9BCCF597C2FB6DC66BEE293FC13F2FC47EC77BC6B2B0D52C11F51192AB8"),
            // Microsoft Edge
            browserEntry("com.microsoft.emmx",
                "01E1999710A82C2749B4D50C445DC85D670B6136089D0A766A73827C82A1EAC9"),
            // Vanadium (GrapheneOS)
            browserEntry("app.vanadium.browser",
                "C6ADB8B83C6D4C17D292AFDE56FD488A51D316FF8F2C11C5410223BFF8A7DBB3"),
        )

        return """{"type":"android","apps":[${apps.joinToString(",")}]}"""
    }

    private fun browserEntry(packageName: String, sha256: String): String {
        return """{"type":"android","info":{"package_name":"$packageName","signatures":[{"build":"release","cert_fingerprint_sha256":"$sha256"}]}}"""
    }
}
