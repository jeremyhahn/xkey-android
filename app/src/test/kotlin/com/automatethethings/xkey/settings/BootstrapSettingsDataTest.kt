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
package com.automatethethings.xkey.settings

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for [BootstrapSettingsData], [BootstrapMethod] and
 * [BootstrapTimeout].
 *
 * Bootstrap decides how the phone learns to trust a go-xkms CA bundle, so the
 * negative paths matter most here: a malformed persisted method list, a
 * truncated Noise key or SPKI pin, and an un-parseable server URL must all
 * degrade to something safe rather than silently enabling a weaker method.
 *
 * [BootstrapSettingsRepository] needs Jetpack DataStore and is covered by
 * instrumented tests.
 */
class BootstrapSettingsDataTest {

    // -------------------------------------------------------------------------
    // BootstrapMethod parsing (the persisted format is a comma-separated string)
    // -------------------------------------------------------------------------

    @Test
    fun `default order runs strongest verification first`() {
        assertEquals(
            listOf(
                BootstrapMethod.DANE,
                BootstrapMethod.NOISE,
                BootstrapMethod.SPKI,
                BootstrapMethod.DIRECT
            ),
            BootstrapMethod.DEFAULT_ORDER
        )
        assertEquals(BootstrapMethod.entries.size, BootstrapMethod.DEFAULT_ORDER.size)
    }

    @Test
    fun `every method carries a display name and description`() {
        for (method in BootstrapMethod.entries) {
            assertTrue(method.displayName.isNotBlank())
            assertTrue(method.description.isNotBlank())
        }
    }

    @Test
    fun `fromName is case insensitive`() {
        assertSame(BootstrapMethod.DANE, BootstrapMethod.fromName("DANE"))
        assertSame(BootstrapMethod.DANE, BootstrapMethod.fromName("dane"))
        assertSame(BootstrapMethod.NOISE, BootstrapMethod.fromName("Noise"))
        assertSame(BootstrapMethod.SPKI, BootstrapMethod.fromName("sPkI"))
        assertSame(BootstrapMethod.DIRECT, BootstrapMethod.fromName("DIRECT"))
    }

    @Test
    fun `fromName returns null for unknown or padded names`() {
        assertNull(BootstrapMethod.fromName("tofu"))
        assertNull(BootstrapMethod.fromName(""))
        assertNull("fromName does not trim; fromCommaSeparated does", BootstrapMethod.fromName(" dane"))
    }

    @Test
    fun `fromCommaSeparated parses a list and trims whitespace`() {
        assertEquals(
            listOf(BootstrapMethod.NOISE, BootstrapMethod.DIRECT),
            BootstrapMethod.fromCommaSeparated("noise, direct")
        )
        assertEquals(
            listOf(BootstrapMethod.DIRECT, BootstrapMethod.DANE),
            BootstrapMethod.fromCommaSeparated(" DIRECT ,DANE ")
        )
    }

    @Test
    fun `fromCommaSeparated falls back to the default order for blank input`() {
        assertEquals(BootstrapMethod.DEFAULT_ORDER, BootstrapMethod.fromCommaSeparated(""))
        assertEquals(BootstrapMethod.DEFAULT_ORDER, BootstrapMethod.fromCommaSeparated("   "))
    }

    @Test
    fun `fromCommaSeparated falls back when nothing parses`() {
        assertEquals(BootstrapMethod.DEFAULT_ORDER, BootstrapMethod.fromCommaSeparated("tofu,bogus"))
        assertEquals(BootstrapMethod.DEFAULT_ORDER, BootstrapMethod.fromCommaSeparated(",,,"))
    }

    @Test
    fun `fromCommaSeparated drops unknown entries but keeps the recognised ones`() {
        assertEquals(
            listOf(BootstrapMethod.DANE, BootstrapMethod.DIRECT),
            BootstrapMethod.fromCommaSeparated("dane,bogus,direct")
        )
    }

    @Test
    fun `fromCommaSeparated preserves duplicates and caller order`() {
        assertEquals(
            listOf(BootstrapMethod.DIRECT, BootstrapMethod.DIRECT, BootstrapMethod.DANE),
            BootstrapMethod.fromCommaSeparated("direct,direct,dane")
        )
    }

    // -------------------------------------------------------------------------
    // BootstrapTimeout
    // -------------------------------------------------------------------------

    @Test
    fun `bootstrap timeouts expose the documented durations`() {
        assertEquals(10, BootstrapTimeout.SECONDS_10.seconds)
        assertEquals(15, BootstrapTimeout.SECONDS_15.seconds)
        assertEquals(30, BootstrapTimeout.SECONDS_30.seconds)
        assertEquals(60, BootstrapTimeout.SECONDS_60.seconds)
        assertEquals(4, BootstrapTimeout.entries.size)
    }

    @Test
    fun `bootstrap timeout lookup matches exactly and otherwise defaults to 15s`() {
        assertSame(BootstrapTimeout.SECONDS_30, BootstrapTimeout.fromSeconds(30))
        assertNull(BootstrapTimeout.fromSeconds(20))
        assertNull(BootstrapTimeout.fromSeconds(0))
        assertEquals(BootstrapTimeout.SECONDS_15, BootstrapTimeout.fromSecondsOrDefault(20))
        assertEquals(
            BootstrapTimeout.SECONDS_60,
            BootstrapTimeout.fromSecondsOrDefault(20, BootstrapTimeout.SECONDS_60)
        )
    }

    // -------------------------------------------------------------------------
    // Defaults
    // -------------------------------------------------------------------------

    @Test
    fun `defaults enable auto-bootstrap with DANE only and no server configured`() {
        val settings = BootstrapSettingsData()

        assertTrue(settings.autoBootstrapEnabled)
        assertEquals(BootstrapMethod.DEFAULT_ORDER, settings.methodOrder)
        assertEquals(15, settings.perMethodTimeoutSeconds)
        assertEquals(15, settings.timeoutSeconds)
        assertTrue(settings.daneEnabled)
        assertTrue(settings.daneRequireDnssec)
        assertFalse(settings.daneDnsOverTls)
        assertEquals("8.8.8.8:53", settings.daneDnsServer)
        assertFalse(settings.noiseEnabled)
        assertFalse(settings.spkiEnabled)
        assertFalse(settings.directEnabled)
        assertEquals("", settings.daneServerUrl)
    }

    @Test
    fun `an unconfigured default has an enabled method but nothing usable`() {
        val settings = BootstrapSettingsData()

        assertEquals(listOf(BootstrapMethod.DANE), settings.getEnabledMethods())
        assertFalse("no server URL means nothing is actually usable", settings.hasConfiguredMethod())
    }

    @Test
    fun `constants match the go-xkms defaults`() {
        assertEquals(15, BootstrapSettingsData.DEFAULT_PER_METHOD_TIMEOUT_SECONDS)
        assertEquals("8.8.8.8:53", BootstrapSettingsData.DEFAULT_DNS_SERVER)
        assertEquals(443, BootstrapSettingsData.DEFAULT_HTTPS_PORT)
        assertEquals(8445, BootstrapSettingsData.DEFAULT_NOISE_PORT)
        assertEquals(64, BootstrapSettingsData.HEX_KEY_LENGTH)
    }

    // -------------------------------------------------------------------------
    // Method enablement
    // -------------------------------------------------------------------------

    @Test
    fun `isMethodEnabled reads the per-method switch`() {
        val settings = BootstrapSettingsData(
            daneEnabled = true, noiseEnabled = false, spkiEnabled = true, directEnabled = false
        )

        assertTrue(settings.isMethodEnabled(BootstrapMethod.DANE))
        assertFalse(settings.isMethodEnabled(BootstrapMethod.NOISE))
        assertTrue(settings.isMethodEnabled(BootstrapMethod.SPKI))
        assertFalse(settings.isMethodEnabled(BootstrapMethod.DIRECT))
    }

    @Test
    fun `getEnabledMethods follows the configured priority order not the enum order`() {
        val settings = BootstrapSettingsData(
            methodOrder = listOf(
                BootstrapMethod.DIRECT, BootstrapMethod.SPKI,
                BootstrapMethod.NOISE, BootstrapMethod.DANE
            ),
            daneEnabled = true, noiseEnabled = false, spkiEnabled = true, directEnabled = true
        )

        assertEquals(
            listOf(BootstrapMethod.DIRECT, BootstrapMethod.SPKI, BootstrapMethod.DANE),
            settings.getEnabledMethods()
        )
    }

    @Test
    fun `getEnabledMethods ignores enabled methods missing from the order`() {
        val settings = BootstrapSettingsData(
            methodOrder = listOf(BootstrapMethod.DANE),
            daneEnabled = false, directEnabled = true
        )

        assertTrue(settings.getEnabledMethods().isEmpty())
        assertFalse(settings.hasConfiguredMethod())
    }

    // -------------------------------------------------------------------------
    // hasConfiguredMethod
    // -------------------------------------------------------------------------

    @Test
    fun `DANE counts as configured once a server url is set`() {
        val settings = BootstrapSettingsData(daneEnabled = true, daneServerUrl = "https://kms:8443")
        assertTrue(settings.hasConfiguredMethod())
        assertFalse(settings.copy(daneServerUrl = "   ").hasConfiguredMethod())
    }

    @Test
    fun `NOISE needs both an address and a static key`() {
        val base = BootstrapSettingsData(
            methodOrder = listOf(BootstrapMethod.NOISE),
            daneEnabled = false, noiseEnabled = true
        )

        assertFalse(base.hasConfiguredMethod())
        assertFalse(base.copy(noiseServerAddr = "kms:8445").hasConfiguredMethod())
        assertFalse(base.copy(noiseServerStaticKey = "ab".repeat(32)).hasConfiguredMethod())
        assertTrue(
            base.copy(
                noiseServerAddr = "kms:8445",
                noiseServerStaticKey = "ab".repeat(32)
            ).hasConfiguredMethod()
        )
    }

    @Test
    fun `SPKI needs both a url and a pin`() {
        val base = BootstrapSettingsData(
            methodOrder = listOf(BootstrapMethod.SPKI), daneEnabled = false, spkiEnabled = true
        )

        assertFalse(base.copy(spkiServerUrl = "https://kms:8443").hasConfiguredMethod())
        assertFalse(base.copy(spkiPinSha256 = "cd".repeat(32)).hasConfiguredMethod())
        assertTrue(
            base.copy(
                spkiServerUrl = "https://kms:8443", spkiPinSha256 = "cd".repeat(32)
            ).hasConfiguredMethod()
        )
    }

    @Test
    fun `DIRECT needs only a url`() {
        val base = BootstrapSettingsData(
            methodOrder = listOf(BootstrapMethod.DIRECT), daneEnabled = false, directEnabled = true
        )

        assertFalse(base.hasConfiguredMethod())
        assertTrue(base.copy(directServerUrl = "https://kms:8443").hasConfiguredMethod())
    }

    @Test
    fun `a configured but disabled method does not count`() {
        val settings = BootstrapSettingsData(
            daneEnabled = false, daneServerUrl = "https://kms:8443",
            noiseEnabled = false, noiseServerAddr = "kms:8445",
            noiseServerStaticKey = "ab".repeat(32),
            spkiEnabled = false, directEnabled = false
        )

        assertFalse(settings.hasConfiguredMethod())
    }

    // -------------------------------------------------------------------------
    // Key / pin validation
    // -------------------------------------------------------------------------

    @Test
    fun `an empty noise key is treated as valid because it is simply unset`() {
        assertTrue(BootstrapSettingsData(noiseServerStaticKey = "").isNoiseKeyValid())
        assertTrue(BootstrapSettingsData(noiseServerStaticKey = "   ").isNoiseKeyValid())
    }

    @Test
    fun `a 64 character hex noise key is valid in either case`() {
        assertTrue(BootstrapSettingsData(noiseServerStaticKey = "ab".repeat(32)).isNoiseKeyValid())
        assertTrue(BootstrapSettingsData(noiseServerStaticKey = "AB".repeat(32)).isNoiseKeyValid())
        assertTrue(BootstrapSettingsData(noiseServerStaticKey = "0f".repeat(32)).isNoiseKeyValid())
    }

    @Test
    fun `a wrong-length or non-hex noise key is rejected`() {
        assertFalse(BootstrapSettingsData(noiseServerStaticKey = "ab".repeat(31)).isNoiseKeyValid())
        assertFalse(BootstrapSettingsData(noiseServerStaticKey = "ab".repeat(33)).isNoiseKeyValid())
        assertFalse(
            "'g' is not a hex digit",
            BootstrapSettingsData(noiseServerStaticKey = "g" + "a".repeat(63)).isNoiseKeyValid()
        )
        assertFalse(
            BootstrapSettingsData(noiseServerStaticKey = "a".repeat(63) + " ").isNoiseKeyValid()
        )
    }

    @Test
    fun `spki pin validation mirrors the noise key rules`() {
        assertTrue(BootstrapSettingsData(spkiPinSha256 = "").isSpkiPinValid())
        assertTrue(BootstrapSettingsData(spkiPinSha256 = "FF".repeat(32)).isSpkiPinValid())
        assertFalse(BootstrapSettingsData(spkiPinSha256 = "ff".repeat(16)).isSpkiPinValid())
        assertFalse(BootstrapSettingsData(spkiPinSha256 = "z".repeat(64)).isSpkiPinValid())
    }

    // -------------------------------------------------------------------------
    // deriveFromUrl
    // -------------------------------------------------------------------------

    @Test
    fun `deriveFromUrl fills every method url and offsets the noise port by two`() {
        val derived = BootstrapSettingsData().deriveFromUrl("https://kms.example.com:8443")

        assertEquals("https://kms.example.com:8443", derived.daneServerUrl)
        assertEquals("https://kms.example.com:8443", derived.spkiServerUrl)
        assertEquals("https://kms.example.com:8443", derived.directServerUrl)
        assertEquals("kms.example.com:8445", derived.noiseServerAddr)
    }

    @Test
    fun `deriveFromUrl assumes 443 and the default noise port when no port is given`() {
        val derived = BootstrapSettingsData().deriveFromUrl("https://kms.example.com")

        assertEquals("https://kms.example.com:443", derived.daneServerUrl)
        assertEquals("kms.example.com:8445", derived.noiseServerAddr)
    }

    @Test
    fun `deriveFromUrl normalises a plain http url to https`() {
        val derived = BootstrapSettingsData().deriveFromUrl("http://kms.example.com:8080")

        assertEquals("https://kms.example.com:8080", derived.directServerUrl)
        assertEquals("kms.example.com:8082", derived.noiseServerAddr)
    }

    @Test
    fun `deriveFromUrl leaves settings untouched for blank input`() {
        val original = BootstrapSettingsData(daneServerUrl = "https://kept:8443")

        assertSame(original, original.deriveFromUrl(""))
        assertSame(original, original.deriveFromUrl("   "))
    }

    @Test
    fun `deriveFromUrl leaves settings untouched for an unparseable url`() {
        val original = BootstrapSettingsData(daneServerUrl = "https://kept:8443")

        assertSame(original, original.deriveFromUrl("not a url at all"))
        assertEquals("https://kept:8443", original.deriveFromUrl("not a url").daneServerUrl)
    }

    @Test
    fun `deriveFromUrl leaves settings untouched when the url has no host`() {
        val original = BootstrapSettingsData(daneServerUrl = "https://kept:8443")

        assertSame(original, original.deriveFromUrl("mailto:ops@example.com"))
        assertSame(original, original.deriveFromUrl("/just/a/path"))
    }

    @Test
    fun `deriveFromUrl preserves unrelated fields`() {
        val original = BootstrapSettingsData(
            autoBootstrapEnabled = false,
            perMethodTimeoutSeconds = 60,
            noiseServerStaticKey = "ab".repeat(32),
            spkiPinSha256 = "cd".repeat(32)
        )

        val derived = original.deriveFromUrl("https://kms.example.com:8443")

        assertFalse(derived.autoBootstrapEnabled)
        assertEquals(60, derived.perMethodTimeoutSeconds)
        assertEquals("ab".repeat(32), derived.noiseServerStaticKey)
        assertEquals("cd".repeat(32), derived.spkiPinSha256)
    }

    // -------------------------------------------------------------------------
    // Timeout helpers and derived configs
    // -------------------------------------------------------------------------

    @Test
    fun `getTimeoutEnum resolves known values and returns null otherwise`() {
        assertEquals(BootstrapTimeout.SECONDS_15, BootstrapSettingsData().getTimeoutEnum())
        assertEquals(
            BootstrapTimeout.SECONDS_60,
            BootstrapSettingsData(perMethodTimeoutSeconds = 60).getTimeoutEnum()
        )
        assertNull(BootstrapSettingsData(perMethodTimeoutSeconds = 17).getTimeoutEnum())
    }

    @Test
    fun `withTimeout updates both the field and its alias`() {
        val updated = BootstrapSettingsData().withTimeout(BootstrapTimeout.SECONDS_30)

        assertEquals(30, updated.perMethodTimeoutSeconds)
        assertEquals(30, updated.timeoutSeconds)
        assertEquals(BootstrapTimeout.SECONDS_30, updated.getTimeoutEnum())
        assertEquals(15, BootstrapSettingsData().perMethodTimeoutSeconds)
    }

    @Test
    fun `per-method configs project the matching fields`() {
        val settings = BootstrapSettingsData(
            daneServerUrl = "https://dane:8443",
            daneDnsServer = "1.1.1.1:53",
            daneDnsOverTls = true,
            daneRequireDnssec = false,
            noiseServerAddr = "noise:8445",
            noiseServerStaticKey = "ab".repeat(32),
            spkiServerUrl = "https://spki:8443",
            spkiPinSha256 = "cd".repeat(32),
            directServerUrl = "https://direct:8443"
        )

        assertEquals(
            DANEConfig("https://dane:8443", "1.1.1.1:53", dnsOverTls = true, requireDnssec = false),
            settings.daneConfig
        )
        assertEquals(NoiseConfig("noise:8445", "ab".repeat(32)), settings.noiseConfig)
        assertEquals(SPKIConfig("https://spki:8443", "cd".repeat(32)), settings.spkiConfig)
        assertEquals(DirectConfig("https://direct:8443"), settings.directConfig)
    }

    @Test
    fun `DANEConfig defaults match the settings defaults`() {
        val config = DANEConfig(serverUrl = "https://kms:8443")

        assertEquals("8.8.8.8:53", config.dnsServer)
        assertFalse(config.dnsOverTls)
        assertTrue("DNSSEC must be required unless explicitly relaxed", config.requireDnssec)
    }

    // -------------------------------------------------------------------------
    // Presets
    // -------------------------------------------------------------------------

    @Test
    fun `DEFAULT preset equals a plain construction`() {
        assertEquals(BootstrapSettingsData(), BootstrapSettingsData.DEFAULT)
    }

    @Test
    fun `HIGH_SECURITY preset forbids the unverified fallbacks`() {
        val high = BootstrapSettingsData.HIGH_SECURITY

        assertEquals(listOf(BootstrapMethod.DANE, BootstrapMethod.NOISE), high.methodOrder)
        assertFalse(high.spkiEnabled)
        assertFalse(high.directEnabled)
        assertTrue(high.daneRequireDnssec)
        assertEquals(
            listOf(BootstrapMethod.DANE, BootstrapMethod.NOISE),
            high.getEnabledMethods()
        )
    }

    @Test
    fun `DEVELOPMENT preset uses direct HTTPS only`() {
        val dev = BootstrapSettingsData.DEVELOPMENT

        assertEquals(listOf(BootstrapMethod.DIRECT), dev.getEnabledMethods())
        assertFalse(dev.daneEnabled)
        assertFalse(dev.noiseEnabled)
        assertFalse(dev.spkiEnabled)
        assertFalse("still unusable until a URL is supplied", dev.hasConfiguredMethod())
        assertTrue(dev.deriveFromUrl("https://localhost:8443").hasConfiguredMethod())
    }
}
