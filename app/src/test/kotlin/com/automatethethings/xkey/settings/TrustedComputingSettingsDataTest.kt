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
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for [TrustedComputingSettingsData].
 *
 * The three derived flags decide who signs device identity certificates and
 * whether the device verifies a peer's identity at all, so each is checked
 * against the full truth table of its inputs rather than just the happy path.
 * [useXkmsCA] and [useLocalCA] are mutually exclusive by construction, and both
 * are gated on the master switch, so a configuration stored while the feature is
 * off must stay inert.
 *
 * [TrustedComputingSettingsRepository] needs Jetpack DataStore and is covered by
 * instrumented tests, which is also where the migration off the old
 * `actAsCAServer` boolean is proved.
 */
class TrustedComputingSettingsDataTest {

    // -------------------------------------------------------------------------
    // Defaults
    // -------------------------------------------------------------------------

    @Test
    fun `trusted computing is off by default`() {
        val settings = TrustedComputingSettingsData()

        assertFalse(settings.enabled)
        assertEquals(
            "nobody signs until an authority is chosen",
            CertificateAuthoritySource.NONE,
            settings.caSource
        )
        assertNull(settings.xkmsEndpoint)
        assertFalse(settings.requireTrustedIDevID)
        assertFalse(settings.requireFullAttestation)
        assertFalse(settings.importToSystemStore)
        assertTrue("first-time pairing is allowed until locked down", settings.trustNewDevices)
        assertEquals("xkey_intermediate_ca", settings.platformCAAlias)
    }

    @Test
    fun `CA subject fields default to empty`() {
        val settings = TrustedComputingSettingsData()

        assertEquals("", settings.caSubjectOrganization)
        assertEquals("", settings.caSubjectOU)
        assertEquals("", settings.caSubjectLocality)
        assertEquals("", settings.caSubjectProvince)
        assertEquals("", settings.caSubjectCountry)
        assertEquals("", settings.caSubjectCommonName)
    }

    // -------------------------------------------------------------------------
    // useXkmsCA
    // -------------------------------------------------------------------------

    @Test
    fun `useXkmsCA needs enabled, the xkms source, and an endpoint`() {
        val xkms = TrustedComputingSettingsData(
            enabled = true,
            caSource = CertificateAuthoritySource.XKMS,
            xkmsEndpoint = "https://xkms.example.com"
        )

        assertTrue(xkms.useXkmsCA)
        assertFalse("only one authority can sign", xkms.useLocalCA)
    }

    @Test
    fun `useXkmsCA is false when the feature is disabled`() {
        val settings = TrustedComputingSettingsData(
            enabled = false,
            caSource = CertificateAuthoritySource.XKMS,
            xkmsEndpoint = "https://xkms.example.com"
        )

        assertFalse(
            "a stored endpoint must not act while the feature is off",
            settings.useXkmsCA
        )
    }

    @Test
    fun `useXkmsCA is false when this device is the selected authority`() {
        val settings = TrustedComputingSettingsData(
            enabled = true,
            caSource = CertificateAuthoritySource.THIS_DEVICE,
            xkmsEndpoint = "https://xkms.example.com"
        )

        assertFalse(
            "an endpoint left behind by an earlier choice must not sign",
            settings.useXkmsCA
        )
    }

    @Test
    fun `useXkmsCA is false when no authority is selected`() {
        val settings = TrustedComputingSettingsData(
            enabled = true,
            caSource = CertificateAuthoritySource.NONE,
            xkmsEndpoint = "https://xkms.example.com"
        )

        assertFalse(settings.useXkmsCA)
    }

    @Test
    fun `useXkmsCA is false for a missing or blank endpoint`() {
        val base = TrustedComputingSettingsData(
            enabled = true,
            caSource = CertificateAuthoritySource.XKMS
        )

        assertFalse("a selected but unconfigured xkms source is not usable", base.useXkmsCA)
        assertFalse(base.copy(xkmsEndpoint = "").useXkmsCA)
        assertFalse(base.copy(xkmsEndpoint = "   ").useXkmsCA)
        assertFalse(base.copy(xkmsEndpoint = "\t\n").useXkmsCA)
    }

    // -------------------------------------------------------------------------
    // useLocalCA
    // -------------------------------------------------------------------------

    @Test
    fun `useLocalCA needs enabled and this device as the authority`() {
        val local = TrustedComputingSettingsData(
            enabled = true,
            caSource = CertificateAuthoritySource.THIS_DEVICE
        )

        assertTrue(local.useLocalCA)
        assertFalse(local.useXkmsCA)
    }

    @Test
    fun `useLocalCA is false when the feature is disabled`() {
        val settings = TrustedComputingSettingsData(
            enabled = false,
            caSource = CertificateAuthoritySource.THIS_DEVICE
        )

        assertFalse(
            "a stored choice must not act while the feature is off",
            settings.useLocalCA
        )
    }

    @Test
    fun `useLocalCA is false for the other authorities`() {
        val base = TrustedComputingSettingsData(enabled = true)

        assertFalse(base.copy(caSource = CertificateAuthoritySource.XKMS).useLocalCA)
        assertFalse(base.copy(caSource = CertificateAuthoritySource.NONE).useLocalCA)
    }

    /**
     * This phone's own CA needs nothing configured to be usable, so the endpoint
     * left over from an xkms deployment must not hold it back either way.
     */
    @Test
    fun `useLocalCA ignores the xkms endpoint`() {
        val settings = TrustedComputingSettingsData(
            enabled = true,
            caSource = CertificateAuthoritySource.THIS_DEVICE,
            xkmsEndpoint = "https://xkms.example.com"
        )

        assertTrue(settings.useLocalCA)
    }

    // -------------------------------------------------------------------------
    // isDeviceVerificationActive
    // -------------------------------------------------------------------------

    @Test
    fun `device verification activates on either IDevID or full attestation`() {
        val idevidOnly = TrustedComputingSettingsData(enabled = true, requireTrustedIDevID = true)
        val attestationOnly =
            TrustedComputingSettingsData(enabled = true, requireFullAttestation = true)
        val both = TrustedComputingSettingsData(
            enabled = true, requireTrustedIDevID = true, requireFullAttestation = true
        )

        assertTrue(idevidOnly.isDeviceVerificationActive)
        assertTrue(attestationOnly.isDeviceVerificationActive)
        assertTrue(both.isDeviceVerificationActive)
    }

    @Test
    fun `device verification is inactive when enabled but nothing is required`() {
        val settings = TrustedComputingSettingsData(
            enabled = true, requireTrustedIDevID = false, requireFullAttestation = false
        )

        assertFalse(settings.isDeviceVerificationActive)
    }

    @Test
    fun `device verification is inactive when the feature is off`() {
        val settings = TrustedComputingSettingsData(
            enabled = false, requireTrustedIDevID = true, requireFullAttestation = true
        )

        assertFalse(
            "requirements stored while disabled must not silently enforce",
            settings.isDeviceVerificationActive
        )
    }

    // -------------------------------------------------------------------------
    // Presets
    // -------------------------------------------------------------------------

    @Test
    fun `DEFAULT preset equals a plain construction`() {
        assertEquals(TrustedComputingSettingsData(), TrustedComputingSettingsData.DEFAULT)
        assertFalse(TrustedComputingSettingsData.DEFAULT.enabled)
    }

    @Test
    fun `PERMISSIVE preset self-issues and trusts new devices`() {
        val permissive = TrustedComputingSettingsData.PERMISSIVE

        assertTrue(permissive.enabled)
        assertEquals(CertificateAuthoritySource.THIS_DEVICE, permissive.caSource)
        assertTrue(permissive.trustNewDevices)
        assertFalse(permissive.requireTrustedIDevID)
        assertFalse(permissive.requireFullAttestation)
        assertFalse(permissive.isDeviceVerificationActive)
        assertTrue(permissive.useLocalCA)
        assertFalse("this phone signing never asks an xkms server", permissive.useXkmsCA)
    }

    @Test
    fun `STRICT preset demands verified identity and refuses unknown devices`() {
        val strict = TrustedComputingSettingsData.STRICT

        assertTrue(strict.enabled)
        assertEquals(CertificateAuthoritySource.XKMS, strict.caSource)
        assertTrue(strict.requireTrustedIDevID)
        assertTrue(strict.requireFullAttestation)
        assertFalse(strict.trustNewDevices)
        assertTrue(strict.isDeviceVerificationActive)
        assertFalse("the enterprise CA is never this phone", strict.useLocalCA)
        assertFalse(
            "STRICT ships without an xkms endpoint, so it must be supplied",
            strict.useXkmsCA
        )
        assertTrue(strict.copy(xkmsEndpoint = "https://xkms.example.com").useXkmsCA)
    }
}
