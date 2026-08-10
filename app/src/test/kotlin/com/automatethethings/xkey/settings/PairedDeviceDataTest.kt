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

import android.util.Base64
import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Unit tests for [PairedDeviceData], the record persisted for every paired
 * desktop.
 *
 * The JSON form is what actually lands in EncryptedSharedPreferences, so the
 * round trip is tested for both a minimal record and a fully populated one
 * (including the DER byte arrays, which the hand-written `equals`/`hashCode`
 * must compare by content). The optional-field behaviour matters because a
 * record written by an older build must still load.
 *
 * `android.util.Base64` is delegated to `java.util.Base64`, matching the
 * NO_WRAP encoding the production code requests.
 *
 * [PairedDeviceRepository] itself needs EncryptedSharedPreferences (Android
 * Keystore) and requires an instrumented test.
 */
class PairedDeviceDataTest {

    @Before
    fun setUp() {
        mockkStatic(Base64::class)
        every { Base64.encodeToString(any(), any()) } answers {
            java.util.Base64.getEncoder().encodeToString(firstArg())
        }
        every { Base64.decode(any<String>(), any()) } answers {
            java.util.Base64.getDecoder().decode(firstArg<String>())
        }
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    private fun minimal() = PairedDeviceData(
        publicKeyHex = "0a1b2c",
        deviceName = "workstation",
        pairedAt = 1_700_000_000_000L
    )

    private fun full() = PairedDeviceData(
        publicKeyHex = "0a1b2c",
        deviceName = "workstation",
        pairedAt = 1_700_000_000_000L,
        bleAddress = "AA:BB:CC:DD:EE:FF",
        lastAttestationTime = 1_700_000_100_000L,
        bootHashHex = "deadbeef",
        bootStateVerified = true,
        securityLevel = "strongbox",
        deviceFingerprint = "fp-sha256",
        requireAttestationForKeyUse = true,
        requireAttestationForKeyAttestation = false,
        attestationGracePeriodMinutes = 30,
        lastConnectedAt = 1_700_000_200_000L,
        connectionCount = 17L,
        idevidCertificateDER = byteArrayOf(0x30, 0x01, 0x02, 0x7F, -128),
        idevidCertificateChain = listOf(byteArrayOf(1, 2, 3), byteArrayOf(4, 5)),
        idevidVerifiedAt = 1_700_000_300_000L,
        idevidTrustLevel = "android-ca",
        idevidSubjectDN = "CN=workstation,O=ATT",
        idevidNotAfter = 4_000_000_000_000L
    )

    // -------------------------------------------------------------------------
    // Defaults
    // -------------------------------------------------------------------------

    @Test
    fun `a newly paired device has no attestation or IDevID state`() {
        val device = minimal()

        assertNull(device.bleAddress)
        assertNull(device.lastAttestationTime)
        assertNull(device.securityLevel)
        assertFalse(device.bootStateVerified)
        assertEquals(0L, device.connectionCount)
        assertNull(device.idevidCertificateDER)
        assertNull(device.idevidCertificateChain)
    }

    @Test
    fun `per-device attestation defaults require attestation only for key attestation`() {
        val device = minimal()

        assertFalse(device.requireAttestationForKeyUse)
        assertTrue(device.requireAttestationForKeyAttestation)
        assertEquals(5, device.attestationGracePeriodMinutes)
    }

    // -------------------------------------------------------------------------
    // hasVerifiedIDevID
    // -------------------------------------------------------------------------

    @Test
    fun `hasVerifiedIDevID needs both a certificate and a trust level`() {
        assertFalse(minimal().hasVerifiedIDevID())
        assertFalse(minimal().copy(idevidCertificateDER = byteArrayOf(1)).hasVerifiedIDevID())
        assertFalse(minimal().copy(idevidTrustLevel = "android-ca").hasVerifiedIDevID())
        assertTrue(
            minimal().copy(
                idevidCertificateDER = byteArrayOf(1), idevidTrustLevel = "android-ca"
            ).hasVerifiedIDevID()
        )
    }

    @Test
    fun `an untrusted IDevID still counts as verified state`() {
        // "untrusted" is a recorded outcome, not the absence of one.
        val device = minimal().copy(
            idevidCertificateDER = byteArrayOf(1), idevidTrustLevel = "untrusted"
        )

        assertTrue(device.hasVerifiedIDevID())
    }

    // -------------------------------------------------------------------------
    // isIDevIDExpired
    // -------------------------------------------------------------------------

    @Test
    fun `a missing expiry is treated as expired`() {
        assertTrue("the conservative default must be 'expired'", minimal().isIDevIDExpired())
    }

    @Test
    fun `a past expiry is expired and a future one is not`() {
        val past = minimal().copy(idevidNotAfter = System.currentTimeMillis() - 60_000L)
        val future = minimal().copy(idevidNotAfter = System.currentTimeMillis() + 600_000L)

        assertTrue(past.isIDevIDExpired())
        assertFalse(future.isIDevIDExpired())
    }

    // -------------------------------------------------------------------------
    // JSON round trip
    // -------------------------------------------------------------------------

    @Test
    fun `a minimal record round-trips and omits every optional key`() {
        val json = minimal().toJson()

        assertFalse(json.has("bleAddress"))
        assertFalse(json.has("lastAttestationTime"))
        assertFalse(json.has("securityLevel"))
        assertFalse(json.has("idevidCertificateDER"))
        assertFalse(json.has("idevidCertificateChain"))
        assertFalse(json.has("idevidNotAfter"))
        assertEquals(minimal(), PairedDeviceData.fromJson(json))
    }

    @Test
    fun `a fully populated record round-trips including the DER byte arrays`() {
        val original = full()

        val restored = PairedDeviceData.fromJson(original.toJson())

        assertEquals(original, restored)
        assertTrue(original.idevidCertificateDER!!.contentEquals(restored.idevidCertificateDER!!))
        assertEquals(2, restored.idevidCertificateChain!!.size)
        assertTrue(byteArrayOf(4, 5).contentEquals(restored.idevidCertificateChain!![1]))
    }

    @Test
    fun `toJson writes the identity and counter fields verbatim`() {
        val json = full().toJson()

        assertEquals("0a1b2c", json.getString("publicKeyHex"))
        assertEquals("workstation", json.getString("deviceName"))
        assertEquals(1_700_000_000_000L, json.getLong("pairedAt"))
        assertEquals("AA:BB:CC:DD:EE:FF", json.getString("bleAddress"))
        assertEquals(17L, json.getLong("connectionCount"))
        assertEquals(30, json.getInt("attestationGracePeriodMinutes"))
        assertTrue(json.getBoolean("bootStateVerified"))
        assertFalse(json.getBoolean("requireAttestationForKeyAttestation"))
        assertEquals("android-ca", json.getString("idevidTrustLevel"))
    }

    @Test
    fun `fromJson applies the documented defaults for absent optional fields`() {
        val json = JSONObject()
            .put("publicKeyHex", "ff00")
            .put("deviceName", "laptop")
            .put("pairedAt", 42L)

        val device = PairedDeviceData.fromJson(json)

        assertEquals("ff00", device.publicKeyHex)
        assertEquals(42L, device.pairedAt)
        assertFalse(device.bootStateVerified)
        assertFalse(device.requireAttestationForKeyUse)
        assertTrue(device.requireAttestationForKeyAttestation)
        assertEquals(5, device.attestationGracePeriodMinutes)
        assertEquals(0L, device.connectionCount)
        assertNull(device.idevidCertificateDER)
        assertNull(device.idevidCertificateChain)
        assertNull(device.lastConnectedAt)
    }

    @Test
    fun `fromJson treats an empty certificate string as no certificate`() {
        val json = minimal().toJson().put("idevidCertificateDER", "")

        assertNull(PairedDeviceData.fromJson(json).idevidCertificateDER)
    }

    @Test
    fun `fromJson restores an empty certificate chain as an empty list`() {
        val json = minimal().toJson().put("idevidCertificateChain", org.json.JSONArray())

        val device = PairedDeviceData.fromJson(json)

        assertEquals(0, device.idevidCertificateChain!!.size)
    }

    // -------------------------------------------------------------------------
    // equals / hashCode (hand-written because of the ByteArray fields)
    // -------------------------------------------------------------------------

    @Test
    fun `equality compares certificate bytes by content not identity`() {
        val a = minimal().copy(idevidCertificateDER = byteArrayOf(9, 8, 7))
        val b = minimal().copy(idevidCertificateDER = byteArrayOf(9, 8, 7))

        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
        assertNotEquals(a, minimal().copy(idevidCertificateDER = byteArrayOf(9, 8, 6)))
    }

    @Test
    fun `equality compares the certificate chain element by element`() {
        val a = minimal().copy(idevidCertificateChain = listOf(byteArrayOf(1), byteArrayOf(2)))
        val b = minimal().copy(idevidCertificateChain = listOf(byteArrayOf(1), byteArrayOf(2)))

        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
        assertNotEquals(a, minimal().copy(idevidCertificateChain = listOf(byteArrayOf(1))))
        assertNotEquals(
            a,
            minimal().copy(idevidCertificateChain = listOf(byteArrayOf(1), byteArrayOf(3)))
        )
    }

    @Test
    fun `a present certificate never equals an absent one`() {
        val withCert = minimal().copy(idevidCertificateDER = byteArrayOf(1))
        val withChain = minimal().copy(idevidCertificateChain = listOf(byteArrayOf(1)))

        assertNotEquals(withCert, minimal())
        assertNotEquals(minimal(), withCert)
        assertNotEquals(withChain, minimal())
        assertNotEquals(minimal(), withChain)
    }

    @Test
    fun `equality is sensitive to every scalar field`() {
        val base = minimal()

        assertNotEquals(base, base.copy(publicKeyHex = "other"))
        assertNotEquals(base, base.copy(deviceName = "other"))
        assertNotEquals(base, base.copy(pairedAt = 1L))
        assertNotEquals(base, base.copy(bleAddress = "AA:BB"))
        assertNotEquals(base, base.copy(bootStateVerified = true))
        assertNotEquals(base, base.copy(connectionCount = 1L))
        assertNotEquals(base, base.copy(attestationGracePeriodMinutes = 6))
        assertNotEquals(base, base.copy(idevidSubjectDN = "CN=x"))
        assertNotEquals(base, base.copy(idevidNotAfter = 1L))
    }

    @Test
    fun `a device never equals an unrelated type`() {
        val unrelated: Any = "0a1b2c"
        val nothing: Any? = null

        assertNotEquals(minimal(), unrelated)
        assertFalse(minimal().equals(nothing))
    }
}
