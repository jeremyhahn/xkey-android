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
package com.automatethethings.xkey.ca

import android.util.Base64
import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Unit tests for the JSON encoding of [EnrolledDevice].
 *
 * `EnrolledDeviceRepository` persists the whole enrolment list as the string
 * produced here, so a field that fails to serialise is silently lost the next
 * time the app starts — attestation baselines, issued IDevID/TLS/SSH
 * certificates and their chains all live in this payload. The round trip is
 * therefore asserted field by field, for a fully populated device and for a
 * minimal one, and the optional-field handling is pinned so a record written by
 * an older build still loads.
 *
 * `android.util.Base64` is delegated to `java.util.Base64` (the production code
 * asks for `NO_WRAP`, which is plain unpadded-line base64); `org.json` is the
 * real implementation, which is on the unit-test classpath.
 *
 * The repository itself needs EncryptedSharedPreferences and is covered by the
 * instrumented `EnrolledDeviceRepositoryTest`.
 */
class EnrolledDeviceJsonTest {

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

    private val ekCert = byteArrayOf(0x30, 0x01, 0x02, 0x7F, -128)
    private val iakCert = byteArrayOf(0x30, 0x11, 0x12)
    private val idevidCert = byteArrayOf(0x30, 0x21, 0x22)
    private val tlsServerCert = byteArrayOf(0x30, 0x31)
    private val tlsClientCert = byteArrayOf(0x30, 0x41)
    private val quote = byteArrayOf(-1, 0, 1)
    private val quoteSignature = byteArrayOf(9, 8, 7)
    private val pcrs = byteArrayOf(0, 0, 0, 1)
    private val eventLog = byteArrayOf(5)

    private fun minimal() = EnrolledDevice(
        deviceId = "device-1",
        publicKeyHex = "0a1b2c",
        enrolledAt = 1_700_000_000_000L,
        trustLevel = "android-ca"
    )

    private fun full() = EnrolledDevice(
        deviceId = "device-1",
        publicKeyHex = "0a1b2c",
        ekCertificateFingerprint = "ab".repeat(32),
        ekCertificateDER = ekCert,
        ekVerifiedAt = 1_700_000_100_000L,
        iakCertificateDER = iakCert,
        idevidCertificateDER = idevidCert,
        idevidCertificateChain = listOf(idevidCert, byteArrayOf(0x30, 0x22)),
        tlsServerCertificateDER = tlsServerCert,
        tlsServerCertificateChain = listOf(tlsServerCert),
        tlsClientCertificateDER = tlsClientCert,
        tlsClientCertificateChain = listOf(tlsClientCert, byteArrayOf(0x30, 0x42), byteArrayOf(0x30, 0x43)),
        sshUserCertificate = "ecdsa-sha2-nistp256-cert-v01@openssh.com AAAAuser",
        sshHostCertificate = "ecdsa-sha2-nistp256-cert-v01@openssh.com AAAAhost",
        initialQuote = quote,
        initialQuoteSignature = quoteSignature,
        initialPCRs = pcrs,
        initialEventLog = eventLog,
        enrolledAt = 1_700_000_000_000L,
        trustLevel = "full-attestation",
        lastVerifiedAt = 1_700_000_200_000L
    )

    /** Serialise and re-parse through text, the way the repository stores it. */
    private fun roundTrip(device: EnrolledDevice): EnrolledDevice =
        EnrolledDevice.fromJson(JSONObject(device.toJson().toString()))

    // -------------------------------------------------------------------------
    // Fully populated devices
    // -------------------------------------------------------------------------

    @Test
    fun `toJson emits every populated field`() {
        val json = full().toJson()

        listOf(
            "deviceId", "publicKeyHex", "ekCertificateFingerprint", "ekCertificateDER",
            "ekVerifiedAt", "iakCertificateDER", "idevidCertificateDER", "idevidCertificateChain",
            "tlsServerCertificateDER", "tlsServerCertificateChain", "tlsClientCertificateDER",
            "tlsClientCertificateChain", "sshUserCertificate", "sshHostCertificate",
            "initialQuote", "initialQuoteSignature", "initialPCRs", "initialEventLog",
            "enrolledAt", "trustLevel", "lastVerifiedAt"
        ).forEach { key ->
            assertTrue("missing key: $key", json.has(key))
        }
    }

    @Test
    fun `a fully populated device survives the JSON round trip`() {
        val original = full()

        val restored = roundTrip(original)

        assertEquals(original.deviceId, restored.deviceId)
        assertEquals(original.publicKeyHex, restored.publicKeyHex)
        assertEquals(original.ekCertificateFingerprint, restored.ekCertificateFingerprint)
        assertArrayEquals(original.ekCertificateDER, restored.ekCertificateDER)
        assertEquals(original.ekVerifiedAt, restored.ekVerifiedAt)
        assertArrayEquals(original.iakCertificateDER, restored.iakCertificateDER)
        assertArrayEquals(original.idevidCertificateDER, restored.idevidCertificateDER)
        assertArrayEquals(original.tlsServerCertificateDER, restored.tlsServerCertificateDER)
        assertArrayEquals(original.tlsClientCertificateDER, restored.tlsClientCertificateDER)
        assertEquals(original.sshUserCertificate, restored.sshUserCertificate)
        assertEquals(original.sshHostCertificate, restored.sshHostCertificate)
        assertArrayEquals(original.initialQuote, restored.initialQuote)
        assertArrayEquals(original.initialQuoteSignature, restored.initialQuoteSignature)
        assertArrayEquals(original.initialPCRs, restored.initialPCRs)
        assertArrayEquals(original.initialEventLog, restored.initialEventLog)
        assertEquals(original.enrolledAt, restored.enrolledAt)
        assertEquals(original.trustLevel, restored.trustLevel)
        assertEquals(original.lastVerifiedAt, restored.lastVerifiedAt)
    }

    @Test
    fun `certificate chains keep their order and their contents`() {
        val restored = roundTrip(full())

        val idevidChain = restored.idevidCertificateChain!!
        assertEquals(2, idevidChain.size)
        assertArrayEquals(idevidCert, idevidChain[0])
        assertArrayEquals(byteArrayOf(0x30, 0x22), idevidChain[1])

        assertEquals(1, restored.tlsServerCertificateChain!!.size)

        val tlsClientChain = restored.tlsClientCertificateChain!!
        assertEquals(3, tlsClientChain.size)
        assertArrayEquals(byteArrayOf(0x30, 0x42), tlsClientChain[1])
        assertArrayEquals(byteArrayOf(0x30, 0x43), tlsClientChain[2])
    }

    @Test
    fun `an empty chain round trips as an empty list rather than null`() {
        val device = minimal().copy(idevidCertificateChain = emptyList())

        val restored = roundTrip(device)

        assertNotNull(restored.idevidCertificateChain)
        assertTrue(restored.idevidCertificateChain!!.isEmpty())
    }

    @Test
    fun `zero-length certificate bytes survive the round trip`() {
        val device = minimal().copy(idevidCertificateDER = ByteArray(0))

        val restored = roundTrip(device)

        assertNotNull(restored.idevidCertificateDER)
        assertEquals(0, restored.idevidCertificateDER!!.size)
        assertTrue(restored.hasIDevIDCertificate())
    }

    @Test
    fun `attestation predicates hold after the round trip`() {
        val restored = roundTrip(full())

        assertTrue(restored.hasFullAttestation())
        assertTrue(restored.hasIDevIDCertificate())
        assertTrue(restored.hasTLSServerCertificate())
        assertTrue(restored.hasTLSClientCertificate())
        assertTrue(restored.hasSSHUserCertificate())
        assertTrue(restored.hasSSHHostCertificate())
    }

    // -------------------------------------------------------------------------
    // Minimal devices and optional fields
    // -------------------------------------------------------------------------

    @Test
    fun `toJson omits every absent optional field`() {
        val json = minimal().toJson()

        listOf(
            "ekCertificateFingerprint", "ekCertificateDER", "ekVerifiedAt", "iakCertificateDER",
            "idevidCertificateDER", "idevidCertificateChain", "tlsServerCertificateDER",
            "tlsServerCertificateChain", "tlsClientCertificateDER", "tlsClientCertificateChain",
            "sshUserCertificate", "sshHostCertificate", "initialQuote", "initialQuoteSignature",
            "initialPCRs", "initialEventLog", "lastVerifiedAt"
        ).forEach { key ->
            assertFalse("unexpected key: $key", json.has(key))
        }
        assertEquals(4, json.length())
    }

    @Test
    fun `a minimal device round trips with every optional field null`() {
        val restored = roundTrip(minimal())

        assertEquals("device-1", restored.deviceId)
        assertEquals("0a1b2c", restored.publicKeyHex)
        assertEquals(1_700_000_000_000L, restored.enrolledAt)
        assertEquals("android-ca", restored.trustLevel)

        assertNull(restored.ekCertificateFingerprint)
        assertNull(restored.ekCertificateDER)
        assertNull(restored.ekVerifiedAt)
        assertNull(restored.iakCertificateDER)
        assertNull(restored.idevidCertificateDER)
        assertNull(restored.idevidCertificateChain)
        assertNull(restored.tlsServerCertificateDER)
        assertNull(restored.tlsServerCertificateChain)
        assertNull(restored.tlsClientCertificateDER)
        assertNull(restored.tlsClientCertificateChain)
        assertNull(restored.sshUserCertificate)
        assertNull(restored.sshHostCertificate)
        assertNull(restored.initialQuote)
        assertNull(restored.initialQuoteSignature)
        assertNull(restored.initialPCRs)
        assertNull(restored.initialEventLog)
        assertNull(restored.lastVerifiedAt)

        assertFalse(restored.hasFullAttestation())
        assertFalse(restored.hasIDevIDCertificate())
    }

    @Test
    fun `an explicit JSON null is read as an absent value`() {
        val json = minimal().toJson().apply {
            put("ekCertificateFingerprint", JSONObject.NULL)
            put("sshUserCertificate", JSONObject.NULL)
            put("initialQuote", JSONObject.NULL)
        }

        val restored = EnrolledDevice.fromJson(JSONObject(json.toString()))

        assertNull(restored.ekCertificateFingerprint)
        assertNull(restored.sshUserCertificate)
        assertNull(restored.initialQuote)
    }

    @Test
    fun `unknown keys written by a newer build are ignored`() {
        val json = minimal().toJson().put("somethingFromTheFuture", "value")

        val restored = EnrolledDevice.fromJson(JSONObject(json.toString()))

        assertEquals("device-1", restored.deviceId)
    }

    @Test
    fun `only the enrolment timestamps that were set are restored`() {
        val withEkOnly = minimal().copy(ekVerifiedAt = 42L)

        val restored = roundTrip(withEkOnly)

        assertEquals(42L, restored.ekVerifiedAt)
        assertNull(restored.lastVerifiedAt)
    }

    // -------------------------------------------------------------------------
    // Malformed payloads
    // -------------------------------------------------------------------------

    @Test
    fun `fromJson rejects a payload without a device id`() {
        val json = minimal().toJson().apply { remove("deviceId") }

        assertThrows(JSONException::class.java) { EnrolledDevice.fromJson(json) }
    }

    @Test
    fun `fromJson rejects a payload without a public key`() {
        val json = minimal().toJson().apply { remove("publicKeyHex") }

        assertThrows(JSONException::class.java) { EnrolledDevice.fromJson(json) }
    }

    @Test
    fun `fromJson rejects a payload without an enrolment time or trust level`() {
        assertThrows(JSONException::class.java) {
            EnrolledDevice.fromJson(minimal().toJson().apply { remove("enrolledAt") })
        }
        assertThrows(JSONException::class.java) {
            EnrolledDevice.fromJson(minimal().toJson().apply { remove("trustLevel") })
        }
    }

    @Test
    fun `a chain stored as an empty JSON array decodes to no certificates`() {
        val json = minimal().toJson().put("tlsServerCertificateChain", JSONArray())

        val restored = EnrolledDevice.fromJson(JSONObject(json.toString()))

        assertNotNull(restored.tlsServerCertificateChain)
        assertTrue(restored.tlsServerCertificateChain!!.isEmpty())
    }

    // -------------------------------------------------------------------------
    // Value semantics used by the repository
    // -------------------------------------------------------------------------

    @Test
    fun `copy replaces a certificate without disturbing the identity`() {
        val original = minimal()

        val updated = original.copy(
            idevidCertificateDER = idevidCert,
            idevidCertificateChain = listOf(idevidCert)
        )

        assertEquals(original.deviceId, updated.deviceId)
        assertEquals(original.publicKeyHex, updated.publicKeyHex)
        assertEquals(original.enrolledAt, updated.enrolledAt)
        assertArrayEquals(idevidCert, updated.idevidCertificateDER)
        assertNull(original.idevidCertificateDER)
        // Identity-based equality: the same device with a new certificate.
        assertEquals(original, updated)
    }

    @Test
    fun `toString exposes the identity and trust level`() {
        val text = minimal().toString()

        assertTrue(text, text.contains("deviceId=device-1"))
        assertTrue(text, text.contains("publicKeyHex=0a1b2c"))
        assertTrue(text, text.contains("trustLevel=android-ca"))
    }
}
