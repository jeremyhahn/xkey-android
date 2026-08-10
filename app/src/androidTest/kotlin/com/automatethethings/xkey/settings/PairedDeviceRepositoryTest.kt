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
package com.automatethethings.xkey.settings

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumented tests for [PairedDeviceRepository].
 *
 * The repository stores the paired-device list in
 * `EncryptedSharedPreferences`, which needs a real Android Keystore master key,
 * and serialises certificates with `android.util.Base64` -- so none of this is
 * reachable from a JVM unit test. `PairedDeviceDataTest` covers the data class
 * in isolation; what is proved here is that a device survives the encrypt /
 * JSON / decrypt round trip with every field intact, and that the
 * replace-on-re-pair rule really does replace rather than duplicate.
 *
 * The preferences file is shared with the app and with the paired-device UI
 * suites, so every device this suite writes carries a per-run unique key and is
 * removed again in teardown; devices belonging to anything else are left alone.
 */
@RunWith(AndroidJUnit4::class)
class PairedDeviceRepositoryTest {

    private val suffix = System.nanoTime().toString()
    private val primaryKey = "aa${suffix}"
    private val secondaryKey = "bb${suffix}"
    private val tertiaryKey = "cc${suffix}"
    private val primaryName = "Test Laptop $suffix"
    private val secondaryName = "Test Desktop $suffix"

    private lateinit var repository: PairedDeviceRepository

    @Before
    fun setUp() {
        repository = PairedDeviceRepository(ApplicationProvider.getApplicationContext<Context>())
        removeTestDevices()
    }

    @After
    fun tearDown() {
        removeTestDevices()
    }

    private fun removeTestDevices() {
        listOf(primaryKey, secondaryKey, tertiaryKey).forEach(repository::removeDevice)
    }

    @Test
    fun addDevice_makesTheDeviceKnown() {
        assertFalse(repository.isDeviceKnown(primaryKey))

        repository.addDevice(primaryKey, primaryName)

        assertTrue(repository.isDeviceKnown(primaryKey))
        val device = repository.getDevice(primaryKey)
        assertNotNull(device)
        assertEquals(primaryName, device!!.deviceName)
        assertNull(device.bleAddress)
        assertTrue(device.pairedAt > 0L)
    }

    @Test
    fun addDevice_storesTheBleAddressWhenSupplied() {
        repository.addDevice(primaryKey, primaryName, bleAddress = "AA:BB:CC:DD:EE:FF")

        assertEquals("AA:BB:CC:DD:EE:FF", repository.getDevice(primaryKey)?.bleAddress)
    }

    @Test
    fun unknownDevice_isNotFound() {
        assertFalse(repository.isDeviceKnown(primaryKey))
        assertNull(repository.getDevice(primaryKey))
    }

    @Test
    fun addDevice_replacesAnEntryWithTheSamePublicKey() {
        repository.addDevice(primaryKey, primaryName)
        val before = repository.getAllDevices().count { it.publicKeyHex == primaryKey }

        repository.addDevice(primaryKey, "$primaryName renamed")

        assertEquals(1, before)
        assertEquals(1, repository.getAllDevices().count { it.publicKeyHex == primaryKey })
        assertEquals("$primaryName renamed", repository.getDevice(primaryKey)?.deviceName)
    }

    @Test
    fun addDevice_replacesAnEntryWithTheSameBleAddress() {
        repository.addDevice(primaryKey, primaryName, bleAddress = "AA:BB:CC:DD:EE:01")

        // A re-pairing desktop presents a fresh Noise static key but the same radio.
        repository.addDevice(secondaryKey, secondaryName, bleAddress = "AA:BB:CC:DD:EE:01")

        assertFalse(repository.isDeviceKnown(primaryKey))
        assertTrue(repository.isDeviceKnown(secondaryKey))
    }

    @Test
    fun addDevice_replacesAnEntryWithTheSameDeviceName() {
        repository.addDevice(primaryKey, primaryName)

        repository.addDevice(secondaryKey, primaryName)

        assertFalse(repository.isDeviceKnown(primaryKey))
        assertEquals(primaryName, repository.getDevice(secondaryKey)?.deviceName)
    }

    @Test
    fun distinctDevices_coexist() {
        repository.addDevice(primaryKey, primaryName)
        repository.addDevice(secondaryKey, secondaryName)

        assertTrue(repository.isDeviceKnown(primaryKey))
        assertTrue(repository.isDeviceKnown(secondaryKey))
    }

    @Test
    fun removeDevice_leavesTheOtherDevicesAlone() {
        repository.addDevice(primaryKey, primaryName)
        repository.addDevice(secondaryKey, secondaryName)
        val totalBefore = repository.getAllDevices().size

        repository.removeDevice(primaryKey)

        assertFalse(repository.isDeviceKnown(primaryKey))
        assertTrue(repository.isDeviceKnown(secondaryKey))
        assertEquals(totalBefore - 1, repository.getAllDevices().size)
    }

    @Test
    fun removeDevice_isSafeForAnUnknownKey() {
        val totalBefore = repository.getAllDevices().size

        repository.removeDevice(primaryKey)

        assertEquals(totalBefore, repository.getAllDevices().size)
    }

    @Test
    fun updateDeviceBleAddress_persists() {
        repository.addDevice(primaryKey, primaryName)

        repository.updateDeviceBleAddress(primaryKey, "11:22:33:44:55:66")

        assertEquals("11:22:33:44:55:66", repository.getDevice(primaryKey)?.bleAddress)
    }

    @Test
    fun updateDeviceBleAddress_ignoresAnUnknownKey() {
        repository.updateDeviceBleAddress(primaryKey, "11:22:33:44:55:66")

        assertNull(repository.getDevice(primaryKey))
    }

    @Test
    fun updateDeviceSettings_persistsThePerDevicePolicy() {
        repository.addDevice(primaryKey, primaryName)

        repository.updateDeviceSettings(
            publicKeyHex = primaryKey,
            requireAttestationForKeyUse = true,
            requireAttestationForKeyAttestation = false,
            attestationGracePeriodMinutes = 30
        )

        val device = repository.getDevice(primaryKey)!!
        assertTrue(device.requireAttestationForKeyUse)
        assertFalse(device.requireAttestationForKeyAttestation)
        assertEquals(30, device.attestationGracePeriodMinutes)
    }

    @Test
    fun updateDeviceSettings_ignoresAnUnknownKey() {
        repository.updateDeviceSettings(primaryKey, true, false, 30)

        assertNull(repository.getDevice(primaryKey))
    }

    @Test
    fun updateDeviceAttestation_recordsTheBootStateAndStampsTheTime() {
        repository.addDevice(primaryKey, primaryName)
        val before = System.currentTimeMillis()

        repository.updateDeviceAttestation(
            publicKeyHex = primaryKey,
            bootHashHex = "deadbeef",
            securityLevel = "strongbox",
            bootStateVerified = true,
            deviceFingerprint = "fingerprint-$suffix"
        )

        val device = repository.getDevice(primaryKey)!!
        assertEquals("deadbeef", device.bootHashHex)
        assertEquals("strongbox", device.securityLevel)
        assertTrue(device.bootStateVerified)
        assertEquals("fingerprint-$suffix", device.deviceFingerprint)
        assertNotNull(device.lastAttestationTime)
        assertTrue(device.lastAttestationTime!! >= before)
    }

    @Test
    fun updateDeviceAttestation_ignoresAnUnknownKey() {
        repository.updateDeviceAttestation(primaryKey, "deadbeef", "tee", true, "fp")

        assertNull(repository.getDevice(primaryKey))
    }

    @Test
    fun updateDeviceIDevID_roundTripsTheCertificateAndChain() {
        repository.addDevice(primaryKey, primaryName)
        val leaf = byteArrayOf(0x30, 0x82.toByte(), 0x01, 0x0A, 0x7F, -1, 0x00)
        val chain = listOf(byteArrayOf(0x30, 0x01, 0x02), byteArrayOf(-128, 0x00, 0x7F))
        val notAfter = System.currentTimeMillis() + 86_400_000L

        repository.updateDeviceIDevID(
            publicKeyHex = primaryKey,
            certificateDER = leaf,
            certificateChain = chain,
            trustLevel = "android-ca",
            subjectDN = "CN=Test Device $suffix",
            notAfter = notAfter
        )

        val device = repository.getDevice(primaryKey)!!
        assertArrayEquals(leaf, device.idevidCertificateDER)
        assertEquals(2, device.idevidCertificateChain!!.size)
        assertArrayEquals(chain[0], device.idevidCertificateChain!![0])
        assertArrayEquals(chain[1], device.idevidCertificateChain!![1])
        assertEquals("android-ca", device.idevidTrustLevel)
        assertEquals("CN=Test Device $suffix", device.idevidSubjectDN)
        assertEquals(notAfter, device.idevidNotAfter)
        assertNotNull(device.idevidVerifiedAt)
        assertTrue(device.hasVerifiedIDevID())
        assertFalse(device.isIDevIDExpired())
    }

    @Test
    fun updateDeviceIDevID_acceptsAnAbsentChain() {
        repository.addDevice(primaryKey, primaryName)

        repository.updateDeviceIDevID(
            publicKeyHex = primaryKey,
            certificateDER = byteArrayOf(0x30, 0x01),
            certificateChain = null,
            trustLevel = "untrusted",
            subjectDN = "CN=Unchained",
            notAfter = System.currentTimeMillis() - 1_000L
        )

        val device = repository.getDevice(primaryKey)!!
        assertNull(device.idevidCertificateChain)
        assertTrue(device.hasVerifiedIDevID())
        assertTrue(device.isIDevIDExpired())
    }

    @Test
    fun recordConnection_stampsTheTimeAndIncrementsTheCount() {
        repository.addDevice(primaryKey, primaryName)
        assertEquals(0L, repository.getDevice(primaryKey)!!.connectionCount)

        repository.recordConnection(primaryKey)
        repository.recordConnection(primaryKey)

        val device = repository.getDevice(primaryKey)!!
        assertEquals(2L, device.connectionCount)
        assertNotNull(device.lastConnectedAt)
    }

    @Test
    fun recordConnection_ignoresAnUnknownKey() {
        repository.recordConnection(primaryKey)

        assertNull(repository.getDevice(primaryKey))
    }

    @Test
    fun everyFieldSurvivesTheEncryptedJsonRoundTrip() {
        repository.addDevice(primaryKey, primaryName, bleAddress = "AA:BB:CC:DD:EE:FF")
        repository.updateDeviceSettings(primaryKey, true, false, 15)
        repository.updateDeviceAttestation(primaryKey, "cafebabe", "tee", true, "fp-$suffix")
        repository.updateDeviceIDevID(
            publicKeyHex = primaryKey,
            certificateDER = byteArrayOf(0x30, 0x7F, -1),
            certificateChain = listOf(byteArrayOf(0x01, -1)),
            trustLevel = "external-ca",
            subjectDN = "CN=Round Trip",
            notAfter = 4_102_444_800_000L
        )
        repository.recordConnection(primaryKey)

        // A second instance reads the encrypted file back from scratch.
        val reread = PairedDeviceRepository(ApplicationProvider.getApplicationContext<Context>())
            .getDevice(primaryKey)!!

        assertEquals(repository.getDevice(primaryKey), reread)
        assertEquals("AA:BB:CC:DD:EE:FF", reread.bleAddress)
        assertEquals(15, reread.attestationGracePeriodMinutes)
        assertEquals("cafebabe", reread.bootHashHex)
        assertEquals("external-ca", reread.idevidTrustLevel)
        assertEquals(1L, reread.connectionCount)
    }

    @Test
    fun clear_emptiesTheStore() {
        val preexisting = repository.getAllDevices()
        repository.addDevice(primaryKey, primaryName)

        repository.clear()

        assertTrue(repository.getAllDevices().isEmpty())

        // Put back anything that was not this suite's, so the paired-device UI
        // suites are not disturbed by a wiped store. In practice those suites
        // seed and remove their own devices, so this list is normally empty.
        preexisting.forEach {
            repository.addDevice(it.publicKeyHex, it.deviceName, it.bleAddress)
        }
    }
}
