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
 * Instrumented tests for [EnrolledDeviceRepository].
 *
 * The enrolment list lives in `EncryptedSharedPreferences`, which needs a real
 * Android Keystore master key, and every certificate in it is serialised with
 * `android.util.Base64` — so none of this is reachable from a JVM unit test.
 * `EnrolledDeviceJsonTest` covers the payload in isolation; what is proved here
 * is that an enrolment survives the encrypt / JSON / decrypt round trip with
 * its attestation baseline and issued certificates intact, that re-enrolling
 * replaces rather than duplicates, and that each `update*` call touches exactly
 * one device and one field.
 *
 * The preferences file is shared with the app, so every device written here
 * carries a per-run unique id and is removed again in teardown; anything else
 * in the store is left alone.
 */
@RunWith(AndroidJUnit4::class)
class EnrolledDeviceRepositoryTest {

    private val suffix = System.nanoTime().toString()
    private val deviceA = "test-device-a-$suffix"
    private val deviceB = "test-device-b-$suffix"
    private val keyA = "aa$suffix"
    private val keyB = "bb$suffix"

    private lateinit var repository: EnrolledDeviceRepository

    @Before
    fun setUp() {
        repository = EnrolledDeviceRepository(ApplicationProvider.getApplicationContext<Context>())
        removeTestDevices()
    }

    @After
    fun tearDown() {
        removeTestDevices()
    }

    private fun removeTestDevices() {
        listOf(deviceA, deviceB).forEach(repository::removeDevice)
    }

    private fun device(
        deviceId: String = deviceA,
        publicKeyHex: String = keyA,
        trustLevel: String = "android-ca"
    ) = EnrolledDevice(
        deviceId = deviceId,
        publicKeyHex = publicKeyHex,
        enrolledAt = 1_700_000_000_000L,
        trustLevel = trustLevel
    )

    private fun fullyAttestedDevice() = device().copy(
        ekCertificateFingerprint = "ab".repeat(32),
        ekCertificateDER = byteArrayOf(0x30, 0x01, 0x02, 0x7F, -128),
        ekVerifiedAt = 1_700_000_100_000L,
        iakCertificateDER = byteArrayOf(0x30, 0x11),
        idevidCertificateDER = byteArrayOf(0x30, 0x21),
        idevidCertificateChain = listOf(byteArrayOf(0x30, 0x21), byteArrayOf(0x30, 0x22)),
        tlsServerCertificateDER = byteArrayOf(0x30, 0x31),
        tlsServerCertificateChain = listOf(byteArrayOf(0x30, 0x31)),
        tlsClientCertificateDER = byteArrayOf(0x30, 0x41),
        tlsClientCertificateChain = listOf(byteArrayOf(0x30, 0x41), byteArrayOf(0x30, 0x42)),
        sshUserCertificate = "ecdsa-sha2-nistp256-cert-v01@openssh.com AAAAuser",
        sshHostCertificate = "ecdsa-sha2-nistp256-cert-v01@openssh.com AAAAhost",
        initialQuote = byteArrayOf(-1, 0, 1),
        initialQuoteSignature = byteArrayOf(9, 8, 7),
        initialPCRs = byteArrayOf(0, 0, 0, 1),
        initialEventLog = byteArrayOf(5),
        trustLevel = "full-attestation",
        lastVerifiedAt = 1_700_000_200_000L
    )

    // -------------------------------------------------------------------------
    // Enrolment
    // -------------------------------------------------------------------------

    @Test
    fun enroll_makesTheDeviceFindable() {
        assertFalse(repository.isEnrolled(deviceA))

        repository.enroll(device())

        assertTrue(repository.isEnrolled(deviceA))
        val stored = repository.getDevice(deviceA)
        assertNotNull(stored)
        assertEquals(keyA, stored!!.publicKeyHex)
        assertEquals("android-ca", stored.trustLevel)
        assertEquals(1_700_000_000_000L, stored.enrolledAt)
    }

    @Test
    fun unknownDevice_isNotEnrolled() {
        assertFalse(repository.isEnrolled(deviceA))
        assertNull(repository.getDevice(deviceA))
        assertNull(repository.getDeviceByPublicKey(keyA))
    }

    @Test
    fun getDeviceByPublicKey_findsTheMatchingEnrolment() {
        repository.enroll(device(deviceId = deviceA, publicKeyHex = keyA))
        repository.enroll(device(deviceId = deviceB, publicKeyHex = keyB))

        assertEquals(deviceA, repository.getDeviceByPublicKey(keyA)?.deviceId)
        assertEquals(deviceB, repository.getDeviceByPublicKey(keyB)?.deviceId)
        assertNull(repository.getDeviceByPublicKey("no-such-key-$suffix"))
    }

    @Test
    fun enroll_replacesAnEntryWithTheSameDeviceId() {
        repository.enroll(device(trustLevel = "external-ca"))

        repository.enroll(device(publicKeyHex = keyB, trustLevel = "full-attestation"))

        assertEquals(1, repository.getAllDevices().count { it.deviceId == deviceA })
        val stored = repository.getDevice(deviceA)!!
        assertEquals(keyB, stored.publicKeyHex)
        assertEquals("full-attestation", stored.trustLevel)
    }

    @Test
    fun enroll_keepsOtherDevices() {
        val before = repository.getDeviceCount()

        repository.enroll(device(deviceId = deviceA, publicKeyHex = keyA))
        repository.enroll(device(deviceId = deviceB, publicKeyHex = keyB))

        assertEquals(before + 2, repository.getDeviceCount())
        assertTrue(repository.isEnrolled(deviceA))
        assertTrue(repository.isEnrolled(deviceB))
    }

    @Test
    fun everyFieldSurvivesTheEncryptedRoundTrip() {
        val original = fullyAttestedDevice()

        repository.enroll(original)

        val stored = repository.getDevice(deviceA)!!
        assertEquals(original.publicKeyHex, stored.publicKeyHex)
        assertEquals(original.ekCertificateFingerprint, stored.ekCertificateFingerprint)
        assertArrayEquals(original.ekCertificateDER, stored.ekCertificateDER)
        assertEquals(original.ekVerifiedAt, stored.ekVerifiedAt)
        assertArrayEquals(original.iakCertificateDER, stored.iakCertificateDER)
        assertArrayEquals(original.idevidCertificateDER, stored.idevidCertificateDER)
        assertArrayEquals(original.tlsServerCertificateDER, stored.tlsServerCertificateDER)
        assertArrayEquals(original.tlsClientCertificateDER, stored.tlsClientCertificateDER)
        assertEquals(original.sshUserCertificate, stored.sshUserCertificate)
        assertEquals(original.sshHostCertificate, stored.sshHostCertificate)
        assertArrayEquals(original.initialQuote, stored.initialQuote)
        assertArrayEquals(original.initialQuoteSignature, stored.initialQuoteSignature)
        assertArrayEquals(original.initialPCRs, stored.initialPCRs)
        assertArrayEquals(original.initialEventLog, stored.initialEventLog)
        assertEquals(original.trustLevel, stored.trustLevel)
        assertEquals(original.lastVerifiedAt, stored.lastVerifiedAt)

        assertTrue(stored.hasFullAttestation())
        assertTrue(stored.hasIDevIDCertificate())
        assertTrue(stored.hasSSHUserCertificate())
        assertTrue(stored.hasSSHHostCertificate())
    }

    @Test
    fun certificateChainsSurviveTheEncryptedRoundTrip() {
        repository.enroll(fullyAttestedDevice())

        val stored = repository.getDevice(deviceA)!!
        assertEquals(2, stored.idevidCertificateChain!!.size)
        assertArrayEquals(byteArrayOf(0x30, 0x22), stored.idevidCertificateChain!![1])
        assertEquals(1, stored.tlsServerCertificateChain!!.size)
        assertEquals(2, stored.tlsClientCertificateChain!!.size)
        assertArrayEquals(byteArrayOf(0x30, 0x42), stored.tlsClientCertificateChain!![1])
    }

    @Test
    fun aMinimalEnrolmentComesBackWithoutCertificates() {
        repository.enroll(device())

        val stored = repository.getDevice(deviceA)!!
        assertNull(stored.ekCertificateDER)
        assertNull(stored.idevidCertificateDER)
        assertNull(stored.idevidCertificateChain)
        assertNull(stored.sshUserCertificate)
        assertNull(stored.lastVerifiedAt)
        assertFalse(stored.hasFullAttestation())
        assertFalse(stored.hasIDevIDCertificate())
    }

    // -------------------------------------------------------------------------
    // Certificate updates
    // -------------------------------------------------------------------------

    @Test
    fun updateIDevIDCertificate_storesTheCertificateAndItsChain() {
        repository.enroll(device())
        val cert = byteArrayOf(0x30, 0x51, 0x52)
        val chain = listOf(cert, byteArrayOf(0x30, 0x53))

        repository.updateIDevIDCertificate(deviceA, cert, chain)

        val stored = repository.getDevice(deviceA)!!
        assertArrayEquals(cert, stored.idevidCertificateDER)
        assertEquals(2, stored.idevidCertificateChain!!.size)
        assertArrayEquals(chain[1], stored.idevidCertificateChain!![1])
        assertTrue(stored.hasIDevIDCertificate())
        // Nothing else moved.
        assertEquals(keyA, stored.publicKeyHex)
        assertNull(stored.tlsServerCertificateDER)
    }

    @Test
    fun updateIDevIDCertificate_acceptsAnAbsentChain() {
        repository.enroll(device())

        repository.updateIDevIDCertificate(deviceA, byteArrayOf(0x30, 0x51), null)

        val stored = repository.getDevice(deviceA)!!
        assertNotNull(stored.idevidCertificateDER)
        assertNull(stored.idevidCertificateChain)
    }

    @Test
    fun theTlsServerAndClientSlotsAreIndependent() {
        repository.enroll(device())

        repository.updateTLSServerCertificate(
            deviceA,
            byteArrayOf(0x30, 0x61),
            listOf(byteArrayOf(0x30, 0x61))
        )

        var stored = repository.getDevice(deviceA)!!
        assertTrue(stored.hasTLSServerCertificate())
        assertFalse(stored.hasTLSClientCertificate())

        repository.updateTLSClientCertificate(deviceA, byteArrayOf(0x30, 0x71), null)

        stored = repository.getDevice(deviceA)!!
        assertArrayEquals(byteArrayOf(0x30, 0x61), stored.tlsServerCertificateDER)
        assertArrayEquals(byteArrayOf(0x30, 0x71), stored.tlsClientCertificateDER)
        assertEquals(1, stored.tlsServerCertificateChain!!.size)
        assertNull(stored.tlsClientCertificateChain)
    }

    @Test
    fun theSshUserAndHostCertificatesAreStoredSeparately() {
        repository.enroll(device())

        repository.updateSSHUserCertificate(deviceA, "ssh-user-cert")
        repository.updateSSHHostCertificate(deviceA, "ssh-host-cert")

        val stored = repository.getDevice(deviceA)!!
        assertEquals("ssh-user-cert", stored.sshUserCertificate)
        assertEquals("ssh-host-cert", stored.sshHostCertificate)
    }

    @Test
    fun updateLastVerified_recordsTheCurrentTime() {
        repository.enroll(device())
        assertNull(repository.getDevice(deviceA)!!.lastVerifiedAt)
        val before = System.currentTimeMillis()

        repository.updateLastVerified(deviceA)

        val verifiedAt = repository.getDevice(deviceA)!!.lastVerifiedAt
        assertNotNull(verifiedAt)
        assertTrue("$verifiedAt < $before", verifiedAt!! >= before)
    }

    @Test
    fun updatesTouchOnlyTheTargetedDevice() {
        repository.enroll(device(deviceId = deviceA, publicKeyHex = keyA))
        repository.enroll(device(deviceId = deviceB, publicKeyHex = keyB))

        repository.updateIDevIDCertificate(deviceA, byteArrayOf(0x30, 0x51), null)
        repository.updateSSHUserCertificate(deviceA, "ssh-user-cert")
        repository.updateLastVerified(deviceA)

        val untouched = repository.getDevice(deviceB)!!
        assertNull(untouched.idevidCertificateDER)
        assertNull(untouched.sshUserCertificate)
        assertNull(untouched.lastVerifiedAt)
    }

    @Test
    fun updatingAnUnknownDeviceIsANoOp() {
        val before = repository.getDeviceCount()

        repository.updateIDevIDCertificate(deviceA, byteArrayOf(0x30, 0x51), null)
        repository.updateTLSServerCertificate(deviceA, byteArrayOf(0x30, 0x61), null)
        repository.updateTLSClientCertificate(deviceA, byteArrayOf(0x30, 0x71), null)
        repository.updateSSHUserCertificate(deviceA, "ssh-user-cert")
        repository.updateSSHHostCertificate(deviceA, "ssh-host-cert")
        repository.updateLastVerified(deviceA)

        assertEquals(before, repository.getDeviceCount())
        assertFalse(repository.isEnrolled(deviceA))
    }

    // -------------------------------------------------------------------------
    // Removal
    // -------------------------------------------------------------------------

    @Test
    fun removeDevice_removesOnlyTheTarget() {
        repository.enroll(device(deviceId = deviceA, publicKeyHex = keyA))
        repository.enroll(device(deviceId = deviceB, publicKeyHex = keyB))

        repository.removeDevice(deviceA)

        assertFalse(repository.isEnrolled(deviceA))
        assertTrue(repository.isEnrolled(deviceB))
    }

    @Test
    fun removingAnUnknownDeviceIsHarmless() {
        repository.enroll(device())
        val before = repository.getDeviceCount()

        repository.removeDevice("no-such-device-$suffix")

        assertEquals(before, repository.getDeviceCount())
        assertTrue(repository.isEnrolled(deviceA))
    }

    @Test
    fun clear_emptiesTheStore() {
        // clear() wipes every enrolment, so anything already on the device is
        // captured first and put back before this test returns.
        val existing = repository.getAllDevices()
        try {
            repository.enroll(device())

            repository.clear()

            assertEquals(0, repository.getDeviceCount())
            assertTrue(repository.getAllDevices().isEmpty())
            assertFalse(repository.isEnrolled(deviceA))
        } finally {
            existing.forEach(repository::enroll)
        }

        assertEquals(existing.size, repository.getDeviceCount())
    }

    @Test
    fun anEmptyStoreReportsNoDevices() {
        assertFalse(repository.isEnrolled(deviceA))
        assertEquals(repository.getAllDevices().size, repository.getDeviceCount())
    }
}
