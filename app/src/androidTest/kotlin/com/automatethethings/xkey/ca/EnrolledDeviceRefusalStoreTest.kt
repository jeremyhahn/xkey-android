/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
 *
 * This file is part of xkey-android.
 *
 * xkey-android is dual-licensed:
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
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The refusal side of [EnrolledDeviceRepository].
 *
 * A device the enrollment ceremony refused holds no certificate and is
 * therefore not in the enrolment list at all, so the reason cannot hang off an
 * [EnrolledDevice]; it is kept beside that list under the device id the
 * ceremony refused. This suite proves it survives the encrypt / JSON / decrypt
 * round trip with its case intact, that only the most recent attempt is kept —
 * an older reason describing a state the device is no longer in would be worse
 * than none — and that a device which later enrols or is removed stops
 * reporting one.
 *
 * The preferences file is shared with the app, so every id written here is
 * per-run and is removed again in teardown.
 */
@RunWith(AndroidJUnit4::class)
class EnrolledDeviceRefusalStoreTest {

    private val suffix = System.nanoTime().toString()
    private val deviceA = "refusal-device-a-$suffix"
    private val deviceB = "refusal-device-b-$suffix"

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
        // removeDevice also forgets the refusal, which is the behaviour one of
        // these tests asserts; clearRefusal is called as well so a failure of
        // that assertion cannot leave a row behind.
        listOf(deviceA, deviceB).forEach {
            repository.removeDevice(it)
            repository.clearRefusal(it)
        }
    }

    private fun record(
        deviceId: String = deviceA,
        refusal: EnrollmentRefusal = EnrollmentRefusal.ActivationMismatch(
            "credential activation returned a different secret"
        ),
        refusedAt: Long = 1_770_000_000_000L
    ) = EnrollmentRefusalRecord(
        deviceId = deviceId,
        deviceName = "Refusal Probe $suffix",
        refusal = refusal,
        refusedAt = refusedAt
    )

    // -------------------------------------------------------------------------
    // Round trip
    // -------------------------------------------------------------------------

    @Test
    fun aRefusalSurvivesTheEncryptedRoundTripWithItsCase() {
        val written = record()

        repository.recordRefusal(written)

        val read = repository.lastRefusal(deviceA)
        assertNotNull("the refusal must be readable back", read)
        assertEquals(written, read)
        assertEquals(EnrollmentRefusal.ActivationMismatch::class, read!!.refusal::class)
        assertEquals(
            "credential activation returned a different secret",
            read.refusal.detail
        )
    }

    @Test
    fun aDeviceThatWasNeverRefusedReportsNothing() {
        assertNull(repository.lastRefusal(deviceA))
    }

    // -------------------------------------------------------------------------
    // Only the most recent attempt
    // -------------------------------------------------------------------------

    @Test
    fun aSecondRefusalReplacesTheFirst() {
        repository.recordRefusal(
            record(refusal = EnrollmentRefusal.QuoteInvalid("quote carries no PCR values"))
        )
        repository.recordRefusal(
            record(
                refusal = EnrollmentRefusal.ActivationMismatch("returned a different secret"),
                refusedAt = 1_770_000_500_000L
            )
        )

        val read = repository.lastRefusal(deviceA)
        assertEquals(
            EnrollmentRefusal.ActivationMismatch("returned a different secret"),
            read?.refusal
        )
        assertEquals(1_770_000_500_000L, read?.refusedAt)
        assertEquals(
            "the device must appear once, not twice",
            1,
            repository.getAllRefusals().count { it.deviceId == deviceA }
        )
    }

    @Test
    fun eachDeviceKeepsItsOwnRefusal() {
        repository.recordRefusal(
            record(deviceId = deviceA, refusal = EnrollmentRefusal.QuoteInvalid("no PCR values"))
        )
        repository.recordRefusal(
            record(
                deviceId = deviceB,
                refusal = EnrollmentRefusal.UntrustedEndorsement("self-signed")
            )
        )

        assertEquals(
            EnrollmentRefusal.QuoteInvalid("no PCR values"),
            repository.lastRefusal(deviceA)?.refusal
        )
        assertEquals(
            EnrollmentRefusal.UntrustedEndorsement("self-signed"),
            repository.lastRefusal(deviceB)?.refusal
        )
    }

    // -------------------------------------------------------------------------
    // When a refusal stops being true
    // -------------------------------------------------------------------------

    @Test
    fun enrollingTheDeviceForgetsWhyItWasOnceRefused() {
        repository.recordRefusal(record())

        repository.enroll(
            EnrolledDevice(
                deviceId = deviceA,
                publicKeyHex = "aa$suffix",
                enrolledAt = System.currentTimeMillis(),
                trustLevel = "full-attestation"
            )
        )

        assertNull(
            "a certified device must not still show a refusal",
            repository.lastRefusal(deviceA)
        )
    }

    @Test
    fun removingTheDeviceForgetsItsRefusal() {
        repository.recordRefusal(record())

        repository.removeDevice(deviceA)

        assertNull(repository.lastRefusal(deviceA))
    }

    @Test
    fun clearingARefusalLeavesOtherDevicesAlone() {
        repository.recordRefusal(record(deviceId = deviceA))
        repository.recordRefusal(record(deviceId = deviceB))

        repository.clearRefusal(deviceA)

        assertNull(repository.lastRefusal(deviceA))
        assertNotNull(repository.lastRefusal(deviceB))
    }
}
