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

package com.automatethethings.xkey.ble

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.MediumTest
import com.automatethethings.xkey.audit.AuditLogDao
import com.automatethethings.xkey.audit.AuditLogEntity
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.audit.AuditOperationType
import com.automatethethings.xkey.ca.EnrolledDeviceRepository
import com.automatethethings.xkey.ca.EnrollmentRefusal
import com.automatethethings.xkey.settings.TrustedComputingSettingsRepository
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.truststore.TrustStoreRepository
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * What a refused enrollment leaves behind.
 *
 * `GattServerTcgEnrollmentTest` establishes that a ceremony which cannot be
 * completed issues nothing. What it cannot reach is any verification step: the
 * first request needs a Noise session to encrypt with, so every refusal site
 * sits behind a transport failure. This suite drives the funnel those sites all
 * call — `refuseEnrollment` — through [GattServerOutboundProbe], and asserts on
 * the two records the first real-hardware run will have to be diagnosed from.
 *
 * The property that matters is that the case is recorded *beside* the message
 * rather than inside it. A device that answered the credential challenge with
 * the wrong secret does not hold the keys it presented; a device that never
 * answered is an interoperability problem. Both used to read as
 * `DEVICE_ATTESTED, success=false` with prose in the error column, and no query
 * could tell them apart.
 *
 * Audit rows carry no key id, so they cannot be removed through `AuditLogDao`;
 * they are written under a per-run device id and deleted by that id in
 * teardown, as `AndroidCATest` does for its certificate events.
 */
@RunWith(AndroidJUnit4::class)
@MediumTest
class GattServerEnrollmentRefusalTest {

    private lateinit var context: Context
    private lateinit var enrolledDevices: EnrolledDeviceRepository
    private lateinit var auditLogDao: AuditLogDao
    private lateinit var settings: TrustedComputingSettingsRepository

    /** A per-run identity, so no other suite's rows can be read as this one's. */
    private val deviceKeyHex = "refusal" + java.util.UUID.randomUUID().toString().replace("-", "")
    private val deviceName = "Enrollment Refusal Probe"

    private val probes = mutableListOf<GattServerProbe>()

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        AuditLogger.initialize(context)
        enrolledDevices = EnrolledDeviceRepository(context)
        auditLogDao = XKeyDatabase.getInstance(context).auditLogDao()
        settings = TrustedComputingSettingsRepository(context)
        enrolledDevices.clearRefusal(deviceKeyHex)
    }

    @After
    fun tearDown() {
        probes.forEach { runCatching { it.close() } }
        probes.clear()
        enrolledDevices.removeDevice(deviceKeyHex)
        enrolledDevices.clearRefusal(deviceKeyHex)
        XKeyDatabase.getInstance(context).openHelper.writableDatabase.delete(
            "audit_logs",
            "device_id = ?",
            arrayOf(deviceKeyHex)
        )
    }

    // -----------------------------------------------------------------
    // The audit record
    // -----------------------------------------------------------------

    @Test
    fun aRefusalIsAuditedAsAFailedAttestationCarryingItsCase() {
        val outbound = enrollmentServer()

        outbound.refuseEnrollment(
            deviceKeyHex, deviceName,
            EnrollmentRefusal.QuoteInvalid("quote echoed a nonce this CA did not send")
        )

        val row = awaitAuditRow()
        assertEquals(AuditOperationType.DEVICE_ATTESTED, row.operationType)
        assertEquals(deviceName, row.deviceName)
        assertFalse("a refusal is not a success", row.success)
        assertEquals(
            "the detail stays where every existing reader looks for it",
            "quote echoed a nonce this CA did not send",
            row.errorMessage
        )
        val details = JSONObject(row.details!!)
        assertEquals("quote-invalid", details.getString("refusalCase"))
        assertEquals("quote echoed a nonce this CA did not send", details.getString("detail"))
    }

    /**
     * The distinction the whole change exists for: a wrong answer and no answer
     * must be separable by the recorded case alone.
     */
    @Test
    fun aWrongActivationSecretAndAnUnanswerableChallengeAreDifferentCases() {
        val outbound = enrollmentServer()

        outbound.refuseEnrollment(
            deviceKeyHex, deviceName,
            EnrollmentRefusal.ActivationMismatch(
                "credential activation returned a different secret"
            )
        )
        val mismatch = awaitAuditRow()

        outbound.refuseEnrollment(
            deviceKeyHex, deviceName,
            EnrollmentRefusal.ActivationUnsupported(
                "EK certificate carries a EC key; credential activation needs an RSA " +
                    "endorsement key"
            )
        )
        val unsupported = awaitAuditRows(2).first { it.id != mismatch.id }

        assertEquals(
            "activation-mismatch",
            JSONObject(mismatch.details!!).getString("refusalCase")
        )
        assertEquals(
            "activation-unsupported",
            JSONObject(unsupported.details!!).getString("refusalCase")
        )
    }

    @Test
    fun everyCaseReachesTheAuditLogUnderItsOwnName() {
        val outbound = enrollmentServer()
        val cases = listOf(
            EnrollmentRefusal.MalformedPackage("TCG-CSR-IDEVID does not parse"),
            EnrollmentRefusal.UntrustedEndorsement("EK certificate is self-signed"),
            EnrollmentRefusal.ActivationMismatch("returned a different secret"),
            EnrollmentRefusal.ActivationUnsupported("could not build a credential challenge"),
            EnrollmentRefusal.QuoteInvalid("quote carries no PCR values")
        )

        cases.forEach { outbound.refuseEnrollment(deviceKeyHex, deviceName, it) }

        val recorded = awaitAuditRows(cases.size)
            .map { JSONObject(it.details!!).getString("refusalCase") }
            .toSet()
        assertEquals(cases.map { it.auditName }.toSet(), recorded)
    }

    // -----------------------------------------------------------------
    // The record the device's own screen reads
    // -----------------------------------------------------------------

    @Test
    fun aRefusalIsKeptBesideTheEnrollmentListForTheDeviceScreen() {
        val outbound = enrollmentServer()
        val before = System.currentTimeMillis()

        outbound.refuseEnrollment(
            deviceKeyHex, deviceName,
            EnrollmentRefusal.UntrustedEndorsement(
                "EK certificate does not chain to a trusted TPM vendor root"
            )
        )

        val record = enrolledDevices.lastRefusal(deviceKeyHex)
        assertNotNull("the device's screen has nothing to show without this", record)
        assertEquals(deviceName, record!!.deviceName)
        assertEquals(
            EnrollmentRefusal.UntrustedEndorsement(
                "EK certificate does not chain to a trusted TPM vendor root"
            ),
            record.refusal
        )
        assertTrue("the refusal must be stamped", record.refusedAt >= before)
    }

    @Test
    fun onlyTheMostRecentRefusalIsKept() {
        val outbound = enrollmentServer()

        outbound.refuseEnrollment(
            deviceKeyHex, deviceName,
            EnrollmentRefusal.MalformedPackage("TCG-CSR-IDEVID does not parse")
        )
        outbound.refuseEnrollment(
            deviceKeyHex, deviceName,
            EnrollmentRefusal.ActivationMismatch("returned a different secret")
        )

        assertEquals(
            EnrollmentRefusal.ActivationMismatch("returned a different secret"),
            enrolledDevices.lastRefusal(deviceKeyHex)?.refusal
        )
    }

    /**
     * A refusal never certifies anything. The enrolment list is the thing the
     * rest of the app trusts, and a refused device must stay out of it.
     */
    @Test
    fun aRefusalEnrolsNothing() {
        val outbound = enrollmentServer()

        outbound.refuseEnrollment(
            deviceKeyHex, deviceName,
            EnrollmentRefusal.ActivationMismatch("returned a different secret")
        )

        assertNull(enrolledDevices.getDevice(deviceKeyHex))
        assertFalse(enrolledDevices.isEnrolled(deviceKeyHex))
    }

    // -----------------------------------------------------------------
    // What the ceremony sees
    // -----------------------------------------------------------------

    @Test
    fun theRefusalEndsTheCeremonyAndNamesItsCase() {
        val outbound = enrollmentServer()

        val thrown = outbound.refuseEnrollment(
            deviceKeyHex, deviceName,
            EnrollmentRefusal.QuoteInvalid("quote omits PCRs [7]")
        )

        // The exception is what unwinds `performPostPairingEnrollment`, and its
        // message is what reaches logcat, so both halves belong in it.
        assertTrue(
            "expected the case in the message, got ${thrown.message}",
            thrown.message!!.contains("quote-invalid")
        )
        assertTrue(thrown.message!!.contains("quote omits PCRs [7]"))
    }

    /**
     * With no enrolment store wired there is nowhere to keep the refusal, but
     * the audit record — the security record — must still be written.
     */
    @Test
    fun aRefusalWithNoEnrolmentStoreStillAudits() {
        val outbound = enrollmentServer(withCA = false)

        outbound.refuseEnrollment(
            deviceKeyHex, deviceName,
            EnrollmentRefusal.MalformedPackage("the two copies of the EK certificate disagree")
        )

        val row = awaitAuditRow()
        assertEquals("malformed-package", JSONObject(row.details!!).getString("refusalCase"))
        assertNull(enrolledDevices.lastRefusal(deviceKeyHex))
    }

    // -----------------------------------------------------------------
    // Harness
    // -----------------------------------------------------------------

    /** Polls until this run's device has at least [expected] audit rows. */
    private fun awaitAuditRows(expected: Int): List<AuditLogEntity> = runBlocking {
        repeat(50) {
            val rows = auditLogDao.getByDeviceId(deviceKeyHex)
            if (rows.size >= expected) return@runBlocking rows
            Thread.sleep(100)
        }
        throw AssertionError(
            "expected $expected audit rows for $deviceKeyHex, saw " +
                auditLogDao.getByDeviceId(deviceKeyHex).size
        )
    }

    private fun awaitAuditRow(): AuditLogEntity = awaitAuditRows(1).first()

    /**
     * A server wired with the enrollment collaborators, reached through the
     * probes rather than a harness of its own — the same wiring
     * `GattServerTcgEnrollmentTest` uses, minus the CA, which no refusal
     * touches.
     */
    private fun enrollmentServer(withCA: Boolean = true): GattServerOutboundProbe {
        val probe = GattServerProbe(context)
        probes.add(probe)

        val server = GattServer(
            context = context,
            requestHandler = probe.requestHandler,
            messageRouter = probe.messageRouter,
            pairingCallback = null,
            pairedDeviceRepository = probe.pairedDeviceRepository,
            trustedComputingSettingsRepository = settings,
            androidCA = null,
            enrolledDeviceRepository = if (withCA) enrolledDevices else null,
            trustStoreRepository = TrustStoreRepository(context)
        )
        return GattServerOutboundProbe(server)
    }
}
