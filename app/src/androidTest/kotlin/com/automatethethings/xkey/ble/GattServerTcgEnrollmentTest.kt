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
import com.automatethethings.xkey.ca.AndroidCA
import com.automatethethings.xkey.ca.CASubject
import com.automatethethings.xkey.ca.EnrolledDeviceRepository
import com.automatethethings.xkey.protocol.MethodNames
import com.automatethethings.xkey.settings.CertificateAuthoritySource
import com.automatethethings.xkey.settings.TrustedComputingSettingsData
import com.automatethethings.xkey.settings.TrustedComputingSettingsRepository
import com.automatethethings.xkey.truststore.TrustStoreRepository
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Drives `GattServer.performPostPairingEnrollment` through the outbound probe.
 *
 * Two things are established here. The first is that the ceremony now speaks
 * `remote.*`: the namespace names the enrollee, the desktop is the enrollee when
 * this phone is the Certificate Authority, and the desktop's bridge routes
 * nothing else — so a ceremony built on `local.*` reaches no handler at all and
 * silently does nothing. The second is that nothing is issued and nothing is
 * recorded when the conversation cannot be completed, which is the property the
 * old implementation lacked: it verified nothing and signed regardless.
 *
 * The full ceremony cannot run here. Every outbound request leaves through
 * `sendResponse`, which returns at its first line while there is no open GATT
 * server, so a reply can never come back and the credential challenge can never
 * be answered. What is reachable is the gating, the refusal, and the guarantee
 * that a failed conversation leaves no certificate behind.
 *
 * The suite writes trusted-computing settings, so it saves and restores whatever
 * was there, and removes the enrolled device and any CA it created itself.
 */
@RunWith(AndroidJUnit4::class)
@MediumTest
class GattServerTcgEnrollmentTest {

    private lateinit var context: Context
    private lateinit var settings: TrustedComputingSettingsRepository
    private lateinit var enrolledDevices: EnrolledDeviceRepository
    private lateinit var ca: AndroidCA

    private lateinit var originalSettings: TrustedComputingSettingsData
    private var caWasAlreadyInitialized = false

    /** A per-run identity so a leftover record from another run cannot be read as this one's. */
    private val deviceKeyHex = "tcgenroll" + java.util.UUID.randomUUID().toString().replace("-", "")
    private val deviceName = "TCG Enrollment Probe"

    private val probes = mutableListOf<GattServerProbe>()

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        settings = TrustedComputingSettingsRepository(context)
        enrolledDevices = EnrolledDeviceRepository(context)
        ca = AndroidCA(context)
        caWasAlreadyInitialized = ca.isInitialized()
        runBlocking {
            originalSettings = settings.getSettings()
            if (!caWasAlreadyInitialized) {
                ca.initialize(CASubject(cn = "GattServerTcgEnrollmentTest Root", org = "xKey Test"))
            }
        }
    }

    @After
    fun tearDown() {
        probes.forEach { runCatching { it.close() } }
        probes.clear()
        enrolledDevices.removeDevice(deviceKeyHex)
        runBlocking {
            settings.updateSettings(originalSettings)
            if (!caWasAlreadyInitialized) {
                ca.reset()
            }
        }
    }

    // -----------------------------------------------------------------
    // The namespace
    // -----------------------------------------------------------------

    @Test
    fun theCeremonyUsesTheRemoteNamespaceTheBridgeRoutes() {
        // `local.*` asks the recipient to enrol. When this phone is the
        // authority the enrollee is the desktop, so every step is `remote.*`,
        // and these are the four names its bridge dispatches.
        assertEquals("remote.getTCGCSRIDevID", MethodNames.REMOTE_GET_TCG_CSR_IDEVID)
        assertEquals("remote.activateCredential", MethodNames.REMOTE_ACTIVATE_CREDENTIAL)
        assertEquals("remote.getAttestationQuote", MethodNames.REMOTE_GET_ATTESTATION_QUOTE)
        assertEquals("remote.storeEnrollmentCerts", MethodNames.REMOTE_STORE_ENROLLMENT_CERTS)

        // The mirror ceremony is still there for the direction in which this
        // phone enrols against the desktop's authority.
        assertTrue(MethodNames.LOCAL_GET_TCG_CSR_IDEVID.startsWith("local."))
        assertTrue(MethodNames.LOCAL_STORE_ENROLLMENT_CERTS.startsWith("local."))
    }

    // -----------------------------------------------------------------
    // Gating: no conversation at all unless this phone is the authority
    // -----------------------------------------------------------------

    @Test
    fun trustedComputingDisabledSendsNothing() = runBlocking {
        settings.updateSettings(
            originalSettings.copy(enabled = false, caSource = CertificateAuthoritySource.THIS_DEVICE)
        )
        val outbound = enrollmentServer()
        val before = outbound.nextEnrollmentRequestId

        outbound.performPostPairingEnrollment(deviceKeyHex, deviceName)

        assertEquals("no request may be sent", before, outbound.nextEnrollmentRequestId)
        assertNull(enrolledDevices.getDevice(deviceKeyHex))
    }

    @Test
    fun anExternalAuthoritySendsNothing() = runBlocking {
        settings.updateSettings(
            originalSettings.copy(
                enabled = true,
                caSource = CertificateAuthoritySource.XKMS,
                xkmsEndpoint = "https://xkms.invalid"
            )
        )
        val outbound = enrollmentServer()
        val before = outbound.nextEnrollmentRequestId

        outbound.performPostPairingEnrollment(deviceKeyHex, deviceName)

        assertEquals(
            "with xkms selected the desktop drives its own enrollment",
            before,
            outbound.nextEnrollmentRequestId
        )
        assertNull(enrolledDevices.getDevice(deviceKeyHex))
    }

    @Test
    fun aMissingCertificateAuthoritySendsNothing() = runBlocking {
        settings.updateSettings(
            originalSettings.copy(enabled = true, caSource = CertificateAuthoritySource.THIS_DEVICE)
        )
        val outbound = enrollmentServer(withCA = false)
        val before = outbound.nextEnrollmentRequestId

        outbound.performPostPairingEnrollment(deviceKeyHex, deviceName)

        assertEquals(before, outbound.nextEnrollmentRequestId)
        assertNull(enrolledDevices.getDevice(deviceKeyHex))
    }

    // -----------------------------------------------------------------
    // Refusal: a conversation that cannot complete issues nothing
    // -----------------------------------------------------------------

    @Test
    fun theCeremonyOpensWithExactlyOneRequestAndIssuesNothingWhenItFails() = runBlocking {
        settings.updateSettings(
            originalSettings.copy(enabled = true, caSource = CertificateAuthoritySource.THIS_DEVICE)
        )
        val outbound = enrollmentServer()
        val before = outbound.nextEnrollmentRequestId

        try {
            outbound.performPostPairingEnrollment(deviceKeyHex, deviceName)
            fail("enrollment cannot succeed with no session to carry it")
        } catch (e: Exception) {
            // The first step reaches sendEncryptedMessage, which has no Noise
            // session to encrypt with. What matters is that it is the *first*
            // step that fails, not a later one.
            assertTrue(
                "expected a transport failure, got ${e::class.java.name}: ${e.message}",
                e is java.io.IOException || e is com.automatethethings.xkey.protocol.ProtocolException
            )
        }

        assertEquals(
            "the ceremony must open with a single request",
            before + 1,
            outbound.nextEnrollmentRequestId
        )
        assertNull(
            "a device that answered nothing must not be enrolled",
            enrolledDevices.getDevice(deviceKeyHex)
        )
    }

    @Test
    fun aFailedEnrollmentLeavesNoTraceToRetryAround() = runBlocking {
        settings.updateSettings(
            originalSettings.copy(enabled = true, caSource = CertificateAuthoritySource.THIS_DEVICE)
        )
        val outbound = enrollmentServer()

        repeat(3) {
            runCatching { outbound.performPostPairingEnrollment(deviceKeyHex, deviceName) }
        }

        assertNull(enrolledDevices.getDevice(deviceKeyHex))
        assertFalse(enrolledDevices.isEnrolled(deviceKeyHex))
    }

    // -----------------------------------------------------------------
    // Harness
    // -----------------------------------------------------------------

    /**
     * A server wired with the enrollment collaborators, reached through the
     * probes rather than a harness of its own.
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
            androidCA = if (withCA) ca else null,
            enrolledDeviceRepository = if (withCA) enrolledDevices else null,
            trustStoreRepository = TrustStoreRepository(context)
        )
        return GattServerOutboundProbe(server)
    }
}
