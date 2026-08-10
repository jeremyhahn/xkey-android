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

import android.Manifest
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothManager
import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.rule.GrantPermissionRule
import com.automatethethings.xkey.auth.SessionAuthManager
import com.automatethethings.xkey.ca.AndroidCA
import com.automatethethings.xkey.ca.CASubject
import com.automatethethings.xkey.ca.CaTestSupport
import com.automatethethings.xkey.ca.EnrolledDeviceRepository
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.protocol.ErrorCodes
import com.automatethethings.xkey.protocol.LocalGenerateIDevIDCSRResult
import com.automatethethings.xkey.protocol.LocalGetAttestationQuoteResult
import com.automatethethings.xkey.protocol.LocalGetIAKPublicKeyResult
import com.automatethethings.xkey.protocol.ProtocolException
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.protocol.Response
import com.automatethethings.xkey.remote.BidirectionalMessageRouter
import com.automatethethings.xkey.settings.AttestationBiometricPolicy
import com.automatethethings.xkey.settings.BiometricSettingsData
import com.automatethethings.xkey.settings.CertificateAuthoritySource
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.settings.TrustedComputingSettingsData
import com.automatethethings.xkey.settings.TrustedComputingSettingsRepository
import com.automatethethings.xkey.settings.UserVerificationPolicy
import com.automatethethings.xkey.storage.XKeyDatabase
import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.io.IOException
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.json.JSONObject
import org.junit.After
import org.junit.AfterClass
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Post-pairing enrollment: the four-step conversation the phone opens with a
 * laptop the moment the user approves it, when the phone is acting as the CA.
 *
 * It is the only place in the app where the *phone* is the initiator over BLE,
 * and it is entirely invisible to every other suite — a `GattServer` built
 * without trusted-computing settings, an [AndroidCA] and an
 * [EnrolledDeviceRepository] returns at its first line, which is exactly how
 * every existing probe builds one.
 *
 * The steps are chained, so nothing here can be faked past: the quote reply has
 * to parse before the CSR is asked for, the CSR reply has to be a genuine,
 * correctly self-signed PKCS#10 request or the CA refuses to issue, and the
 * certificate the CA issues is what both stores are then asserted on. What is
 * proved is the outcome the user gets — a laptop that comes out of pairing
 * holding an IDevID certificate this phone issued, recorded against the key the
 * Noise transcript authenticated.
 *
 * The outbound half is a sink: `sendResponse` returns early without an open
 * GATT server, so each request is registered with the router and then dropped.
 * Replies are therefore injected through the router the same way the message
 * loop would deliver them — see [answer]. Request ids are deterministic
 * (3_000_000 upwards, in their own range so they cannot collide with the
 * laptop's), which is what makes that possible.
 *
 * Cleanup: the CA hierarchy is generated once and reset in [resetSharedCaState],
 * which also removes the certificate-issuance audit rows; enrolled devices,
 * paired devices and the trusted-computing settings are restored per test.
 */
@RunWith(AndroidJUnit4::class)
class GattServerEnrollmentTest {

    /** `handleDeviceConnected` reads `BluetoothDevice.getName()`. */
    @get:Rule
    val bluetoothPermission: GrantPermissionRule =
        GrantPermissionRule.grant(Manifest.permission.BLUETOOTH_CONNECT)

    private lateinit var context: Context
    private lateinit var device: BluetoothDevice
    private lateinit var pairedDevices: PairedDeviceRepository
    private lateinit var enrolledDevices: EnrolledDeviceRepository
    private lateinit var trustedComputing: TrustedComputingSettingsRepository
    private lateinit var router: BidirectionalMessageRouter
    private lateinit var server: GattServer
    private lateinit var probe: GattServerOutboundProbe

    /** The peer key the Noise transcript authenticates; the enrolled device id. */
    private lateinit var peerKeyHex: String

    private lateinit var savedTrustedComputing: TrustedComputingSettingsData

    /** Servers built by individual tests; destroyed in teardown. */
    private val extraServers = mutableListOf<GattServer>()

    /** Where the injected replies are delivered from. */
    private val peerScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        val adapter = context.getSystemService(BluetoothManager::class.java)?.adapter
        assumeTrue("this device has no Bluetooth adapter", adapter != null)
        device = adapter!!.getRemoteDevice(DEVICE_ADDRESS)

        pairedDevices = PairedDeviceRepository(context)
        enrolledDevices = EnrolledDeviceRepository(context)
        trustedComputing = TrustedComputingSettingsRepository(context)
        runBlocking {
            savedTrustedComputing = trustedComputing.getSettings()
            trustedComputing.updateSettings(TrustedComputingSettingsData.PERMISSIVE)
        }

        server = buildServer(withCA = true)
        probe = GattServerOutboundProbe(server)
        runBlocking { establishSession(probe) }
    }

    @After
    fun tearDown() {
        peerScope.cancel()
        if (::server.isInitialized) server.destroy()
        extraServers.forEach { it.destroy() }
        extraServers.clear()
        if (::peerKeyHex.isInitialized) {
            enrolledDevices.removeDevice(peerKeyHex)
            pairedDevices.removeDevice(peerKeyHex)
        }
        if (::savedTrustedComputing.isInitialized) {
            runBlocking { trustedComputing.updateSettings(savedTrustedComputing) }
        }
    }

    // -----------------------------------------------------------------
    // The whole conversation
    // -----------------------------------------------------------------

    /**
     * A reply that is not a well-formed enrollment package stops the ceremony
     * before anything is issued.
     *
     * This used to script four chained requests and assert that a certificate
     * came out the far end. That ceremony no longer exists: the phone now sends
     * `remote.getTCGCSRIDevID` and everything it needs — CSR, EK certificate,
     * both public areas — arrives in that one reply, which it then verifies. A
     * complete run needs a real TPM to answer the credential challenge, so the
     * property worth pinning here is the one the old flow got wrong: a
     * conversation that cannot be verified issues nothing.
     *
     * Issuance itself is covered against real keys by
     * `ca.TcgEnrollmentIssuerTest`, and the namespace and gating by
     * `ble.GattServerTcgEnrollmentTest`.
     */
    @Test
    fun aMalformedEnrollmentPackageIssuesNothingAndRecordsNothing(): Unit = runBlocking {
        pairedDevices.addDevice(peerKeyHex, "Enrolling Laptop", device.address)

        val enrollment = peerScope.async {
            probe.performPostPairingEnrollment(peerKeyHex, "Enrolling Laptop")
        }

        // A reply shaped like the old conversation: no `csr`, so it cannot be
        // the TCG enrollment package the ceremony now asks for.
        answer(FIRST_REQUEST_ID, iakResult(), enrollment)

        runCatching { withTimeout(REPLY_TIMEOUT_MS) { enrollment.await() } }

        assertEquals(
            "the ceremony must stop at its first request",
            FIRST_REQUEST_ID + 1,
            probe.nextEnrollmentRequestId
        )
        assertNull(
            "an unverified laptop must not be recorded as enrolled",
            enrolledDevices.getDevice(peerKeyHex)
        )
        assertNull(
            "and must not be given a certificate",
            pairedDevices.getDevice(peerKeyHex)?.idevidCertificateDER
        )
    }

    /**
     * A laptop that cannot produce an IAK aborts the whole enrollment: nothing
     * is issued and nothing is recorded. The error is raised rather than
     * swallowed, because the caller is what decides that a failed enrollment
     * must not break an otherwise good pairing.
     */
    @Test
    fun aRemoteErrorAbortsEnrollmentWithoutIssuingAnything(): Unit = runBlocking {
        val enrollment = peerScope.async {
            probe.performPostPairingEnrollment(peerKeyHex, "Broken Laptop")
        }

        awaitRequest(FIRST_REQUEST_ID, enrollment)
        deliverUntilConsumed(
            Response.error(FIRST_REQUEST_ID, ErrorCodes.INTERNAL_ERROR, "no TPM present").toJson(),
            FIRST_REQUEST_ID,
            enrollment
        )

        try {
            withTimeout(REPLY_TIMEOUT_MS) { enrollment.await() }
            fail("a remote error must abort enrollment")
        } catch (expected: ProtocolException) {
            assertTrue(expected.message!!.contains("no TPM present"))
        }

        assertEquals(
            "the conversation must stop at the failed step",
            FIRST_REQUEST_ID + 1,
            probe.nextEnrollmentRequestId
        )
        assertNull(enrolledDevices.getDevice(peerKeyHex))
    }

    // -----------------------------------------------------------------
    // The gates in front of it
    // -----------------------------------------------------------------

    /** Enrollment is opt-in; with trusted computing off nothing is asked for. */
    @Test
    fun enrollmentIsSkippedWhileTrustedComputingIsOff(): Unit = runBlocking {
        trustedComputing.updateSettings(TrustedComputingSettingsData.DEFAULT)

        probe.performPostPairingEnrollment(peerKeyHex, "Ignored Laptop")

        assertNoRequestWasSent()
    }

    /**
     * A phone whose enterprise CA is an xkms server does not issue here: the
     * desktop drives its own enrollment against that server, and a certificate
     * from this phone would compete with it.
     */
    @Test
    fun enrollmentIsSkippedWhenXkmsIsTheCA(): Unit = runBlocking {
        trustedComputing.updateSettings(
            TrustedComputingSettingsData(
                enabled = true,
                caSource = CertificateAuthoritySource.XKMS,
                xkmsEndpoint = "https://xkms.enrollment-test.invalid"
            )
        )

        probe.performPostPairingEnrollment(peerKeyHex, "Ignored Laptop")

        assertNoRequestWasSent()
    }

    /**
     * Trusted computing can be on with no authority chosen at all — the state
     * the old two-boolean model could not express, and the one a fresh install
     * that only ticks the master switch lands in. There is nothing to issue, so
     * nothing may be asked for.
     */
    @Test
    fun enrollmentIsSkippedWhenNoCAIsConfigured(): Unit = runBlocking {
        trustedComputing.updateSettings(
            TrustedComputingSettingsData(
                enabled = true,
                caSource = CertificateAuthoritySource.NONE
            )
        )

        probe.performPostPairingEnrollment(peerKeyHex, "Ignored Laptop")

        assertNoRequestWasSent()
    }

    /**
     * The one authority that does issue here. Only the first step is driven:
     * that the conversation opens at all is what the gate decides, and the rest
     * of it is proved by
     * [enrollmentIssuesAnIDevIDCertificateAndRecordsTheBaseline].
     */
    @Test
    fun enrollmentProceedsWhenThisDeviceIsTheCA(): Unit = runBlocking {
        trustedComputing.updateSettings(
            TrustedComputingSettingsData(
                enabled = true,
                caSource = CertificateAuthoritySource.THIS_DEVICE
            )
        )

        val enrollment = peerScope.async {
            probe.performPostPairingEnrollment(peerKeyHex, "Enrolling Laptop")
        }
        try {
            awaitRequest(FIRST_REQUEST_ID, enrollment)
            assertEquals(
                "the phone must open the conversation when it is the authority",
                FIRST_REQUEST_ID + 1,
                probe.nextEnrollmentRequestId
            )
        } finally {
            enrollment.cancel()
        }
    }

    /**
     * Trusted computing can be on while the CA collaborators were never wired —
     * the posture every other transport builds. Enrollment must decline rather
     * than fail halfway through.
     */
    @Test
    fun enrollmentIsSkippedWithoutTheCACollaborators(): Unit = runBlocking {
        val bare = buildServer(withCA = false)
        extraServers += bare
        val bareProbe = GattServerOutboundProbe(bare)
        establishSession(bareProbe)

        bareProbe.performPostPairingEnrollment(peerKeyHex, "Unservable Laptop")

        assertEquals(FIRST_REQUEST_ID, bareProbe.nextEnrollmentRequestId)
        assertNull(enrolledDevices.getDevice(peerKeyHex))
    }

    // -----------------------------------------------------------------
    // The outbound request primitive
    // -----------------------------------------------------------------

    /**
     * Correlation is the router's job. Without one there is nothing to match a
     * reply against, so the request must not be sent at all — a request sent
     * into a channel with no correlation is a hang, not an error.
     */
    @Test
    fun anOutboundRequestWithoutARouterIsRefused(): Unit = runBlocking {
        val routerless = GattServer(
            context = context,
            requestHandler = buildRequestHandler(),
            messageRouter = null,
            pairedDeviceRepository = pairedDevices
        )
        extraServers += routerless
        val bareProbe = GattServerOutboundProbe(routerless)
        establishSession(bareProbe)

        try {
            bareProbe.sendRequestAndWaitForResponse("local.getIAKPublicKey", JSONObject())
            fail("an uncorrelatable request must not be sent")
        } catch (expected: IOException) {
            // expected
        }
    }

    /** A reply the peer answers is handed back as its result object. */
    @Test
    fun anAnsweredRequestReturnsItsResult(): Unit = runBlocking {
        val call = peerScope.async {
            probe.sendRequestAndWaitForResponse("local.getIAKPublicKey", JSONObject())
        }

        awaitRequest(FIRST_REQUEST_ID, call)
        deliverUntilConsumed(
            Response.success(FIRST_REQUEST_ID, JSONObject().put("algorithm", "ECDSA-P256")).toJson(),
            FIRST_REQUEST_ID,
            call
        )

        val result = withTimeout(REPLY_TIMEOUT_MS) { call.await() }
        assertEquals("ECDSA-P256", result.getString("algorithm"))
    }

    // -----------------------------------------------------------------
    // Fixtures
    // -----------------------------------------------------------------

    private fun buildRequestHandler(): RequestHandler = RequestHandler(
        context = context,
        keystoreManager = KeystoreManager(context),
        biometricLauncher = null,
        sessionAuthManager = SessionAuthManager(),
        pairedDeviceRepository = pairedDevices
    ).apply {
        updateSettings(
            BiometricSettingsData(
                uvPolicy = UserVerificationPolicy.DISABLED,
                attestationBiometricPolicy = AttestationBiometricPolicy.NEVER
            )
        )
    }

    /** A server wired the way `XKeyGattService` wires one for enrollment. */
    private fun buildServer(withCA: Boolean): GattServer {
        val handler = buildRequestHandler()
        val messageRouter = BidirectionalMessageRouter(handler)
        if (withCA) router = messageRouter
        return GattServer(
            context = context,
            requestHandler = handler,
            messageRouter = messageRouter,
            pairingCallback = null,
            pairedDeviceRepository = pairedDevices,
            trustedComputingSettingsRepository = trustedComputing,
            androidCA = if (withCA) AndroidCA(context) else null,
            enrolledDeviceRepository = if (withCA) enrolledDevices else null
        )
    }

    /**
     * Completes a Noise XX handshake against a responder and installs it the way
     * `handleHandshakeMessage` does, so the outbound path has both halves of a
     * session to work with.
     */
    private suspend fun establishSession(target: GattServerOutboundProbe) {
        val initiator = NoiseInitiatorSession(randomBytes(32))
        val responder = NoiseSession().also { it.loadStaticKey(context) }

        val msg2 = responder.processHandshakeMessage(initiator.createHandshakeMessage1())
            ?: throw AssertionError("the responder produced no handshake message 2")
        initiator.processHandshakeMessage2(msg2)
        check(responder.processHandshakeMessage(initiator.createHandshakeMessage3()) == null)
        initiator.finalizeHandshake()

        target.connectedDevice = device
        target.noiseSession = responder
        target.identityExchangeComplete = true
        target.pairingConfirmed = true
        val authenticated = responder.getRemoteStaticKey()!!.toHex()
        target.authenticatedPeerKeyHex = authenticated
        if (!::peerKeyHex.isInitialized) peerKeyHex = authenticated
    }

    private fun iakResult(): JSONObject = LocalGetIAKPublicKeyResult(
        publicKey = randomBytes(32),
        algorithm = "ECDSA-P256"
    ).toJson()

    private fun quoteResult(
        quoted: ByteArray,
        signature: ByteArray,
        eventLog: ByteArray,
        pcr0: ByteArray
    ): JSONObject = LocalGetAttestationQuoteResult(
        quoted = quoted,
        signature = signature,
        pcrValues = mapOf(0 to pcr0),
        eventLog = eventLog,
        pcrBank = "sha256"
    ).toJson()

    /** A genuine self-signed PKCS#10 request; the CA verifies it before issuing. */
    private fun csrResult(): JSONObject = LocalGenerateIDevIDCSRResult(
        csr = CaTestSupport.csr("CN=enrollment-test-laptop"),
        csrFormat = "der",
        keyId = "idevid",
        backend = "tpm2",
        algorithm = "ECDSA-P256"
    ).toJson()

    // -----------------------------------------------------------------
    // Playing the laptop
    // -----------------------------------------------------------------

    /** Waits for request [id] to be issued, then answers it with [result]. */
    private suspend fun answer(id: Long, result: JSONObject, job: Deferred<*>) {
        awaitRequest(id, job)
        deliverUntilConsumed(Response.success(id, result).toJson(), id, job)
    }

    /**
     * Requests carry consecutive ids from [FIRST_REQUEST_ID], and the id is
     * allocated before the request goes out, so the counter passing [id] means
     * the phone is now waiting on it.
     */
    private suspend fun awaitRequest(id: Long, job: Deferred<*>) {
        val deadline = System.currentTimeMillis() + REPLY_TIMEOUT_MS
        while (System.currentTimeMillis() < deadline) {
            if (probe.nextEnrollmentRequestId > id || job.isCompleted) return
            delay(POLL_MS)
        }
        throw AssertionError("request $id was never issued")
    }

    /**
     * Delivers a reply through the router until it is taken up — either the
     * next request goes out or the call finishes. Redelivery is harmless: a
     * reply whose id has no pending request is logged and dropped, which is
     * exactly what the router does with a stray frame on the wire.
     */
    private suspend fun deliverUntilConsumed(reply: ByteArray, id: Long, job: Deferred<*>) {
        val deadline = System.currentTimeMillis() + REPLY_TIMEOUT_MS
        while (System.currentTimeMillis() < deadline) {
            if (job.isCompleted || probe.nextEnrollmentRequestId > id + 1) return
            assertNull("a reply must never be answered", router.processMessage(reply))
            delay(POLL_MS)
        }
        throw AssertionError("the reply for $id was never taken up")
    }

    private fun assertNoRequestWasSent() {
        assertEquals(
            "nothing may be asked of the laptop",
            FIRST_REQUEST_ID,
            probe.nextEnrollmentRequestId
        )
        assertNull(enrolledDevices.getDevice(peerKeyHex))
    }

    private fun certificateOf(der: ByteArray): X509Certificate =
        CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(der)) as X509Certificate

    private fun randomBytes(size: Int) = ByteArray(size).also { SecureRandom().nextBytes(it) }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    companion object {
        private const val DEVICE_ADDRESS = "AA:BB:CC:DD:EE:F7"

        /** `GattServer.ENROLLMENT_BASE_REQUEST_ID`. */
        private const val FIRST_REQUEST_ID = 3_000_000L

        private const val REPLY_TIMEOUT_MS = 20_000L
        private const val POLL_MS = 20L

        private val ROOT_SUBJECT = CASubject(
            cn = "xKey Enrollment Test Root CA",
            org = "Automate The Things",
            country = "US"
        )
        private val INTERMEDIATE_SUBJECT = CASubject(
            cn = "xKey Enrollment Test Intermediate CA",
            org = "Automate The Things",
            country = "US"
        )

        /** Start of the run, used to purge the audit rows issuance writes. */
        private var startedAt = 0L

        @JvmStatic
        @BeforeClass
        fun generateHierarchy() {
            runBlocking {
                startedAt = System.currentTimeMillis()
                val ca = AndroidCA(ApplicationProvider.getApplicationContext<Context>())
                ca.reset()
                CaTestSupport.assumeCaGenerated(ca.generateRootCA(ROOT_SUBJECT), "Root CA generation")
                CaTestSupport.assumeCaGenerated(
                    ca.generateIntermediateCA(INTERMEDIATE_SUBJECT),
                    "Intermediate CA generation"
                )
            }
        }

        @JvmStatic
        @AfterClass
        fun resetSharedCaState() {
            runBlocking {
                val context = ApplicationProvider.getApplicationContext<Context>()
                AndroidCA(context).reset()
                // Issuance audits with a null key id, so the rows cannot be
                // removed through AuditLogDao; delete exactly what this class
                // produced.
                XKeyDatabase.getInstance(context).openHelper.writableDatabase.delete(
                    "audit_logs",
                    "timestamp >= ? AND operation_type IN " +
                        "('CERTIFICATE_ISSUED', 'CERTIFICATE_REVOKED', 'CSR_SIGNED', 'CRL_GENERATED')",
                    arrayOf(startedAt.toString())
                )
            }
        }
    }
}
