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

package com.automatethethings.xkey.protocol

import android.app.KeyguardManager
import android.app.NotificationManager
import android.content.Context
import android.os.Looper
import android.util.Log
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.auth.BiometricActivityLauncher
import com.automatethethings.xkey.crypto.AttestationException
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.settings.AttestationBiometricPolicy
import com.automatethethings.xkey.settings.BiometricSettingsData
import com.automatethethings.xkey.settings.PairedDeviceData
import com.automatethethings.xkey.settings.DeviceLookup
import com.automatethethings.xkey.settings.PairedDeviceRepository
import com.automatethethings.xkey.storage.XKeyDatabase
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.KeyEntity
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mockk.verify
import java.security.cert.X509Certificate
import java.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test

/**
 * Every key attestation `local.attestKey` answers, or fails to answer,
 * leaves one `KEY_ATTESTED` audit entry (#219); a request refused before
 * the keystore is asked leaves none.
 *
 * Drives the real handler with its Android edges mocked, as
 * [AttestationPolicyCallerPeerTest] does, and [AuditLogger] mocked so the
 * entries are counted instead of written to Room.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class LocalAttestKeyAuditTest {

    private lateinit var keystoreManager: KeystoreManager
    private lateinit var pairedDevices: PairedDeviceRepository
    private lateinit var handler: RequestHandler

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.v(any(), any<String>()) } returns 0
        every { Log.d(any(), any<String>()) } returns 0
        every { Log.i(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.e(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>(), any()) } returns 0
        every { Log.e(any(), any<String>(), any()) } returns 0

        mockkStatic(Looper::class)
        every { Looper.getMainLooper() } returns mockk(relaxed = true)

        val keyDao = mockk<KeyDao>(relaxed = true)
        coEvery { keyDao.getByKeyId(any()) } returns null
        coEvery { keyDao.getByKeyId(KEY_ID) } returns keyEntity()
        val database = mockk<XKeyDatabase>(relaxed = true)
        // No key has a pending deletion.
        every { database.keyPolicyDao() } returns mockk<com.automatethethings.xkey.storage.dao.KeyPolicyDao>(relaxed = true) { io.mockk.coEvery { deletion(any()) } returns null }
        every { database.keyDao() } returns keyDao
        mockkObject(XKeyDatabase.Companion)
        every { XKeyDatabase.getInstance(any()) } returns database

        mockkObject(AuditLogger)
        every {
            AuditLogger.logKeyAttested(any(), any(), any(), any(), any(), any(), any())
        } returns Unit

        Dispatchers.setMain(UnconfinedTestDispatcher())

        val context = mockk<Context>(relaxed = true)
        every { context.getSystemService(Context.KEYGUARD_SERVICE) } returns
            mockk<KeyguardManager>(relaxed = true)
        every { context.getSystemService(NotificationManager::class.java) } returns
            mockk<NotificationManager>(relaxed = true)

        pairedDevices = mockk(relaxed = true)
        every { pairedDevices.isDeviceKnown(any()) } returns true
        every { pairedDevices.lookupDevice(any()) } returns DeviceLookup.NotPaired

        keystoreManager = mockk(relaxed = true)
        every { keystoreManager.isStrongBoxAvailable() } returns true

        handler = RequestHandler(
            context = context,
            keystoreManager = keystoreManager,
            biometricLauncher = mockk<BiometricActivityLauncher>(relaxed = true),
            sessionAuthManager = null,
            pairedDeviceRepository = pairedDevices
        )
        handler.updateSettings(
            BiometricSettingsData(attestationBiometricPolicy = AttestationBiometricPolicy.NEVER)
        )
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
        unmockkAll()
    }

    @Test
    fun aSuccessfulAttestationRecordsOneEntry() = runTest {
        every { keystoreManager.getKeyAttestationWithChallenge(KEY_ID, any()) } returns
            listOf(leafCertificate())

        val response = Response.fromJson(attest(attestKeyRequest()))

        assertEquals(null, response.error)
        verify(exactly = 1) {
            AuditLogger.logKeyAttested(
                keyId = KEY_ID,
                keyLabel = KEY_LABEL,
                keyType = KEY_TYPE,
                securityLevel = "strongbox",
                success = true,
                errorMessage = null,
                durationMs = any()
            )
        }
        verify(exactly = 1) {
            AuditLogger.logKeyAttested(any(), any(), any(), any(), any(), any(), any())
        }
    }

    @Test
    fun theSuccessResponseIsUnchanged() = runTest {
        every { keystoreManager.getKeyAttestationWithChallenge(KEY_ID, any()) } returns
            listOf(leafCertificate())

        val result = JSONObject(String(attest(attestKeyRequest()), Charsets.UTF_8))
            .getJSONObject("result")

        assertEquals(setOf("certificateChain", "securityLevel", "nonce"), result.keys().asSequence().toSet())
        assertEquals(Base64.getEncoder().encodeToString(LEAF_DER), result.getJSONArray("certificateChain").getString(0))
        assertEquals("strongbox", result.getString("securityLevel"))
        assertEquals(NONCE, result.getString("nonce"))
    }

    @Test
    fun noChainRecordsOneFailedEntry() = runTest {
        every { keystoreManager.getKeyAttestationWithChallenge(KEY_ID, any()) } returns null

        val response = Response.fromJson(attest(attestKeyRequest()))

        assertEquals(ErrorCodes.ATTESTATION_FAILED, response.error?.code)
        verify(exactly = 1) {
            AuditLogger.logKeyAttested(
                keyId = KEY_ID,
                keyLabel = KEY_LABEL,
                keyType = KEY_TYPE,
                securityLevel = null,
                success = false,
                errorMessage = any(),
                durationMs = any()
            )
        }
        verify(exactly = 1) {
            AuditLogger.logKeyAttested(any(), any(), any(), any(), any(), any(), any())
        }
    }

    @Test
    fun aThrownAttestationFailureRecordsOneFailedEntry() = runTest {
        // API 28+ reports a failed attestation by throwing, not by returning null.
        every {
            keystoreManager.getKeyAttestationWithChallenge(KEY_ID, any())
        } throws AttestationException("No certificate chain available for attestation key")

        val response = Response.fromJson(attest(attestKeyRequest()))

        assertEquals(ErrorCodes.INTERNAL_ERROR, response.error?.code)
        verify(exactly = 1) {
            AuditLogger.logKeyAttested(
                keyId = KEY_ID,
                keyLabel = KEY_LABEL,
                keyType = KEY_TYPE,
                securityLevel = null,
                success = false,
                errorMessage = "Key attestation failed: No certificate chain available for attestation key",
                durationMs = any()
            )
        }
        verify(exactly = 1) {
            AuditLogger.logKeyAttested(any(), any(), any(), any(), any(), any(), any())
        }
    }

    @Test
    fun aFailureAfterTheChainRecordsOneFailedEntry() = runTest {
        // A chain whose leaf cannot be encoded fails after the keystore answered.
        val badCert = mockk<X509Certificate>()
        every { badCert.encoded } throws java.security.cert.CertificateEncodingException("bad leaf")
        every { keystoreManager.getKeyAttestationWithChallenge(KEY_ID, any()) } returns listOf(badCert)

        val response = Response.fromJson(attest(attestKeyRequest()))

        assertEquals(ErrorCodes.INTERNAL_ERROR, response.error?.code)
        verify(exactly = 1) {
            AuditLogger.logKeyAttested(
                keyId = KEY_ID,
                keyLabel = KEY_LABEL,
                keyType = KEY_TYPE,
                securityLevel = null,
                success = false,
                errorMessage = "bad leaf",
                durationMs = any()
            )
        }
        verify(exactly = 1) {
            AuditLogger.logKeyAttested(any(), any(), any(), any(), any(), any(), any())
        }
    }

    @Test
    fun anUnknownKeyIsLabelledByItsId() = runTest {
        every { keystoreManager.getKeyAttestationWithChallenge(OTHER_KEY_ID, any()) } returns null

        attest(attestKeyRequest(keyId = OTHER_KEY_ID))

        verify(exactly = 1) {
            AuditLogger.logKeyAttested(
                keyId = OTHER_KEY_ID,
                keyLabel = OTHER_KEY_ID,
                keyType = any(),
                securityLevel = null,
                success = false,
                errorMessage = any(),
                durationMs = any()
            )
        }
    }

    @Test
    fun missingParamsRecordNothing() = runTest {
        val request = Request(id = 1, method = MethodNames.LOCAL_ATTEST_KEY, params = null).toJson()

        val response = Response.fromJson(attest(request))

        assertEquals(ErrorCodes.INVALID_PARAMS, response.error?.code)
        assertNoAttestationEntry()
    }

    @Test
    fun aStaleDeviceAttestationRecordsNothing() = runTest {
        val device = mockk<PairedDeviceData>(relaxed = true)
        every { device.requireAttestationForKeyAttestation } returns true
        every { device.lastAttestationTime } returns null
        every { pairedDevices.lookupDevice(PEER) } returns DeviceLookup.Paired(device)

        val response = Response.fromJson(attest(attestKeyRequest()))

        assertEquals(ErrorCodes.DEVICE_ATTESTATION_REQUIRED, response.error?.code)
        assertNoAttestationEntry()
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private suspend fun attest(request: ByteArray): ByteArray =
        handler.handleRawRequest(request, binding, PEER)

    private fun attestKeyRequest(keyId: String = KEY_ID): ByteArray {
        val params = JSONObject().put("keyId", keyId).put("nonce", NONCE)
        return Request(id = 1, method = MethodNames.LOCAL_ATTEST_KEY, params = params).toJson()
    }

    private fun assertNoAttestationEntry() {
        verify(exactly = 0) {
            AuditLogger.logKeyAttested(any(), any(), any(), any(), any(), any(), any())
        }
    }

    /** A leaf with no attestation extension: the level falls back to StrongBox availability. */
    private fun leafCertificate(): X509Certificate {
        val cert = mockk<X509Certificate>()
        every { cert.encoded } returns LEAF_DER
        every { cert.getExtensionValue(any()) } returns null
        return cert
    }

    private fun keyEntity(): KeyEntity {
        val entity = mockk<KeyEntity>(relaxed = true)
        every { entity.keyId } returns KEY_ID
        every { entity.label } returns KEY_LABEL
        every { entity.keyType } returns KEY_TYPE
        return entity
    }

    private companion object {
        const val PEER = "aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11"
        const val KEY_ID = "key-attest-1"
        const val OTHER_KEY_ID = "key-unknown"
        const val KEY_LABEL = "Work signing key"
        const val KEY_TYPE = "ec"
        val NONCE: String = Base64.getEncoder().encodeToString(ByteArray(32) { 7 })
        val LEAF_DER = byteArrayOf(0x30, 0x03, 0x02, 0x01, 0x01)

        val binding = SessionBindingProvider {
            SessionBinding(ByteArray(32) { 1 }, ByteArray(32) { 2 }, ByteArray(0))
        }
    }
}
