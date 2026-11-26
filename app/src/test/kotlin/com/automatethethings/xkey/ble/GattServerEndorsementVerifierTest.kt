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
import android.util.Log
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.crypto.TcgCsrIDevID
import com.automatethethings.xkey.crypto.TpmTestStructures
import com.automatethethings.xkey.protocol.RemoteGetTCGCSRIDevIDResult
import com.automatethethings.xkey.protocol.RequestHandler
import com.automatethethings.xkey.truststore.TestCertificates
import com.automatethethings.xkey.truststore.TrustStoreRepository
import com.automatethethings.xkey.truststore.VerificationResult
import io.mockk.coEvery
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.runs
import io.mockk.slot
import io.mockk.unmockkAll
import io.mockk.verify
import java.lang.reflect.InvocationTargetException
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.util.Base64
import kotlin.coroutines.Continuation
import kotlin.coroutines.intrinsics.suspendCoroutineUninterceptedOrReturn
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

/**
 * TPM enrollment trusts an EK certificate only when `IDevIDVerifier` reports
 * it `Trusted`.
 *
 * The private `GattServer.verifyEndorsementKey` is driven by reflection with a
 * parsed TCG-CSR-IDEVID that carries a CA-issued EK certificate, as the
 * enrollment ceremony hands it over after `remote.getTCGCSRIDevID`. The trust
 * store is mocked so each verification outcome can be produced.
 */
class GattServerEndorsementVerifierTest {

    private companion object {
        const val DEVICE_KEY = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
        const val DEVICE_NAME = "Endorsement Probe"
        const val UNTRUSTED_ENDORSEMENT = "untrusted-endorsement"
    }

    private val ekDer: ByteArray = TestCertificates.der(TestCertificates.LEAF_A_PEM)
    private val detail = slot<String>()
    private val refusalCase = slot<String>()

    @Before
    fun setUp() {
        NoiseTestKeyStore.install()
        mockkStatic(Log::class)
        every { Log.v(any(), any<String>()) } returns 0
        every { Log.d(any(), any<String>()) } returns 0
        every { Log.i(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.e(any(), any<String>()) } returns 0
        every { Log.d(any(), any<String>(), any()) } returns 0
        every { Log.i(any(), any<String>(), any()) } returns 0
        every { Log.w(any(), any<String>(), any()) } returns 0
        every { Log.e(any(), any<String>(), any()) } returns 0
        mockkObject(AuditLogger)
        every {
            AuditLogger.logDeviceEnrollmentRefused(
                deviceId = any(),
                deviceName = any(),
                refusalCase = capture(refusalCase),
                detail = capture(detail)
            )
        } just runs
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `a store with no trust anchors refuses the EK certificate`() = runBlocking {
        val store = mockk<TrustStoreRepository>()
        coEvery { store.verifyIDevIDChain(any()) } returns VerificationResult.NoTrustAnchors

        assertRefused(server(store))
    }

    @Test
    fun `a chain check that throws refuses rather than escaping`() = runBlocking {
        val store = mockk<TrustStoreRepository>()
        coEvery { store.verifyIDevIDChain(any()) } throws IllegalStateException("store offline")

        assertRefused(server(store))
    }

    @Test
    fun `no verifier wired refuses the EK certificate`() = runBlocking {
        assertRefused(server(null))
    }

    @Test
    fun `a chain that does not reach a trusted root refuses the EK certificate`() = runBlocking {
        val store = mockk<TrustStoreRepository>()
        coEvery { store.verifyIDevIDChain(any()) } returns
            VerificationResult.Invalid("path does not chain with any of the trust anchors")

        assertRefused(server(store))
    }

    @Test
    fun `a self-signed chain verdict refuses the EK certificate`() = runBlocking {
        val store = mockk<TrustStoreRepository>()
        coEvery { store.verifyIDevIDChain(any()) } returns VerificationResult.SelfSigned

        assertRefused(server(store))
    }

    @Test
    fun `a trusted EK certificate lets enrollment continue`() = runBlocking {
        val store = mockk<TrustStoreRepository>()
        coEvery { store.verifyIDevIDChain(any()) } returns VerificationResult.Valid("external-ca")

        val cert = verifyEndorsementKey(server(store))

        assertArrayEquals(ekDer, cert.encoded)
        verify(exactly = 0) { AuditLogger.logDeviceEnrollmentRefused(any(), any(), any(), any()) }
    }

    // -----------------------------------------------------------------
    // Harness
    // -----------------------------------------------------------------

    private suspend fun assertRefused(server: GattServer) {
        try {
            verifyEndorsementKey(server)
            fail("enrollment continued with an EK certificate IDevIDVerifier does not trust")
        } catch (e: Exception) {
            assertTrue(
                "expected an untrusted-endorsement refusal, got ${e::class.java.name}: ${e.message}",
                e.message?.startsWith("$UNTRUSTED_ENDORSEMENT:") == true
            )
        }
        assertEquals(UNTRUSTED_ENDORSEMENT, refusalCase.captured)
        assertTrue("the refusal names its reason", detail.captured.isNotBlank())
        val ekBase64 = Base64.getEncoder().encodeToString(ekDer)
        val ekHex = ekDer.joinToString("") { "%02x".format(it) }
        assertFalse(
            "the refusal must not carry certificate bytes",
            detail.captured.contains(ekBase64.substring(0, 40)) ||
                detail.captured.contains(ekHex.substring(0, 40))
        )
    }

    private fun server(store: TrustStoreRepository?): GattServer = GattServer(
        context = mockk<Context>(relaxed = true),
        requestHandler = mockk<RequestHandler>(relaxed = true),
        trustStoreRepository = store
    )

    private fun enrollmentPackage(): Pair<TcgCsrIDevID, RemoteGetTCGCSRIDevIDResult> {
        val iakPub = TpmTestStructures.eccPublicArea(
            TpmTestStructures.generateEcKeyPair().public as ECPublicKey,
            TpmTestStructures.IAK_ATTRIBUTES
        )
        val idevidPub = TpmTestStructures.eccPublicArea(
            TpmTestStructures.generateEcKeyPair().public as ECPublicKey,
            TpmTestStructures.IDEVID_ATTRIBUTES
        )
        val contents = TpmTestStructures.csrContents(
            ekCert = ekDer,
            attestPub = iakPub,
            signingPub = idevidPub
        )
        val packed = TpmTestStructures.packCsr(contents, ByteArray(64))
        val csr = TcgCsrIDevID.parse(packed)
        return csr to RemoteGetTCGCSRIDevIDResult(
            csr = packed,
            ekCert = ekDer,
            iakPublicKey = iakPub,
            idevidPublicKey = idevidPub
        )
    }

    /** Calls the private suspend `verifyEndorsementKey` and unwraps reflection. */
    private suspend fun verifyEndorsementKey(server: GattServer): X509Certificate {
        val (csr, result) = enrollmentPackage()
        val method = GattServer::class.java.declaredMethods.single {
            it.name == "verifyEndorsementKey"
        }
        method.isAccessible = true
        return suspendCoroutineUninterceptedOrReturn { cont: Continuation<X509Certificate> ->
            try {
                method.invoke(server, csr, result, DEVICE_KEY, DEVICE_NAME, cont)
            } catch (e: InvocationTargetException) {
                throw e.targetException
            }
        }
    }
}
