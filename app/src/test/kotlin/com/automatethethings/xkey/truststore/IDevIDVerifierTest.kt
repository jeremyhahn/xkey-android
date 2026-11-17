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
package com.automatethethings.xkey.truststore

import android.util.Log
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Unit tests for [IDevIDVerifier].
 *
 * The verifier owns two trust decisions of its own — the unconditional self-signed
 * rejection that happens *before* the trust store is consulted, and the translation
 * of a [VerificationResult] into an [IDevIDVerificationResult] — so the trust store
 * is mocked here and only the verifier's logic is under test. The reported
 * fingerprint is checked against a SHA-256 digest computed inside the test.
 */
class IDevIDVerifierTest {

    private lateinit var trustStore: TrustStoreRepository
    private lateinit var verifier: IDevIDVerifier

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.i(any(), any()) } returns 0
        every { Log.d(any(), any()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.e(any(), any(), any()) } returns 0

        trustStore = mockk()
        verifier = IDevIDVerifier(trustStore)
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    // -------------------------------------------------------------------------
    // Input validation
    // -------------------------------------------------------------------------

    @Test
    fun `verify reports NoCertificate for an empty chain`() = runTest {
        val result = verifier.verify(emptyList())

        assertEquals(IDevIDVerificationResult.NoCertificate, result)
        coVerify(exactly = 0) { trustStore.verifyIDevIDChain(any()) }
    }

    @Test
    fun `verify reports Error for garbage DER`() = runTest {
        val result = verifier.verify(listOf(byteArrayOf(0x01, 0x02, 0x03)))

        assertTrue("expected Error but was $result", result is IDevIDVerificationResult.Error)
        coVerify(exactly = 0) { trustStore.verifyIDevIDChain(any()) }
    }

    @Test
    fun `verify reports Error when the trust store throws`() = runTest {
        coEvery { trustStore.verifyIDevIDChain(any()) } throws IllegalStateException("store offline")

        val result = verifier.verify(listOf(TestCertificates.der(TestCertificates.LEAF_A_PEM)))

        assertEquals(IDevIDVerificationResult.Error("store offline"), result)
    }

    // -------------------------------------------------------------------------
    // Self-signed certificates are never trusted
    // -------------------------------------------------------------------------

    @Test
    fun `verify rejects a self-signed leaf without consulting the trust store`() = runTest {
        val result = verifier.verify(listOf(TestCertificates.der(TestCertificates.ROOT_CA_A_PEM)))

        assertEquals(IDevIDVerificationResult.SelfSigned, result)
        coVerify(exactly = 0) { trustStore.verifyIDevIDChain(any()) }
    }

    @Test
    fun `verify maps a trust store SelfSigned verdict to SelfSigned`() = runTest {
        coEvery { trustStore.verifyIDevIDChain(any()) } returns VerificationResult.SelfSigned

        val result = verifier.verify(listOf(TestCertificates.der(TestCertificates.LEAF_A_PEM)))

        assertEquals(IDevIDVerificationResult.SelfSigned, result)
    }

    // -------------------------------------------------------------------------
    // Trusted / untrusted mapping
    // -------------------------------------------------------------------------

    @Test
    fun `verify reports Trusted with the leaf details and fingerprint`() = runTest {
        coEvery { trustStore.verifyIDevIDChain(any()) } returns VerificationResult.Valid("android-ca")

        val result = verifier.verify(listOf(TestCertificates.der(TestCertificates.LEAF_A_PEM)))

        assertTrue("expected Trusted but was $result", result is IDevIDVerificationResult.Trusted)
        val trusted = result as IDevIDVerificationResult.Trusted
        assertEquals("android-ca", trusted.trustLevel)
        assertTrue(trusted.subjectDN.startsWith(TestCertificates.LEAF_A_CN))
        assertEquals(TestCertificates.LONG_LIVED_NOT_AFTER_MILLIS, trusted.notAfter)
        assertEquals(TestCertificates.fingerprint(TestCertificates.LEAF_A_PEM), trusted.fingerprint)
    }

    @Test
    fun `verify uses the first certificate in the chain as the leaf`() = runTest {
        coEvery { trustStore.verifyIDevIDChain(any()) } returns VerificationResult.Valid("external-ca")

        val result = verifier.verify(
            listOf(
                TestCertificates.der(TestCertificates.LEAF_VIA_INTERMEDIATE_PEM),
                TestCertificates.der(TestCertificates.INTERMEDIATE_A_PEM)
            )
        )

        val trusted = result as IDevIDVerificationResult.Trusted
        assertTrue(trusted.subjectDN.startsWith(TestCertificates.LEAF_VIA_INTERMEDIATE_CN))
        assertEquals(
            TestCertificates.fingerprint(TestCertificates.LEAF_VIA_INTERMEDIATE_PEM),
            trusted.fingerprint
        )
    }

    @Test
    fun `verify maps an Invalid verdict to Untrusted with the reason`() = runTest {
        coEvery { trustStore.verifyIDevIDChain(any()) } returns
            VerificationResult.Invalid("unable to find valid certification path")

        val result = verifier.verify(listOf(TestCertificates.der(TestCertificates.LEAF_A_PEM)))

        assertEquals(
            IDevIDVerificationResult.Untrusted("unable to find valid certification path"),
            result
        )
    }

    @Test
    fun `verify maps NoTrustAnchors to a descriptive Untrusted result`() = runTest {
        coEvery { trustStore.verifyIDevIDChain(any()) } returns VerificationResult.NoTrustAnchors

        val result = verifier.verify(listOf(TestCertificates.der(TestCertificates.LEAF_A_PEM)))

        assertEquals(
            IDevIDVerificationResult.Untrusted("No trusted CA certificates configured"),
            result
        )
    }

    @Test
    fun `verify passes the raw chain through to the trust store`() = runTest {
        coEvery { trustStore.verifyIDevIDChain(any()) } returns VerificationResult.Valid("external-ca")
        val chain = listOf(
            TestCertificates.der(TestCertificates.LEAF_VIA_INTERMEDIATE_PEM),
            TestCertificates.der(TestCertificates.INTERMEDIATE_A_PEM)
        )

        verifier.verify(chain)

        coVerify(exactly = 1) { trustStore.verifyIDevIDChain(chain) }
    }

    // -------------------------------------------------------------------------
    // isIDevIDStillValid
    // -------------------------------------------------------------------------

    @Test
    fun `isIDevIDStillValid accepts an unexpired CA-signed certificate`() {
        assertTrue(
            verifier.isIDevIDStillValid(
                certificateDER = TestCertificates.der(TestCertificates.LEAF_A_PEM),
                verifiedAt = 1_700_000_000_000L,
                trustLevel = "android-ca"
            )
        )
    }

    @Test
    fun `isIDevIDStillValid rejects a null certificate`() {
        assertFalse(verifier.isIDevIDStillValid(null, 1L, "android-ca"))
    }

    @Test
    fun `isIDevIDStillValid rejects a null verification timestamp`() {
        assertFalse(
            verifier.isIDevIDStillValid(
                TestCertificates.der(TestCertificates.LEAF_A_PEM),
                null,
                "android-ca"
            )
        )
    }

    @Test
    fun `isIDevIDStillValid rejects a null trust level`() {
        assertFalse(
            verifier.isIDevIDStillValid(
                TestCertificates.der(TestCertificates.LEAF_A_PEM),
                1L,
                null
            )
        )
    }

    @Test
    fun `isIDevIDStillValid rejects an expired certificate`() {
        assertFalse(
            verifier.isIDevIDStillValid(
                TestCertificates.der(TestCertificates.EXPIRED_LEAF_A_PEM),
                1L,
                "android-ca"
            )
        )
    }

    @Test
    fun `isIDevIDStillValid rejects a self-signed certificate`() {
        assertFalse(
            verifier.isIDevIDStillValid(
                TestCertificates.der(TestCertificates.ROOT_CA_A_PEM),
                1L,
                "android-ca"
            )
        )
    }

    @Test
    fun `isIDevIDStillValid rejects unparseable bytes`() {
        assertFalse(verifier.isIDevIDStillValid(byteArrayOf(0x30, 0x03, 0x02), 1L, "android-ca"))
    }

    @Test
    fun `isIDevIDStillValid rejects an empty certificate`() {
        assertFalse(verifier.isIDevIDStillValid(ByteArray(0), 1L, "android-ca"))
    }
}
