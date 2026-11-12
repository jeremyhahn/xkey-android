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
package com.automatethethings.xkey.piv

import android.util.Log
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import kotlinx.coroutines.test.runTest
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import java.util.Date

/**
 * Unit tests for [PivKeyManager] paths that run without the Android Keystore.
 *
 * The Android Keystore is not available in JVM unit tests, so key generation
 * and signing are covered by instrumented tests. [PivKeyManager.sign] records
 * each use through [PivSlotDao.recordUsage] without a timestamp; this pins that
 * the omitted timestamp is the current time.
 *
 * [PivKeyManager.importCertificate] reads the slot key from the `piv_slots`
 * row, so it is tested over a mocked [PivSlotDao] whose row carries a
 * JDK-generated P-256 key standing in for the Keystore key (#173).
 */
class PivKeyManagerTest {

    private lateinit var pivSlotDao: PivSlotDao
    private val slotKey = PivTestCertificates.ecKeyPair()

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.i(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.d(any(), any<String>()) } returns 0
        pivSlotDao = mockk(relaxed = true)
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `recordUsage without a timestamp stamps the current time`() = runTest {
        val before = System.currentTimeMillis()
        pivSlotDao.recordUsage("9A")
        val after = System.currentTimeMillis()

        coVerify { pivSlotDao.recordUsage("9A", match { it in before..after }) }
    }

    @Test
    fun `importCertificate stores a certificate for the slot key`() = runTest {
        coEvery { pivSlotDao.getBySlotId("9A") } returns PivTestCertificates.slotRow(slotKey.public.encoded)
        val cert = PivTestCertificates.selfSigned(slotKey)

        PivKeyManager(pivSlotDao).importCertificate(PivSlot.AUTHENTICATION, cert)

        coVerify { pivSlotDao.upsert(match { it.slotId == "9A" && it.certificateDer.contentEquals(cert) }) }
    }

    @Test
    fun `importCertificate refuses a certificate for another key and keeps the earlier one`() = runTest {
        val earlier = PivTestCertificates.selfSigned(slotKey)
        coEvery { pivSlotDao.getBySlotId("9A") } returns PivTestCertificates.slotRow(slotKey.public.encoded, earlier)
        val other = PivTestCertificates.selfSigned(PivTestCertificates.ecKeyPair())

        val error = importError(other)

        assertTrue("got $error", error is IllegalArgumentException)
        coVerify(exactly = 0) { pivSlotDao.upsert(any()) }
    }

    @Test
    fun `importCertificate refuses bytes that are not a certificate`() = runTest {
        coEvery { pivSlotDao.getBySlotId("9A") } returns PivTestCertificates.slotRow(slotKey.public.encoded)

        val error = importError(byteArrayOf(0x30, 0x03, 0x02, 0x01, 0x01))

        assertTrue("got $error", error is IllegalArgumentException)
        coVerify(exactly = 0) { pivSlotDao.upsert(any()) }
    }

    @Test
    fun `importCertificate refuses a certificate followed by trailing bytes`() = runTest {
        coEvery { pivSlotDao.getBySlotId("9A") } returns PivTestCertificates.slotRow(slotKey.public.encoded)

        val error = importError(PivTestCertificates.selfSigned(slotKey) + byteArrayOf(0))

        assertTrue("got $error", error is IllegalArgumentException)
        coVerify(exactly = 0) { pivSlotDao.upsert(any()) }
    }

    @Test
    fun `importCertificate refuses a slot with no key`() = runTest {
        coEvery { pivSlotDao.getBySlotId("9A") } returns null

        val error = importError(PivTestCertificates.selfSigned(slotKey))

        assertTrue("got $error", error is IllegalStateException)
        coVerify(exactly = 0) { pivSlotDao.upsert(any()) }
    }

    @Test
    fun `test certificate carries the slot key as its SubjectPublicKeyInfo`() {
        val cert = PivTestCertificates.selfSigned(slotKey)
        val parsed = java.security.cert.CertificateFactory.getInstance("X.509")
            .generateCertificate(cert.inputStream())

        assertArrayEquals(slotKey.public.encoded, parsed.publicKey.encoded)
    }

    private suspend fun importError(certDer: ByteArray): Throwable? =
        runCatching { PivKeyManager(pivSlotDao).importCertificate(PivSlot.AUTHENTICATION, certDer) }
            .exceptionOrNull()
}

/**
 * Keys, certificates and `piv_slots` rows for the PIV import tests, shared
 * with the handler tests in the protocol package.
 */
internal object PivTestCertificates {

    /** A fresh P-256 key pair, the shape an `ES256` slot key has. */
    fun ecKeyPair(): KeyPair = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair()

    /** A self-signed DER certificate whose subject key is [keyPair]'s public key. */
    fun selfSigned(keyPair: KeyPair): ByteArray {
        val name = X500Name("CN=xkey PIV test")
        val now = System.currentTimeMillis()
        val builder = JcaX509v3CertificateBuilder(
            name,
            BigInteger.ONE,
            Date(now - 60_000),
            Date(now + 86_400_000),
            name,
            keyPair.public
        )
        val signer = JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.private)
        return builder.build(signer).encoded
    }

    /** The `piv_slots` row for slot 9A holding [publicKeyDer]. */
    fun slotRow(publicKeyDer: ByteArray, certificateDer: ByteArray? = null) = PivSlotEntity(
        slotId = "9A",
        algorithm = PivAlgorithm.ES256.name,
        publicKeyDer = publicKeyDer,
        certificateDer = certificateDer,
        hasKey = true
    )
}
