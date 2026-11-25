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

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.util.Log
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.crypto.KeySecurityLevel
import com.automatethethings.xkey.crypto.KeystoreAeadCipher
import com.automatethethings.xkey.crypto.MlDsaParameterSet
import com.automatethethings.xkey.crypto.PqcBacking
import com.automatethethings.xkey.crypto.PqcHardware
import com.automatethethings.xkey.crypto.PqcHardwareBackend
import com.automatethethings.xkey.crypto.PqcKeysTest
import com.automatethethings.xkey.crypto.PqcSoftwareKeyStore
import com.automatethethings.xkey.crypto.UnsupportedAlgorithmException
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.coVerifyOrder
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mockk.unmockkObject
import io.mockk.verify
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Provider
import java.security.ProviderException
import java.security.Security
import java.security.Signature
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.ECGenParameterSpec
import java.util.Date
import javax.crypto.KeyAgreement

/** Every algorithm a device offers without the curve 25519 hardware probe. */
private val NON_CURVE_25519 = PivAlgorithm.entries.filterNot { it.isCurve25519 }

/** Class name prefixes of the providers the JDK installs. */
private val JDK_PROVIDER_PACKAGES = listOf("sun.", "com.sun.", "jdk.", "org.jcp.xml.")

/**
 * Unit tests for [PivKeyManager] paths that run without the Android Keystore.
 *
 * The Android Keystore is not available in JVM unit tests, so key generation
 * and signing are covered by instrumented tests. [PivKeyManager.sign] records
 * each use through [PivSlotDao.recordUsage] without a timestamp; this pins that
 * the omitted timestamp is the current time.
 *
 * [PivKeyManager.importCertificate] checks a certificate against the slot's
 * live Keystore key, so it is tested over a mocked [PivSlotDao] and a
 * [FakePivKeystore] holding a JDK-generated P-256 key in place of the
 * AndroidKeyStore entry (#173). The `piv_slots` row is only a cache: tests
 * where it disagrees with the Keystore pin that the Keystore decides.
 *
 * Ed25519 and X25519 slot keys are generated through the manager's
 * `generateKeyPair` seam with JDK keys, with the platform level and the
 * key's security level injected: the refusals on a device below Android 13
 * or without secure hardware are decided by the manager, not the Keystore.
 */
class PivKeyManagerTest {

    private lateinit var pivSlotDao: PivSlotDao
    private val slotKey = PivTestCertificates.ecKeyPair()
    private lateinit var keystore: FakePivKeystore
    private var generatorCalls = 0
    private val generatedAliases = mutableListOf<String>()

    /** Providers an earlier test in this JVM installed, with their 1-based positions. */
    private val foreignProviders = mutableListOf<Pair<Int, Provider>>()

    @Before
    fun setUp() {
        // Earlier tests in the same JVM can leave Conscrypt or Bouncy Castle first, which refuse the JDK test keys.
        Security.getProviders().forEachIndexed { index, provider ->
            val jdk = JDK_PROVIDER_PACKAGES.any { provider.javaClass.name.startsWith(it) }
            if (!jdk) foreignProviders += (index + 1) to provider
        }
        foreignProviders.forEach { (_, provider) -> Security.removeProvider(provider.name) }
        mockkStatic(Log::class)
        every { Log.i(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.d(any(), any<String>()) } returns 0
        pivSlotDao = mockk(relaxed = true)
        keystore = FakePivKeystore(slotKey).also { it.install() }
        mockkObject(AuditLogger)
        every { AuditLogger.logKeyDeleted(any(), any(), any()) } returns Unit
        every { AuditLogger.logKeyCreated(any(), any(), any(), any()) } returns Unit
        every { AuditLogger.logPivCertImported(any(), any()) } returns Unit
        every {
            AuditLogger.logSigningRequest(any(), any(), any(), any(), any(), any(), any(), any(), any())
        } returns Unit
        every { AuditLogger.logKeyUsed(any(), any(), any(), any(), any(), any(), any()) } returns Unit
        // No shared software ML-DSA store from another test class.
        PqcSoftwareKeyStore.clearSharedForTest()
    }

    @After
    fun tearDown() {
        // The Keystore probe's answers are kept for the process.
        PivKeyManager.forgetHardwareProbes()
        PqcSoftwareKeyStore.clearSharedForTest()
        unmockkAll()
        foreignProviders.forEach { (position, provider) -> Security.insertProviderAt(provider, position) }
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

        testPivKeyManager(pivSlotDao).importCertificate(PivSlot.AUTHENTICATION, cert)

        coVerify { pivSlotDao.upsert(match { it.slotId == "9A" && it.certificateDer.contentEquals(cert) }) }
    }

    @Test
    fun `importCertificate writes one audit entry naming the slot and subject`() = runTest {
        coEvery { pivSlotDao.getBySlotId("9A") } returns PivTestCertificates.slotRow(slotKey.public.encoded)

        testPivKeyManager(pivSlotDao).importCertificate(PivSlot.AUTHENTICATION, PivTestCertificates.selfSigned(slotKey))

        verify(exactly = 1) { AuditLogger.logPivCertImported(any(), any()) }
        verify(exactly = 1) { AuditLogger.logPivCertImported("9A", "CN=xkey PIV test") }
    }

    @Test
    fun `importCertificate refused for its key writes no audit entry`() = runTest {
        coEvery { pivSlotDao.getBySlotId("9A") } returns PivTestCertificates.slotRow(slotKey.public.encoded)

        val error = importError(PivTestCertificates.selfSigned(PivTestCertificates.ecKeyPair()))

        assertTrue("got $error", error is PivCertificateKeyMismatchException)
        verify(exactly = 0) { AuditLogger.logPivCertImported(any(), any()) }
    }

    @Test
    fun `importCertificate of unparseable bytes writes no audit entry`() = runTest {
        coEvery { pivSlotDao.getBySlotId("9A") } returns PivTestCertificates.slotRow(slotKey.public.encoded)

        val error = importError(byteArrayOf(0x30, 0x03, 0x02, 0x01, 0x01))

        assertTrue("got $error", error is PivCertificateNotParseableException)
        verify(exactly = 0) { AuditLogger.logPivCertImported(any(), any()) }
    }

    @Test
    fun `importCertificate succeeds with AuditLogger not initialized`() = runTest {
        unmockkObject(AuditLogger)
        coEvery { pivSlotDao.getBySlotId("9A") } returns PivTestCertificates.slotRow(slotKey.public.encoded)
        val cert = PivTestCertificates.selfSigned(slotKey)

        testPivKeyManager(pivSlotDao).importCertificate(PivSlot.AUTHENTICATION, cert)

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

    /**
     * Two managers (the GATT service and a PIV screen each build one) work on
     * slot 9A at once. The import has read key A's row and is suspended before
     * its check and upsert when the other manager deletes the key. The delete
     * must wait for the import, or the import's upsert would bring back key
     * A's row, with the certificate, after the delete.
     */
    @OptIn(ExperimentalCoroutinesApi::class)
    @Test
    fun `deleteKey on another manager waits for an import of the same slot`() = runTest(StandardTestDispatcher()) {
        val readGate = CompletableDeferred<Unit>()
        coEvery { pivSlotDao.getBySlotId("9A") } coAnswers {
            readGate.await()
            PivTestCertificates.slotRow(slotKey.public.encoded)
        }
        val importer = testPivKeyManager(pivSlotDao)
        val deleter = testPivKeyManager(pivSlotDao)
        val cert = PivTestCertificates.selfSigned(slotKey)

        val import = launch { importer.importCertificate(PivSlot.AUTHENTICATION, cert) }
        runCurrent()
        val delete = launch { deleter.deleteKey(PivSlot.AUTHENTICATION) }
        runCurrent()

        assertFalse("deleteKey ran while the import held a snapshot of the slot", delete.isCompleted)

        readGate.complete(Unit)
        import.join()
        delete.join()

        coVerifyOrder {
            pivSlotDao.upsert(match { it.slotId == "9A" })
            pivSlotDao.deleteBySlotId("9A")
        }
    }

    @Test
    fun `importCertificate refuses a slot whose row has a key but whose Keystore alias is gone`() = runTest {
        // The general key screen or a failed generate removed xkey_piv_9A
        // without touching piv_slots: the row still says hasKey with key A.
        coEvery { pivSlotDao.getBySlotId("9A") } returns PivTestCertificates.slotRow(slotKey.public.encoded)
        keystore.live = null

        val error = importError(PivTestCertificates.selfSigned(slotKey))

        assertTrue("got $error", error is PivSlotEmptyException)
        coVerify(exactly = 0) { pivSlotDao.upsert(any()) }
    }

    @Test
    fun `importCertificate refuses a certificate for the row's stale key when the Keystore holds another`() = runTest {
        coEvery { pivSlotDao.getBySlotId("9A") } returns PivTestCertificates.slotRow(slotKey.public.encoded)
        keystore.live = PivTestCertificates.ecKeyPair()

        val error = importError(PivTestCertificates.selfSigned(slotKey))

        assertTrue("got $error", error is PivCertificateKeyMismatchException)
        coVerify(exactly = 0) { pivSlotDao.upsert(any()) }
    }

    @Test
    fun `importCertificate accepts a certificate for the Keystore key when the row is stale`() = runTest {
        coEvery { pivSlotDao.getBySlotId("9A") } returns PivTestCertificates.slotRow(slotKey.public.encoded)
        val liveKey = PivTestCertificates.ecKeyPair()
        keystore.live = liveKey
        val cert = PivTestCertificates.selfSigned(liveKey)

        testPivKeyManager(pivSlotDao).importCertificate(PivSlot.AUTHENTICATION, cert)

        coVerify {
            pivSlotDao.upsert(match {
                it.certificateDer.contentEquals(cert) && it.publicKeyDer.contentEquals(liveKey.public.encoded)
            })
        }
    }

    /**
     * generateKey replaces xkey_piv_9A with key B, then its upsert fails. The
     * row still names key A; a certificate for A must not be accepted, and
     * the slot must not be left holding a key its row does not describe.
     */
    @Test
    fun `generateKey whose upsert fails leaves no slot that accepts the old key's certificate`() = runTest {
        coEvery { pivSlotDao.getBySlotId("9A") } returns PivTestCertificates.slotRow(slotKey.public.encoded)
        val newKey = PivTestCertificates.ecKeyPair()
        keystore.generatesOnNextCall(newKey)
        coEvery { pivSlotDao.upsert(match { it.publicKeyDer.contentEquals(newKey.public.encoded) }) } throws
            IllegalStateException("database is closed")
        val manager = testPivKeyManager(pivSlotDao)

        val generateError = runCatching { manager.generateKey(PivSlot.AUTHENTICATION, PivAlgorithm.ES256) }
            .exceptionOrNull()
        val importOld = importError(PivTestCertificates.selfSigned(slotKey))

        assertTrue("generate must report the failure, got $generateError", generateError is IllegalStateException)
        assertTrue("a certificate for the replaced key was accepted: $importOld", importOld != null)
        assertNull("the Keystore kept a key the row does not describe", keystore.live)
        coVerify { pivSlotDao.deleteBySlotId("9A") }
    }

    /**
     * generateKey is cancelled after it replaced xkey_piv_9A and while its
     * upsert runs. The upsert must still finish, so the row describes the
     * Keystore key rather than the replaced one.
     */
    @OptIn(ExperimentalCoroutinesApi::class)
    @Test
    fun `generateKey cancelled after the Keystore replace still records the new key`() = runTest(StandardTestDispatcher()) {
        val newKey = PivTestCertificates.ecKeyPair()
        keystore.generatesOnNextCall(newKey)
        val upsertGate = CompletableDeferred<Unit>()
        var stored: PivSlotEntity? = null
        coEvery { pivSlotDao.upsert(any()) } coAnswers {
            upsertGate.await()
            stored = firstArg()
            1L
        }

        val generate = launch { testPivKeyManager(pivSlotDao).generateKey(PivSlot.AUTHENTICATION, PivAlgorithm.ES256) }
        runCurrent()
        assertTrue("generate did not reach its upsert", keystore.live === newKey)
        generate.cancel()
        upsertGate.complete(Unit)
        generate.join()

        assertTrue(
            "the row was left naming the replaced key",
            stored?.publicKeyDer.contentEquals(newKey.public.encoded)
        )
    }

    /**
     * Another manager regenerates slot 9A from ES256 (key A, with a
     * certificate) to RS2048 (key B) while a listing runs: the listing has
     * read A's row, and the Keystore already holds B. The listing must
     * describe one generation, never B's key with A's algorithm and
     * certificate.
     */
    @OptIn(ExperimentalCoroutinesApi::class)
    @Test
    fun `listSlots during a regenerate lists one generation of the slot`() = runTest(StandardTestDispatcher()) {
        val oldRow = PivTestCertificates.slotRow(slotKey.public.encoded, PivTestCertificates.selfSigned(slotKey))
        var row = oldRow
        coEvery { pivSlotDao.getAll() } answers { listOf(oldRow) }
        coEvery { pivSlotDao.getBySlotId("9A") } answers { row }
        val newKey = PivTestCertificates.ecKeyPair()
        keystore.generatesOnNextCall(newKey)
        val upsertGate = CompletableDeferred<Unit>()
        coEvery { pivSlotDao.upsert(any()) } coAnswers {
            upsertGate.await()
            row = firstArg()
            1L
        }

        val generate = launch { testPivKeyManager(pivSlotDao).generateKey(PivSlot.AUTHENTICATION, PivAlgorithm.RS2048) }
        runCurrent()
        assertTrue("generate did not reach its upsert", keystore.live === newKey)
        val listing = async { testPivKeyManager(pivSlotDao).listSlots() }
        runCurrent()
        upsertGate.complete(Unit)
        generate.join()
        val info = listing.await().single()

        val oldGeneration = info.algorithm == PivAlgorithm.ES256 && info.hasCertificate &&
            info.publicKeyDer.contentEquals(slotKey.public.encoded)
        val newGeneration = info.algorithm == PivAlgorithm.RS2048 && !info.hasCertificate &&
            info.publicKeyDer.contentEquals(newKey.public.encoded)
        assertTrue("listing mixed two generations: $info", oldGeneration || newGeneration)
    }

    @Test
    fun `generateKey RS3072 and RS4096 ask the Keystore TEE for that modulus`() = runTest {
        for (algorithm in listOf(PivAlgorithm.RS3072, PivAlgorithm.RS4096)) {
            val newKey = KeyPairGenerator.getInstance("RSA").apply { initialize(1024) }.generateKeyPair()
            keystore.generatesOnNextCall(newKey)

            val info = testPivKeyManager(pivSlotDao).generateKey(PivSlot.AUTHENTICATION, algorithm)

            assertTrue("$algorithm reported as ${info.algorithm}", info.algorithm == algorithm)
            assertTrue(info.hasKey)
            verify { anyConstructed<KeyGenParameterSpec.Builder>().setKeySize(algorithm.keySizeBits) }
            // StrongBox guarantees RSA 2048 only: PIV keys stay in the TEE.
            verify(exactly = 0) { anyConstructed<KeyGenParameterSpec.Builder>().setIsStrongBoxBacked(any()) }
            verify { KeyPairGenerator.getInstance("RSA", "AndroidKeyStore") }
            unmockkAll()
            setUp()
        }
    }

    @Test
    fun `test certificate carries the slot key as its SubjectPublicKeyInfo`() {
        val cert = PivTestCertificates.selfSigned(slotKey)
        val parsed = java.security.cert.CertificateFactory.getInstance("X.509")
            .generateCertificate(cert.inputStream())

        assertArrayEquals(slotKey.public.encoded, parsed.publicKey.encoded)
    }

    @Test
    fun `the JVM fixture level makes every algorithm available`() {
        assertTrue(PivAlgorithm.entries.all { it.isAvailableOn(SUPPORTED_TEST_SDK) })
    }

    /**
     * A manager left on a level below [PivAlgorithm.minSdk], as one on the
     * platform default is off a device, refuses even ES256 before its
     * generator runs: a fixture that skips [testPivKeyManager] fails this way.
     */
    @Test
    fun `a manager below the algorithm's minSdk refuses ES256 before its generator runs`() = runTest {
        val manager = testPivKeyManager(
            pivSlotDao,
            generateKeyPair = { _, _ ->
                generatorCalls++
                PivTestCertificates.ecKeyPair()
            },
            sdkInt = PivAlgorithm.ES256.minSdk - 1
        )

        val error = generateError(manager, PivAlgorithm.ES256)

        assertTrue("got $error", error is PivAlgorithmUnavailableException)
        assertEquals("the generator ran", 0, generatorCalls)
        assertTrue("the slot lost its key", keystore.live === slotKey)
    }

    // -------------------------------------------------------------------------
    // Ed25519 and X25519 slot keys
    // -------------------------------------------------------------------------

    @Test
    fun `generateKey Ed25519 below Android 13 is refused before the Keystore is touched`() = runTest {
        coEvery { pivSlotDao.getBySlotId("9A") } returns PivTestCertificates.slotRow(slotKey.public.encoded)

        val error = generateError(manager(sdkInt = 32, generates = PivTestCertificates.ed25519KeyPair()), PivAlgorithm.ED25519)

        assertTrue("got $error", error is PivAlgorithmUnavailableException)
        assertTrue(error?.message, error?.message?.contains("Ed25519") == true)
        assertTrue(error?.message, error?.message?.contains("Android 13 secure hardware") == true)
        assertEquals("the Keystore generator ran", 0, generatorCalls)
        assertTrue("the slot lost its key", keystore.live === slotKey)
        coVerify(exactly = 0) { pivSlotDao.upsert(any()) }
        coVerify(exactly = 0) { pivSlotDao.deleteBySlotId(any()) }
    }

    @Test
    fun `generateKey X25519 below Android 13 is refused and the slot keeps its key`() = runTest {
        val error = generateError(manager(sdkInt = 32, generates = PivTestCertificates.x25519KeyPair()), PivAlgorithm.X25519)

        assertTrue("got $error", error is PivAlgorithmUnavailableException)
        assertTrue(error?.message, error?.message?.contains("X25519") == true)
        assertEquals(0, generatorCalls)
        assertTrue(keystore.live === slotKey)
        coVerify(exactly = 0) { pivSlotDao.upsert(any()) }
        coVerify(exactly = 0) { pivSlotDao.deleteBySlotId(any()) }
    }

    @Test
    fun `generateKey ES256 below Android 13 still runs`() = runTest {
        val newKey = PivTestCertificates.ecKeyPair()

        val info = manager(sdkInt = 28, level = null, generates = newKey).generateKey(PivSlot.AUTHENTICATION, PivAlgorithm.ES256)

        assertEquals(PivAlgorithm.ES256, info.algorithm)
        assertTrue(keystore.live === newKey)
    }

    @Test
    fun `generateKey Ed25519 whose probe passed but whose key is software empties the slot and is refused`() = runTest {
        val newKey = PivTestCertificates.ed25519KeyPair()
        val manager = manager(level = KeySecurityLevel.SOFTWARE, probe = KeySecurityLevel.TEE, generates = newKey)

        val error = generateError(manager, PivAlgorithm.ED25519)

        assertTrue("got $error", error is PivAlgorithmUnavailableException)
        assertTrue(error?.message, error?.message?.contains("Android 13 secure hardware") == true)
        assertNull("the slot kept a software key", keystore.live)
        coVerify { pivSlotDao.deleteBySlotId("9A") }
        coVerify(exactly = 0) { pivSlotDao.upsert(any()) }
    }

    @Test
    fun `generateKey X25519 whose probe passed but whose key level cannot be read empties the slot and is refused`() = runTest {
        val manager = manager(level = null, probe = KeySecurityLevel.STRONGBOX, generates = PivTestCertificates.x25519KeyPair())

        val error = generateError(manager, PivAlgorithm.X25519)

        assertTrue("got $error", error is PivAlgorithmUnavailableException)
        assertNull(keystore.live)
        coVerify { pivSlotDao.deleteBySlotId("9A") }
        coVerify(exactly = 0) { pivSlotDao.upsert(any()) }
    }

    @Test
    fun `generateKey Ed25519 the Keystore cannot create is refused and the slot keeps its key`() = runTest {
        // The slot's row describes its key, so a failed replacement keeps both.
        coEvery { pivSlotDao.getBySlotId("9A") } returns PivTestCertificates.slotRow(slotKey.public.encoded)
        val manager = manager(generatorError = ProviderException("Unsupported EC curve: ed25519"))

        val error = generateError(manager, PivAlgorithm.ED25519)

        assertTrue("got $error", error is PivAlgorithmUnavailableException)
        assertTrue(keystore.live === slotKey)
        coVerify(exactly = 0) { pivSlotDao.upsert(any()) }
        coVerify(exactly = 0) { pivSlotDao.deleteBySlotId(any()) }
    }

    @Test
    fun `generateKey Ed25519 in the TEE records the key`() = runTest {
        val newKey = PivTestCertificates.ed25519KeyPair()

        val info = manager(level = KeySecurityLevel.TEE, generates = newKey).generateKey(PivSlot.AUTHENTICATION, PivAlgorithm.ED25519)

        assertEquals(PivAlgorithm.ED25519, info.algorithm)
        assertArrayEquals(newKey.public.encoded, info.publicKeyDer)
        coVerify {
            pivSlotDao.upsert(match {
                it.algorithm == "ED25519" && it.publicKeyDer.contentEquals(newKey.public.encoded) && it.hasKey
            })
        }
    }

    @Test
    fun `deleteKey of an empty slot writes no deleted entry`() = runTest {
        keystore.live = null
        coEvery { pivSlotDao.deleteBySlotId("9A") } returns 0

        testPivKeyManager(pivSlotDao).deleteKey(PivSlot.AUTHENTICATION)

        verify(exactly = 0) { AuditLogger.logKeyDeleted(any(), any(), any()) }
    }

    @Test
    fun `deleteKey of a populated slot writes one deleted entry`() = runTest {
        coEvery { pivSlotDao.deleteBySlotId("9A") } returns 1

        testPivKeyManager(pivSlotDao).deleteKey(PivSlot.AUTHENTICATION)

        assertNull(keystore.live)
        verify(exactly = 1) {
            AuditLogger.logKeyDeleted(PivSlot.AUTHENTICATION.keystoreAlias, PivSlot.AUTHENTICATION.label, "piv")
        }
    }

    @Test
    fun `generateKey X25519 in StrongBox records the key`() = runTest {
        val newKey = PivTestCertificates.x25519KeyPair()

        val info = manager(level = KeySecurityLevel.STRONGBOX, generates = newKey).generateKey(PivSlot.AUTHENTICATION, PivAlgorithm.X25519)

        assertEquals(PivAlgorithm.X25519, info.algorithm)
        coVerify { pivSlotDao.upsert(match { it.algorithm == "X25519" }) }
    }

    @Test
    fun `generateKey Ed25519 whose hardware probe reads software keeps the slot's key, row and certificate`() = runTest {
        val manager = manager(probe = KeySecurityLevel.SOFTWARE, generates = PivTestCertificates.ed25519KeyPair())

        assertRefusedBeforeTheSlot(manager, PivAlgorithm.ED25519)
    }

    @Test
    fun `generateKey X25519 whose hardware probe level cannot be read keeps the slot's key, row and certificate`() = runTest {
        val manager = manager(probe = null, generates = PivTestCertificates.x25519KeyPair())

        assertRefusedBeforeTheSlot(manager, PivAlgorithm.X25519)
    }

    /**
     * The manager's own probe, over the generator and level reader: it makes
     * its key under a disposable alias no slot has, always removes it, and
     * asks the Keystore once per algorithm.
     */
    @Test
    fun `the Keystore hardware probe uses a disposable alias, removes it, and runs once`() = runTest {
        val slotAlias = PivSlot.AUTHENTICATION.keystoreAlias
        val manager = testPivKeyManager(
            pivSlotDao,
            generateKeyPair = { alias, _ -> generate(alias, PivTestCertificates.ed25519KeyPair(), null) },
            securityLevelOf = { alias -> if (alias == slotAlias) KeySecurityLevel.TEE else KeySecurityLevel.SOFTWARE },
            probeSecurityLevel = null
        )

        assertRefusedBeforeTheSlot(manager, PivAlgorithm.ED25519)
        val probeAlias = generatedAliases.single()
        assertTrue(probeAlias, probeAlias.startsWith(PIV_KEYSTORE_ALIAS_PREFIX))
        assertFalse("the probe alias is a slot's", PivSlot.entries.any { it.keystoreAlias == probeAlias })
        verify { keystore.keyStore.deleteEntry(probeAlias) }

        assertFalse(PivAlgorithm.ED25519 in manager.availableAlgorithms())
        assertEquals("the probe ran again", 1, generatedAliases.count { it == probeAlias })
    }

    @Test
    fun `the Keystore hardware probe that cannot generate removes its alias and offers no curve 25519`() = runTest {
        val manager = testPivKeyManager(
            pivSlotDao,
            generateKeyPair = { alias, _ -> generate(alias, null, ProviderException("Unsupported EC curve")) },
            probeSecurityLevel = null
        )

        val offered = manager.availableAlgorithms()

        assertEquals(NON_CURVE_25519, offered)
        assertEquals(2, generatedAliases.size)
        generatedAliases.forEach { alias -> verify { keystore.keyStore.deleteEntry(alias) } }
        assertTrue(keystore.live === slotKey)
    }

    @Test
    fun `availableAlgorithms on API 33 whose probe reads software offers only ECDSA and RSA`() = runTest {
        val offered = manager(probe = KeySecurityLevel.SOFTWARE).availableAlgorithms()

        assertEquals(NON_CURVE_25519, offered)
    }

    @Test
    fun `availableAlgorithms offers curve 25519 only on API 33 with a secure hardware probe`() = runTest {
        assertEquals(PivAlgorithm.entries.toList(), manager(probe = KeySecurityLevel.TEE).availableAlgorithms())
        assertEquals(PivAlgorithm.entries.toList(), manager(probe = KeySecurityLevel.STRONGBOX).availableAlgorithms())
        assertEquals(
            NON_CURVE_25519,
            manager(sdkInt = 32, probe = KeySecurityLevel.TEE).availableAlgorithms()
        )
    }

    /**
     * Slot 9A holds key A with a row and an imported certificate; generating
     * [algorithm] with [manager] is refused as unavailable without the slot's
     * alias reaching the generator, and A, its row and its certificate stay.
     */
    private suspend fun assertRefusedBeforeTheSlot(manager: PivKeyManager, algorithm: PivAlgorithm) {
        val cert = PivTestCertificates.selfSigned(slotKey)
        coEvery { pivSlotDao.getBySlotId("9A") } returns PivTestCertificates.slotRow(slotKey.public.encoded, cert)

        val error = generateError(manager, algorithm)

        assertTrue("got $error", error is PivAlgorithmUnavailableException)
        assertFalse(
            "the generator ran under the slot's alias",
            PivSlot.AUTHENTICATION.keystoreAlias in generatedAliases
        )
        assertTrue("the slot lost its key", keystore.live === slotKey)
        verify(exactly = 0) { keystore.keyStore.deleteEntry(PivSlot.AUTHENTICATION.keystoreAlias) }
        coVerify(exactly = 0) { pivSlotDao.upsert(any()) }
        coVerify(exactly = 0) { pivSlotDao.deleteBySlotId(any()) }
        assertArrayEquals(cert, manager.getCertificate(PivSlot.AUTHENTICATION))
    }

    @Test
    fun `sign without an algorithm uses the slot's Ed25519 key over the raw message`() = runTest {
        val edKey = PivTestCertificates.ed25519KeyPair()
        keystore.live = edKey
        coEvery { pivSlotDao.getBySlotId("9A") } returns
            PivTestCertificates.slotRow(edKey.public.encoded, algorithm = PivAlgorithm.ED25519)
        val message = "xKey PIV Ed25519 message".toByteArray()

        val signature = manager().sign(PivSlot.AUTHENTICATION, message)

        val verifier = Signature.getInstance("Ed25519").apply {
            initVerify(edKey.public)
            update(message)
        }
        assertTrue("the Ed25519 signature does not verify", verifier.verify(signature))
        coVerify { pivSlotDao.recordUsage("9A", any()) }
    }

    @Test
    fun `sign on an X25519 slot is refused`() = runTest {
        val xKey = PivTestCertificates.x25519KeyPair()
        keystore.live = xKey
        coEvery { pivSlotDao.getBySlotId("9A") } returns
            PivTestCertificates.slotRow(xKey.public.encoded, algorithm = PivAlgorithm.X25519)

        val error = runCatching { manager().sign(PivSlot.AUTHENTICATION, byteArrayOf(1, 2, 3)) }.exceptionOrNull()

        assertTrue("got $error", error is IllegalArgumentException)
        assertEquals("X25519 keys cannot sign", error?.message)
        coVerify(exactly = 0) { pivSlotDao.recordUsage(any(), any()) }
    }

    @Test
    fun `sign with an algorithm other than the slot's is refused with a clear message`() = runTest {
        val edKey = PivTestCertificates.ed25519KeyPair()
        keystore.live = edKey
        coEvery { pivSlotDao.getBySlotId("9A") } returns
            PivTestCertificates.slotRow(edKey.public.encoded, algorithm = PivAlgorithm.ED25519)

        val error = runCatching { manager().sign(PivSlot.AUTHENTICATION, byteArrayOf(1), PivAlgorithm.ES256) }
            .exceptionOrNull()

        assertTrue("got $error", error is PivAlgorithmMismatchException)
        assertTrue(error?.message, error?.message?.contains("Ed25519") == true)
    }

    @Test
    fun `agree on an X25519 slot matches the peer's agreement`() = runTest {
        val phoneKey = PivTestCertificates.x25519KeyPair()
        keystore.live = phoneKey
        coEvery { pivSlotDao.getBySlotId("9A") } returns
            PivTestCertificates.slotRow(phoneKey.public.encoded, algorithm = PivAlgorithm.X25519)
        val peer = PivTestCertificates.x25519KeyPair()
        val peerRaw = PivPublicKeyEncoding.pivPublicKeyValue(peer.public.encoded)

        val secret = manager().agree(PivSlot.AUTHENTICATION, peerRaw)

        val expected = KeyAgreement.getInstance("XDH").run {
            init(peer.private)
            doPhase(phoneKey.public, true)
            generateSecret()
        }
        assertArrayEquals(expected, secret)
        coVerify { pivSlotDao.recordUsage("9A", any()) }
        verify { AuditLogger.logKeyUsed(PivSlot.AUTHENTICATION.keystoreAlias, any(), "piv", "key agreement", true, any(), any()) }
    }

    @Test
    fun `agree on a slot that is not X25519 is refused`() = runTest {
        coEvery { pivSlotDao.getBySlotId("9A") } returns PivTestCertificates.slotRow(slotKey.public.encoded)
        val peerRaw = PivPublicKeyEncoding.pivPublicKeyValue(PivTestCertificates.x25519KeyPair().public.encoded)

        val error = runCatching { manager().agree(PivSlot.AUTHENTICATION, peerRaw) }.exceptionOrNull()

        assertTrue("got $error", error is IllegalArgumentException)
        coVerify(exactly = 0) { pivSlotDao.recordUsage(any(), any()) }
    }

    @Test
    fun `agree refuses a peer key that is not 32 bytes or is all zeros`() = runTest {
        val phoneKey = PivTestCertificates.x25519KeyPair()
        keystore.live = phoneKey
        coEvery { pivSlotDao.getBySlotId("9A") } returns
            PivTestCertificates.slotRow(phoneKey.public.encoded, algorithm = PivAlgorithm.X25519)

        listOf(ByteArray(31) { 1 }, ByteArray(33) { 1 }, ByteArray(32)).forEach { peer ->
            val error = runCatching { manager().agree(PivSlot.AUTHENTICATION, peer) }.exceptionOrNull()
            assertTrue("peer of ${peer.size} bytes: got $error", error is IllegalArgumentException)
        }
        coVerify(exactly = 0) { pivSlotDao.recordUsage(any(), any()) }
    }

    @Test
    fun `getCertificate of an X25519 slot without an imported certificate is null`() = runTest {
        val xKey = PivTestCertificates.x25519KeyPair()
        keystore.live = xKey
        coEvery { pivSlotDao.getBySlotId("9A") } returns
            PivTestCertificates.slotRow(xKey.public.encoded, algorithm = PivAlgorithm.X25519)

        assertNull(manager().getCertificate(PivSlot.AUTHENTICATION))
    }

    @Test
    fun `listSlots reports a curve 25519 slot with its algorithm`() = runTest {
        val edKey = PivTestCertificates.ed25519KeyPair()
        keystore.live = edKey
        val row = PivTestCertificates.slotRow(edKey.public.encoded, algorithm = PivAlgorithm.ED25519)
        coEvery { pivSlotDao.getAll() } returns listOf(row)
        coEvery { pivSlotDao.getBySlotId("9A") } returns row

        val info = manager().listSlots().single()

        assertEquals(PivAlgorithm.ED25519, info.algorithm)
        assertArrayEquals(edKey.public.encoded, info.publicKeyDer)
    }

    // -------------------------------------------------------------------------
    // Slot users during a regenerate
    // -------------------------------------------------------------------------

    /**
     * Slot 9A holds an ES384 key A; another manager regenerates it as ES256
     * key B. A sign that starts once the Keystore holds B and before B's row
     * is written must wait for the row and sign with B as ES256, never pair
     * A's ES384 row with B.
     */
    @Test
    fun `sign during a regenerate waits for it and signs with the new key's algorithm`() = runTest(StandardTestDispatcher()) {
        val oldKey = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp384r1")) }
            .generateKeyPair()
        val newKey = PivTestCertificates.ecKeyPair()
        val message = "signed during a regenerate".toByteArray()

        val signature = whileRegenerating(
            oldKey,
            PivTestCertificates.slotRow(oldKey.public.encoded, algorithm = PivAlgorithm.ES384),
            PivAlgorithm.ES256,
            newKey
        ) { manager().sign(PivSlot.AUTHENTICATION, message) }

        val verifier = Signature.getInstance("SHA256withECDSA").apply {
            initVerify(newKey.public)
            update(message)
        }
        assertTrue("the signature is not B's ES256 signature", verifier.verify(signature))
    }

    /** As for sign: an agree during an ES256-to-X25519 regenerate agrees with the new X25519 key. */
    @Test
    fun `agree during a regenerate waits for it and agrees with the new key`() = runTest(StandardTestDispatcher()) {
        val newKey = PivTestCertificates.x25519KeyPair()
        val peer = PivTestCertificates.x25519KeyPair()
        val peerRaw = PivPublicKeyEncoding.pivPublicKeyValue(peer.public.encoded)

        val secret = whileRegenerating(
            slotKey,
            PivTestCertificates.slotRow(slotKey.public.encoded),
            PivAlgorithm.X25519,
            newKey
        ) { manager().agree(PivSlot.AUTHENTICATION, peerRaw) }

        val expected = KeyAgreement.getInstance("XDH").run {
            init(peer.private)
            doPhase(newKey.public, true)
            generateSecret()
        }
        assertArrayEquals(expected, secret)
    }

    /**
     * getCertificate during a regenerate from ES256 key A with an imported
     * certificate to X25519 key B answers for B (no certificate), never A's.
     */
    @Test
    fun `getCertificate during a regenerate waits for it and answers for the new key`() = runTest(StandardTestDispatcher()) {
        val oldRow = PivTestCertificates.slotRow(slotKey.public.encoded, PivTestCertificates.selfSigned(slotKey))

        val certificate = whileRegenerating(slotKey, oldRow, PivAlgorithm.X25519, PivTestCertificates.x25519KeyPair()) {
            manager().getCertificate(PivSlot.AUTHENTICATION)
        }

        assertNull("the replaced key's certificate was returned", certificate)
    }

    /**
     * Slot 9A holds [oldKey] with [oldRow]; a generation of [algorithm] makes
     * [newKey] and is held after the Keystore holds it and before its row is
     * written. [use] starts there, must not finish while the generation holds
     * the slot, and its result is returned once the generation is done.
     */
    @OptIn(ExperimentalCoroutinesApi::class)
    private suspend fun <T> TestScope.whileRegenerating(
        oldKey: KeyPair,
        oldRow: PivSlotEntity,
        algorithm: PivAlgorithm,
        newKey: KeyPair,
        use: suspend () -> T
    ): T {
        keystore.live = oldKey
        var row = oldRow
        coEvery { pivSlotDao.getBySlotId("9A") } answers { row }
        val upsertGate = CompletableDeferred<Unit>()
        coEvery { pivSlotDao.upsert(any()) } coAnswers {
            upsertGate.await()
            row = firstArg()
            1L
        }

        val generate = launch { manager(generates = newKey).generateKey(PivSlot.AUTHENTICATION, algorithm) }
        runCurrent()
        assertTrue("generate did not reach its upsert", keystore.live === newKey)
        val using = async { use() }
        runCurrent()
        assertFalse("the slot was used while a generation held it", using.isCompleted)

        upsertGate.complete(Unit)
        generate.join()
        return using.await()
    }

    /**
     * A manager whose Keystore generator puts the next key in [keystore] when
     * it generates under the slot's alias (or throws [generatorError]), on
     * platform level [sdkInt], reading [level] as every key's security level
     * and [probe] as the hardware probe's answer for every curve 25519
     * algorithm. Every alias the generator is called with lands in
     * [generatedAliases].
     */
    private fun manager(
        sdkInt: Int = SUPPORTED_TEST_SDK,
        level: KeySecurityLevel? = KeySecurityLevel.TEE,
        probe: KeySecurityLevel? = level,
        generates: KeyPair? = null,
        generatorError: Exception? = null
    ) = testPivKeyManager(
        pivSlotDao,
        generateKeyPair = { alias, _ -> generate(alias, generates, generatorError) },
        sdkInt = sdkInt,
        securityLevelOf = { level },
        probeSecurityLevel = { probe }
    )

    private fun generate(alias: String, generates: KeyPair?, generatorError: Exception?): KeyPair {
        generatorCalls++
        generatedAliases += alias
        generatorError?.let { throw it }
        val next = generates ?: error("this test generates no key")
        if (alias == PivSlot.AUTHENTICATION.keystoreAlias) keystore.live = next
        return next
    }

    private suspend fun generateError(manager: PivKeyManager, algorithm: PivAlgorithm): Throwable? =
        runCatching { manager.generateKey(PivSlot.AUTHENTICATION, algorithm) }.exceptionOrNull()

    @Test
    fun `a hardware ML-DSA-87 slot asked for ML-DSA-44 refuses before it signs`() = runTest {
        val slotCertificate = mockk<Certificate>()
        every { slotCertificate.publicKey.encoded } returns PqcKeysTest.spkiOf(MlDsaParameterSet.ML_DSA_87)
        every { keystore.keyStore.getCertificate(PivSlot.AUTHENTICATION.keystoreAlias) } returns slotCertificate
        val saved = PqcHardware.backend
        PqcHardware.backend = object : PqcHardwareBackend {
            override fun supportedParameterSets() = MlDsaParameterSet.entries.toSet()
            override fun generate(
                alias: String,
                set: MlDsaParameterSet,
                authDurationSeconds: Int,
                preferStrongBox: Boolean
            ): ByteArray = throw UnsupportedOperationException()
            override fun jcaSignatureAlgorithm(set: MlDsaParameterSet) = "ML-DSA"
        }
        try {
            val error = runCatching {
                testPivKeyManager(pivSlotDao).sign(PivSlot.AUTHENTICATION, byteArrayOf(1), PivAlgorithm.ML_DSA_44)
            }.exceptionOrNull()
            assertTrue("$error", error is UnsupportedAlgorithmException)
            coVerify(exactly = 0) { pivSlotDao.recordUsage(any()) }
        } finally {
            PqcHardware.backend = saved
        }
    }

    @Test
    fun `deleteKey of a slot with only its row writes one deleted entry`() = runTest {
        keystore.live = null
        coEvery { pivSlotDao.deleteBySlotId("9A") } returns 1

        testPivKeyManager(pivSlotDao).deleteKey(PivSlot.AUTHENTICATION)

        verify(exactly = 1) { AuditLogger.logKeyDeleted(any(), any(), "piv") }
    }

    @Test
    fun `a software ML-DSA slot key whose record cannot be removed keeps its row and is not audited as deleted`() =
        runTest {
            keystore.live = null
            val store = softwareStore()
            val alias = PivSlot.AUTHENTICATION.keystoreAlias
            store.generate(alias, MlDsaParameterSet.ML_DSA_44)
            store.removeFile = { false }

            val error = runCatching { testPivKeyManager(pivSlotDao, pqcStore = store).deleteKey(PivSlot.AUTHENTICATION) }
                .exceptionOrNull()

            assertTrue("delete must fail, got $error", error != null)
            coVerify(exactly = 0) { pivSlotDao.deleteBySlotId(any()) }
            verify(exactly = 0) { AuditLogger.logKeyDeleted(any(), any(), any()) }
            assertTrue(store.contains(alias))
        }

    @Test
    fun `a PIV delete keeps the slot row and skips the audit whenever the store delete throws`() = runTest {
        keystore.live = null
        val store = io.mockk.spyk(softwareStore())
        val alias = PivSlot.AUTHENTICATION.keystoreAlias
        store.generate(alias, MlDsaParameterSet.ML_DSA_44)
        every { store.delete(any()) } throws java.io.IOException("Cannot delete ML-DSA key")

        val error = runCatching { testPivKeyManager(pivSlotDao, pqcStore = store).deleteKey(PivSlot.AUTHENTICATION) }
            .exceptionOrNull()

        assertTrue("delete must fail, got $error", error is java.io.IOException)
        coVerify(exactly = 0) { pivSlotDao.deleteBySlotId(any()) }
        verify(exactly = 0) { AuditLogger.logKeyDeleted(any(), any(), any()) }
    }

    /** A software ML-DSA store over a temporary directory and a stand-in seal. */
    private fun softwareStore(): PqcSoftwareKeyStore {
        val cipher = mockk<KeystoreAeadCipher>()
        every { cipher.encrypt(any()) } answers { firstArg<ByteArray>().reversedArray() }
        every { cipher.decrypt(any()) } answers { firstArg<ByteArray>().reversedArray() }
        val context = mockk<Context>(relaxed = true)
        every { context.filesDir } returns java.nio.file.Files.createTempDirectory("piv-pqc").toFile()
        return PqcSoftwareKeyStore(context, cipher)
    }

    private fun stubSigningAudit() {
        every {
            AuditLogger.logSigningRequest(any(), any(), any(), any(), any(), any(), any(), any(), any())
        } returns Unit
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    @Test
    fun `a software ML-DSA sign holds the slot lock until it has recorded its use`() = runTest(StandardTestDispatcher()) {
        stubSigningAudit()
        keystore.live = null
        val store = softwareStore()
        val alias = PivSlot.AUTHENTICATION.keystoreAlias
        store.generate(alias, MlDsaParameterSet.ML_DSA_44)
        val usageGate = CompletableDeferred<Unit>()
        coEvery { pivSlotDao.recordUsage(any(), any()) } coAnswers { usageGate.await() }

        val sign = async {
            testPivKeyManager(pivSlotDao, pqcStore = store)
                .sign(PivSlot.AUTHENTICATION, byteArrayOf(1), PivAlgorithm.ML_DSA_44)
        }
        runCurrent()
        assertFalse("sign ended before it recorded its use: ${runCatching { sign.getCompleted() }}", sign.isCompleted)
        val generate = launch {
            testPivKeyManager(pivSlotDao, pqcStore = store)
                .generateKey(PivSlot.AUTHENTICATION, PivAlgorithm.ML_DSA_87, PqcBacking.SOFTWARE)
        }
        runCurrent()

        assertFalse("generateKey ran while a sign held the slot", generate.isCompleted)
        assertEquals(MlDsaParameterSet.ML_DSA_44, store.parameterSet(alias))

        usageGate.complete(Unit)
        assertEquals(MlDsaParameterSet.ML_DSA_44.signatureBytes, sign.await().size)
        generate.join()
        assertEquals(MlDsaParameterSet.ML_DSA_87, store.parameterSet(alias))
    }

    @Test
    fun `a software slot regenerated as ML-DSA-87 refuses an ML-DSA-44 sign`() = runTest {
        stubSigningAudit()
        keystore.live = null
        val store = softwareStore()
        val manager = testPivKeyManager(pivSlotDao, pqcStore = store)
        manager.generateKey(PivSlot.AUTHENTICATION, PivAlgorithm.ML_DSA_44, PqcBacking.SOFTWARE)
        manager.generateKey(PivSlot.AUTHENTICATION, PivAlgorithm.ML_DSA_87, PqcBacking.SOFTWARE)

        val error = runCatching {
            manager.sign(PivSlot.AUTHENTICATION, byteArrayOf(1), PivAlgorithm.ML_DSA_44)
        }.exceptionOrNull()
        assertTrue("$error", error is IllegalStateException)
        coVerify(exactly = 0) { pivSlotDao.recordUsage(any()) }
    }

    private suspend fun importError(certDer: ByteArray): Throwable? =
        runCatching { testPivKeyManager(pivSlotDao).importCertificate(PivSlot.AUTHENTICATION, certDer) }
            .exceptionOrNull()
}

/**
 * A stand-in for the AndroidKeyStore that holds at most the slot 9A key,
 * [live], and serves it the way the provider does: as the public key of the
 * alias's self-signed certificate. [install] routes
 * `KeyStore.getInstance("AndroidKeyStore")` to it; [generatesOnNextCall]
 * routes the Keystore key generator in [PivKeyManager.generateKey] to it.
 */
internal class FakePivKeystore(@Volatile var live: KeyPair?) {
    private val alias = PivSlot.AUTHENTICATION.keystoreAlias
    private val certificates = HashMap<KeyPair, Certificate>()
    val keyStore: KeyStore = mockk(relaxed = true)

    init {
        every { keyStore.containsAlias(any()) } returns false
        every { keyStore.getCertificate(any()) } returns null
        every { keyStore.getKey(any(), any()) } returns null
        every { keyStore.containsAlias(alias) } answers { live != null }
        every { keyStore.getCertificate(alias) } answers { live?.let(::certificateOf) }
        every { keyStore.getKey(alias, any()) } answers { live?.private }
        every { keyStore.deleteEntry(alias) } answers { live = null }
    }

    fun install() {
        mockkStatic(KeyStore::class)
        every { KeyStore.getInstance("AndroidKeyStore") } returns keyStore
    }

    /** The next AndroidKeyStore key generation replaces [live] with [next]. */
    fun generatesOnNextCall(next: KeyPair) {
        mockkConstructor(KeyGenParameterSpec.Builder::class)
        val spec = mockk<KeyGenParameterSpec>()
        every { anyConstructed<KeyGenParameterSpec.Builder>().setDigests(*anyVararg()) } answers { self as KeyGenParameterSpec.Builder }
        every { anyConstructed<KeyGenParameterSpec.Builder>().setKeySize(any()) } answers { self as KeyGenParameterSpec.Builder }
        every { anyConstructed<KeyGenParameterSpec.Builder>().setSignaturePaddings(*anyVararg()) } answers { self as KeyGenParameterSpec.Builder }
        every { anyConstructed<KeyGenParameterSpec.Builder>().build() } returns spec
        val generator = mockk<KeyPairGenerator>(relaxed = true)
        every { generator.initialize(any<AlgorithmParameterSpec>()) } returns Unit
        every { generator.generateKeyPair() } answers { live = next; next }
        mockkStatic(KeyPairGenerator::class)
        every { KeyPairGenerator.getInstance(any<String>(), "AndroidKeyStore") } returns generator
    }

    private fun certificateOf(keyPair: KeyPair): Certificate = certificates.getOrPut(keyPair) {
        CertificateFactory.getInstance("X.509")
            .generateCertificate(PivTestCertificates.selfSigned(keyPair).inputStream())
    }
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

    /** A fresh Ed25519 key pair, the shape an `ED25519` slot key has. */
    fun ed25519KeyPair(): KeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()

    /** A fresh X25519 key pair, the shape an `X25519` slot key has. */
    fun x25519KeyPair(): KeyPair = KeyPairGenerator.getInstance("X25519").generateKeyPair()

    /**
     * A DER certificate whose subject key is [keyPair]'s public key, signed by
     * that key. An X25519 key cannot sign, so its certificate is signed by a
     * throwaway P-256 key, as the Keystore's certificate for such a key
     * carries no valid self-signature either.
     */
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
        val (signingKey, signatureAlgorithm) = when (keyPair.public.algorithm) {
            "EdDSA", "Ed25519" -> keyPair.private to "Ed25519"
            "XDH", "X25519" -> ecKeyPair().private to "SHA256withECDSA"
            "RSA" -> keyPair.private to "SHA256withRSA"
            else -> keyPair.private to "SHA256withECDSA"
        }
        val signer = JcaContentSignerBuilder(signatureAlgorithm).build(signingKey)
        return builder.build(signer).encoded
    }

    /** The `piv_slots` row for slot 9A holding [publicKeyDer]. */
    fun slotRow(
        publicKeyDer: ByteArray,
        certificateDer: ByteArray? = null,
        algorithm: PivAlgorithm = PivAlgorithm.ES256
    ) = PivSlotEntity(
        slotId = "9A",
        algorithm = algorithm.name,
        publicKeyDer = publicKeyDer,
        certificateDer = certificateDer,
        hasKey = true
    )
}
