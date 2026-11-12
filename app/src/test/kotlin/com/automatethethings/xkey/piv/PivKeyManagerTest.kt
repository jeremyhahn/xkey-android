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

import android.security.keystore.KeyGenParameterSpec
import android.util.Log
import com.automatethethings.xkey.audit.AuditLogger
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.coVerifyOrder
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.spec.AlgorithmParameterSpec
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
 * [PivKeyManager.importCertificate] checks a certificate against the slot's
 * live Keystore key, so it is tested over a mocked [PivSlotDao] and a
 * [FakePivKeystore] holding a JDK-generated P-256 key in place of the
 * AndroidKeyStore entry (#173). The `piv_slots` row is only a cache: tests
 * where it disagrees with the Keystore pin that the Keystore decides.
 */
class PivKeyManagerTest {

    private lateinit var pivSlotDao: PivSlotDao
    private val slotKey = PivTestCertificates.ecKeyPair()
    private lateinit var keystore: FakePivKeystore

    @Before
    fun setUp() {
        mockkStatic(Log::class)
        every { Log.i(any(), any<String>()) } returns 0
        every { Log.w(any(), any<String>()) } returns 0
        every { Log.d(any(), any<String>()) } returns 0
        pivSlotDao = mockk(relaxed = true)
        keystore = FakePivKeystore(slotKey).also { it.install() }
        mockkObject(AuditLogger)
        every { AuditLogger.logKeyDeleted(any(), any(), any()) } returns Unit
        every { AuditLogger.logKeyCreated(any(), any(), any(), any()) } returns Unit
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
        val importer = PivKeyManager(pivSlotDao)
        val deleter = PivKeyManager(pivSlotDao)
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

        PivKeyManager(pivSlotDao).importCertificate(PivSlot.AUTHENTICATION, cert)

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
        val manager = PivKeyManager(pivSlotDao)

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

        val generate = launch { PivKeyManager(pivSlotDao).generateKey(PivSlot.AUTHENTICATION, PivAlgorithm.ES256) }
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

        val generate = launch { PivKeyManager(pivSlotDao).generateKey(PivSlot.AUTHENTICATION, PivAlgorithm.RS2048) }
        runCurrent()
        assertTrue("generate did not reach its upsert", keystore.live === newKey)
        val listing = async { PivKeyManager(pivSlotDao).listSlots() }
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
