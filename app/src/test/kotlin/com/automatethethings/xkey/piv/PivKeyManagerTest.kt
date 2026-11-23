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
import com.automatethethings.xkey.crypto.KeySecurityLevel
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
import java.security.ProviderException
import java.security.Signature
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.ECGenParameterSpec
import java.util.Date
import javax.crypto.KeyAgreement

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
        every { AuditLogger.logPivCertImported(any(), any()) } returns Unit
        every {
            AuditLogger.logSigningRequest(any(), any(), any(), any(), any(), any(), any(), any(), any())
        } returns Unit
        every { AuditLogger.logKeyUsed(any(), any(), any(), any(), any(), any(), any()) } returns Unit
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
    fun `importCertificate writes one audit entry naming the slot and subject`() = runTest {
        coEvery { pivSlotDao.getBySlotId("9A") } returns PivTestCertificates.slotRow(slotKey.public.encoded)

        PivKeyManager(pivSlotDao).importCertificate(PivSlot.AUTHENTICATION, PivTestCertificates.selfSigned(slotKey))

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
    fun `generateKey Ed25519 in a software Keystore empties the slot and is refused`() = runTest {
        val newKey = PivTestCertificates.ed25519KeyPair()

        val error = generateError(manager(level = KeySecurityLevel.SOFTWARE, generates = newKey), PivAlgorithm.ED25519)

        assertTrue("got $error", error is PivAlgorithmUnavailableException)
        assertTrue(error?.message, error?.message?.contains("Android 13 secure hardware") == true)
        assertNull("the slot kept a software key", keystore.live)
        coVerify { pivSlotDao.deleteBySlotId("9A") }
        coVerify(exactly = 0) { pivSlotDao.upsert(any()) }
    }

    @Test
    fun `generateKey X25519 whose security level cannot be read empties the slot and is refused`() = runTest {
        val error = generateError(manager(level = null, generates = PivTestCertificates.x25519KeyPair()), PivAlgorithm.X25519)

        assertTrue("got $error", error is PivAlgorithmUnavailableException)
        assertNull(keystore.live)
        coVerify { pivSlotDao.deleteBySlotId("9A") }
        coVerify(exactly = 0) { pivSlotDao.upsert(any()) }
    }

    @Test
    fun `generateKey Ed25519 the Keystore cannot create is refused and the slot keeps its key`() = runTest {
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
    fun `generateKey X25519 in StrongBox records the key`() = runTest {
        val newKey = PivTestCertificates.x25519KeyPair()

        val info = manager(level = KeySecurityLevel.STRONGBOX, generates = newKey).generateKey(PivSlot.AUTHENTICATION, PivAlgorithm.X25519)

        assertEquals(PivAlgorithm.X25519, info.algorithm)
        coVerify { pivSlotDao.upsert(match { it.algorithm == "X25519" }) }
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

    /**
     * A manager whose Keystore generator puts the next key in [keystore] (or
     * throws [generatorError]), on platform level [sdkInt], reading [level]
     * as every key's security level.
     */
    private fun manager(
        sdkInt: Int = 33,
        level: KeySecurityLevel? = KeySecurityLevel.TEE,
        generates: KeyPair? = null,
        generatorError: Exception? = null
    ) = PivKeyManager(
        pivSlotDao,
        generateKeyPair = { _, _ ->
            generatorCalls++
            generatorError?.let { throw it }
            val next = generates ?: error("this test generates no key")
            keystore.live = next
            next
        },
        sdkInt = sdkInt,
        securityLevelOf = { level }
    )

    private suspend fun generateError(manager: PivKeyManager, algorithm: PivAlgorithm): Throwable? =
        runCatching { manager.generateKey(PivSlot.AUTHENTICATION, algorithm) }.exceptionOrNull()

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
