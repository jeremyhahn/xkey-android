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

import android.content.Context
import com.automatethethings.xkey.audit.AuditLogDao
import com.automatethethings.xkey.audit.AuditLogEntity
import com.automatethethings.xkey.audit.AuditLogger
import com.automatethethings.xkey.audit.AuditOperationType
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.unmockkAll
import java.io.File
import java.security.cert.CertificateException
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * Unit tests for [TrustStoreRepository].
 *
 * The repository is one of the few trust-critical classes that is fully exercisable
 * on the JVM: it touches only `Context.getDir`, the file system and the JCA, so a
 * mocked [Context] pointing at a [TemporaryFolder] gives a real, isolated trust store
 * per test. Certificate fixtures come from [TestCertificates]; fingerprints are
 * asserted against a SHA-256 digest computed in the test rather than against the
 * repository's own output.
 *
 * Coverage focuses on the trust decisions: self-signed rejection, duplicate handling,
 * chain validation against imported anchors, and rejection of chains that do not
 * lead to a trusted root.
 */
class TrustStoreRepositoryTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    private lateinit var context: Context
    private lateinit var caFetcher: CABundleFetcher
    private lateinit var repository: TrustStoreRepository
    private lateinit var storeDir: File

    @Before
    fun setUp() {
        storeDir = tempFolder.newFolder("trust_store")
        context = mockk()
        every { context.getDir("trust_store", Context.MODE_PRIVATE) } returns storeDir
        caFetcher = mockk()
        repository = TrustStoreRepository(context, caFetcher)
    }

    @After
    fun tearDown() {
        auditHolder<AuditLogDao>("daoRef").set(null)
        auditHolder<CoroutineScope>("scopeRef").set(null)
        unmockkAll()
    }

    private fun newRepository() = TrustStoreRepository(context, caFetcher)

    // -------------------------------------------------------------------------
    // Audit capture
    // -------------------------------------------------------------------------

    private val audited = mutableListOf<AuditLogEntity>()

    @Suppress("UNCHECKED_CAST")
    private fun <T> auditHolder(name: String): AtomicReference<T?> =
        AuditLogger::class.java.getDeclaredField(name)
            .apply { isAccessible = true }
            .get(AuditLogger) as AtomicReference<T?>

    /** Route [AuditLogger] writes into [audited], synchronously. */
    private fun captureAudit() {
        audited.clear()
        val dao = mockk<AuditLogDao>(relaxed = true)
        coEvery { dao.insert(any()) } answers {
            audited += firstArg<AuditLogEntity>()
            audited.size.toLong()
        }
        auditHolder<AuditLogDao>("daoRef").set(dao)
        auditHolder<CoroutineScope>("scopeRef").set(CoroutineScope(Dispatchers.Unconfined))
    }

    private fun auditedOf(type: AuditOperationType) = audited.filter { it.operationType == type }

    private fun details(entry: AuditLogEntity): JSONObject = JSONObject(entry.details!!)

    // -------------------------------------------------------------------------
    // importCertificate — accepted input
    // -------------------------------------------------------------------------

    @Test
    fun `importCertificate stores a CA-signed certificate with its metadata`() = runTest {
        val der = TestCertificates.der(TestCertificates.LEAF_A_PEM)

        val stored = repository.importCertificate(der, label = "laptop")

        assertNotNull(stored)
        assertEquals(TestCertificates.fingerprint(TestCertificates.LEAF_A_PEM), stored!!.fingerprint)
        assertTrue(stored.subjectDN.startsWith(TestCertificates.LEAF_A_CN))
        assertTrue(stored.issuerDN.startsWith(TestCertificates.ROOT_A_CN))
        assertEquals(TestCertificates.LONG_LIVED_NOT_AFTER_MILLIS, stored.notAfter)
        assertEquals("laptop", stored.label)
        assertEquals("manual", stored.source)
        assertFalse(stored.systemInstalled)
    }

    @Test
    fun `importCertificate writes the DER to disk under its fingerprint`() = runTest {
        val der = TestCertificates.der(TestCertificates.LEAF_A_PEM)
        val fingerprint = TestCertificates.fingerprint(TestCertificates.LEAF_A_PEM)

        repository.importCertificate(der)

        val onDisk = File(storeDir, "$fingerprint.der")
        assertTrue(onDisk.exists())
        assertArrayEqualsBytes(der, onDisk.readBytes())
    }

    @Test
    fun `importCertificate allows a null label`() = runTest {
        val stored = repository.importCertificate(TestCertificates.der(TestCertificates.LEAF_A_PEM))

        assertNotNull(stored)
        assertNull(stored!!.label)
    }

    // -------------------------------------------------------------------------
    // importCertificate — rejected input
    // -------------------------------------------------------------------------

    @Test
    fun `importCertificate rejects a self-signed certificate`() = runTest {
        val der = TestCertificates.der(TestCertificates.ROOT_CA_A_PEM)

        val error = assertFails(IllegalArgumentException::class.java) {
            repository.importCertificate(der)
        }

        assertEquals("Self-signed certificates are not accepted", error.message)
        assertEquals(0, repository.getCertificateCount())
    }

    @Test
    fun `importCertificate rejects garbage bytes`() = runTest {
        assertFails(CertificateException::class.java) {
            repository.importCertificate(byteArrayOf(0x01, 0x02, 0x03, 0x04))
        }
        assertEquals(0, repository.getCertificateCount())
    }

    @Test
    fun `importCertificate rejects an empty byte array`() = runTest {
        assertFails(CertificateException::class.java) {
            repository.importCertificate(ByteArray(0))
        }
        assertEquals(0, repository.getCertificateCount())
    }

    @Test
    fun `importCertificate returns null for a duplicate import`() = runTest {
        val der = TestCertificates.der(TestCertificates.LEAF_A_PEM)

        assertNotNull(repository.importCertificate(der, label = "first"))
        assertNull(repository.importCertificate(der, label = "second"))
        assertEquals(1, repository.getCertificateCount())
    }

    // -------------------------------------------------------------------------
    // Lookup semantics
    // -------------------------------------------------------------------------

    @Test
    fun `getCertificate finds an imported certificate by fingerprint`() = runTest {
        repository.importCertificate(TestCertificates.der(TestCertificates.LEAF_A_PEM), "laptop")
        val fingerprint = TestCertificates.fingerprint(TestCertificates.LEAF_A_PEM)

        val found = repository.getCertificate(fingerprint)

        assertNotNull(found)
        assertEquals(fingerprint, found!!.fingerprint)
        assertEquals("laptop", found.label)
    }

    @Test
    fun `getCertificate returns null for an unknown fingerprint`() = runTest {
        repository.importCertificate(TestCertificates.der(TestCertificates.LEAF_A_PEM))

        assertNull(repository.getCertificate("00".repeat(32)))
    }

    @Test
    fun `getCertificateDER returns the exact stored bytes`() = runTest {
        val der = TestCertificates.der(TestCertificates.LEAF_A_PEM)
        repository.importCertificate(der)

        val readBack = repository.getCertificateDER(
            TestCertificates.fingerprint(TestCertificates.LEAF_A_PEM)
        )

        assertNotNull(readBack)
        assertArrayEqualsBytes(der, readBack!!)
    }

    @Test
    fun `getCertificateDER returns null for an unknown fingerprint`() = runTest {
        assertNull(repository.getCertificateDER("ff".repeat(32)))
    }

    @Test
    fun `hasCertificate reflects presence`() = runTest {
        repository.importCertificate(TestCertificates.der(TestCertificates.LEAF_A_PEM))

        assertTrue(repository.hasCertificate(TestCertificates.fingerprint(TestCertificates.LEAF_A_PEM)))
        assertFalse(repository.hasCertificate(TestCertificates.fingerprint(TestCertificates.LEAF_B_PEM)))
    }

    @Test
    fun `getCertificateCount counts distinct certificates`() = runTest {
        assertEquals(0, repository.getCertificateCount())

        repository.importCertificate(TestCertificates.der(TestCertificates.LEAF_A_PEM))
        repository.importCertificate(TestCertificates.der(TestCertificates.LEAF_B_PEM))

        assertEquals(2, repository.getCertificateCount())
    }

    @Test
    fun `searchBySubject matches case-insensitively`() = runTest {
        repository.importCertificate(TestCertificates.der(TestCertificates.LEAF_A_PEM))
        repository.importCertificate(TestCertificates.der(TestCertificates.LEAF_B_PEM))

        val matches = repository.searchBySubject("DEVICE-A.XKEY")

        assertEquals(1, matches.size)
        assertTrue(matches[0].subjectDN.startsWith(TestCertificates.LEAF_A_CN))
    }

    @Test
    fun `searchBySubject returns empty when nothing matches`() = runTest {
        repository.importCertificate(TestCertificates.der(TestCertificates.LEAF_A_PEM))

        assertTrue(repository.searchBySubject("no-such-device").isEmpty())
    }

    // -------------------------------------------------------------------------
    // Expiry queries
    // -------------------------------------------------------------------------

    @Test
    fun `getExpiredCertificates returns only past-dated certificates`() = runTest {
        repository.importCertificate(TestCertificates.der(TestCertificates.LEAF_A_PEM))
        repository.importCertificate(TestCertificates.der(TestCertificates.EXPIRED_LEAF_A_PEM))

        val expired = repository.getExpiredCertificates()

        assertEquals(1, expired.size)
        assertTrue(expired[0].subjectDN.startsWith(TestCertificates.EXPIRED_LEAF_A_CN))
        assertEquals(TestCertificates.EXPIRED_LEAF_A_NOT_AFTER_MILLIS, expired[0].notAfter)
    }

    @Test
    fun `getExpiringCertificates excludes long-lived certificates`() = runTest {
        repository.importCertificate(TestCertificates.der(TestCertificates.LEAF_A_PEM))
        repository.importCertificate(TestCertificates.der(TestCertificates.EXPIRED_LEAF_A_PEM))

        val expiring = repository.getExpiringCertificates(days = 30)

        assertEquals(1, expiring.size)
        assertTrue(expiring[0].subjectDN.startsWith(TestCertificates.EXPIRED_LEAF_A_CN))
    }

    // -------------------------------------------------------------------------
    // Deletion
    // -------------------------------------------------------------------------

    @Test
    fun `deleteCertificate removes the entry and leaves the others`() = runTest {
        repository.importCertificate(TestCertificates.der(TestCertificates.LEAF_A_PEM))
        repository.importCertificate(TestCertificates.der(TestCertificates.LEAF_B_PEM))
        val fingerprintA = TestCertificates.fingerprint(TestCertificates.LEAF_A_PEM)

        assertTrue(repository.deleteCertificate(fingerprintA))

        assertFalse(repository.hasCertificate(fingerprintA))
        assertNull(repository.getCertificate(fingerprintA))
        assertEquals(1, repository.getCertificateCount())
        assertTrue(
            repository.hasCertificate(TestCertificates.fingerprint(TestCertificates.LEAF_B_PEM))
        )
    }

    @Test
    fun `deleteCertificate returns false for an unknown fingerprint`() = runTest {
        repository.importCertificate(TestCertificates.der(TestCertificates.LEAF_A_PEM))

        assertFalse(repository.deleteCertificate("ab".repeat(32)))
        assertEquals(1, repository.getCertificateCount())
    }

    // -------------------------------------------------------------------------
    // Metadata persistence
    // -------------------------------------------------------------------------

    @Test
    fun `getAllCertificates is empty when no metadata file exists`() = runTest {
        assertTrue(repository.getAllCertificates().isEmpty())
    }

    @Test
    fun `getAllCertificates is empty when metadata is corrupt`() = runTest {
        File(storeDir, "metadata.json").writeText("this is not json")

        assertTrue(repository.getAllCertificates().isEmpty())
    }

    // -------------------------------------------------------------------------
    // Internal CA import (self-signed roots are allowed here)
    // -------------------------------------------------------------------------

    @Test
    fun `importInternalCACertificate accepts a self-signed root`() = runTest {
        val root = TestCertificates.cert(TestCertificates.ROOT_CA_A_PEM)

        val fingerprint = repository.importInternalCACertificate(root, "xKey Root CA")

        assertEquals(TestCertificates.fingerprint(TestCertificates.ROOT_CA_A_PEM), fingerprint)
        val stored = repository.getCertificate(fingerprint)
        assertNotNull(stored)
        assertEquals("internal-ca", stored!!.source)
        assertEquals("xKey Root CA", stored.label)
    }

    @Test
    fun `importInternalCACertificate is idempotent`() = runTest {
        val root = TestCertificates.cert(TestCertificates.ROOT_CA_A_PEM)

        val first = repository.importInternalCACertificate(root, "xKey Root CA")
        val second = repository.importInternalCACertificate(root, "different label")

        assertEquals(first, second)
        assertEquals(1, repository.getCertificateCount())
        assertEquals("xKey Root CA", repository.getCertificate(first)!!.label)
    }

    // -------------------------------------------------------------------------
    // System install flag
    // -------------------------------------------------------------------------

    @Test
    fun `updateSystemInstalled only changes the targeted certificate`() = runTest {
        repository.importCertificate(TestCertificates.der(TestCertificates.LEAF_A_PEM))
        repository.importCertificate(TestCertificates.der(TestCertificates.LEAF_B_PEM))
        val fingerprintA = TestCertificates.fingerprint(TestCertificates.LEAF_A_PEM)
        val fingerprintB = TestCertificates.fingerprint(TestCertificates.LEAF_B_PEM)

        repository.updateSystemInstalled(fingerprintA, true)

        assertTrue(repository.getCertificate(fingerprintA)!!.systemInstalled)
        assertFalse(repository.getCertificate(fingerprintB)!!.systemInstalled)
    }

    @Test
    fun `updateSystemInstalled can clear the flag again`() = runTest {
        repository.importCertificate(TestCertificates.der(TestCertificates.LEAF_A_PEM))
        val fingerprint = TestCertificates.fingerprint(TestCertificates.LEAF_A_PEM)

        repository.updateSystemInstalled(fingerprint, true)
        repository.updateSystemInstalled(fingerprint, false)

        assertFalse(repository.getCertificate(fingerprint)!!.systemInstalled)
    }

    @Test
    fun `refreshSystemInstallStatus is a no-op without an Android CA store`() = runTest {
        repository.importCertificate(TestCertificates.der(TestCertificates.LEAF_A_PEM))
        val before = repository.getAllCertificates()

        repository.refreshSystemInstallStatus()

        assertEquals(before, repository.getAllCertificates())
    }

    // -------------------------------------------------------------------------
    // Chain verification — rejection
    // -------------------------------------------------------------------------

    @Test
    fun `verifyIDevIDChain rejects an empty chain`() = runTest {
        val result = repository.verifyIDevIDChain(emptyList())

        assertTrue(result is VerificationResult.Invalid)
        assertEquals("Empty certificate chain", (result as VerificationResult.Invalid).error)
    }

    @Test
    fun `verifyIDevIDChain rejects a self-signed leaf even with anchors present`() = runTest {
        repository.importInternalCACertificate(
            TestCertificates.cert(TestCertificates.ROOT_CA_A_PEM),
            "root"
        )

        val result = repository.verifyIDevIDChain(
            listOf(TestCertificates.der(TestCertificates.ROOT_CA_A_PEM))
        )

        assertEquals(VerificationResult.SelfSigned, result)
    }

    @Test
    fun `verifyIDevIDChain reports no trust anchors on an empty store`() = runTest {
        val result = repository.verifyIDevIDChain(
            listOf(TestCertificates.der(TestCertificates.LEAF_A_PEM))
        )

        assertEquals(VerificationResult.NoTrustAnchors, result)
    }

    @Test
    fun `verifyIDevIDChain rejects a leaf from an unrelated CA`() = runTest {
        repository.importInternalCACertificate(
            TestCertificates.cert(TestCertificates.ROOT_CA_A_PEM),
            "root A"
        )

        val result = repository.verifyIDevIDChain(
            listOf(TestCertificates.der(TestCertificates.LEAF_B_PEM))
        )

        assertTrue("expected Invalid but was $result", result is VerificationResult.Invalid)
    }

    @Test
    fun `verifyIDevIDChain rejects an expired leaf`() = runTest {
        repository.importInternalCACertificate(
            TestCertificates.cert(TestCertificates.ROOT_CA_A_PEM),
            "root A"
        )

        val result = repository.verifyIDevIDChain(
            listOf(TestCertificates.der(TestCertificates.EXPIRED_LEAF_A_PEM))
        )

        assertTrue("expected Invalid but was $result", result is VerificationResult.Invalid)
    }

    @Test
    fun `verifyIDevIDChain rejects a chain in the wrong order`() = runTest {
        repository.importInternalCACertificate(
            TestCertificates.cert(TestCertificates.ROOT_CA_A_PEM),
            "root A"
        )

        val result = repository.verifyIDevIDChain(
            listOf(
                TestCertificates.der(TestCertificates.INTERMEDIATE_A_PEM),
                TestCertificates.der(TestCertificates.LEAF_VIA_INTERMEDIATE_PEM)
            )
        )

        assertTrue("expected Invalid but was $result", result is VerificationResult.Invalid)
    }

    @Test
    fun `verifyIDevIDChain rejects a chain missing its intermediate`() = runTest {
        repository.importInternalCACertificate(
            TestCertificates.cert(TestCertificates.ROOT_CA_A_PEM),
            "root A"
        )

        val result = repository.verifyIDevIDChain(
            listOf(TestCertificates.der(TestCertificates.LEAF_VIA_INTERMEDIATE_PEM))
        )

        assertTrue("expected Invalid but was $result", result is VerificationResult.Invalid)
    }

    @Test
    fun `verifyIDevIDChain propagates a parse failure for malformed DER`() = runTest {
        repository.importInternalCACertificate(
            TestCertificates.cert(TestCertificates.ROOT_CA_A_PEM),
            "root A"
        )

        assertFails(CertificateException::class.java) {
            repository.verifyIDevIDChain(listOf(byteArrayOf(0x30, 0x00, 0x01)))
        }
    }

    // -------------------------------------------------------------------------
    // Chain verification — acceptance and trust levels
    // -------------------------------------------------------------------------

    @Test
    fun `verifyIDevIDChain accepts a leaf issued by an imported root`() = runTest {
        repository.importInternalCACertificate(
            TestCertificates.cert(TestCertificates.ROOT_CA_A_PEM),
            "root A"
        )

        val result = repository.verifyIDevIDChain(
            listOf(TestCertificates.der(TestCertificates.LEAF_A_PEM))
        )

        assertTrue("expected Valid but was $result", result is VerificationResult.Valid)
        assertEquals("external-ca", (result as VerificationResult.Valid).trustLevel)
    }

    @Test
    fun `verifyIDevIDChain accepts a full leaf plus intermediate chain`() = runTest {
        repository.importInternalCACertificate(
            TestCertificates.cert(TestCertificates.ROOT_CA_A_PEM),
            "root A"
        )

        val result = repository.verifyIDevIDChain(
            listOf(
                TestCertificates.der(TestCertificates.LEAF_VIA_INTERMEDIATE_PEM),
                TestCertificates.der(TestCertificates.INTERMEDIATE_A_PEM)
            )
        )

        assertTrue("expected Valid but was $result", result is VerificationResult.Valid)
    }

    @Test
    fun `verifyIDevIDChain reports android-ca for an Android issuer`() = runTest {
        repository.importInternalCACertificate(
            TestCertificates.cert(TestCertificates.ROOT_CA_B_ANDROID_PEM),
            "root B"
        )

        val result = repository.verifyIDevIDChain(
            listOf(TestCertificates.der(TestCertificates.LEAF_B_PEM))
        )

        assertTrue("expected Valid but was $result", result is VerificationResult.Valid)
        assertEquals("android-ca", (result as VerificationResult.Valid).trustLevel)
    }

    @Test
    fun `verifyIDevIDChain reports hardware-backed for a StrongBox issuer`() = runTest {
        repository.importInternalCACertificate(
            TestCertificates.cert(TestCertificates.ROOT_CA_C_STRONGBOX_PEM),
            "root C"
        )

        val result = repository.verifyIDevIDChain(
            listOf(TestCertificates.der(TestCertificates.LEAF_C_PEM))
        )

        assertTrue("expected Valid but was $result", result is VerificationResult.Valid)
        assertEquals("hardware-backed", (result as VerificationResult.Valid).trustLevel)
    }

    @Test
    fun `verifyIDevIDChain reports tee-backed for a TEE issuer`() = runTest {
        repository.importInternalCACertificate(
            TestCertificates.cert(TestCertificates.ROOT_CA_D_TEE_PEM),
            "root D"
        )

        val result = repository.verifyIDevIDChain(
            listOf(TestCertificates.der(TestCertificates.LEAF_D_PEM))
        )

        assertTrue("expected Valid but was $result", result is VerificationResult.Valid)
        assertEquals("tee-backed", (result as VerificationResult.Valid).trustLevel)
    }

    // -------------------------------------------------------------------------
    // importFromURL
    // -------------------------------------------------------------------------

    @Test
    fun `importFromURL imports every CA-signed certificate in the bundle`() = runTest {
        coEvery { caFetcher.fetchBundle("https://ca.example.com") } returns bundleOf(
            TestCertificates.INTERMEDIATE_A_PEM,
            TestCertificates.LEAF_A_PEM
        )

        val result = repository.importFromURL("https://ca.example.com", label = "corp")

        assertEquals(2, result.imported)
        assertEquals(0, result.skipped)
        assertTrue(result.errors.isEmpty())
        val stored = repository.getCertificate(
            TestCertificates.fingerprint(TestCertificates.INTERMEDIATE_A_PEM)
        )
        assertNotNull(stored)
        assertEquals("url:https://ca.example.com", stored!!.source)
        assertEquals("corp", stored.label)
    }

    @Test
    fun `importFromURL skips self-signed roots and records an error`() = runTest {
        coEvery { caFetcher.fetchBundle(any()) } returns bundleOf(
            TestCertificates.INTERMEDIATE_A_PEM,
            TestCertificates.ROOT_CA_A_PEM
        )

        val result = repository.importFromURL("https://ca.example.com")

        assertEquals(1, result.imported)
        assertEquals(1, result.skipped)
        assertEquals(1, result.errors.size)
        assertTrue(result.errors[0].startsWith("Skipped self-signed certificate:"))
        assertFalse(
            repository.hasCertificate(TestCertificates.fingerprint(TestCertificates.ROOT_CA_A_PEM))
        )
    }

    @Test
    fun `importFromURL skips certificates that are already present`() = runTest {
        coEvery { caFetcher.fetchBundle(any()) } returns bundleOf(TestCertificates.LEAF_A_PEM)

        val first = repository.importFromURL("https://ca.example.com")
        val second = repository.importFromURL("https://ca.example.com")

        assertEquals(1, first.imported)
        assertEquals(0, second.imported)
        assertEquals(1, second.skipped)
        assertEquals(1, repository.getCertificateCount())
    }

    @Test
    fun `importFromURL propagates fetch failures`() = runTest {
        coEvery { caFetcher.fetchBundle(any()) } throws CABundleFetchException("boom")

        val error = assertFails(CABundleFetchException::class.java) {
            repository.importFromURL("https://ca.example.com")
        }

        assertEquals("boom", error.message)
        assertEquals(0, repository.getCertificateCount())
    }

    // -------------------------------------------------------------------------
    // Audit log
    // -------------------------------------------------------------------------

    private fun subjectOf(pem: String) = TestCertificates.cert(pem).subjectX500Principal.name

    @Test
    fun `importCertificate records one trust store import with source manual`() = runTest {
        captureAudit()

        repository.importCertificate(TestCertificates.der(TestCertificates.LEAF_A_PEM))

        val imports = auditedOf(AuditOperationType.TRUST_STORE_IMPORT)
        assertEquals(1, imports.size)
        assertEquals(1, audited.size)
        val details = details(imports[0])
        assertEquals(subjectOf(TestCertificates.LEAF_A_PEM), details.getString("subject"))
        assertEquals(
            TestCertificates.fingerprint(TestCertificates.LEAF_A_PEM),
            details.getString("fingerprint")
        )
        assertEquals("manual", details.getString("source"))
        assertTrue(imports[0].success)
    }

    @Test
    fun `a duplicate import records nothing`() = runTest {
        val der = TestCertificates.der(TestCertificates.LEAF_A_PEM)
        repository.importCertificate(der)
        captureAudit()

        assertNull(repository.importCertificate(der))

        assertTrue(audited.isEmpty())
    }

    @Test
    fun `a refused self-signed certificate records nothing`() = runTest {
        captureAudit()

        assertFails(IllegalArgumentException::class.java) {
            repository.importCertificate(TestCertificates.der(TestCertificates.ROOT_CA_A_PEM))
        }

        assertTrue(audited.isEmpty())
    }

    @Test
    fun `importFromURL records one import per stored certificate with its url`() = runTest {
        coEvery { caFetcher.fetchBundle(any()) } returns bundleOf(
            TestCertificates.INTERMEDIATE_A_PEM,
            TestCertificates.LEAF_A_PEM,
            TestCertificates.ROOT_CA_A_PEM
        )
        captureAudit()

        repository.importFromURL("https://ca.example.com")

        val imports = auditedOf(AuditOperationType.TRUST_STORE_IMPORT)
        assertEquals(2, imports.size)
        assertEquals(
            setOf(
                TestCertificates.fingerprint(TestCertificates.INTERMEDIATE_A_PEM),
                TestCertificates.fingerprint(TestCertificates.LEAF_A_PEM)
            ),
            imports.map { details(it).getString("fingerprint") }.toSet()
        )
        imports.forEach {
            assertEquals("url:https://ca.example.com", details(it).getString("source"))
        }
    }

    @Test
    fun `importInternalCACertificate records source internal-ca`() = runTest {
        captureAudit()

        repository.importInternalCACertificate(
            TestCertificates.cert(TestCertificates.ROOT_CA_A_PEM),
            "xKey Root CA"
        )
        repository.importInternalCACertificate(
            TestCertificates.cert(TestCertificates.ROOT_CA_A_PEM),
            "xKey Root CA"
        )

        val imports = auditedOf(AuditOperationType.TRUST_STORE_IMPORT)
        assertEquals(1, imports.size)
        assertEquals("internal-ca", details(imports[0]).getString("source"))
        assertEquals(subjectOf(TestCertificates.ROOT_CA_A_PEM), details(imports[0]).getString("subject"))
    }

    @Test
    fun `deleteCertificate of a stored certificate records one trust store delete`() = runTest {
        repository.importCertificate(TestCertificates.der(TestCertificates.LEAF_A_PEM))
        val fingerprint = TestCertificates.fingerprint(TestCertificates.LEAF_A_PEM)
        captureAudit()

        assertTrue(repository.deleteCertificate(fingerprint))

        assertEquals(1, audited.size)
        val delete = auditedOf(AuditOperationType.TRUST_STORE_DELETE).single()
        assertEquals(fingerprint, details(delete).getString("fingerprint"))
        assertEquals(subjectOf(TestCertificates.LEAF_A_PEM), details(delete).getString("subject"))
    }

    @Test
    fun `deleteCertificate of an unknown fingerprint records nothing`() = runTest {
        repository.importCertificate(TestCertificates.der(TestCertificates.LEAF_A_PEM))
        captureAudit()

        assertFalse(repository.deleteCertificate("ab".repeat(32)))

        assertTrue(audited.isEmpty())
    }

    @Test
    fun `clearAll over two certificates records two deletes`() = runTest {
        repository.importCertificate(TestCertificates.der(TestCertificates.LEAF_A_PEM))
        repository.importCertificate(TestCertificates.der(TestCertificates.LEAF_B_PEM))
        captureAudit()

        repository.clearAll()

        val deletes = auditedOf(AuditOperationType.TRUST_STORE_DELETE)
        assertEquals(2, deletes.size)
        assertEquals(2, audited.size)
        assertEquals(
            setOf(
                TestCertificates.fingerprint(TestCertificates.LEAF_A_PEM),
                TestCertificates.fingerprint(TestCertificates.LEAF_B_PEM)
            ),
            deletes.map { details(it).getString("fingerprint") }.toSet()
        )
        assertEquals(0, repository.getCertificateCount())
    }

    /** A repository whose file deleter refuses the DER file of [pem]. */
    private fun repositoryRefusingToDelete(pem: String): TrustStoreRepository {
        val refused = "${TestCertificates.fingerprint(pem)}.der"
        return TrustStoreRepository(context, caFetcher, fileDeleter = { file ->
            if (file.name == refused) false else file.delete()
        })
    }

    @Test
    fun `clearAll records a failed delete for a certificate it cannot remove`() = runTest {
        repository.importCertificate(TestCertificates.der(TestCertificates.LEAF_A_PEM))
        repository.importCertificate(TestCertificates.der(TestCertificates.LEAF_B_PEM))
        val fingerprintA = TestCertificates.fingerprint(TestCertificates.LEAF_A_PEM)
        val fingerprintB = TestCertificates.fingerprint(TestCertificates.LEAF_B_PEM)
        val stubborn = repositoryRefusingToDelete(TestCertificates.LEAF_B_PEM)
        captureAudit()

        val result = stubborn.clearAll()

        assertEquals(listOf(fingerprintA), result.removed)
        assertEquals(listOf(fingerprintB), result.failed)
        assertFalse(result.complete)
        val deletes = auditedOf(AuditOperationType.TRUST_STORE_DELETE)
        assertEquals(2, deletes.size)
        val succeeded = deletes.filter { it.success }
        val failed = deletes.filter { !it.success }
        assertEquals(listOf(fingerprintA), succeeded.map { details(it).getString("fingerprint") })
        assertEquals(listOf(fingerprintB), failed.map { details(it).getString("fingerprint") })
        assertNotNull(failed[0].errorMessage)
        // B is still trusted and still listed; A is gone.
        assertTrue(newRepository().hasCertificate(fingerprintB))
        assertNotNull(newRepository().getCertificate(fingerprintB))
        assertNull(newRepository().getCertificate(fingerprintA))
        assertFalse(newRepository().hasCertificate(fingerprintA))
    }

    @Test
    fun `clearAll reports a complete clear when every certificate is removed`() = runTest {
        repository.importCertificate(TestCertificates.der(TestCertificates.LEAF_A_PEM))
        captureAudit()

        val result = repository.clearAll()

        assertTrue(result.complete)
        assertTrue(result.failed.isEmpty())
        assertTrue(auditedOf(AuditOperationType.TRUST_STORE_DELETE).all { it.success })
    }

    @Test
    fun `deleteCertificate records a failure and keeps the entry when the file cannot be removed`() = runTest {
        repository.importCertificate(TestCertificates.der(TestCertificates.LEAF_A_PEM))
        val fingerprint = TestCertificates.fingerprint(TestCertificates.LEAF_A_PEM)
        val stubborn = repositoryRefusingToDelete(TestCertificates.LEAF_A_PEM)
        captureAudit()

        assertFalse(stubborn.deleteCertificate(fingerprint))

        val delete = auditedOf(AuditOperationType.TRUST_STORE_DELETE).single()
        assertFalse(delete.success)
        assertEquals(fingerprint, details(delete).getString("fingerprint"))
        assertTrue(newRepository().hasCertificate(fingerprint))
        assertNotNull(newRepository().getCertificate(fingerprint))
    }

    @Test
    fun `a metadata write that fails part-way keeps the previous metadata`() = runTest {
        repository.importCertificate(TestCertificates.der(TestCertificates.LEAF_A_PEM))
        repository.importCertificate(TestCertificates.der(TestCertificates.LEAF_B_PEM))
        val fingerprintA = TestCertificates.fingerprint(TestCertificates.LEAF_A_PEM)
        val fingerprintB = TestCertificates.fingerprint(TestCertificates.LEAF_B_PEM)
        val refused = "$fingerprintB.der"
        // Deletes every file but B's, and fails every write after truncating
        // its target and writing a fragment.
        val failing = TrustStoreRepository(
            context,
            caFetcher,
            fileDeleter = { file -> if (file.name == refused) false else file.delete() },
            fileWriter = { file, text ->
                file.writeText(text.take(3))
                throw java.io.IOException("disk full")
            }
        )

        val result = failing.clearAll()

        assertFalse(result.complete)
        // B was never removed: it is still listed, and so is A, whose row
        // the failed rewrite could not drop.
        val listed = newRepository().getAllCertificates().map { it.fingerprint }.toSet()
        assertTrue(fingerprintB in listed)
        assertEquals(setOf(fingerprintA, fingerprintB), listed)
        assertTrue(newRepository().hasCertificate(fingerprintB))
    }

    @Test
    fun `clearAll removes and audits a certificate file without metadata`() = runTest {
        repository.importCertificate(TestCertificates.der(TestCertificates.LEAF_A_PEM))
        val fingerprintA = TestCertificates.fingerprint(TestCertificates.LEAF_A_PEM)
        // An interrupted rewrite lost A's metadata row; its DER remains.
        assertTrue(File(storeDir, "metadata.json").delete())
        captureAudit()

        val result = repository.clearAll()

        assertEquals(listOf(fingerprintA), result.removed)
        assertTrue(result.complete)
        val deletes = auditedOf(AuditOperationType.TRUST_STORE_DELETE)
        assertEquals(1, deletes.size)
        assertTrue(deletes[0].success)
        assertEquals(fingerprintA, details(deletes[0]).getString("fingerprint"))
        assertFalse(newRepository().hasCertificate(fingerprintA))
    }

    @Test
    fun `imports and deletes still succeed with the audit logger uninitialized`() = runTest {
        assertFalse(AuditLogger.isInitialized())
        val der = TestCertificates.der(TestCertificates.LEAF_A_PEM)

        assertNotNull(repository.importCertificate(der))
        assertTrue(repository.deleteCertificate(TestCertificates.fingerprint(TestCertificates.LEAF_A_PEM)))
        repository.importCertificate(der)
        repository.clearAll()

        assertEquals(0, repository.getCertificateCount())
    }

    // -------------------------------------------------------------------------
    // Writers on separate repository instances
    // -------------------------------------------------------------------------

    /**
     * A repository whose metadata writes stop, after writing, until [release]
     * opens; [entered] opens once the first write is held.
     */
    private fun repositoryHoldingWrite(entered: CountDownLatch, release: CountDownLatch) =
        TrustStoreRepository(
            context,
            caFetcher,
            fileWriter = { file, text ->
                file.writeText(text)
                entered.countDown()
                release.await(5, TimeUnit.SECONDS)
            }
        )

    private fun <T> startCall(block: suspend () -> T): CompletableFuture<Result<T>> =
        CompletableFuture.supplyAsync { runBlocking { runCatching { block() } } }

    /**
     * Run [held] until its metadata write is held, start [overlapping], give it
     * time to finish inside the held write, then let [held] go.
     */
    private fun <A, B> overlap(
        entered: CountDownLatch,
        release: CountDownLatch,
        held: suspend () -> A,
        overlapping: suspend () -> B
    ): Pair<Result<A>, Result<B>> {
        val first = startCall(held)
        assertTrue(entered.await(5, TimeUnit.SECONDS))
        val second = startCall(overlapping)
        // Without one writer at a time the second call completes here,
        // between the first call's write and its rename.
        runCatching { second.get(500, TimeUnit.MILLISECONDS) }
        release.countDown()
        return first.get(10, TimeUnit.SECONDS) to second.get(10, TimeUnit.SECONDS)
    }

    private fun metadataFingerprints(): Set<String> {
        val array = JSONArray(File(storeDir, "metadata.json").readText())
        return (0 until array.length()).map { array.getJSONObject(it).getString("fingerprint") }.toSet()
    }

    private fun tempFiles(): List<String> =
        storeDir.listFiles().orEmpty().map { it.name }.filter { it.endsWith(".tmp") }

    @Test
    fun `two repositories importing at once both keep their certificate`() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val holding = repositoryHoldingWrite(entered, release)
        val other = newRepository()

        val (first, second) = overlap(
            entered,
            release,
            { holding.importCertificate(TestCertificates.der(TestCertificates.LEAF_A_PEM)) },
            { other.importCertificate(TestCertificates.der(TestCertificates.LEAF_B_PEM)) }
        )

        assertNotNull(first.getOrThrow())
        assertNotNull(second.getOrThrow())
        assertEquals(
            setOf(
                TestCertificates.fingerprint(TestCertificates.LEAF_A_PEM),
                TestCertificates.fingerprint(TestCertificates.LEAF_B_PEM)
            ),
            metadataFingerprints()
        )
        assertEquals(emptyList<String>(), tempFiles())
    }

    @Test
    fun `a delete on another repository during an import keeps the imported certificate`() {
        val fingerprintA = TestCertificates.fingerprint(TestCertificates.LEAF_A_PEM)
        val fingerprintB = TestCertificates.fingerprint(TestCertificates.LEAF_B_PEM)
        runBlocking { repository.importCertificate(TestCertificates.der(TestCertificates.LEAF_A_PEM)) }
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val holding = repositoryHoldingWrite(entered, release)
        val other = newRepository()

        val (imported, deleted) = overlap(
            entered,
            release,
            { holding.importCertificate(TestCertificates.der(TestCertificates.LEAF_B_PEM)) },
            { other.deleteCertificate(fingerprintA) }
        )

        assertNotNull(imported.getOrThrow())
        assertTrue(deleted.getOrThrow())
        assertEquals(setOf(fingerprintB), metadataFingerprints())
        assertFalse(File(storeDir, "$fingerprintA.der").exists())
        assertTrue(File(storeDir, "$fingerprintB.der").exists())
        assertEquals(emptyList<String>(), tempFiles())
    }

    @Test
    fun `an import on another repository during a delete is kept`() {
        val fingerprintA = TestCertificates.fingerprint(TestCertificates.LEAF_A_PEM)
        val fingerprintB = TestCertificates.fingerprint(TestCertificates.LEAF_B_PEM)
        runBlocking { repository.importCertificate(TestCertificates.der(TestCertificates.LEAF_A_PEM)) }
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val holding = repositoryHoldingWrite(entered, release)
        val other = newRepository()

        val (deleted, imported) = overlap(
            entered,
            release,
            { holding.deleteCertificate(fingerprintA) },
            { other.importCertificate(TestCertificates.der(TestCertificates.LEAF_B_PEM)) }
        )

        assertTrue(deleted.getOrThrow())
        assertNotNull(imported.getOrThrow())
        assertEquals(setOf(fingerprintB), metadataFingerprints())
        assertEquals(listOf(fingerprintB), runBlocking { newRepository().getAllCertificates() }.map { it.fingerprint })
        assertEquals(emptyList<String>(), tempFiles())
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private fun bundleOf(vararg pems: String): CABundleResult {
        val certificates = pems.map { TestCertificates.cert(it) }
        return CABundleResult(
            pemBundle = pems.joinToString("").toByteArray(),
            certificates = certificates,
            cacheControl = null
        )
    }

    /** Assert that [block] fails with [type], without nesting a blocking dispatcher. */
    private suspend fun <T : Throwable> assertFails(type: Class<T>, block: suspend () -> Unit): T {
        try {
            block()
        } catch (e: Throwable) {
            if (type.isInstance(e)) return type.cast(e)!!
            throw AssertionError("expected ${type.name} but was ${e.javaClass.name}: ${e.message}", e)
        }
        throw AssertionError("expected ${type.name} but nothing was thrown")
    }

    private fun assertArrayEqualsBytes(expected: ByteArray, actual: ByteArray) {
        assertEquals(
            TestCertificates.sha256Hex(expected),
            TestCertificates.sha256Hex(actual)
        )
    }
}
