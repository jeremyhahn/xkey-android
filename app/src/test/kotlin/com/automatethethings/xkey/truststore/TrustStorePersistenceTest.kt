/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
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
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.unmockkAll
import java.io.File
import kotlinx.coroutines.test.runTest
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
 * Unit tests for how [TrustStoreRepository] persists and re-reads its metadata.
 *
 * `TrustStoreRepositoryTest` covers the trust decisions; this suite covers the
 * storage layer underneath them, which is a hand-rolled JSON writer and a
 * regex-based reader. Everything here is about what survives a restart: the
 * metadata is rewritten in full on every import and delete, so an escaping or
 * parsing bug silently rewrites the operator's trust store rather than failing
 * loudly.
 *
 * Each test gets its own [TemporaryFolder]-backed store through a mocked
 * [Context], and reloads through a *new* repository instance so nothing is
 * served from in-process state.
 */
class TrustStorePersistenceTest {

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
        unmockkAll()
    }

    /** A second repository over the same directory: proves the data is on disk. */
    private fun reloaded() = TrustStoreRepository(context, caFetcher)

    private val metadataFile: File get() = File(storeDir, "metadata.json")

    private fun bundleOf(vararg pems: String): CABundleResult = CABundleResult(
        pemBundle = pems.joinToString("").toByteArray(),
        certificates = pems.map { TestCertificates.cert(it) },
        cacheControl = null
    )

    // -------------------------------------------------------------------------
    // Escaping
    // -------------------------------------------------------------------------

    @Test
    fun `a label containing quotes and backslashes survives a reload`() = runTest {
        val label = """Corp "Root" CA \ archive\path"""

        repository.importCertificate(TestCertificates.der(TestCertificates.LEAF_A_PEM), label)

        val stored = reloaded().getCertificate(
            TestCertificates.fingerprint(TestCertificates.LEAF_A_PEM)
        )
        assertNotNull(stored)
        assertEquals(label, stored!!.label)
    }

    @Test
    fun `a label containing newlines tabs and carriage returns survives a reload`() = runTest {
        val label = "line one\nline two\tcolumn\rreturn"

        repository.importCertificate(TestCertificates.der(TestCertificates.LEAF_A_PEM), label)

        // A raw newline inside a JSON string would make the document unreadable,
        // so this also proves the escape is applied rather than the value dropped.
        assertFalse(metadataFile.readText().contains("line one\nline two"))
        assertEquals(
            label,
            reloaded()
                .getCertificate(TestCertificates.fingerprint(TestCertificates.LEAF_A_PEM))!!
                .label
        )
    }

    @Test
    fun `a source URL containing quotes survives a reload`() = runTest {
        val url = """https://ca.example.com/"odd"/path"""
        coEvery { caFetcher.fetchBundle(url) } returns bundleOf(TestCertificates.LEAF_A_PEM)

        repository.importFromURL(url)

        assertEquals(
            "url:$url",
            reloaded()
                .getCertificate(TestCertificates.fingerprint(TestCertificates.LEAF_A_PEM))!!
                .source
        )
    }

    @Test
    fun `a unicode label survives a reload`() = runTest {
        val label = "Zertifizierungsstelle über alles — 日本"

        repository.importCertificate(TestCertificates.der(TestCertificates.LEAF_A_PEM), label)

        assertEquals(
            label,
            reloaded()
                .getCertificate(TestCertificates.fingerprint(TestCertificates.LEAF_A_PEM))!!
                .label
        )
    }

    @Test
    fun `a label containing a closing brace does not lose the certificate`() = runTest {
        // The metadata reader splits objects on braces, so a brace inside a value
        // is the worst case for it. The entry -- and above all the fingerprint
        // that identifies the trusted key -- must still come back.
        repository.importCertificate(
            TestCertificates.der(TestCertificates.LEAF_A_PEM),
            label = "corp}team"
        )
        val fingerprint = TestCertificates.fingerprint(TestCertificates.LEAF_A_PEM)

        val stored = reloaded().getAllCertificates()

        assertEquals(1, stored.size)
        assertEquals(fingerprint, stored[0].fingerprint)
        assertTrue(stored[0].subjectDN.startsWith(TestCertificates.LEAF_A_CN))
        assertEquals(TestCertificates.LONG_LIVED_NOT_AFTER_MILLIS, stored[0].notAfter)
        assertTrue(reloaded().hasCertificate(fingerprint))
    }

    // -------------------------------------------------------------------------
    // Full-file rewrites
    // -------------------------------------------------------------------------

    @Test
    fun `deleting one certificate preserves the metadata of the others`() = runTest {
        repository.importCertificate(
            TestCertificates.der(TestCertificates.LEAF_A_PEM),
            label = """first "quoted" label"""
        )
        repository.importCertificate(
            TestCertificates.der(TestCertificates.LEAF_B_PEM),
            label = "second\tlabel"
        )

        repository.deleteCertificate(TestCertificates.fingerprint(TestCertificates.LEAF_A_PEM))

        val remaining = reloaded().getAllCertificates()
        assertEquals(1, remaining.size)
        assertEquals("second\tlabel", remaining[0].label)
        assertEquals("manual", remaining[0].source)
        assertTrue(remaining[0].subjectDN.startsWith("CN=device-b.xkey.test"))
    }

    @Test
    fun `the system-installed flag survives a reload`() = runTest {
        repository.importCertificate(TestCertificates.der(TestCertificates.LEAF_A_PEM), "corp")
        val fingerprint = TestCertificates.fingerprint(TestCertificates.LEAF_A_PEM)

        repository.updateSystemInstalled(fingerprint, true)

        val stored = reloaded().getCertificate(fingerprint)!!
        assertTrue(stored.systemInstalled)
        assertEquals("corp", stored.label)
    }

    @Test
    fun `importing a second certificate keeps the first entry intact`() = runTest {
        repository.importCertificate(TestCertificates.der(TestCertificates.LEAF_A_PEM), "first")

        repository.importCertificate(TestCertificates.der(TestCertificates.LEAF_B_PEM), "second")

        val all = reloaded().getAllCertificates()
        assertEquals(2, all.size)
        assertEquals(
            setOf("first", "second"),
            all.mapNotNull { it.label }.toSet()
        )
    }

    @Test
    fun `clearAll wipes the metadata and the store still accepts imports`() = runTest {
        repository.importCertificate(TestCertificates.der(TestCertificates.LEAF_A_PEM))

        repository.clearAll()
        assertFalse(metadataFile.exists())
        assertEquals(0, reloaded().getCertificateCount())

        repository.importCertificate(TestCertificates.der(TestCertificates.LEAF_B_PEM), "after")

        val all = reloaded().getAllCertificates()
        assertEquals(1, all.size)
        assertEquals("after", all[0].label)
    }

    // -------------------------------------------------------------------------
    // Degraded metadata written by something else
    // -------------------------------------------------------------------------

    @Test
    fun `an entry missing its optional fields falls back to defaults`() = runTest {
        metadataFile.writeText(
            """[{"fingerprint":"${"ab".repeat(32)}","subjectDN":"CN=partial"}]"""
        )

        val all = repository.getAllCertificates()

        assertEquals(1, all.size)
        val entry = all.single()
        assertEquals("ab".repeat(32), entry.fingerprint)
        assertEquals("CN=partial", entry.subjectDN)
        assertEquals("", entry.issuerDN)
        assertEquals(0L, entry.notBefore)
        assertEquals(0L, entry.notAfter)
        assertEquals(0L, entry.importedAt)
        assertEquals("unknown", entry.source)
        assertNull(entry.label)
        assertFalse(entry.systemInstalled)
    }

    @Test
    fun `an entry without a fingerprint is skipped`() = runTest {
        metadataFile.writeText(
            """[{"subjectDN":"CN=no-fingerprint","source":"manual"},""" +
                """{"fingerprint":"${"cd".repeat(32)}","subjectDN":"CN=kept"}]"""
        )

        val all = repository.getAllCertificates()

        assertEquals(1, all.size)
        assertEquals("CN=kept", all.single().subjectDN)
    }

    @Test
    fun `a metadata document that is not an array yields nothing`() = runTest {
        metadataFile.writeText("""{"fingerprint":"${"ef".repeat(32)}"}""")

        assertTrue(repository.getAllCertificates().isEmpty())
    }

    @Test
    fun `an empty metadata array yields nothing`() = runTest {
        metadataFile.writeText("[]")

        assertTrue(repository.getAllCertificates().isEmpty())
        assertEquals(0, repository.getCertificateCount())
    }

    @Test
    fun `a non-boolean system-installed value is read as false`() = runTest {
        metadataFile.writeText(
            """[{"fingerprint":"${"ab".repeat(32)}","systemInstalled":"yes"}]"""
        )

        assertFalse(repository.getAllCertificates().single().systemInstalled)
    }

    @Test
    fun `a non-numeric timestamp is read as zero`() = runTest {
        metadataFile.writeText(
            """[{"fingerprint":"${"ab".repeat(32)}","notAfter":"soon","importedAt":"never"}]"""
        )

        val entry = repository.getAllCertificates().single()
        assertEquals(0L, entry.notAfter)
        assertEquals(0L, entry.importedAt)
        // A zero notAfter is in the past, so the entry shows up as expired.
        assertEquals(1, repository.getExpiredCertificates().size)
    }

    @Test
    fun `an explicit null label is read as null`() = runTest {
        metadataFile.writeText(
            """[{"fingerprint":"${"ab".repeat(32)}","label":null,"source":"manual"}]"""
        )

        assertNull(repository.getAllCertificates().single().label)
    }

    // -------------------------------------------------------------------------
    // A store that has lost its certificate files
    // -------------------------------------------------------------------------

    @Test
    fun `an anchor whose DER file has vanished is not usable for verification`() = runTest {
        repository.importInternalCACertificate(
            TestCertificates.cert(TestCertificates.ROOT_CA_A_PEM),
            "root A"
        )
        val fingerprint = TestCertificates.fingerprint(TestCertificates.ROOT_CA_A_PEM)
        assertTrue(File(storeDir, "$fingerprint.der").delete())

        val result = repository.verifyIDevIDChain(
            listOf(TestCertificates.der(TestCertificates.LEAF_A_PEM))
        )

        // The metadata still lists the anchor, but nothing can be loaded from it.
        assertEquals(1, repository.getAllCertificates().size)
        assertEquals(VerificationResult.NoTrustAnchors, result)
    }

    @Test
    fun `an anchor file that has been corrupted is ignored`() = runTest {
        repository.importInternalCACertificate(
            TestCertificates.cert(TestCertificates.ROOT_CA_A_PEM),
            "root A"
        )
        val fingerprint = TestCertificates.fingerprint(TestCertificates.ROOT_CA_A_PEM)
        File(storeDir, "$fingerprint.der").writeBytes(byteArrayOf(0x30, 0x00, 0x01))

        val result = repository.verifyIDevIDChain(
            listOf(TestCertificates.der(TestCertificates.LEAF_A_PEM))
        )

        assertEquals(VerificationResult.NoTrustAnchors, result)
    }

    @Test
    fun `a certificate listed in the metadata but missing on disk reports absent`() = runTest {
        repository.importCertificate(TestCertificates.der(TestCertificates.LEAF_A_PEM))
        val fingerprint = TestCertificates.fingerprint(TestCertificates.LEAF_A_PEM)
        assertTrue(File(storeDir, "$fingerprint.der").delete())

        assertFalse(repository.hasCertificate(fingerprint))
        assertNull(repository.getCertificateDER(fingerprint))

        // Deleting must still clear the orphaned metadata row. Reporting failure
        // and leaving it behind would strand the entry: it stays listed forever
        // and only clearAll() could remove it.
        assertTrue(repository.deleteCertificate(fingerprint))
        assertNull(repository.getCertificate(fingerprint))

        // Nothing is left to delete the second time round.
        assertFalse(repository.deleteCertificate(fingerprint))
    }

    // -------------------------------------------------------------------------
    // A store that cannot be written
    // -------------------------------------------------------------------------

    @Test
    fun `importFromURL records an error when a certificate cannot be stored`() = runTest {
        // getDir points at a regular file, so every write into it fails.
        val blocked = tempFolder.newFile("not-a-directory")
        val blockedContext = mockk<Context>()
        every { blockedContext.getDir("trust_store", Context.MODE_PRIVATE) } returns blocked
        val blockedFetcher = mockk<CABundleFetcher>()
        coEvery { blockedFetcher.fetchBundle(any()) } returns bundleOf(TestCertificates.LEAF_A_PEM)

        val result = TrustStoreRepository(blockedContext, blockedFetcher)
            .importFromURL("https://ca.example.com")

        assertEquals(0, result.imported)
        assertEquals(0, result.skipped)
        assertEquals(1, result.errors.size)
        assertTrue(result.errors[0], result.errors[0].startsWith("Failed to store certificate"))
    }

    // -------------------------------------------------------------------------
    // Default construction
    // -------------------------------------------------------------------------

    @Test
    fun `a repository built without an injected fetcher still stores certificates`() = runTest {
        // This is how the app constructs it: the CA-bundle fetcher (and the
        // OkHttp client behind it) is only built because of the default argument.
        val store = TrustStoreRepository(context)

        val imported = store.importCertificate(
            TestCertificates.der(TestCertificates.LEAF_A_PEM),
            "default construction"
        )

        assertNotNull(imported)
        assertEquals(1, store.getCertificateCount())
        assertTrue(
            store.hasCertificate(TestCertificates.fingerprint(TestCertificates.LEAF_A_PEM))
        )
    }

    // -------------------------------------------------------------------------
    // Expiry queries against reloaded metadata
    // -------------------------------------------------------------------------

    @Test
    fun `expiry queries work against reloaded metadata`() = runTest {
        repository.importCertificate(TestCertificates.der(TestCertificates.LEAF_A_PEM))
        repository.importCertificate(TestCertificates.der(TestCertificates.EXPIRED_LEAF_A_PEM))

        val store = reloaded()

        assertEquals(1, store.getExpiredCertificates().size)
        assertEquals(1, store.getExpiringCertificates(days = 0).size)
        assertEquals(2, store.getExpiringCertificates(days = 40_000).size)
    }
}
