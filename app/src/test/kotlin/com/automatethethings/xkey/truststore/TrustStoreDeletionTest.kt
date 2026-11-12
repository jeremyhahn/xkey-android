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
import io.mockk.every
import io.mockk.mockk
import io.mockk.unmockkAll
import java.io.File
import java.io.IOException
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * Unit tests for the deletion paths the certificate screens call: a
 * certificate the trust store could not remove keeps its database row and
 * the caller learns of the failure.
 */
class TrustStoreDeletionTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    private lateinit var context: Context
    private lateinit var repository: TrustStoreRepository

    private val fingerprintA = TestCertificates.fingerprint(TestCertificates.LEAF_A_PEM)
    private val fingerprintB = TestCertificates.fingerprint(TestCertificates.LEAF_B_PEM)
    private val rootA = TestCertificates.fingerprint(TestCertificates.ROOT_CA_A_PEM)

    @Before
    fun setUp() {
        val storeDir = tempFolder.newFolder("trust_store")
        context = mockk()
        every { context.getDir("trust_store", Context.MODE_PRIVATE) } returns storeDir
        repository = TrustStoreRepository(context, mockk())
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    /** A repository whose file deleter refuses the DER file of [fingerprint]. */
    private fun refusingToDelete(fingerprint: String) =
        TrustStoreRepository(context, mockk(), fileDeleter = { file: File ->
            if (file.name == "$fingerprint.der") false else file.delete()
        })

    @Test
    fun `removeTrustedCertificate keeps the row of a certificate it could not remove`() = runTest {
        repository.importCertificate(TestCertificates.der(TestCertificates.LEAF_A_PEM))
        val deletedRows = mutableListOf<String>()

        val removed = removeTrustedCertificate(refusingToDelete(fingerprintA), fingerprintA) {
            deletedRows += fingerprintA
        }

        assertFalse(removed)
        assertTrue(deletedRows.isEmpty())
        assertTrue(repository.hasCertificate(fingerprintA))
    }

    @Test
    fun `removeTrustedCertificate deletes the row once the certificate is gone`() = runTest {
        repository.importCertificate(TestCertificates.der(TestCertificates.LEAF_A_PEM))
        val deletedRows = mutableListOf<String>()

        val removed = removeTrustedCertificate(repository, fingerprintA) { deletedRows += fingerprintA }

        assertTrue(removed)
        assertEquals(listOf(fingerprintA), deletedRows)
        assertFalse(repository.hasCertificate(fingerprintA))
    }

    @Test
    fun `removeTrustedCertificate deletes the row of a certificate not in the trust store`() = runTest {
        val deletedRows = mutableListOf<String>()

        val removed = removeTrustedCertificate(repository, fingerprintA) { deletedRows += fingerprintA }

        assertTrue(removed)
        assertEquals(listOf(fingerprintA), deletedRows)
    }

    @Test
    fun `clearTrustStore keeps the rows of certificates it could not remove`() = runTest {
        repository.importCertificate(TestCertificates.der(TestCertificates.LEAF_A_PEM))
        repository.importCertificate(TestCertificates.der(TestCertificates.LEAF_B_PEM))
        val deletedRows = mutableListOf<String>()

        val result = clearTrustStore(refusingToDelete(fingerprintB)) { deletedRows += it }

        assertFalse(result.complete)
        assertEquals(listOf(fingerprintA), deletedRows)
        assertTrue(repository.hasCertificate(fingerprintB))
    }

    /**
     * A repository whose metadata writes all fail, and whose file deleter
     * refuses the DER file of [refused] (when given).
     */
    private fun failingMetadataWrites(refused: String? = null) =
        TrustStoreRepository(
            context,
            mockk(),
            fileDeleter = { file: File -> if (file.name == "$refused.der") false else file.delete() },
            fileWriter = { _, _ -> throw IOException("disk full") }
        )

    private suspend fun leafAVerifies(): Boolean =
        repository.verifyIDevIDChain(listOf(TestCertificates.der(TestCertificates.LEAF_A_PEM))) is
            VerificationResult.Valid

    @Test
    fun `removeTrustedCertificate keeps a CA whose metadata rewrite fails trusted for chain verification`() = runTest {
        repository.importInternalCACertificate(TestCertificates.cert(TestCertificates.ROOT_CA_A_PEM), "root A")
        assertTrue(leafAVerifies())
        val deletedRows = mutableListOf<String>()

        val removed = removeTrustedCertificate(failingMetadataWrites(), rootA) { deletedRows += rootA }

        // Reported trusted, row kept: chain verification must agree.
        assertFalse(removed)
        assertTrue(deletedRows.isEmpty())
        assertNotNull(repository.getCertificate(rootA))
        assertTrue(repository.hasCertificate(rootA))
        assertTrue("a CA reported trusted must still anchor its chains", leafAVerifies())
    }

    @Test
    fun `clearTrustStore keeps CAs whose metadata rewrite fails trusted for chain verification`() = runTest {
        repository.importInternalCACertificate(TestCertificates.cert(TestCertificates.ROOT_CA_A_PEM), "root A")
        repository.importCertificate(TestCertificates.der(TestCertificates.LEAF_B_PEM))
        val deletedRows = mutableListOf<String>()

        val result = clearTrustStore(failingMetadataWrites(refused = fingerprintB)) { deletedRows += it }

        assertFalse(result.complete)
        assertTrue(rootA in result.failed)
        assertFalse(rootA in result.removed)
        assertTrue(deletedRows.isEmpty())
        assertNotNull(repository.getCertificate(rootA))
        assertTrue(repository.hasCertificate(rootA))
        assertTrue("a CA reported trusted must still anchor its chains", leafAVerifies())
    }
}
