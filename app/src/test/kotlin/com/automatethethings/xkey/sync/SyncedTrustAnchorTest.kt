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
package com.automatethethings.xkey.sync

import android.content.Context
import com.automatethethings.xkey.crypto.SyncCodec
import com.automatethethings.xkey.truststore.TestCertificates
import com.automatethethings.xkey.truststore.TrustStoreRepository
import com.automatethethings.xkey.truststore.VerificationResult
import io.mockk.every
import io.mockk.mockk
import io.mockk.unmockkAll
import java.io.File
import kotlinx.coroutines.test.runTest
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * A certificate a paired desktop sends through sync is stored, shown and
 * synced back out, but never anchors an endorsement-key / IDevID chain: only
 * a certificate added on the phone does. Each incoming certificate merges on
 * its own, so a self-signed root or an unparsable entry is skipped and
 * counted, never thrown.
 *
 * The real [SyncEngine] and [TrustStoreRepository] run against a trust store
 * in a [TemporaryFolder]; only `Context.getDir` is mocked.
 */
class SyncedTrustAnchorTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    private lateinit var context: Context
    private lateinit var storeDir: File
    private lateinit var engine: SyncEngine

    @Before
    fun setUp() {
        storeDir = tempFolder.newFolder("trust_store")
        context = mockk()
        every { context.getDir("trust_store", Context.MODE_PRIVATE) } returns storeDir
        engine = SyncEngine(context)
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    private fun repository() = TrustStoreRepository(context)

    private fun synced(pem: String) = JSONObject()
        .put("fingerprint", TestCertificates.fingerprint(pem))
        .put("pem", pem)

    private fun incoming(vararg objects: JSONObject) = JSONArray().apply {
        for (obj in objects) put(obj)
    }

    /** The EK leaf the attacker's CA signed, verified the way enrollment does. */
    private suspend fun verifyLeaf() = repository().verifyIDevIDChain(
        listOf(TestCertificates.der(TestCertificates.LEAF_VIA_INTERMEDIATE_PEM))
    )

    @Test
    fun `a CA merged through sync does not anchor a leaf it signed`() = runTest {
        val counts = engine.mergeCertificates(incoming(synced(TestCertificates.INTERMEDIATE_A_PEM)))

        assertEquals(1, counts.added)
        val result = verifyLeaf()
        assertFalse(
            "a synced CA must not anchor endorsement verification, got $result",
            result is VerificationResult.Valid
        )
    }

    @Test
    fun `a synced CA is stored as synced and still syncs back out`() = runTest {
        engine.mergeCertificates(incoming(synced(TestCertificates.INTERMEDIATE_A_PEM)))

        val stored = repository().getAllCertificates().single()
        assertEquals("sync", stored.source)
        val out = engine.gatherCertificates()
        assertEquals(1, out.length())
        assertEquals(TestCertificates.fingerprint(TestCertificates.INTERMEDIATE_A_PEM), out.getJSONObject(0).getString("fingerprint"))
    }

    @Test
    fun `a CA added on the phone still anchors a leaf it signed`() = runTest {
        repository().importCertificate(TestCertificates.der(TestCertificates.INTERMEDIATE_A_PEM))

        assertTrue(verifyLeaf() is VerificationResult.Valid)
    }

    @Test
    fun `adding a synced CA on the phone makes it an anchor`() = runTest {
        engine.mergeCertificates(incoming(synced(TestCertificates.INTERMEDIATE_A_PEM)))

        repository().importCertificate(TestCertificates.der(TestCertificates.INTERMEDIATE_A_PEM))

        assertEquals("manual", repository().getAllCertificates().single().source)
        assertTrue(verifyLeaf() is VerificationResult.Valid)
    }

    @Test
    fun `a synced CA beside a phone-added anchor still does not anchor its own leaf`() = runTest {
        repository().importCertificate(TestCertificates.der(TestCertificates.LEAF_B_PEM))
        engine.mergeCertificates(incoming(synced(TestCertificates.INTERMEDIATE_A_PEM)))

        assertFalse(verifyLeaf() is VerificationResult.Valid)
    }

    @Test
    fun `each certificate merges on its own`() = runTest {
        val garbage = JSONObject().put("pem", SyncCodec.derToPem(byteArrayOf(0x30, 0x03, 0x01, 0x02, 0x03)))

        val counts = engine.mergeCertificates(
            incoming(
                synced(TestCertificates.INTERMEDIATE_A_PEM),
                synced(TestCertificates.ROOT_CA_A_PEM),
                garbage,
                synced(TestCertificates.LEAF_B_PEM)
            )
        )

        assertEquals(2, counts.added)
        assertEquals(2, counts.skipped)
        assertEquals(2, repository().getCertificateCount())
    }
}
