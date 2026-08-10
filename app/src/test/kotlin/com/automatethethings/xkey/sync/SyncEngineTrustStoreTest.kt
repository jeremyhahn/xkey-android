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
import com.automatethethings.xkey.truststore.TrustStoreRepository
import com.automatethethings.xkey.truststore.TrustedCA
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.slot
import io.mockk.unmockkAll
import kotlinx.coroutines.test.runTest
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Unit tests for the trust-store half of [SyncEngine].
 *
 * The engine's OATH and password paths go through Room and the Android
 * Keystore, so they can only be covered by the instrumented `SyncEngineTest`.
 * The certificate paths depend solely on [TrustStoreRepository] and the pure
 * [SyncCodec], so they can be reached on the JVM with a MockK constructor mock
 * and are worth pinning here: the DTO field names (`pem` / `fingerprint` /
 * `source` / `purpose`) are the go-xkms `SyncCertificate` contract, and the
 * added/skipped accounting is what both sync directions report to the user.
 */
class SyncEngineTrustStoreTest {

    private lateinit var engine: SyncEngine

    @Before
    fun setUp() {
        mockkConstructor(TrustStoreRepository::class)
        engine = SyncEngine(mockk<Context>())
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    private fun trustedCA(fingerprint: String, source: String = "manual") = TrustedCA(
        fingerprint = fingerprint,
        subjectDN = "CN=$fingerprint",
        issuerDN = "CN=issuer",
        notBefore = 0L,
        notAfter = 4_000_000_000_000L,
        label = null,
        importedAt = 1_700_000_000_000L,
        source = source
    )

    private fun pemOf(vararg der: Byte): String = SyncCodec.derToPem(der)

    // -------------------------------------------------------------------------
    // gatherCertificates
    // -------------------------------------------------------------------------

    @Test
    fun `gatherCertificates returns an empty array for an empty trust store`() = runTest {
        coEvery { anyConstructed<TrustStoreRepository>().getAllCertificates() } returns emptyList()

        assertEquals(0, engine.gatherCertificates().length())
    }

    @Test
    fun `gatherCertificates emits pem, fingerprint and source per certificate`() = runTest {
        coEvery { anyConstructed<TrustStoreRepository>().getAllCertificates() } returns
            listOf(trustedCA("aa11", source = "xkmsd"))
        coEvery { anyConstructed<TrustStoreRepository>().getCertificateDER("aa11") } returns
            byteArrayOf(0x30, 0x01, 0x02)

        val out = engine.gatherCertificates()

        assertEquals(1, out.length())
        val cert = out.getJSONObject(0)
        assertEquals(pemOf(0x30, 0x01, 0x02), cert.getString("pem"))
        assertEquals("aa11", cert.getString("fingerprint"))
        assertEquals("xkmsd", cert.getString("source"))
        assertEquals("only the three SyncCertificate fields are sent", 3, cert.length())
    }

    @Test
    fun `gatherCertificates skips certificates whose DER cannot be read`() = runTest {
        coEvery { anyConstructed<TrustStoreRepository>().getAllCertificates() } returns
            listOf(trustedCA("aa11"), trustedCA("bb22"), trustedCA("cc33"))
        coEvery { anyConstructed<TrustStoreRepository>().getCertificateDER("aa11") } returns
            byteArrayOf(1)
        coEvery { anyConstructed<TrustStoreRepository>().getCertificateDER("bb22") } returns null
        coEvery { anyConstructed<TrustStoreRepository>().getCertificateDER("cc33") } returns
            byteArrayOf(2)

        val out = engine.gatherCertificates()

        assertEquals(2, out.length())
        assertEquals("aa11", out.getJSONObject(0).getString("fingerprint"))
        assertEquals("cc33", out.getJSONObject(1).getString("fingerprint"))
    }

    // -------------------------------------------------------------------------
    // mergeCertificates
    // -------------------------------------------------------------------------

    private fun incoming(vararg objects: JSONObject) = JSONArray().apply {
        for (obj in objects) put(obj)
    }

    private fun syncCertificate(
        fingerprint: String,
        pem: String = SyncCodec.derToPem(byteArrayOf(0x30, 0x01)),
        purpose: String? = null
    ) = JSONObject().apply {
        put("fingerprint", fingerprint)
        put("pem", pem)
        purpose?.let { put("purpose", it) }
    }

    @Test
    fun `mergeCertificates on an empty array does nothing`() = runTest {
        val counts = engine.mergeCertificates(JSONArray())

        assertEquals(0, counts.added)
        assertEquals(0, counts.skipped)
        coVerify(exactly = 0) { anyConstructed<TrustStoreRepository>().importCertificate(any(), any()) }
    }

    @Test
    fun `mergeCertificates imports a certificate the phone does not have`() = runTest {
        coEvery { anyConstructed<TrustStoreRepository>().hasCertificate(any()) } returns false
        coEvery { anyConstructed<TrustStoreRepository>().importCertificate(any(), any()) } returns
            trustedCA("aa11")

        val counts = engine.mergeCertificates(incoming(syncCertificate("aa11")))

        assertEquals(1, counts.added)
        assertEquals(0, counts.skipped)
    }

    @Test
    fun `mergeCertificates skips a fingerprint that is already present`() = runTest {
        coEvery { anyConstructed<TrustStoreRepository>().hasCertificate("aa11") } returns true

        val counts = engine.mergeCertificates(incoming(syncCertificate("aa11")))

        assertEquals(0, counts.added)
        assertEquals(1, counts.skipped)
        coVerify(exactly = 0) { anyConstructed<TrustStoreRepository>().importCertificate(any(), any()) }
    }

    @Test
    fun `mergeCertificates skips an entry whose pem cannot be decoded`() = runTest {
        coEvery { anyConstructed<TrustStoreRepository>().hasCertificate(any()) } returns false

        val counts = engine.mergeCertificates(
            incoming(
                syncCertificate("aa11", pem = ""),
                syncCertificate("bb22", pem = "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"),
                syncCertificate("cc33", pem = "not base64 at all !!!")
            )
        )

        assertEquals(0, counts.added)
        assertEquals(3, counts.skipped)
        coVerify(exactly = 0) { anyConstructed<TrustStoreRepository>().importCertificate(any(), any()) }
    }

    @Test
    fun `mergeCertificates counts a rejected import as skipped`() = runTest {
        coEvery { anyConstructed<TrustStoreRepository>().hasCertificate(any()) } returns false
        coEvery { anyConstructed<TrustStoreRepository>().importCertificate(any(), any()) } returns null

        val counts = engine.mergeCertificates(incoming(syncCertificate("aa11")))

        assertEquals(0, counts.added)
        assertEquals("a repository rejection must not be reported as an import", 1, counts.skipped)
    }

    @Test
    fun `mergeCertificates labels imports with the purpose, defaulting to sync`() = runTest {
        val label = slot<String>()
        coEvery { anyConstructed<TrustStoreRepository>().hasCertificate(any()) } returns false
        coEvery {
            anyConstructed<TrustStoreRepository>().importCertificate(any(), capture(label))
        } returns trustedCA("aa11")

        engine.mergeCertificates(incoming(syncCertificate("aa11", purpose = "idevid")))
        assertEquals("idevid", label.captured)

        engine.mergeCertificates(incoming(syncCertificate("bb22", purpose = "   ")))
        assertEquals("a blank purpose falls back to 'sync'", "sync", label.captured)

        engine.mergeCertificates(incoming(syncCertificate("cc33")))
        assertEquals("sync", label.captured)
    }

    @Test
    fun `mergeCertificates forwards the decoded DER, not the pem text`() = runTest {
        val der = slot<ByteArray>()
        coEvery { anyConstructed<TrustStoreRepository>().hasCertificate(any()) } returns false
        coEvery {
            anyConstructed<TrustStoreRepository>().importCertificate(capture(der), any())
        } returns trustedCA("aa11")

        engine.mergeCertificates(
            incoming(syncCertificate("aa11", pem = SyncCodec.derToPem(byteArrayOf(0x30, 0x7F, 0x01))))
        )

        assertTrue(byteArrayOf(0x30, 0x7F, 0x01).contentEquals(der.captured))
    }

    @Test
    fun `mergeCertificates imports an entry with a blank fingerprint`() = runTest {
        // A blank fingerprint skips the duplicate check entirely, so the
        // repository is the only thing standing between it and the trust store.
        coEvery { anyConstructed<TrustStoreRepository>().importCertificate(any(), any()) } returns
            trustedCA("aa11")

        val counts = engine.mergeCertificates(
            incoming(JSONObject().put("pem", SyncCodec.derToPem(byteArrayOf(0x30, 0x01))))
        )

        assertEquals(1, counts.added)
        coVerify(exactly = 0) { anyConstructed<TrustStoreRepository>().hasCertificate(any()) }
    }

    @Test
    fun `mergeCertificates ignores non-object entries without counting them`() = runTest {
        // Documents current accounting: malformed array elements are dropped
        // silently and appear in neither the added nor the skipped total.
        coEvery { anyConstructed<TrustStoreRepository>().hasCertificate(any()) } returns false
        coEvery { anyConstructed<TrustStoreRepository>().importCertificate(any(), any()) } returns
            trustedCA("aa11")
        val array = JSONArray().apply {
            put("just a string")
            put(syncCertificate("aa11"))
        }

        val counts = engine.mergeCertificates(array)

        assertEquals(1, counts.added)
        assertEquals(0, counts.skipped)
    }

    @Test
    fun `mergeCertificates tallies a mixed batch`() = runTest {
        coEvery { anyConstructed<TrustStoreRepository>().hasCertificate("aa11") } returns true
        coEvery { anyConstructed<TrustStoreRepository>().hasCertificate("bb22") } returns false
        coEvery { anyConstructed<TrustStoreRepository>().hasCertificate("cc33") } returns false
        coEvery { anyConstructed<TrustStoreRepository>().importCertificate(any(), any()) } returns
            trustedCA("bb22")

        val counts = engine.mergeCertificates(
            incoming(
                syncCertificate("aa11"),
                syncCertificate("bb22"),
                syncCertificate("cc33", pem = "")
            )
        )

        assertEquals(1, counts.added)
        assertEquals(2, counts.skipped)
    }

    // -------------------------------------------------------------------------
    // Count value types
    // -------------------------------------------------------------------------

    @Test
    fun `count types are structural values`() {
        assertEquals(SyncEngine.CertCounts(1, 2), SyncEngine.CertCounts(1, 2))
        assertEquals(SyncEngine.ItemCounts(1, 2, 3), SyncEngine.ItemCounts(1, 2, 3))

        val certs = SyncEngine.CertCounts(added = 4, skipped = 5)
        assertEquals(4, certs.added)
        assertEquals(5, certs.skipped)

        val items = SyncEngine.ItemCounts(added = 6, updated = 7, skipped = 8)
        assertEquals(6, items.added)
        assertEquals(7, items.updated)
        assertEquals(8, items.skipped)
    }
}
