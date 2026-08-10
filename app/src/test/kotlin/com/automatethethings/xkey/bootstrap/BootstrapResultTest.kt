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
package com.automatethethings.xkey.bootstrap

import com.automatethethings.xkey.settings.BootstrapMethod
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for [CABundleResult] and the [BootstrapException] hierarchy.
 *
 * `CABundleResult` carries byte arrays, so its generated `equals`/`hashCode`
 * would compare by identity; both are hand-written and every discriminating
 * field is asserted here. The exception messages matter because they are what a
 * failed bootstrap surfaces to the user and to the audit log.
 */
class BootstrapResultTest {

    private val pem = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
        .toByteArray(Charsets.UTF_8)

    private fun result(
        bundle: ByteArray = pem,
        certificates: List<ByteArray> = listOf(byteArrayOf(1, 2, 3)),
        method: BootstrapMethod = BootstrapMethod.DIRECT,
        fetchedAt: Long = 1_700_000_000_000L
    ) = CABundleResult(bundle, certificates, method, fetchedAt)

    // ---------------------------------------------------------- CABundleResult

    @Test
    fun countsAndReportsItsCertificates() {
        val bundle = result(certificates = listOf(byteArrayOf(1), byteArrayOf(2)))

        assertEquals(2, bundle.certificateCount)
        assertTrue(bundle.isNotEmpty)
    }

    @Test
    fun anEmptyBundleReportsItself() {
        val bundle = result(bundle = ByteArray(0), certificates = emptyList())

        assertEquals(0, bundle.certificateCount)
        assertFalse(bundle.isNotEmpty)
    }

    @Test
    fun equalsComparesEveryFieldByContent() {
        val original = result()

        assertEquals(original, original)
        assertEquals(original, result(bundle = pem.copyOf(), certificates = listOf(byteArrayOf(1, 2, 3))))
        assertEquals(original.hashCode(), result().hashCode())
    }

    @Test
    fun equalsRejectsADifferentBundle() {
        assertNotEquals(result(), result(bundle = "different".toByteArray()))
    }

    @Test
    fun equalsRejectsADifferentCertificateCount() {
        assertNotEquals(result(), result(certificates = emptyList()))
    }

    @Test
    fun equalsRejectsDifferentCertificateContent() {
        assertNotEquals(result(), result(certificates = listOf(byteArrayOf(9, 9, 9))))
    }

    @Test
    fun equalsRejectsADifferentMethod() {
        assertNotEquals(result(), result(method = BootstrapMethod.DANE))
    }

    @Test
    fun equalsRejectsADifferentFetchTimestamp() {
        assertNotEquals(result(), result(fetchedAt = 1L))
    }

    @Test
    fun equalsRejectsAnUnrelatedType() {
        val other: Any = "not a bundle"
        assertFalse(result().equals(other))
    }

    @Test
    fun toStringSummarisesTheBundleWithoutDumpingIt() {
        val text = result().toString()

        assertTrue(text, text.contains("method=DIRECT"))
        assertTrue(text, text.contains("certificates=1"))
        assertTrue(text, text.contains("bundleSize=${pem.size}"))
    }

    @Test
    fun aFreshResultTimestampsItself() {
        val before = System.currentTimeMillis()
        val bundle = CABundleResult(pem, emptyList(), BootstrapMethod.SPKI)

        assertTrue(bundle.fetchedAt >= before)
    }

    // ------------------------------------------------------------- exceptions

    @Test
    fun daneAndNoiseExceptionsPrefixTheirReason() {
        val cause = IllegalStateException("boom")

        assertEquals("DANE bootstrap failed: no records", DANEException("no records").message)
        assertEquals(cause, DANEException("no records", cause).cause)
        assertEquals("Noise bootstrap failed: no key", NoiseBootstrapException("no key").message)
        assertEquals(cause, NoiseBootstrapException("no key", cause).cause)
    }

    @Test
    fun spkiExceptionDistinguishesAMismatchFromAFailure() {
        val expected = "aa".repeat(32)

        assertTrue(SPKIException(expected).message!!.contains("verification failed"))
        val mismatch = SPKIException(expected, "bb".repeat(32))
        assertTrue(mismatch.message!!, mismatch.message!!.contains("pin mismatch"))
        assertEquals(expected, mismatch.expectedPin)
        assertEquals("bb".repeat(32), mismatch.actualPin)
        assertNull(SPKIException(expected).actualPin)
    }

    @Test
    fun directExceptionNamesTheHttpStatusWhenThereIsOne() {
        assertEquals("Direct bootstrap failed: offline", DirectException("offline").message)
        assertEquals(
            "Direct bootstrap failed (HTTP 503): unavailable",
            DirectException("unavailable", 503).message
        )
        assertEquals(503, DirectException("unavailable", 503).httpStatusCode)
        assertNull(DirectException("offline").httpStatusCode)
    }

    @Test
    fun bootstrapFailureAggregatesEveryAttempt() {
        val failure = BootstrapFailedException(
            listOf(
                MethodAttemptError(BootstrapMethod.NOISE, NoiseBootstrapException("no address")),
                MethodAttemptError(BootstrapMethod.DIRECT, DirectException("offline"))
            )
        )

        assertTrue(failure.message!!, failure.message!!.contains("all methods failed"))
        assertTrue(failure.message!!, failure.message!!.contains("NOISE"))
        assertTrue(failure.message!!, failure.message!!.contains("DIRECT"))
        assertEquals(2, failure.attempts.size)
    }

    @Test
    fun bootstrapFailureWithNoAttemptsSaysSo() {
        assertEquals(
            "Bootstrap failed: no methods configured",
            BootstrapFailedException(emptyList()).message
        )
    }

    @Test
    fun configurationAndCertificateFailuresPrefixTheirReason() {
        assertTrue(
            BootstrapConfigException("pin is not hex").message!!
                .contains("Invalid bootstrap configuration: pin is not hex")
        )
        assertTrue(
            CertificateParseException("no blocks").message!!
                .contains("Certificate parsing failed: no blocks")
        )
        assertTrue(NoMethodsConfiguredException().message!!.contains("at least one"))
    }

    @Test
    fun everyBootstrapFailureIsCatchableAsItsSealedSupertype() {
        val failures: List<BootstrapException> = listOf(
            DANEException("a"),
            NoiseBootstrapException("b"),
            SPKIException("c"),
            DirectException("d"),
            BootstrapConfigException("e"),
            CertificateParseException("f"),
            NoMethodsConfiguredException(),
            BootstrapFailedException(emptyList())
        )

        failures.forEach { failure ->
            assertTrue(failure.message.orEmpty().isNotEmpty())
        }
    }

    // ----------------------------------------------------------- TLSA records

    @Test
    fun tlsaRecordsCompareByAssociationData() {
        val record = TlsaRecord(3, 1, 1, byteArrayOf(1, 2, 3))

        assertEquals(record, record)
        assertEquals(record, TlsaRecord(3, 1, 1, byteArrayOf(1, 2, 3)))
        assertEquals(record.hashCode(), TlsaRecord(3, 1, 1, byteArrayOf(1, 2, 3)).hashCode())
        assertNotEquals(record, TlsaRecord(2, 1, 1, byteArrayOf(1, 2, 3)))
        assertNotEquals(record, TlsaRecord(3, 0, 1, byteArrayOf(1, 2, 3)))
        assertNotEquals(record, TlsaRecord(3, 1, 2, byteArrayOf(1, 2, 3)))
        assertNotEquals(record, TlsaRecord(3, 1, 1, byteArrayOf(9)))
        val other: Any = "not a record"
        assertFalse(record.equals(other))
    }
}
