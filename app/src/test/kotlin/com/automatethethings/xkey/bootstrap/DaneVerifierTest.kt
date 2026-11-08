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

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * Unit tests for [DaneVerifier] against a fixed self-signed certificate with
 * SANs `kms.example.com` and `*.wild.example.com`.
 */
class DaneVerifierTest {

    private val certPem = """
        -----BEGIN CERTIFICATE-----
        MIIBuzCCAWGgAwIBAgIUJPDNZcTgxm99lYOhuF10ft90Z70wCgYIKoZIzj0EAwIw
        GjEYMBYGA1UEAwwPa21zLmV4YW1wbGUuY29tMB4XDTI2MDgwNDEzMjYxM1oXDTI3
        MDgwNDEzMjYxM1owGjEYMBYGA1UEAwwPa21zLmV4YW1wbGUuY29tMFkwEwYHKoZI
        zj0CAQYIKoZIzj0DAQcDQgAEBTPCQhbzmNpe9xLB07U/Pvz77AX5SF4en9ET1DTm
        /eVZ8PZpyPxlZ68GQmieapLTtXU6OE5L3lQffGnnLnJfpqOBhDCBgTAdBgNVHQ4E
        FgQUQLQOseVOWjFUD8GHI/s+/RN0EtYwHwYDVR0jBBgwFoAUQLQOseVOWjFUD8GH
        I/s+/RN0EtYwDwYDVR0TAQH/BAUwAwEB/zAuBgNVHREEJzAlgg9rbXMuZXhhbXBs
        ZS5jb22CEioud2lsZC5leGFtcGxlLmNvbTAKBggqhkjOPQQDAgNIADBFAiAEtMWa
        v5YDrxKalKT0Wk6NviJD59pdCmSg6+7VmFyQqwIhAKbOZMIBlF84j8yBGQhId+8g
        CZ/XFp4IiZLRCuUgjaWv
        -----END CERTIFICATE-----
    """.trimIndent()

    private val cert: X509Certificate = CertificateFactory.getInstance("X.509")
        .generateCertificate(ByteArrayInputStream(certPem.toByteArray())) as X509Certificate

    private fun sha256(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(data)

    // --- computeTlsaData ---

    @Test
    fun computesExactMatchAsTheRawCertificateDer() {
        assertArrayEquals(
            cert.encoded,
            DaneVerifier.computeTlsaData(cert, TlsaRecord.SELECTOR_FULL_CERT, TlsaRecord.MATCHING_EXACT)
        )
    }

    // --- verifyPeerChain ---

    @Test
    fun daneEeLeafMatchPasses() {
        val record = TlsaRecord(
            usage = TlsaRecord.USAGE_DANE_EE,
            selector = TlsaRecord.SELECTOR_SPKI,
            matchingType = TlsaRecord.MATCHING_SHA256,
            certData = sha256(cert.publicKey.encoded)
        )
        DaneVerifier.verifyPeerChain(listOf(cert), listOf(record), "anything.example.org")
    }

    @Test
    fun daneEeWrongDigestFails() {
        val record = TlsaRecord(
            usage = TlsaRecord.USAGE_DANE_EE,
            selector = TlsaRecord.SELECTOR_SPKI,
            matchingType = TlsaRecord.MATCHING_SHA256,
            certData = ByteArray(32)
        )
        assertThrows(DaneTlsaException::class.java) {
            DaneVerifier.verifyPeerChain(listOf(cert), listOf(record), "kms.example.com")
        }
    }

    @Test
    fun daneTaSelfSignedAnchorWithHostnamePasses() {
        val record = TlsaRecord(
            usage = TlsaRecord.USAGE_DANE_TA,
            selector = TlsaRecord.SELECTOR_FULL_CERT,
            matchingType = TlsaRecord.MATCHING_SHA256,
            certData = sha256(cert.encoded)
        )
        DaneVerifier.verifyPeerChain(listOf(cert), listOf(record), "kms.example.com")
    }

    // The anchor is the leaf itself, so this takes the anchor == leaf fast path in
    // verifyDaneTa; the hostname check must still reject a name the leaf does not carry.
    @Test
    fun daneTaSelfSignedAnchorWithWrongHostnameFails() {
        val record = TlsaRecord(
            usage = TlsaRecord.USAGE_DANE_TA,
            selector = TlsaRecord.SELECTOR_FULL_CERT,
            matchingType = TlsaRecord.MATCHING_SHA256,
            certData = sha256(cert.encoded)
        )
        assertThrows(DaneTlsaException::class.java) {
            DaneVerifier.verifyPeerChain(listOf(cert), listOf(record), "other.example.com")
        }
    }

    @Test
    fun pkixOnlyRecordsAreUnusable() {
        val record = TlsaRecord(
            usage = 1, // PKIX-EE requires WebPKI, not usable for bootstrap
            selector = TlsaRecord.SELECTOR_SPKI,
            matchingType = TlsaRecord.MATCHING_SHA256,
            certData = sha256(cert.publicKey.encoded)
        )
        assertThrows(DaneTlsaException::class.java) {
            DaneVerifier.verifyPeerChain(listOf(cert), listOf(record), "kms.example.com")
        }
    }

    @Test
    fun emptyChainFails() {
        val record = TlsaRecord(
            usage = TlsaRecord.USAGE_DANE_EE,
            selector = TlsaRecord.SELECTOR_SPKI,
            matchingType = TlsaRecord.MATCHING_SHA256,
            certData = sha256(cert.publicKey.encoded)
        )
        assertThrows(DaneTlsaException::class.java) {
            DaneVerifier.verifyPeerChain(emptyList(), listOf(record), "kms.example.com")
        }
    }

    // --- hostname matching ---

    @Test
    fun hostnameExactMatch() {
        assertTrue(DaneVerifier.matchesHostname(cert, "kms.example.com"))
        assertTrue(DaneVerifier.matchesHostname(cert, "KMS.EXAMPLE.COM"))
    }

    @Test
    fun hostnameWildcardMatchesSingleLabel() {
        assertTrue(DaneVerifier.matchesHostname(cert, "a.wild.example.com"))
        assertFalse("wildcard must not span labels", DaneVerifier.matchesHostname(cert, "a.b.wild.example.com"))
        assertFalse("wildcard must not match apex", DaneVerifier.matchesHostname(cert, "wild.example.com"))
    }

    // --- DNS response parsing (no network I/O: messages are built in-memory) ---

    private val resolver = DnsTlsaResolver("192.0.2.1", requireDnssec = true)
    private val query = resolver.buildQuery(QNAME)

    /** An answer-section resource record to serialize into a synthetic response. */
    private class Answer(
        val owner: String,
        val type: Int,
        val rrClass: Int = CLASS_IN,
        val rdata: ByteArray
    )

    private fun tlsaRdata(usage: Int = 3, selector: Int = 1, matching: Int = 1) =
        byteArrayOf(usage.toByte(), selector.toByte(), matching.toByte()) +
            sha256(cert.publicKey.encoded)

    private fun encodeName(name: String): ByteArray {
        val out = ByteArrayOutputStream()
        for (label in name.trimEnd('.').split('.')) {
            val bytes = label.toByteArray(Charsets.US_ASCII)
            out.write(bytes.size)
            out.write(bytes)
        }
        out.write(0)
        return out.toByteArray()
    }

    private fun ByteArrayOutputStream.writeU16(value: Int) {
        write((value shr 8) and 0xFF)
        write(value and 0xFF)
    }

    private fun ByteArrayOutputStream.writeHeader(answerCount: Int, flags: Int = FLAGS_OK) {
        write(query[0].toInt())
        write(query[1].toInt())
        writeU16(flags)
        writeU16(1)             // QDCOUNT
        writeU16(answerCount)   // ANCOUNT
        writeU16(0)             // NSCOUNT
        writeU16(0)             // ARCOUNT
    }

    private fun ByteArrayOutputStream.writeQuestion(
        qname: String = QNAME,
        qtype: Int = TYPE_TLSA,
        qclass: Int = CLASS_IN
    ) {
        write(encodeName(qname))
        writeU16(qtype)
        writeU16(qclass)
    }

    private fun ByteArrayOutputStream.writeAnswer(answer: Answer) {
        write(encodeName(answer.owner))
        writeU16(answer.type)
        writeU16(answer.rrClass)
        writeU16(0)                     // TTL high
        writeU16(300)                   // TTL low
        writeU16(answer.rdata.size)
        write(answer.rdata)
    }

    private fun buildResponse(
        answers: List<Answer>,
        qname: String = QNAME,
        qtype: Int = TYPE_TLSA,
        qclass: Int = CLASS_IN,
        flags: Int = FLAGS_OK
    ): ByteArray {
        val out = ByteArrayOutputStream()
        out.writeHeader(answers.size, flags)
        out.writeQuestion(qname, qtype, qclass)
        answers.forEach { out.writeAnswer(it) }
        return out.toByteArray()
    }

    @Test
    fun parsesOwnerNameCompressedToTheQuestion() {
        // Real resolvers compress the answer owner to the question at offset 12.
        val out = ByteArrayOutputStream()
        out.writeHeader(answerCount = 1)
        out.writeQuestion()
        out.write(0xC0)
        out.write(12)
        out.writeU16(TYPE_TLSA)
        out.writeU16(CLASS_IN)
        out.writeU16(0)
        out.writeU16(300)
        val rdata = tlsaRdata()
        out.writeU16(rdata.size)
        out.write(rdata)

        assertEquals(1, resolver.parseResponse(out.toByteArray(), query).size)
    }

    @Test
    fun rejectsQuestionThatDoesNotMatchTheQuery() {
        val response = buildResponse(
            answers = listOf(Answer(QNAME, TYPE_TLSA, rdata = tlsaRdata())),
            qname = "_443._tcp.evil.example.com."
        )
        assertThrows(DaneTlsaException::class.java) { resolver.parseResponse(response, query) }
    }

    @Test
    fun rejectsQuestionWithMismatchedTypeOrClass() {
        val wrongType = buildResponse(
            answers = listOf(Answer(QNAME, TYPE_TLSA, rdata = tlsaRdata())),
            qtype = 1 // A
        )
        assertThrows(DaneTlsaException::class.java) { resolver.parseResponse(wrongType, query) }

        val wrongClass = buildResponse(
            answers = listOf(Answer(QNAME, TYPE_TLSA, rdata = tlsaRdata())),
            qclass = CLASS_CH
        )
        assertThrows(DaneTlsaException::class.java) { resolver.parseResponse(wrongClass, query) }
    }

    @Test
    fun rejectsTlsaAnswerForADifferentOwner() {
        val response = buildResponse(
            listOf(Answer("_443._tcp.evil.example.com.", TYPE_TLSA, rdata = tlsaRdata()))
        )
        assertThrows(DaneTlsaException::class.java) { resolver.parseResponse(response, query) }
    }

    @Test
    fun rejectsTlsaAnswerInAForeignClass() {
        val response = buildResponse(
            listOf(Answer(QNAME, TYPE_TLSA, rrClass = CLASS_CH, rdata = tlsaRdata()))
        )
        assertThrows(DaneTlsaException::class.java) { resolver.parseResponse(response, query) }
    }

    @Test
    fun ignoresAnswersOfOtherTypes() {
        val response = buildResponse(
            listOf(Answer(QNAME, 1, rdata = byteArrayOf(192.toByte(), 0, 2, 1)))
        )
        // Type A only: nothing usable, so the lookup must fail rather than
        // silently return an empty TLSA set.
        assertThrows(DaneTlsaException::class.java) { resolver.parseResponse(response, query) }
    }

    @Test(timeout = 10_000)
    fun rejectsSelfReferentialCompressionPointer() {
        val out = ByteArrayOutputStream()
        out.writeHeader(answerCount = 1)
        out.writeQuestion()
        val pointerOffset = out.size()
        out.write(0xC0)
        out.write(pointerOffset) // points at itself: a loop if followed naively
        out.writeU16(TYPE_TLSA)
        out.writeU16(CLASS_IN)

        assertThrows(DaneTlsaException::class.java) {
            resolver.parseResponse(out.toByteArray(), query)
        }
    }

    @Test(timeout = 10_000)
    fun rejectsForwardCompressionPointer() {
        val out = ByteArrayOutputStream()
        out.writeHeader(answerCount = 1)
        out.writeQuestion()
        val pointerOffset = out.size()
        out.write(0xC0)
        out.write(pointerOffset + 2) // forward pointer, out of the parsed region
        out.writeU16(TYPE_TLSA)
        out.writeU16(CLASS_IN)

        assertThrows(DaneTlsaException::class.java) {
            resolver.parseResponse(out.toByteArray(), query)
        }
    }

    @Test(timeout = 10_000)
    fun rejectsTruncatedNameRunningPastTheMessage() {
        val out = ByteArrayOutputStream()
        out.writeHeader(answerCount = 1)
        out.writeQuestion()
        out.write(63)              // label length with no label bytes following
        out.write("abc".toByteArray(Charsets.US_ASCII))

        assertThrows(DaneTlsaException::class.java) {
            resolver.parseResponse(out.toByteArray(), query)
        }
    }

    @Test
    fun rejectsAnswerWithRdLengthPastTheMessage() {
        val out = ByteArrayOutputStream()
        out.writeHeader(answerCount = 1)
        out.writeQuestion()
        out.write(encodeName(QNAME))
        out.writeU16(TYPE_TLSA)
        out.writeU16(CLASS_IN)
        out.writeU16(0)
        out.writeU16(300)
        out.writeU16(4096)         // RDLENGTH far beyond the buffer
        out.write(tlsaRdata())

        assertThrows(DaneTlsaException::class.java) {
            resolver.parseResponse(out.toByteArray(), query)
        }
    }

    @Test
    fun rejectsTransactionIdMismatch() {
        val response = buildResponse(listOf(Answer(QNAME, TYPE_TLSA, rdata = tlsaRdata())))
        response[0] = (response[0].toInt() xor 0xFF).toByte()
        assertThrows(DaneTlsaException::class.java) { resolver.parseResponse(response, query) }
    }

    // --- bootstrap bundle size limits ---

    @Test
    fun bundleWithinTheCapParsesEveryCertificate() {
        val bundle = (1..4).joinToString("\n") { certPem }.toByteArray()
        assertEquals(4, BootstrapClient.parsePemBundle(bundle, maxCertificates = 4).size)
    }

    @Test
    fun defaultBundleCapRejectsCertificateFlood() {
        val flood = (1..(BootstrapClient.MAX_BUNDLE_CERTIFICATES + 1))
            .joinToString("\n") { certPem }
            .toByteArray()
        assertThrows(CertificateParseException::class.java) {
            BootstrapClient.parsePemBundle(flood)
        }
    }

}

private const val QNAME = "_443._tcp.kms.example.com."
private const val TYPE_TLSA = 52
private const val TYPE_CNAME = 5
private const val CLASS_IN = 1
private const val CLASS_CH = 3
private const val FLAG_AD = 0x0020

/** QR + RD + RA + AD, rcode NOERROR. */
private const val FLAGS_OK = 0x8000 or 0x0100 or 0x0080 or FLAG_AD
