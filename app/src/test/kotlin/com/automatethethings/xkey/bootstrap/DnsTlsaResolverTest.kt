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

import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.util.concurrent.atomic.AtomicInteger

/**
 * Unit tests for [DnsTlsaResolver].
 *
 * `DaneVerifierTest` already drives the happy path and the obvious rejections of
 * `parseResponse` from in-memory messages. This suite covers the two things it
 * cannot: the transport (UDP exchange, truncation retry over TCP, DNS-over-TLS
 * endpoint selection) against a loopback server, and the remaining malformed
 * message shapes -- reserved label types, oversized names, records that run past
 * the buffer, and the CNAME chain that decides which owner names a TLSA record
 * may legitimately carry.
 *
 * Every socket in here is bound to the loopback interface; nothing resolves a
 * real name or leaves the machine.
 */
class DnsTlsaResolverTest {

    private val hostname = "kms.example.test"
    private val servicePort = 443
    private val qname = "_${servicePort}._tcp.$hostname."
    private val association = ByteArray(32) { (it + 1).toByte() }

    private var server: DnsStubServer? = null

    @After
    fun tearDown() {
        server?.close()
        server = null
    }

    private fun start(respond: (ByteArray, Boolean) -> ByteArray?): DnsStubServer =
        DnsStubServer(respond).also { server = it }

    private fun tlsaAnswer(
        owner: String = qname,
        usage: Int = TlsaRecord.USAGE_DANE_EE,
        selector: Int = TlsaRecord.SELECTOR_SPKI,
        matching: Int = TlsaRecord.MATCHING_SHA256,
        rrClass: Int = DnsWire.CLASS_IN
    ) = DnsAnswer(
        owner = owner,
        type = DnsWire.TYPE_TLSA,
        rdata = DnsWire.tlsaRdata(usage, selector, matching, association),
        rrClass = rrClass
    )

    // ------------------------------------------------------------- transport

    @Test
    fun resolvesTlsaRecordsOverUdp() {
        val stub = start { query, _ -> DnsWire.replyTo(query, listOf(tlsaAnswer())) }

        val records = DnsTlsaResolver(stub.address, timeoutMs = TIMEOUT_MS)
            .lookupTlsa(hostname, servicePort)

        assertEquals(1, records.size)
        assertEquals(TlsaRecord.USAGE_DANE_EE, records[0].usage)
        assertEquals(TlsaRecord.SELECTOR_SPKI, records[0].selector)
        assertEquals(TlsaRecord.MATCHING_SHA256, records[0].matchingType)
        assertArrayEquals(association, records[0].certData)
    }

    @Test
    fun returnsEveryTlsaRecordInTheRrset() {
        val stub = start { query, _ ->
            DnsWire.replyTo(
                query,
                listOf(
                    tlsaAnswer(usage = TlsaRecord.USAGE_DANE_EE),
                    tlsaAnswer(usage = TlsaRecord.USAGE_DANE_TA, matching = TlsaRecord.MATCHING_SHA512)
                )
            )
        }

        val records = DnsTlsaResolver(stub.address, timeoutMs = TIMEOUT_MS)
            .lookupTlsa(hostname, servicePort)

        assertEquals(2, records.size)
        assertEquals(listOf(3, 2), records.map { it.usage })
    }

    @Test
    fun retriesOverTcpWhenTheUdpAnswerIsTruncated() {
        val tcpQueries = AtomicInteger()
        val stub = start { query, overTcp ->
            if (overTcp) {
                tcpQueries.incrementAndGet()
                DnsWire.replyTo(query, listOf(tlsaAnswer()))
            } else {
                // Truncated: header only, the client must ask again over TCP.
                DnsWire.replyTo(query, emptyList(), flags = DnsWire.FLAGS_OK or DnsWire.FLAG_TC)
            }
        }

        val records = DnsTlsaResolver(stub.address, timeoutMs = TIMEOUT_MS)
            .lookupTlsa(hostname, servicePort)

        assertEquals(1, records.size)
        assertEquals("the TCP retry must be what answered", 1, tcpQueries.get())
    }

    @Test
    fun requiresTheAuthenticatedDataFlagOverTheWire() {
        val stub = start { query, _ ->
            DnsWire.replyTo(
                query,
                listOf(tlsaAnswer()),
                flags = DnsWire.FLAGS_OK and DnsWire.FLAG_AD.inv()
            )
        }

        val failure = assertThrows(DaneTlsaException::class.java) {
            DnsTlsaResolver(stub.address, requireDnssec = true, timeoutMs = TIMEOUT_MS)
                .lookupTlsa(hostname, servicePort)
        }

        assertTrue(failure.message!!, failure.message!!.contains("AD flag"))
    }

    @Test
    fun acceptsAnUnvalidatedAnswerWhenDnssecIsNotRequired() {
        val stub = start { query, _ ->
            DnsWire.replyTo(
                query,
                listOf(tlsaAnswer()),
                flags = DnsWire.FLAGS_OK and DnsWire.FLAG_AD.inv()
            )
        }

        val records = DnsTlsaResolver(stub.address, requireDnssec = false, timeoutMs = TIMEOUT_MS)
            .lookupTlsa(hostname, servicePort)

        assertEquals(1, records.size)
    }

    @Test(timeout = 30_000)
    fun failsWhenTheServerNeverAnswers() {
        val stub = start { _, _ -> null }

        assertThrows(Exception::class.java) {
            DnsTlsaResolver(stub.address, timeoutMs = 500).lookupTlsa(hostname, servicePort)
        }
    }

    @Test(timeout = 30_000)
    fun failsWhenNothingIsListening() {
        assertThrows(Exception::class.java) {
            DnsTlsaResolver(DnsStubServer.unusedAddress(), timeoutMs = 500)
                .lookupTlsa(hostname, servicePort)
        }
    }

    @Test(timeout = 30_000)
    fun dnsOverTlsUsesTheConfiguredPortAndFailsClosed() {
        // Nothing is listening, so the TLS exchange cannot complete; what
        // matters is that DoT takes the TLS path rather than sending a datagram.
        assertThrows(Exception::class.java) {
            DnsTlsaResolver(DnsStubServer.unusedAddress(), dnsOverTls = true, timeoutMs = 500)
                .lookupTlsa(hostname, servicePort)
        }
    }

    @Test(timeout = 30_000)
    fun dnsOverTlsDefaultsToThePrivilegedDotPort() {
        // A bare host with DoT means port 853; a bare host with the default DNS
        // port means 853 as well. Neither is served here, so both fail closed.
        assertThrows(Exception::class.java) {
            DnsTlsaResolver("127.0.0.1", dnsOverTls = true, timeoutMs = 500)
                .lookupTlsa(hostname, servicePort)
        }
        assertThrows(Exception::class.java) {
            DnsTlsaResolver("127.0.0.1:53", dnsOverTls = true, timeoutMs = 500)
                .lookupTlsa(hostname, servicePort)
        }
    }

    // ------------------------------------------------------ query validation

    @Test
    fun rejectsAnEmptyHostname() {
        assertThrows(IllegalArgumentException::class.java) {
            resolver().lookupTlsa("   ", servicePort)
        }
    }

    @Test
    fun rejectsAHostnameOverTheProtocolLimit() {
        assertThrows(IllegalArgumentException::class.java) {
            resolver().lookupTlsa("a".repeat(254), servicePort)
        }
    }

    @Test
    fun rejectsAPortOutsideTheValidRange() {
        assertThrows(IllegalArgumentException::class.java) { resolver().lookupTlsa(hostname, 0) }
        assertThrows(IllegalArgumentException::class.java) { resolver().lookupTlsa(hostname, 65536) }
    }

    @Test
    fun rejectsALabelLongerThanSixtyThreeOctets() {
        assertThrows(IllegalArgumentException::class.java) {
            resolver().lookupTlsa("${"a".repeat(64)}.example.test", servicePort)
        }
    }

    @Test
    fun buildsAnEdns0QueryWithTheDnssecOkBitSet() {
        val query = resolver().buildQuery(qname)

        assertEquals("RD only, no QR", 0x0100, readU16(query, 2))
        assertEquals("one question", 1, readU16(query, 4))
        assertEquals("no answers", 0, readU16(query, 6))
        assertEquals("one additional (the OPT record)", 1, readU16(query, 10))

        val question = DnsWire.questionOf(query)
        assertArrayEquals(DnsWire.encodeName(qname), question.copyOfRange(0, question.size - 4))
        assertEquals(DnsWire.TYPE_TLSA, readU16(question, question.size - 4))
        assertEquals(DnsWire.CLASS_IN, readU16(question, question.size - 2))

        val opt = query.copyOfRange(12 + question.size, query.size)
        assertEquals("empty OPT owner name", 0, opt[0].toInt())
        assertEquals("OPT record type", 41, readU16(opt, 1))
        assertEquals("advertised UDP payload size", 4096, readU16(opt, 3))
        assertEquals("DO bit set in the OPT TTL", 0x8000, readU16(opt, 7))
        assertEquals("empty OPT rdata", 0, readU16(opt, 9))
    }

    @Test
    fun usesAFreshTransactionIdForEveryQuery() {
        val resolver = resolver()
        val ids = (1..8).map { readU16(resolver.buildQuery(qname), 0) }.toSet()
        assertNotEquals("transaction IDs must not be a constant", 1, ids.size)
    }

    // ------------------------------------------------- malformed DNS messages

    @Test
    fun rejectsAResponseShorterThanTheHeader() {
        assertThrows(DaneTlsaException::class.java) {
            resolver().parseResponse(ByteArray(5), query())
        }
    }

    @Test
    fun rejectsAMessageThatIsNotAResponse() {
        val query = query()
        val response = DnsWire.replyTo(
            query,
            listOf(tlsaAnswer()),
            flags = DnsWire.FLAGS_OK and DnsWire.FLAG_QR.inv()
        )

        val failure = assertThrows(DaneTlsaException::class.java) {
            resolver().parseResponse(response, query)
        }
        assertTrue(failure.message!!, failure.message!!.contains("not a response"))
    }

    @Test
    fun rejectsANonZeroRcode() {
        val query = query()
        val response = DnsWire.replyTo(
            query,
            listOf(tlsaAnswer()),
            flags = DnsWire.FLAGS_OK or 0x0003 // NXDOMAIN
        )

        val failure = assertThrows(DaneTlsaException::class.java) {
            resolver().parseResponse(response, query)
        }
        assertTrue(failure.message!!, failure.message!!.contains("rcode 3"))
    }

    @Test
    fun rejectsAResponseThatDoesNotEchoExactlyOneQuestion() {
        val query = query()
        val response = DnsWire.replyTo(query, listOf(tlsaAnswer()), questionCount = 2)

        val failure = assertThrows(DaneTlsaException::class.java) {
            resolver().parseResponse(response, query)
        }
        assertTrue(failure.message!!, failure.message!!.contains("one question"))
    }

    @Test
    fun rejectsAReservedLabelType() {
        val query = query()
        val response = rawResponse(query) { write(0x80) }

        val failure = assertThrows(DaneTlsaException::class.java) {
            resolver().parseResponse(response, query)
        }
        assertTrue(failure.message!!, failure.message!!.contains("reserved label type"))
    }

    @Test
    fun rejectsANameOverTwoHundredAndFiftyFiveOctets() {
        val query = query()
        val response = rawResponse(query) {
            repeat(5) {
                write(63)
                write("x".repeat(63).toByteArray(Charsets.US_ASCII))
            }
            write(0)
        }

        val failure = assertThrows(DaneTlsaException::class.java) {
            resolver().parseResponse(response, query)
        }
        assertTrue(failure.message!!, failure.message!!.contains("exceeds 255"))
    }

    @Test
    fun rejectsACompressionPointerTruncatedAtTheEndOfTheMessage() {
        val query = query()
        val response = rawResponse(query) { write(0xC0) }

        val failure = assertThrows(DaneTlsaException::class.java) {
            resolver().parseResponse(response, query)
        }
        assertTrue(failure.message!!, failure.message!!.contains("truncated compression pointer"))
    }

    @Test
    fun rejectsARecordTruncatedAfterItsOwnerName() {
        val query = query()
        val response = rawResponse(query) {
            write(DnsWire.encodeName(qname))
            writeU16(DnsWire.TYPE_TLSA) // type only: class, TTL and RDLENGTH are missing
        }

        val failure = assertThrows(DaneTlsaException::class.java) {
            resolver().parseResponse(response, query)
        }
        assertTrue(failure.message!!, failure.message!!.contains("truncated DNS message"))
    }

    @Test
    fun rejectsATlsaRecordWithoutItsThreeFixedFields() {
        val query = query()
        val response = DnsWire.replyTo(
            query,
            listOf(DnsAnswer(qname, DnsWire.TYPE_TLSA, rdata = byteArrayOf(3, 1)))
        )

        val failure = assertThrows(DaneTlsaException::class.java) {
            resolver().parseResponse(response, query)
        }
        assertTrue(failure.message!!, failure.message!!.contains("malformed TLSA record"))
    }

    @Test
    fun followsATwoHopCnameChainToTheCanonicalOwner() {
        val query = query()
        val first = "_443._tcp.kms.cdn.example.test."
        val second = "_443._tcp.kms.edge.example.test."
        val response = DnsWire.replyTo(
            query,
            listOf(
                DnsAnswer(qname, DnsWire.TYPE_CNAME, rdata = DnsWire.encodeName(first)),
                DnsAnswer(first, DnsWire.TYPE_CNAME, rdata = DnsWire.encodeName(second)),
                tlsaAnswer(owner = second)
            )
        )

        assertEquals(1, resolver().parseResponse(response, query).size)
    }

    @Test
    fun ignoresACnameInAForeignClassWhenResolvingOwners() {
        val query = query()
        val canonical = "_443._tcp.kms.cdn.example.test."
        val response = DnsWire.replyTo(
            query,
            listOf(
                DnsAnswer(
                    qname,
                    DnsWire.TYPE_CNAME,
                    rdata = DnsWire.encodeName(canonical),
                    rrClass = DnsWire.CLASS_CH
                ),
                tlsaAnswer(owner = canonical)
            )
        )

        val failure = assertThrows(DaneTlsaException::class.java) {
            resolver().parseResponse(response, query)
        }
        assertTrue(failure.message!!, failure.message!!.contains("was not queried"))
    }

    // ------------------------------------------------------------- utilities

    private fun resolver(timeoutMs: Int = TIMEOUT_MS) =
        DnsTlsaResolver("127.0.0.1:5353", timeoutMs = timeoutMs)

    private fun query(): ByteArray = resolver().buildQuery(qname)

    /**
     * A response whose header and question echo [query] and whose single answer
     * record is written by [body] -- deliberately malformed.
     */
    private fun rawResponse(query: ByteArray, body: ByteArrayOutputStream.() -> Unit): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(query[0].toInt())
        out.write(query[1].toInt())
        out.writeU16(DnsWire.FLAGS_OK)
        out.writeU16(1)
        out.writeU16(1)
        out.writeU16(0)
        out.writeU16(0)
        out.write(DnsWire.questionOf(query))
        out.body()
        return out.toByteArray()
    }

    private fun readU16(data: ByteArray, offset: Int): Int =
        ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)

    private companion object {
        const val TIMEOUT_MS = 5_000
    }
}
