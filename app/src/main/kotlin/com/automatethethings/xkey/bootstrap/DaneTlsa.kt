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

import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.CertPathValidator
import java.security.cert.CertificateFactory
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import javax.net.ssl.SNIHostName
import javax.net.ssl.SNIServerName
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.X509TrustManager

/**
 * RFC 6698 TLSA record as returned from DNS.
 *
 * Mirrors go-truststrap's `dane.TLSARecord`; the Android bootstrap DANE mode
 * is wire- and policy-compatible with the go-xkms desktop implementation.
 */
data class TlsaRecord(
    val usage: Int,
    val selector: Int,
    val matchingType: Int,
    val certData: ByteArray
) {
    companion object {
        /** Certificate Usage 2 (DANE-TA): trust anchor assertion. */
        const val USAGE_DANE_TA = 2

        /** Certificate Usage 3 (DANE-EE): end-entity assertion. */
        const val USAGE_DANE_EE = 3

        /** Selector 0: match the full certificate. */
        const val SELECTOR_FULL_CERT = 0

        /** Selector 1: match the SubjectPublicKeyInfo. */
        const val SELECTOR_SPKI = 1

        /** Matching Type 0: exact match of the selected content. */
        const val MATCHING_EXACT = 0

        /** Matching Type 1: SHA-256 of the selected content. */
        const val MATCHING_SHA256 = 1

        /** Matching Type 2: SHA-512 of the selected content. */
        const val MATCHING_SHA512 = 2
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is TlsaRecord) return false
        return usage == other.usage && selector == other.selector &&
            matchingType == other.matchingType && certData.contentEquals(other.certData)
    }

    override fun hashCode(): Int {
        var result = usage
        result = 31 * result + selector
        result = 31 * result + matchingType
        result = 31 * result + certData.contentHashCode()
        return result
    }
}

/** Thrown for DNS lookup or TLSA verification failures in the DANE pipeline. */
class DaneTlsaException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * Minimal DNS TLSA resolver querying `_<port>._tcp.<hostname>.` (RFC 6698
 * Section 3) against a configured DNS server over UDP (with TCP fallback on
 * truncation) or DNS-over-TLS. Sets the EDNS0 DO bit and, when
 * [requireDnssec] is set, requires the Authenticated Data flag in the
 * response — the same trust model as go-truststrap's resolver (`RequireAD`).
 */
class DnsTlsaResolver(
    dnsServer: String,
    private val dnsOverTls: Boolean = false,
    private val requireDnssec: Boolean = true,
    private val timeoutMs: Int = 5000
) {
    private val serverHost: String
    private val serverPort: Int

    init {
        val idx = dnsServer.lastIndexOf(':')
        if (idx > 0 && !dnsServer.substring(idx + 1).contains(']')) {
            serverHost = dnsServer.substring(0, idx)
            val configured = dnsServer.substring(idx + 1).toIntOrNull() ?: DEFAULT_DNS_PORT
            // A plain-DNS port with DoT enabled means the default DoT port.
            serverPort = if (dnsOverTls && configured == DEFAULT_DNS_PORT) DOT_PORT else configured
        } else {
            serverHost = dnsServer
            serverPort = if (dnsOverTls) DOT_PORT else DEFAULT_DNS_PORT
        }
    }

    companion object {
        private const val DEFAULT_DNS_PORT = 53
        private const val DOT_PORT = 853
        private const val TYPE_TLSA = 52
        private const val TYPE_CNAME = 5
        private const val CLASS_IN = 1
        private const val UDP_PAYLOAD_SIZE = 4096
        private const val HEADER_SIZE = 12
        private const val FLAG_QR = 0x8000
        private const val FLAG_TC = 0x0200
        private const val FLAG_AD = 0x0020

        /** RFC 1035 2.3.4: a DNS name is at most 255 octets on the wire. */
        private const val MAX_NAME_LENGTH = 255

        /** Compression pointers per name; bounds the work a hostile message can force. */
        private const val MAX_NAME_JUMPS = 16

        /** Longest CNAME chain followed when resolving the TLSA owner name. */
        private const val MAX_CNAME_DEPTH = 8
    }

    /** A resource record located in a DNS message, with its RDATA left in place. */
    private data class ResourceRecord(
        val owner: String,
        val type: Int,
        val rrClass: Int,
        val rdataStart: Int,
        val rdLength: Int
    )

    /** The question section of a DNS message. */
    private data class Question(val qname: String, val qtype: Int, val qclass: Int)

    /**
     * Looks up TLSA records for [hostname]:[port]. Throws [DaneTlsaException]
     * when the lookup fails, DNSSEC is required but the AD flag is absent, or
     * no TLSA records exist.
     */
    fun lookupTlsa(hostname: String, port: Int): List<TlsaRecord> {
        require(hostname.isNotBlank() && hostname.length <= 253) { "invalid hostname" }
        require(port in 1..65535) { "invalid port" }

        val qname = "_$port._tcp.${hostname.trimEnd('.')}."
        val query = buildQuery(qname)

        val response = if (dnsOverTls) {
            exchangeTls(query)
        } else {
            val udpResponse = exchangeUdp(query)
            if (udpResponse.size < HEADER_SIZE) throw DaneTlsaException("DNS response too short")
            // Retry over TCP when the response is truncated.
            if ((readU16(udpResponse, 2) and FLAG_TC) != 0) exchangeTcp(query) else udpResponse
        }
        return parseResponse(response, query)
    }

    internal fun buildQuery(qname: String): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        val id = SecureRandom().nextInt(0x10000)
        writeU16(out, id)
        writeU16(out, 0x0100)          // RD=1
        writeU16(out, 1)               // QDCOUNT
        writeU16(out, 0)               // ANCOUNT
        writeU16(out, 0)               // NSCOUNT
        writeU16(out, 1)               // ARCOUNT (EDNS0 OPT)
        for (label in qname.trimEnd('.').split('.')) {
            val bytes = label.toByteArray(Charsets.US_ASCII)
            require(bytes.size in 1..63) { "invalid DNS label: $label" }
            out.write(bytes.size)
            out.write(bytes)
        }
        out.write(0)                   // root label
        writeU16(out, TYPE_TLSA)
        writeU16(out, CLASS_IN)
        // EDNS0 OPT pseudo-record with the DO bit set.
        out.write(0)                   // empty name
        writeU16(out, 41)              // OPT
        writeU16(out, UDP_PAYLOAD_SIZE)
        out.write(0)                   // extended RCODE
        out.write(0)                   // EDNS version
        writeU16(out, 0x8000)          // DO bit
        writeU16(out, 0)               // RDLEN
        return out.toByteArray()
    }

    /**
     * Sends [query] over UDP and returns the first datagram that actually came
     * from the configured server. Accepting any arriving datagram would let an
     * off-path attacker race the real resolver, so the socket is connected (the
     * kernel then drops foreign sources) and the source address and port are
     * re-checked on every datagram; unmatched datagrams are discarded and the
     * receive is retried until the overall timeout expires.
     */
    private fun exchangeUdp(query: ByteArray): ByteArray {
        DatagramSocket().use { socket ->
            val address = InetAddress.getByName(serverHost)
            socket.connect(address, serverPort)
            socket.send(DatagramPacket(query, query.size, address, serverPort))

            val deadline = System.nanoTime() + timeoutMs * 1_000_000L
            val buffer = ByteArray(UDP_PAYLOAD_SIZE)
            while (true) {
                val remainingMs = (deadline - System.nanoTime()) / 1_000_000L
                if (remainingMs <= 0) throw DaneTlsaException("DNS query timed out")
                socket.soTimeout = remainingMs.coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
                val packet = DatagramPacket(buffer, buffer.size)
                socket.receive(packet)
                if (packet.address == address && packet.port == serverPort) {
                    return buffer.copyOf(packet.length)
                }
            }
        }
    }

    private fun exchangeTcp(query: ByteArray): ByteArray {
        Socket().use { socket ->
            socket.soTimeout = timeoutMs
            socket.connect(InetSocketAddress(serverHost, serverPort), timeoutMs)
            return exchangeStream(socket, query)
        }
    }

    /**
     * Performs the exchange over DNS-over-TLS. The socket enables endpoint
     * identification so the DNS server's certificate is checked against
     * [serverHost] — without it an SSLSocket validates the chain but not the
     * name, which leaves DoT open to any host holding a valid certificate
     * (RFC 8310 Section 8.1) — and restricts the connection to TLS 1.2+ to
     * match go-truststrap's resolver `tls.Config`.
     */
    private fun exchangeTls(query: ByteArray): ByteArray {
        val socket = SSLSocketFactory.getDefault().createSocket() as SSLSocket
        socket.use { tls ->
            tls.soTimeout = timeoutMs
            tls.sslParameters = tls.sslParameters.apply {
                endpointIdentificationAlgorithm = "HTTPS"
                // RFC 6066 Section 3: literal addresses must not be sent as SNI.
                if (!isIpLiteral(serverHost)) {
                    serverNames = listOf<SNIServerName>(SNIHostName(serverHost))
                }
            }
            val modern = tls.supportedProtocols.filter { it == "TLSv1.2" || it == "TLSv1.3" }
            if (modern.isNotEmpty()) tls.enabledProtocols = modern.toTypedArray()
            tls.connect(InetSocketAddress(serverHost, serverPort), timeoutMs)
            tls.startHandshake()
            return exchangeStream(tls, query)
        }
    }

    private fun isIpLiteral(host: String): Boolean =
        host.contains(':') || (host.isNotEmpty() && host.all { it.isDigit() || it == '.' })

    /** TCP/TLS DNS framing: 2-byte big-endian length prefix (RFC 1035 4.2.2). */
    private fun exchangeStream(socket: Socket, query: ByteArray): ByteArray {
        val output = DataOutputStream(socket.getOutputStream())
        output.writeShort(query.size)
        output.write(query)
        output.flush()
        val input = DataInputStream(socket.getInputStream())
        val length = input.readUnsignedShort()
        val response = ByteArray(length)
        input.readFully(response)
        return response
    }

    /**
     * Parses the TLSA RRset out of [response], which must be an answer to
     * [query]. Beyond the transaction ID, rcode and AD flag, the response has
     * to echo the exact question that was asked and every returned TLSA record
     * has to be owned by the queried name (or by a canonical name a CNAME in
     * the same response points at) and be of class IN — otherwise a hostile or
     * compromised resolver could hand back trust anchors for a name that was
     * never queried.
     */
    internal fun parseResponse(response: ByteArray, query: ByteArray): List<TlsaRecord> {
        if (response.size < HEADER_SIZE) throw DaneTlsaException("DNS response too short")
        if (readU16(response, 0) != readU16(query, 0)) {
            throw DaneTlsaException("DNS response ID mismatch")
        }
        val flags = readU16(response, 2)
        if ((flags and FLAG_QR) == 0) throw DaneTlsaException("DNS message is not a response")
        val rcode = flags and 0x000F
        if (rcode != 0) throw DaneTlsaException("DNS lookup failed: rcode $rcode")
        if (requireDnssec && (flags and FLAG_AD) == 0) {
            throw DaneTlsaException("DNSSEC validation required but AD flag not set")
        }

        if (readU16(response, 4) != 1) throw DaneTlsaException("DNS response must echo one question")
        val asked = readQuestion(query)
        if (readQuestion(response) != asked) {
            throw DaneTlsaException("DNS response question does not match the query")
        }

        var offset = readName(response, HEADER_SIZE).second + 4
        val answers = mutableListOf<ResourceRecord>()
        repeat(readU16(response, 6)) {
            val (owner, afterName) = readName(response, offset)
            val rdLength = readU16(response, afterName + 8)
            val rdataStart = afterName + 10
            if (rdataStart + rdLength > response.size) {
                throw DaneTlsaException("truncated DNS answer record")
            }
            answers.add(
                ResourceRecord(
                    owner = owner,
                    type = readU16(response, afterName),
                    rrClass = readU16(response, afterName + 2),
                    rdataStart = rdataStart,
                    rdLength = rdLength
                )
            )
            offset = rdataStart + rdLength
        }

        val owners = resolveOwnerNames(response, answers, asked.qname)
        val records = mutableListOf<TlsaRecord>()
        for (answer in answers) {
            if (answer.type != TYPE_TLSA) continue
            if (answer.rrClass != CLASS_IN) {
                throw DaneTlsaException("TLSA record has unexpected class ${answer.rrClass}")
            }
            if (answer.owner !in owners) {
                throw DaneTlsaException("TLSA record owner '${answer.owner}' was not queried")
            }
            if (answer.rdLength < 3) throw DaneTlsaException("malformed TLSA record")
            records.add(
                TlsaRecord(
                    usage = response[answer.rdataStart].toInt() and 0xFF,
                    selector = response[answer.rdataStart + 1].toInt() and 0xFF,
                    matchingType = response[answer.rdataStart + 2].toInt() and 0xFF,
                    certData = response.copyOfRange(
                        answer.rdataStart + 3,
                        answer.rdataStart + answer.rdLength
                    )
                )
            )
        }
        if (records.isEmpty()) throw DaneTlsaException("no TLSA records for query")
        return records
    }

    /**
     * Returns the owner names a TLSA record may legitimately carry: the queried
     * name plus any canonical name reachable from it through CNAMEs in the same
     * answer section (RFC 1034 Section 3.6.2). The chain is depth-limited.
     */
    private fun resolveOwnerNames(
        response: ByteArray,
        answers: List<ResourceRecord>,
        qname: String
    ): Set<String> {
        val owners = linkedSetOf(qname)
        var depth = 0
        var extended = true
        while (extended && depth++ < MAX_CNAME_DEPTH) {
            extended = false
            for (answer in answers) {
                if (answer.type != TYPE_CNAME || answer.rrClass != CLASS_IN) continue
                if (answer.owner !in owners) continue
                if (owners.add(readName(response, answer.rdataStart).first)) extended = true
            }
        }
        return owners
    }

    private fun readQuestion(message: ByteArray): Question {
        val (qname, afterName) = readName(message, HEADER_SIZE)
        return Question(qname, readU16(message, afterName), readU16(message, afterName + 2))
    }

    /**
     * Reads the DNS name starting at [start], following compression pointers
     * (RFC 1035 Section 4.1.4), and returns the lowercased dotted name together
     * with the offset just past the name in the enclosing record. Every offset
     * is bounds-checked, pointers must point strictly backwards (which makes a
     * pointer loop impossible), the number of jumps is capped, and the decoded
     * name may not exceed the protocol's 255-octet limit.
     */
    private fun readName(data: ByteArray, start: Int): Pair<String, Int> {
        val name = StringBuilder()
        var offset = start
        var next = -1
        var jumps = 0
        var encodedLength = 0
        while (true) {
            if (offset < 0 || offset >= data.size) {
                throw DaneTlsaException("malformed DNS name: offset out of bounds")
            }
            val label = data[offset].toInt() and 0xFF
            when {
                (label and 0xC0) == 0xC0 -> {
                    if (offset + 1 >= data.size) {
                        throw DaneTlsaException("malformed DNS name: truncated compression pointer")
                    }
                    val target = ((label and 0x3F) shl 8) or (data[offset + 1].toInt() and 0xFF)
                    if (target >= offset) {
                        throw DaneTlsaException("malformed DNS name: non-backward compression pointer")
                    }
                    if (++jumps > MAX_NAME_JUMPS) {
                        throw DaneTlsaException("malformed DNS name: too many compression pointers")
                    }
                    if (next < 0) next = offset + 2
                    offset = target
                }
                (label and 0xC0) != 0 ->
                    throw DaneTlsaException("malformed DNS name: reserved label type")
                label == 0 -> return Pair(name.toString(), if (next < 0) offset + 1 else next)
                else -> {
                    val labelEnd = offset + 1 + label
                    if (labelEnd > data.size) {
                        throw DaneTlsaException("malformed DNS name: label out of bounds")
                    }
                    encodedLength += label + 1
                    if (encodedLength > MAX_NAME_LENGTH) {
                        throw DaneTlsaException("malformed DNS name: exceeds $MAX_NAME_LENGTH octets")
                    }
                    name.append(String(data, offset + 1, label, Charsets.US_ASCII).lowercase())
                    name.append('.')
                    offset = labelEnd
                }
            }
        }
    }

    private fun writeU16(out: java.io.ByteArrayOutputStream, value: Int) {
        out.write((value shr 8) and 0xFF)
        out.write(value and 0xFF)
    }

    private fun readU16(data: ByteArray, offset: Int): Int {
        if (offset < 0 || offset + 1 >= data.size) {
            throw DaneTlsaException("truncated DNS message")
        }
        return ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)
    }
}

/**
 * RFC 6698/7671 DANE verification of TLS-presented certificate chains,
 * mirroring go-truststrap's `VerifyPeerChain`:
 *
 * - DANE-EE (usage 3) records match the leaf certificate directly with no
 *   PKIX validation and no name check (RFC 7671 Section 5.1).
 * - DANE-TA (usage 2) records require the trust anchor to be present in the
 *   chain; the leaf must PKIX-validate to that anchor and pass a hostname
 *   check (RFC 7671 Sections 5.2.1–5.2.2).
 * - PKIX-TA/EE (0/1) records require WebPKI and are not usable for bootstrap.
 */
object DaneVerifier {

    /**
     * Computes the RFC 6698 Certificate Association Data for [cert] with the
     * given selector and matching type.
     */
    fun computeTlsaData(cert: X509Certificate, selector: Int, matchingType: Int): ByteArray {
        val selected = when (selector) {
            TlsaRecord.SELECTOR_FULL_CERT -> cert.encoded
            TlsaRecord.SELECTOR_SPKI -> cert.publicKey.encoded
            else -> throw DaneTlsaException("unsupported TLSA selector: $selector")
        }
        return when (matchingType) {
            TlsaRecord.MATCHING_EXACT -> selected
            TlsaRecord.MATCHING_SHA256 -> MessageDigest.getInstance("SHA-256").digest(selected)
            TlsaRecord.MATCHING_SHA512 -> MessageDigest.getInstance("SHA-512").digest(selected)
            else -> throw DaneTlsaException("unsupported TLSA matching type: $matchingType")
        }
    }

    /** Verifies a single certificate against a single TLSA record. */
    fun matches(cert: X509Certificate, record: TlsaRecord): Boolean = try {
        MessageDigest.isEqual(computeTlsaData(cert, record.selector, record.matchingType), record.certData)
    } catch (_: DaneTlsaException) {
        false
    }

    /**
     * Verifies a presented chain against TLSA [records] for [hostname]. Any
     * single matching DANE-TA or DANE-EE record satisfies the policy. Throws
     * [DaneTlsaException] when no usable records exist or nothing matches.
     */
    fun verifyPeerChain(chain: List<X509Certificate>, records: List<TlsaRecord>, hostname: String) {
        if (chain.isEmpty()) throw DaneTlsaException("empty peer certificate chain")
        val usable = records.filter {
            it.usage == TlsaRecord.USAGE_DANE_TA || it.usage == TlsaRecord.USAGE_DANE_EE
        }
        if (usable.isEmpty()) throw DaneTlsaException("no usable (DANE-TA/DANE-EE) TLSA records")

        val leaf = chain[0]
        for (record in usable) {
            when (record.usage) {
                TlsaRecord.USAGE_DANE_EE -> if (matches(leaf, record)) return
                TlsaRecord.USAGE_DANE_TA -> if (verifyDaneTa(chain, record, hostname)) return
            }
        }
        throw DaneTlsaException("TLSA verification failed: no record matches presented chain")
    }

    /**
     * Returns an [X509TrustManager] whose sole verification is
     * [verifyPeerChain] — the custom-verifier pattern go-truststrap uses for
     * its DANE `tls.Config`.
     */
    fun trustManager(records: List<TlsaRecord>, hostname: String): X509TrustManager =
        object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
                throw java.security.cert.CertificateException("client authentication not supported")
            }

            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
                try {
                    verifyPeerChain(chain.toList(), records, hostname)
                } catch (e: DaneTlsaException) {
                    throw java.security.cert.CertificateException(e.message, e)
                }
            }

            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        }

    private fun verifyDaneTa(chain: List<X509Certificate>, record: TlsaRecord, hostname: String): Boolean {
        val anchor = chain.firstOrNull { matches(it, record) } ?: return false
        val leaf = chain[0]
        if (!matchesHostname(leaf, hostname)) return false
        if (anchor == leaf) return true
        return try {
            val factory = CertificateFactory.getInstance("X.509")
            val path = factory.generateCertPath(chain.takeWhile { it != anchor })
            val params = PKIXParameters(setOf(TrustAnchor(anchor, null))).apply {
                isRevocationEnabled = false
            }
            CertPathValidator.getInstance("PKIX").validate(path, params)
            true
        } catch (_: Exception) {
            false
        }
    }

    /**
     * RFC 6125-style hostname check against the certificate's dNSName SANs:
     * case-insensitive exact match or a single left-most wildcard label.
     */
    internal fun matchesHostname(cert: X509Certificate, hostname: String): Boolean {
        val host = hostname.trimEnd('.').lowercase()
        val sans = try {
            cert.subjectAlternativeNames ?: return false
        } catch (_: Exception) {
            return false
        }
        for (san in sans) {
            if ((san[0] as? Int) != 2) continue // dNSName
            val pattern = (san[1] as? String)?.trimEnd('.')?.lowercase() ?: continue
            if (pattern == host) return true
            if (pattern.startsWith("*.")) {
                val suffix = pattern.substring(1) // ".example.com"
                val prefix = host.removeSuffix(suffix)
                if (host.endsWith(suffix) && prefix.isNotEmpty() && !prefix.contains('.')) return true
            }
        }
        return false
    }
}
