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

import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.ServerSocket
import java.net.SocketException

/**
 * A loopback DNS server that answers TLSA queries with canned bytes.
 *
 * `DnsTlsaResolver` only reaches its UDP exchange, truncation retry and TCP
 * framing when something actually answers on the wire, so this binds the *same*
 * ephemeral port for both UDP and TCP -- which is what a real resolver does, and
 * what the truncation fallback needs, since the client derives the TCP endpoint
 * from the same configured `host:port`.
 *
 * [respond] receives the raw query and whether it arrived over TCP; returning
 * null leaves the query unanswered, which is how the timeout path is driven.
 */
internal class DnsStubServer(
    private val respond: (query: ByteArray, overTcp: Boolean) -> ByteArray?
) : AutoCloseable {

    private val loopback: InetAddress = InetAddress.getLoopbackAddress()
    private val udp: DatagramSocket
    private val tcp: ServerSocket

    /** The port both listeners share. */
    val port: Int

    /** `host:port` for `daneDnsServer`. */
    val address: String

    init {
        var boundUdp: DatagramSocket? = null
        var boundTcp: ServerSocket? = null
        for (attempt in 1..BIND_ATTEMPTS) {
            val candidate = DatagramSocket(0, loopback)
            try {
                boundTcp = ServerSocket(candidate.localPort, 1, loopback)
                boundUdp = candidate
                break
            } catch (_: SocketException) {
                candidate.close()
            } catch (_: java.io.IOException) {
                candidate.close()
            }
        }
        udp = requireNotNull(boundUdp) { "could not bind UDP and TCP to one loopback port" }
        tcp = requireNotNull(boundTcp)
        port = udp.localPort
        address = "127.0.0.1:$port"

        Thread({ serveUdp() }, "dns-stub-udp").apply { isDaemon = true }.start()
        Thread({ serveTcp() }, "dns-stub-tcp").apply { isDaemon = true }.start()
    }

    private fun serveUdp() {
        val buffer = ByteArray(BUFFER_SIZE)
        while (!udp.isClosed) {
            try {
                val packet = DatagramPacket(buffer, buffer.size)
                udp.receive(packet)
                val reply = respond(buffer.copyOf(packet.length), false) ?: continue
                udp.send(DatagramPacket(reply, reply.size, packet.address, packet.port))
            } catch (_: Exception) {
                return
            }
        }
    }

    private fun serveTcp() {
        while (!tcp.isClosed) {
            try {
                tcp.accept().use { socket ->
                    val input = DataInputStream(socket.getInputStream())
                    val query = ByteArray(input.readUnsignedShort())
                    input.readFully(query)
                    val reply = respond(query, true) ?: return@use
                    val output = DataOutputStream(socket.getOutputStream())
                    output.writeShort(reply.size)
                    output.write(reply)
                    output.flush()
                }
            } catch (_: Exception) {
                return
            }
        }
    }

    override fun close() {
        runCatching { udp.close() }
        runCatching { tcp.close() }
    }

    companion object {
        private const val BIND_ATTEMPTS = 32
        private const val BUFFER_SIZE = 4096

        /** A loopback port with nothing bound to it. */
        fun unusedAddress(): String {
            val socket = DatagramSocket(0, InetAddress.getLoopbackAddress())
            val port = socket.localPort
            socket.close()
            return "127.0.0.1:$port"
        }
    }
}

/** A resource record to serialize into a synthetic DNS answer section. */
internal class DnsAnswer(
    val owner: String,
    val type: Int,
    val rdata: ByteArray,
    val rrClass: Int = DnsWire.CLASS_IN
)

/**
 * Hand encoders for the slice of RFC 1035 the resolver parses. Responses are
 * built from the real query so the transaction ID and question section echo
 * exactly what was asked, which is what `parseResponse` insists on.
 */
internal object DnsWire {

    const val TYPE_TLSA = 52
    const val TYPE_CNAME = 5
    const val CLASS_IN = 1
    const val CLASS_CH = 3

    const val FLAG_QR = 0x8000
    const val FLAG_RD = 0x0100
    const val FLAG_RA = 0x0080
    const val FLAG_TC = 0x0200
    const val FLAG_AD = 0x0020

    /** QR + RD + RA + AD, rcode NOERROR: what a validating resolver returns. */
    const val FLAGS_OK = FLAG_QR or FLAG_RD or FLAG_RA or FLAG_AD

    fun encodeName(name: String): ByteArray {
        val out = ByteArrayOutputStream()
        for (label in name.trimEnd('.').split('.')) {
            val bytes = label.toByteArray(Charsets.US_ASCII)
            out.write(bytes.size)
            out.write(bytes)
        }
        out.write(0)
        return out.toByteArray()
    }

    fun tlsaRdata(usage: Int, selector: Int, matching: Int, association: ByteArray): ByteArray =
        byteArrayOf(usage.toByte(), selector.toByte(), matching.toByte()) + association

    /** The (lowercased, dot-terminated) name [query] asks about. */
    fun queriedName(query: ByteArray): String {
        val name = StringBuilder()
        var offset = HEADER_SIZE
        while (query[offset].toInt() != 0) {
            val length = query[offset].toInt() and 0xFF
            name.append(String(query, offset + 1, length, Charsets.US_ASCII).lowercase())
            name.append('.')
            offset += length + 1
        }
        return name.toString()
    }

    /** The question section of [query], copied verbatim. */
    fun questionOf(query: ByteArray): ByteArray {
        var offset = HEADER_SIZE
        while (query[offset].toInt() != 0) {
            offset += (query[offset].toInt() and 0xFF) + 1
        }
        return query.copyOfRange(HEADER_SIZE, offset + 1 + 4)
    }

    /**
     * A response to [query] carrying [answers], with [flags] in the header and
     * an optional [answerCount] override so a test can lie about ANCOUNT.
     */
    fun replyTo(
        query: ByteArray,
        answers: List<DnsAnswer>,
        flags: Int = FLAGS_OK,
        questionCount: Int = 1,
        answerCount: Int = answers.size
    ): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(query[0].toInt())
        out.write(query[1].toInt())
        out.writeU16(flags)
        out.writeU16(questionCount)
        out.writeU16(answerCount)
        out.writeU16(0)
        out.writeU16(0)
        out.write(questionOf(query))
        answers.forEach { answer ->
            out.write(encodeName(answer.owner))
            out.writeU16(answer.type)
            out.writeU16(answer.rrClass)
            out.writeU16(0)
            out.writeU16(300)
            out.writeU16(answer.rdata.size)
            out.write(answer.rdata)
        }
        return out.toByteArray()
    }

    private const val HEADER_SIZE = 12
}

/** Writes [value] as a big-endian 16-bit field, the only integer DNS uses. */
internal fun ByteArrayOutputStream.writeU16(value: Int) {
    write((value shr 8) and 0xFF)
    write(value and 0xFF)
}
