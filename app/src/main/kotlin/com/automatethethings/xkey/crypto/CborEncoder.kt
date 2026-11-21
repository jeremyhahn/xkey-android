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
package com.automatethethings.xkey.crypto

import java.io.ByteArrayOutputStream

/**
 * Minimal CBOR encoder for COSE_Key structures.
 *
 * This encoder implements only what is needed for EC2 P-256 public keys
 * used in FIDO2/WebAuthn credential responses. The encoding follows
 * RFC 8949 (CBOR) and RFC 9052 (COSE).
 *
 * COSE_Key structure for EC2 P-256:
 * ```
 * {
 *   1: 2,    // kty: EC2
 *   3: -7,   // alg: ES256
 *   -1: 1,   // crv: P-256
 *   -2: x,   // x coordinate (32 bytes)
 *   -3: y    // y coordinate (32 bytes)
 * }
 * ```
 */
object CborEncoder {

    // COSE key type constants
    private const val COSE_KEY_TYPE_EC2 = 2

    // COSE algorithm constants
    private const val COSE_ALG_ES256 = -7

    // COSE curve constants
    private const val COSE_CURVE_P256 = 1

    // COSE key parameter labels
    private const val COSE_LABEL_KTY = 1
    private const val COSE_LABEL_ALG = 3
    private const val COSE_LABEL_CRV = -1
    private const val COSE_LABEL_X = -2
    private const val COSE_LABEL_Y = -3

    // CBOR major types
    private const val CBOR_UNSIGNED_INT: Byte = 0x00
    private const val CBOR_NEGATIVE_INT: Byte = 0x20
    private const val CBOR_BYTE_STRING: Byte = 0x40
    private const val CBOR_MAP: Byte = 0xA0.toByte()

    // EC coordinate size for P-256
    private const val P256_COORDINATE_SIZE = 32

    /**
     * Encode a COSE EC2 P-256 public key.
     *
     * The COSE_Key structure is encoded in canonical CBOR format with
     * map keys sorted in ascending order (as required by CTAP2).
     *
     * @param x The X coordinate of the EC point (must be exactly 32 bytes).
     * @param y The Y coordinate of the EC point (must be exactly 32 bytes).
     * @return CBOR-encoded COSE_Key byte array.
     * @throws CborEncodingException if coordinates are invalid.
     */
    fun encodeCOSEEC2Key(x: ByteArray, y: ByteArray): ByteArray {
        if (x.size != P256_COORDINATE_SIZE) {
            throw CborEncodingException(
                "X coordinate must be $P256_COORDINATE_SIZE bytes, got ${x.size}"
            )
        }
        if (y.size != P256_COORDINATE_SIZE) {
            throw CborEncodingException(
                "Y coordinate must be $P256_COORDINATE_SIZE bytes, got ${y.size}"
            )
        }

        val buffer = ByteArrayOutputStream(128)

        // Map with 5 items: 0xA5
        buffer.write(CBOR_MAP.toInt() or 5)

        // Keys must be in canonical order (numerically ascending):
        // -3, -2, -1, 1, 3 -> encoded as: 1, 3, -1, -2, -3
        // Actually canonical CBOR sorts by encoded bytes, so:
        // positive ints come before negative ints of same magnitude
        // 1 (0x01) < 3 (0x03) < -1 (0x20) < -2 (0x21) < -3 (0x22)

        // 1: 2 (kty: EC2)
        encodeUnsignedInt(buffer, COSE_LABEL_KTY)
        encodeUnsignedInt(buffer, COSE_KEY_TYPE_EC2)

        // 3: -7 (alg: ES256)
        encodeUnsignedInt(buffer, COSE_LABEL_ALG)
        encodeNegativeInt(buffer, COSE_ALG_ES256)

        // -1: 1 (crv: P-256)
        encodeNegativeInt(buffer, COSE_LABEL_CRV)
        encodeUnsignedInt(buffer, COSE_CURVE_P256)

        // -2: x (32 bytes)
        encodeNegativeInt(buffer, COSE_LABEL_X)
        encodeByteString(buffer, x)

        // -3: y (32 bytes)
        encodeNegativeInt(buffer, COSE_LABEL_Y)
        encodeByteString(buffer, y)

        return buffer.toByteArray()
    }

    /**
     * Encode an unsigned integer in CBOR format.
     *
     * CBOR unsigned integers:
     * - 0-23: single byte (major type | value)
     * - 24-255: 0x18 followed by 1 byte
     * - 256-65535: 0x19 followed by 2 bytes
     *
     * @param buffer Output buffer to write to.
     * @param value The unsigned integer value to encode.
     */
    private fun encodeUnsignedInt(buffer: ByteArrayOutputStream, value: Int) {
        require(value >= 0) { "Value must be non-negative for unsigned encoding" }

        when {
            value <= 23 -> {
                buffer.write(CBOR_UNSIGNED_INT.toInt() or value)
            }
            value <= 255 -> {
                buffer.write(CBOR_UNSIGNED_INT.toInt() or 24)
                buffer.write(value)
            }
            value <= 65535 -> {
                buffer.write(CBOR_UNSIGNED_INT.toInt() or 25)
                buffer.write(value shr 8)
                buffer.write(value and 0xFF)
            }
            else -> {
                buffer.write(CBOR_UNSIGNED_INT.toInt() or 26)
                buffer.write(value shr 24)
                buffer.write((value shr 16) and 0xFF)
                buffer.write((value shr 8) and 0xFF)
                buffer.write(value and 0xFF)
            }
        }
    }

    /**
     * Encode a negative integer in CBOR format.
     *
     * CBOR negative integers are encoded as major type 1 with the value
     * being (-1 - n), so -1 is encoded as 0x20, -7 is encoded as 0x26.
     *
     * @param buffer Output buffer to write to.
     * @param value The negative integer value to encode.
     */
    private fun encodeNegativeInt(buffer: ByteArrayOutputStream, value: Int) {
        require(value < 0) { "Value must be negative for negative encoding" }

        // CBOR negative int encoding: -1 - n, where n is the encoded value
        // So -1 becomes 0, -7 becomes 6, etc.
        val encodedValue = -1 - value

        when {
            encodedValue <= 23 -> {
                buffer.write(CBOR_NEGATIVE_INT.toInt() or encodedValue)
            }
            encodedValue <= 255 -> {
                buffer.write(CBOR_NEGATIVE_INT.toInt() or 24)
                buffer.write(encodedValue)
            }
            encodedValue <= 65535 -> {
                buffer.write(CBOR_NEGATIVE_INT.toInt() or 25)
                buffer.write(encodedValue shr 8)
                buffer.write(encodedValue and 0xFF)
            }
            else -> {
                buffer.write(CBOR_NEGATIVE_INT.toInt() or 26)
                buffer.write(encodedValue shr 24)
                buffer.write((encodedValue shr 16) and 0xFF)
                buffer.write((encodedValue shr 8) and 0xFF)
                buffer.write(encodedValue and 0xFF)
            }
        }
    }

    /**
     * Encode a byte string in CBOR format.
     *
     * CBOR byte strings use major type 2 (0x40) with the length encoded
     * the same way as unsigned integers.
     *
     * @param buffer Output buffer to write to.
     * @param bytes The byte array to encode.
     */
    private fun encodeByteString(buffer: ByteArrayOutputStream, bytes: ByteArray) {
        val length = bytes.size

        when {
            length <= 23 -> {
                buffer.write(CBOR_BYTE_STRING.toInt() or length)
            }
            length <= 255 -> {
                buffer.write(CBOR_BYTE_STRING.toInt() or 24)
                buffer.write(length)
            }
            length <= 65535 -> {
                buffer.write(CBOR_BYTE_STRING.toInt() or 25)
                buffer.write(length shr 8)
                buffer.write(length and 0xFF)
            }
            else -> {
                buffer.write(CBOR_BYTE_STRING.toInt() or 26)
                buffer.write(length shr 24)
                buffer.write((length shr 16) and 0xFF)
                buffer.write((length shr 8) and 0xFF)
                buffer.write(length and 0xFF)
            }
        }

        buffer.write(bytes)
    }

    /**
     * Encode [value] as CTAP2 canonical CBOR (CTAP 2.1, "Message Encoding").
     *
     * Supports [Int], [Long], [ByteArray], [String], [Boolean], `null`,
     * [List] and [Map]. Integers use their shortest form, lengths are
     * definite, and map keys (integers or text) are sorted by their encoded
     * bytes, shorter first, which is the CTAP2 canonical order.
     *
     * @throws CborEncodingException for a value of any other type.
     */
    fun encode(value: Any?): ByteArray {
        val buffer = ByteArrayOutputStream()
        writeValue(buffer, value)
        return buffer.toByteArray()
    }

    private fun writeValue(buffer: ByteArrayOutputStream, value: Any?) {
        when (value) {
            null -> buffer.write(0xF6)
            is Boolean -> buffer.write(if (value) 0xF5 else 0xF4)
            is Int -> writeInteger(buffer, value.toLong())
            is Long -> writeInteger(buffer, value)
            is ByteArray -> {
                writeHead(buffer, 2, value.size.toLong())
                buffer.write(value)
            }
            is String -> {
                val utf8 = value.toByteArray(Charsets.UTF_8)
                writeHead(buffer, 3, utf8.size.toLong())
                buffer.write(utf8)
            }
            is List<*> -> {
                writeHead(buffer, 4, value.size.toLong())
                value.forEach { writeValue(buffer, it) }
            }
            is Map<*, *> -> {
                val entries = value.entries.map { (k, v) ->
                    if (k !is Int && k !is Long && k !is String) {
                        throw CborEncodingException("CBOR map key must be an integer or text, got ${k?.javaClass}")
                    }
                    encode(k) to v
                }.sortedWith { a, b -> compareCanonical(a.first, b.first) }
                writeHead(buffer, 5, entries.size.toLong())
                entries.forEach { (key, v) ->
                    buffer.write(key)
                    writeValue(buffer, v)
                }
            }
            else -> throw CborEncodingException("Cannot CBOR-encode ${value.javaClass}")
        }
    }

    private fun writeInteger(buffer: ByteArrayOutputStream, value: Long) {
        if (value >= 0) writeHead(buffer, 0, value) else writeHead(buffer, 1, -1 - value)
    }

    private fun writeHead(buffer: ByteArrayOutputStream, major: Int, argument: Long) {
        val type = major shl 5
        when {
            argument < 24 -> buffer.write(type or argument.toInt())
            argument <= 0xFF -> {
                buffer.write(type or 24)
                buffer.write(argument.toInt())
            }
            argument <= 0xFFFF -> {
                buffer.write(type or 25)
                for (shift in intArrayOf(8, 0)) buffer.write((argument shr shift).toInt() and 0xFF)
            }
            argument <= 0xFFFFFFFFL -> {
                buffer.write(type or 26)
                for (shift in intArrayOf(24, 16, 8, 0)) buffer.write((argument shr shift).toInt() and 0xFF)
            }
            else -> {
                buffer.write(type or 27)
                for (shift in 56 downTo 0 step 8) buffer.write((argument shr shift).toInt() and 0xFF)
            }
        }
    }

    /**
     * CTAP2 canonical key order over encoded keys: major type first
     * (unsigned, then negative integers, then text), then within a type the
     * shorter encoding, then bytewise. Within a type this orders unsigned
     * integers by value, negative integers by magnitude (-1 before -2) and
     * text shorter first, then lexically.
     */
    private fun compareCanonical(a: ByteArray, b: ByteArray): Int {
        val majorA = (a[0].toInt() and 0xFF) shr 5
        val majorB = (b[0].toInt() and 0xFF) shr 5
        if (majorA != majorB) return majorA - majorB
        if (a.size != b.size) return a.size - b.size
        for (i in a.indices) {
            val d = (a[i].toInt() and 0xFF) - (b[i].toInt() and 0xFF)
            if (d != 0) return d
        }
        return 0
    }
}

/** Thrown when CBOR input is malformed, truncated or outside what [CborDecoder] accepts. */
class CborDecodingException(message: String) : Exception(message)

/**
 * Minimal CBOR decoder (RFC 8949) for CTAP2 requests.
 *
 * Accepts definite-length unsigned and negative integers, byte strings, text
 * strings, arrays, maps, `false`, `true` and `null`. Integers decode to
 * [Long], byte strings to [ByteArray], text to [String], arrays to [List] and
 * maps to an insertion-ordered [Map]. Indefinite lengths, tags, floats,
 * trailing bytes and nesting deeper than [MAX_DEPTH] are refused: CTAP2
 * messages never use them, and refusing keeps a hostile client from
 * steering the parser.
 */
object CborDecoder {

    /** Deepest nesting accepted; CTAP2 messages need four levels. */
    const val MAX_DEPTH = 8

    fun decode(bytes: ByteArray): Any? {
        val reader = Reader(bytes)
        val value = reader.read(0)
        if (reader.pos != bytes.size) {
            throw CborDecodingException("${bytes.size - reader.pos} trailing bytes after the CBOR item")
        }
        return value
    }

    private class Reader(val bytes: ByteArray) {
        var pos = 0

        fun byte(): Int {
            if (pos >= bytes.size) throw CborDecodingException("CBOR input ends early")
            return bytes[pos++].toInt() and 0xFF
        }

        fun argument(info: Int): Long = when {
            info < 24 -> info.toLong()
            info == 24 -> byte().toLong()
            info == 25 -> (byte().toLong() shl 8) or byte().toLong()
            info == 26 -> (0 until 4).fold(0L) { acc, _ -> (acc shl 8) or byte().toLong() }
            info == 27 -> {
                val v = (0 until 8).fold(0L) { acc, _ -> (acc shl 8) or byte().toLong() }
                if (v < 0) throw CborDecodingException("CBOR integer exceeds 63 bits")
                v
            }
            else -> throw CborDecodingException("CBOR indefinite or reserved length (info $info)")
        }

        fun length(info: Int): Int {
            val n = argument(info)
            if (n > bytes.size - pos) throw CborDecodingException("CBOR length $n exceeds the input")
            return n.toInt()
        }

        fun read(depth: Int): Any? {
            if (depth > MAX_DEPTH) throw CborDecodingException("CBOR nesting deeper than $MAX_DEPTH")
            val initial = byte()
            val major = initial shr 5
            val info = initial and 0x1F
            return when (major) {
                0 -> argument(info)
                1 -> -1L - argument(info)
                2 -> {
                    val n = length(info)
                    bytes.copyOfRange(pos, pos + n).also { pos += n }
                }
                3 -> {
                    val n = length(info)
                    val decoder = Charsets.UTF_8.newDecoder()
                        .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                        .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
                    val text = try {
                        decoder.decode(java.nio.ByteBuffer.wrap(bytes, pos, n)).toString()
                    } catch (e: java.nio.charset.CharacterCodingException) {
                        throw CborDecodingException("CBOR text string is not valid UTF-8")
                    }
                    pos += n
                    text
                }
                4 -> {
                    // Each element takes at least one byte, so the bound holds.
                    val n = length(info)
                    List(n) { read(depth + 1) }
                }
                5 -> {
                    val n = length(info)
                    val map = LinkedHashMap<Any?, Any?>()
                    repeat(n) {
                        val key = read(depth + 1)
                        if (key is ByteArray || key is List<*> || key is Map<*, *>) {
                            throw CborDecodingException("CBOR map key must be an integer or text")
                        }
                        if (map.containsKey(key)) throw CborDecodingException("CBOR map has duplicate key $key")
                        map[key] = read(depth + 1)
                    }
                    map
                }
                7 -> when (info) {
                    20 -> false
                    21 -> true
                    22 -> null
                    else -> throw CborDecodingException("CBOR simple or float value $info is not supported")
                }
                else -> throw CborDecodingException("CBOR major type $major is not supported")
            }
        }
    }
}
