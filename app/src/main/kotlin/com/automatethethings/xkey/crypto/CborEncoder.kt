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
}
