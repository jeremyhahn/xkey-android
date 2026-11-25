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
package com.automatethethings.xkey.piv

/**
 * PIV public key values, the tag 0x86 value a YubiKey returns inside TLV
 * 0x7F49 for an EC or curve 25519 key:
 *
 * - Ed25519 and X25519: the raw 32-byte key (RFC 8410 carries exactly this
 *   in the SubjectPublicKeyInfo BIT STRING).
 * - ECDSA P-256 and P-384: the uncompressed point `04 || X || Y`.
 *
 * RSA keys have no tag 0x86 value (a YubiKey answers tags 0x81/0x82) and are
 * refused. Parsing is strict DER: a truncated encoding, trailing bytes, an
 * unknown curve or a key of the wrong length is refused with
 * [IllegalArgumentException].
 */
object PivPublicKeyEncoding {

    private val OID_ED25519 = byteArrayOf(0x2B, 0x65, 0x70)
    private val OID_X25519 = byteArrayOf(0x2B, 0x65, 0x6E)
    private val OID_EC_PUBLIC_KEY = byteArrayOf(0x2A, 0x86.toByte(), 0x48, 0xCE.toByte(), 0x3D, 0x02, 0x01)
    private val OID_P256 = byteArrayOf(0x2A, 0x86.toByte(), 0x48, 0xCE.toByte(), 0x3D, 0x03, 0x01, 0x07)
    private val OID_P384 = byteArrayOf(0x2B, 0x81.toByte(), 0x04, 0x00, 0x22)

    private const val TAG_SEQUENCE = 0x30
    private const val TAG_OID = 0x06
    private const val TAG_BIT_STRING = 0x03

    /** Length in bytes of a raw Ed25519 or X25519 public key. */
    const val CURVE25519_KEY_SIZE = 32

    /**
     * The PIV tag 0x86 value of the key in SubjectPublicKeyInfo [spki].
     *
     * @throws IllegalArgumentException if [spki] is not a well-formed
     *   Ed25519, X25519, P-256 or P-384 SubjectPublicKeyInfo.
     */
    fun pivPublicKeyValue(spki: ByteArray): ByteArray {
        val outer = Der(spki, 0, spki.size)
        val body = outer.read(TAG_SEQUENCE)
        outer.requireEnd()

        val algorithm = body.read(TAG_SEQUENCE)
        val keyBits = body.read(TAG_BIT_STRING)
        body.requireEnd()

        val oid = algorithm.read(TAG_OID).bytes()
        val key = keyBits.bytes()
        require(key.isNotEmpty() && key[0] == 0.toByte()) { "public key BIT STRING has unused bits" }
        val value = key.copyOfRange(1, key.size)

        return when {
            oid.contentEquals(OID_ED25519) || oid.contentEquals(OID_X25519) -> {
                algorithm.requireEnd()
                require(value.size == CURVE25519_KEY_SIZE) {
                    "curve 25519 public key is ${value.size} bytes, not $CURVE25519_KEY_SIZE"
                }
                value
            }
            oid.contentEquals(OID_EC_PUBLIC_KEY) -> {
                val curve = algorithm.read(TAG_OID).bytes()
                algorithm.requireEnd()
                val coordinateSize = when {
                    curve.contentEquals(OID_P256) -> 32
                    curve.contentEquals(OID_P384) -> 48
                    else -> throw IllegalArgumentException("unsupported EC curve")
                }
                require(value.size == 1 + 2 * coordinateSize && value[0] == 0x04.toByte()) {
                    "EC public key is not an uncompressed point"
                }
                value
            }
            else -> throw IllegalArgumentException("public key has no PIV tag 0x86 value")
        }
    }

    /** The Ed25519 SubjectPublicKeyInfo (RFC 8410) carrying raw key [raw32]. */
    fun ed25519Spki(raw32: ByteArray): ByteArray = curve25519Spki(OID_ED25519, raw32)

    /** The X25519 SubjectPublicKeyInfo (RFC 8410) carrying raw key [raw32]. */
    fun x25519Spki(raw32: ByteArray): ByteArray = curve25519Spki(OID_X25519, raw32)

    private fun curve25519Spki(oid: ByteArray, raw32: ByteArray): ByteArray {
        require(raw32.size == CURVE25519_KEY_SIZE) {
            "curve 25519 public key is ${raw32.size} bytes, not $CURVE25519_KEY_SIZE"
        }
        // SEQUENCE(42) { SEQUENCE(5) { OID(3) }, BIT STRING(33) { 00, key } }
        return byteArrayOf(TAG_SEQUENCE.toByte(), 0x2A, TAG_SEQUENCE.toByte(), 0x05, TAG_OID.toByte(), 0x03) +
            oid + byteArrayOf(TAG_BIT_STRING.toByte(), 0x21, 0x00) + raw32
    }

    /** A cursor over the DER bytes `data[start until end]`. */
    private class Der(private val data: ByteArray, private var pos: Int, private val end: Int) {

        /** Reads one element with [tag] and returns a cursor over its content. */
        fun read(tag: Int): Der {
            require(pos < end && (data[pos].toInt() and 0xFF) == tag) { "expected DER tag 0x%02X".format(tag) }
            pos++
            require(pos < end) { "DER element is truncated" }
            val first = data[pos++].toInt() and 0xFF
            val length = when {
                first < 0x80 -> first
                first == 0x81 -> {
                    require(pos < end) { "DER length is truncated" }
                    (data[pos++].toInt() and 0xFF).also { require(it >= 0x80) { "DER length is not minimal" } }
                }
                first == 0x82 -> {
                    require(pos + 1 < end) { "DER length is truncated" }
                    (((data[pos].toInt() and 0xFF) shl 8) or (data[pos + 1].toInt() and 0xFF)).also {
                        pos += 2
                        require(it >= 0x100) { "DER length is not minimal" }
                    }
                }
                else -> throw IllegalArgumentException("unsupported DER length")
            }
            require(length <= end - pos) { "DER element is truncated" }
            return Der(data, pos, pos + length).also { pos += length }
        }

        /** The remaining content bytes. */
        fun bytes(): ByteArray = data.copyOfRange(pos, end).also { pos = end }

        fun requireEnd() = require(pos == end) { "unexpected bytes after DER element" }
    }
}
