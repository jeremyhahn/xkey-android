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

/**
 * RFC 4648 Base32 codec (standard alphabet A-Z, 2-7), used for OATH shared
 * secrets. Encoding is unpadded by default to match common authenticator output;
 * decoding accepts optional `=` padding and is case-insensitive.
 */
object Base32 {
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    /**
     * Encode [data] to an (unpadded) Base32 string.
     */
    fun encode(data: ByteArray): String {
        if (data.isEmpty()) return ""
        val sb = StringBuilder((data.size * 8 + 4) / 5)
        var buffer = 0
        var bitsLeft = 0
        for (b in data) {
            buffer = (buffer shl 8) or (b.toInt() and 0xFF)
            bitsLeft += 8
            while (bitsLeft >= 5) {
                val index = (buffer shr (bitsLeft - 5)) and 0x1F
                sb.append(ALPHABET[index])
                bitsLeft -= 5
            }
        }
        if (bitsLeft > 0) {
            val index = (buffer shl (5 - bitsLeft)) and 0x1F
            sb.append(ALPHABET[index])
        }
        return sb.toString()
    }

    /**
     * Decode a Base32 [encoded] string to raw bytes. Whitespace and `=` padding
     * are ignored; input is case-insensitive.
     *
     * @throws IllegalArgumentException if the input contains invalid characters.
     */
    fun decode(encoded: String): ByteArray {
        val clean = encoded.trim().trimEnd('=').uppercase().replace(" ", "")
        if (clean.isEmpty()) return ByteArray(0)
        val out = ArrayList<Byte>(clean.length * 5 / 8)
        var buffer = 0
        var bitsLeft = 0
        for (char in clean) {
            val index = ALPHABET.indexOf(char)
            require(index >= 0) { "Invalid Base32 character: '$char'" }
            buffer = (buffer shl 5) or index
            bitsLeft += 5
            if (bitsLeft >= 8) {
                out.add(((buffer shr (bitsLeft - 8)) and 0xFF).toByte())
                bitsLeft -= 8
            }
        }
        return out.toByteArray()
    }
}
